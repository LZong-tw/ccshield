"""Experimental process-local OPF CPU MoE replacement, never installed live."""
import torch
import torch.nn.functional as F
from opf._common.env import get_env_bool
from opf._model.model import swiglu


def grouped_forward(self, x):
    if x.dim() != 3:
        raise ValueError("MLPBlock expects batched 3D tensor input")
    if self.training or torch.is_grad_enabled():
        raise RuntimeError("grouped prototype supports inference only")
    if x.device.type != "cpu" or self.world_size != 1:
        raise RuntimeError("grouped prototype supports CPU world_size=1 only")
    if get_env_bool("OPF_MOE_TRITON", default=False):
        raise RuntimeError("grouped CPU prototype does not support Triton")
    if any(parameter.device.type != "cpu" for parameter in self.parameters()):
        raise RuntimeError("all expert parameters must be on CPU")

    batch_shape = x.shape[:-1]
    t = self.norm(x).reshape(-1, x.shape[-1])
    g = F.linear(t.float(), self.gate.weight.float(), self.gate.bias.float())
    experts = torch.topk(g, k=self.experts_per_token, dim=-1, sorted=True)
    weights = F.softmax(experts.values, dim=1) / self.experts_per_token
    indices = experts.indices
    flat_indices = indices.reshape(-1)
    sorted_slots = torch.argsort(flat_indices)
    counts = torch.bincount(flat_indices, minlength=self.num_experts).tolist()
    output = torch.empty((t.shape[0], self.experts_per_token, t.shape[1]),
                         dtype=torch.float32, device=t.device)
    flat_output = output.reshape(-1, t.shape[1])
    offset = 0
    for expert, count in enumerate(counts):
        if count == 0:
            continue
        slots = sorted_slots[offset:offset+count]
        token_ids = torch.div(slots, self.experts_per_token, rounding_mode="floor")
        # Convert one expert's matrices rather than a token-expanded gather.
        selected = t[token_ids].float()
        hidden = selected @ self.mlp1_weight[expert].float()
        hidden = hidden + self.mlp1_bias[expert].float()
        hidden = swiglu(hidden, limit=self.swiglu_limit, packed=self.packed_geglu)
        expert_output = hidden.float() @ self.mlp2_weight[expert].float()
        expert_output = expert_output + self.mlp2_bias[expert].float()
        flat_output[slots] = expert_output
        offset += count
    # Restore top-k slot order before the unchanged weighted reduction.
    output = torch.einsum("bec,be->bc", output, weights)
    output = output * self.experts_per_token
    return x + output.to(x.dtype).reshape(*batch_shape, -1)
