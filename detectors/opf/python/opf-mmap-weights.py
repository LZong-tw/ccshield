import json
import mmap
import os
import struct
import warnings

import torch

DTYPES = {"BF16": torch.bfloat16, "F16": torch.float16, "F32": torch.float32}


class MappedCheckpoint:
    """Read-only mmap views of a safetensors checkpoint directory.

    File-backed pages can be dropped and re-read under memory pressure instead of being compressed or
    swapped like the anonymous copies OPF loads. The mapping is read-only, so any write through a view
    faults instead of silently changing weights.
    """

    def __init__(self, checkpoint):
        self.root = os.path.realpath(checkpoint)
        self.index = {}
        self.mappings = []
        for name in sorted(os.listdir(self.root)):
            if not name.endswith(".safetensors"):
                continue
            path = os.path.join(self.root, name)
            with open(path, "rb") as file:
                (header_bytes,) = struct.unpack("<Q", file.read(8))
                header = json.loads(file.read(header_bytes))
                mapping = mmap.mmap(file.fileno(), 0, access=mmap.ACCESS_READ)
            self.mappings.append(mapping)
            for key, entry in header.items():
                if key == "__metadata__" or entry.get("dtype") not in DTYPES:
                    continue
                if key in self.index:
                    raise RuntimeError("duplicate checkpoint tensor")
                start, end = entry["data_offsets"]
                self.index[key] = (path, mapping, DTYPES[entry["dtype"]], tuple(entry["shape"]), 8 + header_bytes + start, end - start)

    def view(self, name):
        _, mapping, dtype, shape, offset, size = self.index[name]
        with warnings.catch_warnings():
            # Read-only on purpose: a write faults rather than reaching the checkpoint.
            warnings.filterwarnings("ignore", message="The given buffer is not writable")
            tensor = torch.frombuffer(mapping, dtype=dtype, count=size // torch.empty((), dtype=dtype).element_size(), offset=offset)
        return tensor.view(shape)

    def serve(self, reader):
        """Make OPF's checkpoint reader return views of this mapping instead of reading private copies."""
        original = reader._get_tensor
        index = self.index

        def get_tensor(checkpoint, name):
            entry = index.get(name)
            if entry is None or os.path.realpath(checkpoint.tensor_name_to_file[name]) != entry[0]:
                return original(checkpoint, name)
            return self.view(name)

        reader._get_tensor = get_tensor

    def map_parameters(self, model, name_map):
        """Swap loaded parameters for the mapped views they were copied from.

        OPF loaded these through serve(), so a parameter whose dtype and shape match already holds the
        mapped bytes; anything converted or reshaped keeps its loaded copy. Comparing the two would only
        compare the mapping with itself, so correctness is proved by the worker's known-answer warm-up.
        """
        mapped = kept = 0
        for name, param in model.named_parameters():
            source = name_map.get(name, name)
            if isinstance(source, tuple):
                source = source[0].rsplit(".blocks", 1)[0]
            entry = self.index.get(source)
            size = param.numel() * param.element_size()
            if entry is None or entry[2] != param.dtype or entry[3] != tuple(param.shape) or entry[5] != size:
                kept += size
                continue
            param.data = self.view(source)
            mapped += size
        if mapped == 0:
            raise RuntimeError("no weights mapped")
        # The mappings must outlive every view; keep them on the model.
        model._ccshield_weight_mappings = self.mappings
        return {"mapped_bytes": mapped, "kept_bytes": kept}
