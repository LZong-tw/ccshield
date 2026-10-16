"""Offline exact-window logits cache prototype; never caches privacy decisions."""
from collections import OrderedDict
from math import isfinite
from time import monotonic
import torch


class CooperativeScanTimeout(TimeoutError):
    """The current scan exhausted its budget without invalidating complete windows."""


class ScanInterrupted(CooperativeScanTimeout):
    """Background work yielded to a caller; completed windows stay cached."""


class ExactWindowLogitsCache:
    """One immutable CPU model; caller changes namespace before changing its weights/code.

    Byte limits count token/mask/namespace bytes and logits payload, not Python overhead.
    Assign model.forward = cache.forward; restore cache.original_forward afterward.
    """

    def __init__(self, model, *, namespace, max_bytes=64*1024*1024, max_entries=256,
                 clock=monotonic):
        if not isinstance(model, torch.nn.Module):
            raise TypeError("cache requires one torch model")
        if any(not isinstance(limit, int) or isinstance(limit, bool) or limit <= 0
               for limit in [max_bytes, max_entries]):
            raise ValueError("cache limits must be positive integers")
        if not callable(clock):
            raise TypeError("cache clock must be callable")
        self.model = model
        self.original_forward = model.forward
        self.max_bytes, self.max_entries = max_bytes, max_entries
        self._entries = OrderedDict()
        self._bytes = self._hits = self._misses = self._evictions = 0
        self._clock, self._deadline, self._interrupt = clock, None, None
        self.set_namespace(namespace)

    def begin_scan(self, budget_seconds, interrupt=None):
        if not isinstance(budget_seconds, (int, float)) or isinstance(budget_seconds, bool) \
                or not isfinite(budget_seconds) or budget_seconds <= 0:
            raise ValueError("scan budget must be finite and positive")
        if interrupt is not None and not callable(interrupt):
            raise TypeError("scan interrupt must be callable")
        if self._deadline is not None:
            raise RuntimeError("scan budget is already active")
        self._deadline = self._clock() + budget_seconds
        self._interrupt = interrupt

    def end_scan(self):
        self._deadline = self._interrupt = None

    def check_deadline(self):
        if self._deadline is not None and self._clock() >= self._deadline:
            raise CooperativeScanTimeout("scan budget exhausted")
        if self._interrupt is not None and self._interrupt():
            raise ScanInterrupted("scan interrupted")

    @staticmethod
    def _tensor_key(tensor):
        return (str(tensor.dtype), tuple(tensor.shape), tensor.detach().contiguous().numpy().tobytes())

    def forward(self, tokens, attention_mask=None, **kwargs):
        self.check_deadline()
        if kwargs:
            raise TypeError("only tokens and attention_mask are supported")
        if torch.is_grad_enabled() or any(module.training for module in self.model.modules()):
            raise RuntimeError("cache supports inference only")
        if torch.is_autocast_enabled("cpu"):
            raise RuntimeError("cache supports CPU inference without autocast only")
        if any(t.device.type != "cpu" for t in list(self.model.parameters()) + list(self.model.buffers())):
            raise RuntimeError("cache supports CPU models only")
        if not isinstance(tokens, torch.Tensor) or tokens.device.type != "cpu":
            raise RuntimeError("cache supports CPU token tensors only")
        if tokens.layout != torch.strided or tokens.dim() != 2 or tokens.dtype not in [torch.int32, torch.int64]:
            raise ValueError("tokens must be a dense 2D int32/int64 tensor")
        if attention_mask is not None and (
            not isinstance(attention_mask, torch.Tensor) or attention_mask.device.type != "cpu"
            or attention_mask.layout != torch.strided or attention_mask.dtype != torch.bool
            or attention_mask.shape != tokens.shape):
            raise ValueError("attention_mask must be a matching CPU boolean tensor or None")
        token_key = self._tensor_key(tokens)
        mask_key = None if attention_mask is None else self._tensor_key(attention_mask)
        key = (self._namespace, token_key, mask_key)
        self.check_deadline()
        if key in self._entries:
            self._hits += 1
            self._entries.move_to_end(key)
            result = self._entries[key][0].clone()
            self.check_deadline()
            return result
        self._misses += 1
        logits = self.original_forward(tokens, attention_mask=attention_mask)
        if not isinstance(logits, torch.Tensor) or logits.device.type != "cpu":
            raise RuntimeError("model must return CPU logits")
        stored = logits.detach().clone()
        size = stored.numel()*stored.element_size() + len(token_key[2]) + len(self._namespace.encode())
        if mask_key is not None:
            size += len(mask_key[2])
        if size <= self.max_bytes:
            while self._entries and (len(self._entries) >= self.max_entries or self._bytes+size > self.max_bytes):
                _, (_, removed_size) = self._entries.popitem(last=False)
                self._bytes -= removed_size
                self._evictions += 1
            self._entries[key] = (stored, size)
            self._bytes += size
        self.check_deadline()
        result = stored.clone()
        self.check_deadline()
        return result

    def snapshot(self):
        return {"hits": self._hits, "misses": self._misses, "evictions": self._evictions,
                "bytes": self._bytes, "entries": len(self._entries)}

    def clear(self):
        self._entries.clear()
        self._bytes = 0

    def set_namespace(self, namespace):
        if not isinstance(namespace, str) or not namespace.strip():
            raise ValueError("namespace must identify immutable model/checkpoint/candidate versions")
        if namespace != getattr(self, "_namespace", None):
            self.clear()
            self._namespace = namespace


def self_test():
    import unittest

    class Model(torch.nn.Module):
        def __init__(self):
            super().__init__()
            self.register_buffer("bias", torch.tensor(0.5))
            self.calls = 0
            self.fail = False

        def forward(self, tokens, attention_mask=None):
            self.calls += 1
            if self.fail:
                raise RuntimeError("synthetic compute failure")
            logits = tokens.float().unsqueeze(-1) + self.bias
            return logits if attention_mask is None else logits * attention_mask.unsqueeze(-1)

    class CacheTests(unittest.TestCase):
        def setUp(self):
            self.model = Model().eval()
            self.cache = ExactWindowLogitsCache(self.model, namespace="model/checkpoint/candidate-v1")
            self.tokens = torch.tensor([[1, 2]], dtype=torch.int32)

        def test_identical_window_hits_and_returns_independent_logits(self):
            with torch.inference_mode():
                first = self.cache.forward(self.tokens)
                first.fill_(100)
                second = self.cache.forward(self.tokens.clone())
                self.assertTrue(torch.equal(second, torch.tensor([[[1.5], [2.5]]])))
                second.zero_()
                self.assertTrue(torch.equal(self.cache.forward(self.tokens), torch.tensor([[[1.5], [2.5]]])))
            self.assertEqual(self.model.calls, 1)
            self.assertEqual(self.cache.snapshot()["hits"], 2)

        def test_changed_tokens_mask_dtype_shape_and_namespace_miss(self):
            with torch.inference_mode():
                self.cache.forward(self.tokens)
                self.cache.forward(torch.tensor([[1, 3]], dtype=torch.int32))
                self.cache.forward(self.tokens, attention_mask=torch.tensor([[True, False]]))
                self.cache.forward(self.tokens, attention_mask=torch.tensor([[True, True]]))
                self.cache.forward(self.tokens.to(torch.int64))
                self.cache.forward(self.tokens.reshape(2, 1))
                self.cache.set_namespace("model/checkpoint/candidate-v2")
                self.cache.forward(self.tokens)
                self.cache.clear()
                self.cache.forward(self.tokens)
            self.assertEqual(self.model.calls, 8)
            self.assertEqual(self.cache.snapshot()["entries"], 1)

        def test_lru_entry_and_payload_byte_limits(self):
            cache = ExactWindowLogitsCache(self.model, namespace="v1", max_entries=2, max_bytes=1000)
            a, b, c = [torch.tensor([[n]], dtype=torch.int32) for n in [1, 2, 3]]
            with torch.inference_mode():
                cache.forward(a)
                cache.forward(b)
                cache.forward(a)
                cache.forward(c)
                cache.forward(a)
                cache.forward(b)
            self.assertEqual(self.model.calls, 4)
            self.assertEqual(cache.snapshot()["entries"], 2)
            self.assertEqual(cache.snapshot()["evictions"], 2)
            tiny = ExactWindowLogitsCache(self.model, namespace="v1", max_bytes=1)
            with torch.inference_mode():
                tiny.forward(a)
                tiny.forward(a)
            self.assertEqual(tiny.snapshot()["entries"], 0)
            self.assertLessEqual(tiny.snapshot()["bytes"], 1)

        def test_interrupt_stops_scan_and_keeps_completed_windows(self):
            a, b = [torch.tensor([[n]], dtype=torch.int32) for n in [1, 2]]
            stop = []
            with torch.inference_mode():
                self.cache.begin_scan(100, interrupt=lambda: bool(stop))
                self.cache.forward(a)
                stop.append(True)
                with self.assertRaises(ScanInterrupted):
                    self.cache.forward(b)
                self.cache.end_scan()
                self.cache.forward(b)
                self.cache.forward(a)
            self.assertEqual(self.cache.snapshot()["hits"], 1)
            with self.assertRaises(TypeError):
                self.cache.begin_scan(1, interrupt=3)

        def test_failed_compute_is_not_cached(self):
            self.model.fail = True
            with torch.inference_mode():
                with self.assertRaises(RuntimeError):
                    self.cache.forward(self.tokens)
                self.assertEqual(self.cache.snapshot()["entries"], 0)
                self.model.fail = False
                self.cache.forward(self.tokens)
            self.assertEqual(self.model.calls, 2)

        def test_rejects_grad_training_non_cpu_and_unsupported_inputs(self):
            with self.assertRaises(RuntimeError):
                self.cache.forward(self.tokens)
            with torch.inference_mode():
                self.model.train()
                with self.assertRaises(RuntimeError):
                    self.cache.forward(self.tokens)

                self.model.eval()
                for tokens, kwargs in [
                    (self.tokens.to("meta"), {}), (self.tokens.float(), {}),
                    (self.tokens, {"attention_mask": torch.ones(1, 2)}),
                    (self.tokens, {"attention_mask": torch.ones(2, 1, dtype=torch.bool)}),
                    (self.tokens, {"unexpected": True})]:
                    with self.assertRaises((RuntimeError, ValueError, TypeError)):
                        self.cache.forward(tokens, **kwargs)
                self.model.bias = self.model.bias.to("meta")
                with self.assertRaises(RuntimeError):
                    self.cache.forward(self.tokens)

        def test_rejects_autocast_instead_of_reusing_different_precision_logits(self):
            with torch.inference_mode():
                self.cache.forward(self.tokens)
                with torch.autocast("cpu", dtype=torch.bfloat16):
                    with self.assertRaises(RuntimeError):
                        self.cache.forward(self.tokens)

    suite = unittest.defaultTestLoader.loadTestsFromTestCase(CacheTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return result.wasSuccessful()


if __name__ == "__main__":
    import sys
    if sys.argv[1:] != ["--self-test"]:
        raise SystemExit("usage: opf-window-cache.py --self-test")
    raise SystemExit(0 if self_test() else 1)
