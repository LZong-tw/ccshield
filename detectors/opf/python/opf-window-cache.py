"""Offline exact-window logits cache; never caches privacy decisions."""
from collections import OrderedDict
from hashlib import sha256
import errno
import json
import os
import stat
from math import isfinite
from time import monotonic
import torch


class CooperativeScanTimeout(TimeoutError):
    """The current scan exhausted its budget without invalidating complete windows."""


class ScanInterrupted(CooperativeScanTimeout):
    """Background work yielded to a caller; completed windows stay cached."""


def _length_prefixed(*fields):
    out = bytearray()
    for field in fields:
        out += len(field).to_bytes(8, "big") + field
    return bytes(out)


def runtime_fingerprint():
    """Identifies the numeric runtime; logits are only reused under the same one."""
    import platform
    import sys

    def probe(read):
        try:
            value = read()
        except Exception:  # an absent API is recorded, never guessed
            return "unavailable"
        return "unavailable" if value is None else str(value)

    def numpy_version():
        import numpy
        return numpy.__version__

    fields = [
        probe(lambda: torch.__version__),
        probe(lambda: sys.version),
        probe(numpy_version),
        probe(lambda: torch.backends.cpu.get_cpu_capability()),
        probe(lambda: platform.machine()),
        probe(lambda: torch.__config__.show()),
    ]
    return sha256(_length_prefixed(*[f.encode() for f in fields])).hexdigest()


class DiskTier:
    """Write-through logits store under one private directory.

    Entries are plaintext logits in 0600 files owned by the current uid. There is
    deliberately no HMAC: anyone who can forge a file here runs as the same uid and
    can already point ANTHROPIC_BASE_URL around the Shield, so a key would only add
    key management. The trailing checksum covers truncation and corruption. Every
    operation is relative to one O_NOFOLLOW directory fd. Nothing in here calls the
    cache deadline; callers own timeouts.
    """

    MAGIC = b"OPFWC\x00"
    VERSION = 1
    DTYPES = frozenset(["torch.float32", "torch.float16", "torch.bfloat16"])
    TOUCH_SECONDS = 3600

    def __init__(self, path, *, max_bytes=256*1024*1024, ttl_seconds=7*24*3600,
                 full_window=4096, fingerprint=None, wall_clock=None):
        import time
        self.max_bytes, self.ttl_seconds, self.full_window = max_bytes, ttl_seconds, full_window
        self.fingerprint = runtime_fingerprint() if fingerprint is None else fingerprint
        self._now = time.time if wall_clock is None else wall_clock
        self.hits = self.misses = self.writes = self.errors = 0
        self.disabled = None
        self._dfd = None
        self._index = {}
        reason = self._open(path)
        if reason is not None:
            self.disabled = reason
            return
        self._scan()

    def _open(self, path):
        needed = [os.open in os.supports_dir_fd, os.unlink in os.supports_dir_fd,
                  os.rename in os.supports_dir_fd, os.utime in os.supports_dir_fd,
                  os.stat in os.supports_dir_fd, os.utime in os.supports_follow_symlinks,
                  os.scandir in os.supports_fd]
        if not all(needed):
            return "platform"
        try:
            os.makedirs(path, mode=0o700, exist_ok=True)
            dfd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        except OSError:
            return "open"
        info = os.fstat(dfd)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            os.close(dfd)
            return "permissions"
        self._dfd = dfd
        return None

    @property
    def enabled(self):
        return self.disabled is None

    @property
    def bytes(self):
        return sum(size for _, size in self._index.values())

    def close(self):
        if self._dfd is not None:
            os.close(self._dfd)
            self._dfd = None

    def key(self, namespace, tokens, attention_mask):
        mask = [b"\x00"] if attention_mask is None else [
            b"\x01", str(attention_mask.dtype).encode(), repr(tuple(attention_mask.shape)).encode(),
            attention_mask.detach().contiguous().numpy().tobytes()]
        return sha256(_length_prefixed(
            self.MAGIC + bytes([self.VERSION]), namespace.encode(), self.fingerprint.encode(),
            str(tokens.dtype).encode(), repr(tuple(tokens.shape)).encode(),
            tokens.detach().contiguous().numpy().tobytes(), *mask)).digest()

    def storable(self, tokens, attention_mask):
        return tokens.shape[-1] == self.full_window and (
            attention_mask is None or bool(attention_mask.all()))

    def _scan(self):
        now = self._now()
        for entry in os.scandir(self._dfd):
            if entry.name.startswith("."):
                self._discard(entry.name)
                continue
            try:
                info = os.stat(entry.name, dir_fd=self._dfd, follow_symlinks=False)
            except OSError:
                continue
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or info.st_mode & 0o077 or now - info.st_mtime > self.ttl_seconds):
                self._discard(entry.name)
                continue
            self._index[entry.name] = (info.st_mtime, info.st_size)
        self._evict()

    def _discard(self, name):
        self._index.pop(name, None)
        try:
            os.unlink(name, dir_fd=self._dfd)
        except FileNotFoundError:
            pass

    def _reject(self, name):
        self.errors += 1
        self.misses += 1
        self._discard(name)
        return None

    def get(self, key, window_len):
        if not self.enabled:
            return None
        name = key.hex()
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=self._dfd)
        except FileNotFoundError:
            self.misses += 1
            return None
        except OSError as error:
            if error.errno == errno.ELOOP:
                return self._reject(name)
            raise
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
                return self._reject(name)
            if self._now() - info.st_mtime > self.ttl_seconds:
                self._discard(name)
                self.misses += 1
                return None
            with os.fdopen(os.dup(fd), "rb") as handle:
                data = handle.read()
        finally:
            os.close(fd)
        logits = self._decode(data, key, window_len)
        if logits is None:
            return self._reject(name)
        if self._now() - info.st_mtime > self.TOUCH_SECONDS:
            os.utime(name, dir_fd=self._dfd, follow_symlinks=False)
            self._index[name] = (self._now(), info.st_size)
        self.hits += 1
        return logits

    def _decode(self, data, key, window_len):
        if len(data) < 32 or sha256(data[:-32]).digest() != data[-32:]:
            return None
        body = data[:-32]
        head = len(self.MAGIC) + 1 + 32 + 32
        if body[:len(self.MAGIC)] != self.MAGIC or body[len(self.MAGIC)] != self.VERSION:
            return None
        if body[len(self.MAGIC)+1:len(self.MAGIC)+33] != key:
            return None
        if body[len(self.MAGIC)+33:head] != sha256(self.fingerprint.encode()).digest():
            return None
        try:
            meta_len = int.from_bytes(body[head:head+8], "big")
            dtype_name, shape = json.loads(body[head+8:head+8+meta_len])
        except (ValueError, TypeError):
            return None
        if dtype_name not in self.DTYPES:
            return None
        dtype = getattr(torch, dtype_name.split(".", 1)[1])
        if ( not isinstance(shape, list) or len(shape) != 3
                or not all(isinstance(n, int) and n > 0 for n in shape)
                or shape[0] != 1 or shape[1] != window_len):
            return None
        payload = body[head+8+meta_len:]
        if len(payload) != shape[0]*shape[1]*shape[2]*torch.empty((), dtype=dtype).element_size():
            return None
        return torch.frombuffer(bytearray(payload), dtype=dtype).reshape(shape).clone()

    def _encode(self, key, logits):
        meta = json.dumps([str(logits.dtype), list(logits.shape)]).encode()
        body = (self.MAGIC + bytes([self.VERSION]) + key + sha256(self.fingerprint.encode()).digest()
                + len(meta).to_bytes(8, "big") + meta
                + logits.detach().contiguous().view(torch.uint8).numpy().tobytes())
        return body + sha256(body).digest()

    def put(self, key, logits):
        if not self.enabled or str(logits.dtype) not in self.DTYPES:
            return
        data = self._encode(key, logits)
        if len(data) > self.max_bytes:
            return
        name = key.hex()
        temp = f".{name}.{os.getpid()}.tmp"
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=self._dfd)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.rename(temp, name, src_dir_fd=self._dfd, dst_dir_fd=self._dfd)
        except BaseException:
            try:
                os.unlink(temp, dir_fd=self._dfd)
            except OSError:
                pass
            raise
        self.writes += 1
        self._index[name] = (self._now(), len(data))
        self._evict()

    def _evict(self):
        total = self.bytes
        for name, (_, size) in sorted(self._index.items(), key=lambda item: item[1][0]):
            if total <= self.max_bytes:
                break
            self._discard(name)
            total -= size

    def snapshot(self):
        return {"disk_hits": self.hits, "disk_misses": self.misses, "disk_writes": self.writes,
                "disk_errors": self.errors, "disk_bytes": self.bytes,
                "diskTier": "enabled" if self.enabled else f"disabled:{self.disabled}"}


class ExactWindowLogitsCache:
    """One immutable CPU model; caller changes namespace before changing its weights/code.

    Byte limits count token/mask/namespace bytes and logits payload, not Python overhead.
    Assign model.forward = cache.forward; restore cache.original_forward afterward.
    """

    def __init__(self, model, *, namespace, max_bytes=64*1024*1024, max_entries=256,
                 clock=monotonic, disk=None):
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
        if disk is not None and not isinstance(disk, DiskTier):
            raise TypeError("disk must be a DiskTier or None")
        self._disk, self._disk_errors = disk, 0
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
        disk_key = stored = None
        if self._disk is not None and self._disk.enabled:
            disk_key = self._disk.key(self._namespace, tokens, attention_mask)
            stored = self._disk_call(self._disk.get, disk_key, tokens.shape[-1])
        if stored is None:
            logits = self.original_forward(tokens, attention_mask=attention_mask)
            if not isinstance(logits, torch.Tensor) or logits.device.type != "cpu":
                raise RuntimeError("model must return CPU logits")
            stored = logits.detach().clone()
            if disk_key is not None and self._disk.storable(tokens, attention_mask):
                self._disk_call(self._disk.put, disk_key, stored)
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

    def _disk_call(self, operation, *args):
        try:
            return operation(*args)
        except CooperativeScanTimeout:  # an OSError subclass: must be re-raised before OSError
            raise
        except (OSError, ValueError):
            self._disk_errors += 1
            return None

    def snapshot(self):
        result = {"hits": self._hits, "misses": self._misses, "evictions": self._evictions,
                  "bytes": self._bytes, "entries": len(self._entries)}
        if self._disk is not None:
            disk = self._disk.snapshot()
            disk["disk_errors"] += self._disk_errors
            result.update(disk)
        return result

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

    class DiskTests(unittest.TestCase):
        def setUp(self):
            import tempfile
            self.tmp = tempfile.TemporaryDirectory()
            self.dir = os.path.join(self.tmp.name, "opf-window-cache")
            self.tokens = torch.tensor([[1, 2]], dtype=torch.int32)
            self.now = [1_000_000.0]

        def tearDown(self):
            self.tmp.cleanup()

        def tier(self, **options):
            options.setdefault("full_window", 2)
            options.setdefault("fingerprint", "runtime-a")
            options.setdefault("wall_clock", lambda: self.now[0])
            return DiskTier(self.dir, **options)

        def cache(self, tier, namespace="ns-v1"):
            model = Model().eval()
            return model, ExactWindowLogitsCache(model, namespace=namespace, disk=tier)

        def files(self):
            return sorted(name for name in os.listdir(self.dir) if not name.startswith("."))

        def baseline(self, tokens=None):
            model, cache = self.cache(None)
            with torch.inference_mode():
                return cache.forward(self.tokens if tokens is None else tokens)

        def test_cold_result_survives_a_new_process_byte_equal(self):
            import subprocess
            import sys
            probe = (
                "import importlib.util, sys, torch\n"
                "spec = importlib.util.spec_from_file_location('c', sys.argv[1])\n"
                "c = importlib.util.module_from_spec(spec); spec.loader.exec_module(c)\n"
                "class M(torch.nn.Module):\n"
                "    def __init__(self):\n"
                "        super().__init__(); self.register_buffer('bias', torch.tensor(0.5)); self.calls = 0\n"
                "    def forward(self, tokens, attention_mask=None):\n"
                "        self.calls += 1; return tokens.float().unsqueeze(-1) / 3 + self.bias\n"
                "m = M().eval()\n"
                "cache = c.ExactWindowLogitsCache(m, namespace='ns', disk=c.DiskTier(sys.argv[2], full_window=2))\n"
                "with torch.inference_mode():\n"
                "    out = cache.forward(torch.tensor([[1, 2]], dtype=torch.int32))\n"
                "print(m.calls, out.numpy().tobytes().hex())\n")
            runs = [subprocess.run([sys.executable, "-B", "-c", probe, __file__, self.dir],
                                   capture_output=True, text=True, check=True).stdout.split()
                    for _ in range(2)]
            self.assertEqual([runs[0][0], runs[1][0]], ["1", "0"])
            self.assertEqual(runs[0][1], runs[1][1])

        def test_disk_hit_backfills_memory(self):
            tier = self.tier()
            with torch.inference_mode():
                self.cache(tier)[1].forward(self.tokens)
                model, cache = self.cache(tier)
                first = cache.forward(self.tokens)
                second = cache.forward(self.tokens)
            self.assertEqual(model.calls, 0)
            self.assertTrue(torch.equal(first, second))
            self.assertTrue(torch.equal(first, self.baseline()))
            snap = cache.snapshot()
            self.assertEqual((snap["hits"], snap["disk_hits"], snap["disk_writes"]), (1, 1, 1))

        def test_key_covers_every_field_and_is_length_prefixed(self):
            tier = self.tier()
            mask = torch.tensor([[True, True]])
            base = tier.key("ns", self.tokens, None)
            variants = [tier.key("ns2", self.tokens, None),
                        self.tier(fingerprint="runtime-b").key("ns", self.tokens, None),
                        tier.key("ns", self.tokens.to(torch.int64), None),
                        tier.key("ns", self.tokens.reshape(2, 1), None),
                        tier.key("ns", torch.tensor([[1, 3]], dtype=torch.int32), None),
                        tier.key("ns", self.tokens, mask),
                        tier.key("ns", self.tokens, torch.tensor([[True, False]]))]
            self.assertEqual(len({base, *variants}), len(variants) + 1)
            self.assertNotEqual(_length_prefixed(b"ab", b"c"), _length_prefixed(b"a", b"bc"))

        def test_namespace_or_runtime_change_misses(self):
            with torch.inference_mode():
                self.cache(self.tier())[1].forward(self.tokens)
                for tier, namespace in [(self.tier(), "ns-v2"), (self.tier(fingerprint="runtime-b"), "ns-v1")]:
                    model, cache = self.cache(tier, namespace)
                    cache.forward(self.tokens)
                    self.assertEqual(model.calls, 1)

        def reset(self):
            if os.path.isdir(self.dir):
                for name in os.listdir(self.dir):
                    os.unlink(os.path.join(self.dir, name))

        def assert_damage_misses(self, damage, tokens):
            self.reset()
            with torch.inference_mode():
                self.cache(self.tier())[1].forward(self.tokens)
            [name] = self.files()
            damage(os.path.join(self.dir, name))
            model, cache = self.cache(self.tier())
            with torch.inference_mode():
                out = cache.forward(tokens)
            self.assertEqual(model.calls, 1)
            self.assertTrue(torch.equal(out, self.baseline(tokens)))
            self.assertEqual(cache.snapshot()["disk_errors"], 1)
            self.assertEqual(cache.snapshot()["disk_writes"], 1)
            healed, cache = self.cache(self.tier())  # the damaged file was replaced by a valid one
            with torch.inference_mode():
                cache.forward(tokens)
            self.assertEqual(healed.calls, 0)

        def test_damaged_entries_miss_and_are_deleted(self):
            def flip(offset):
                def apply(path):
                    data = bytearray(open(path, "rb").read())
                    data[offset] ^= 1
                    open(path, "wb").write(bytes(data))
                return apply

            other = torch.tensor([[7, 8]], dtype=torch.int32)
            moved_to = self.tier().key("ns-v1", other, None).hex()
            cases = {"truncated": (lambda path: os.truncate(path, os.path.getsize(path) - 5), self.tokens),
                     "magic": (flip(3), self.tokens), "payload": (flip(-40), self.tokens),
                     "renamed": (lambda path: os.rename(path, os.path.join(self.dir, moved_to)), other)}
            for label, (damage, tokens) in cases.items():
                with self.subTest(damage=label):
                    self.assert_damage_misses(damage, tokens)

        def test_losing_every_file_only_costs_time(self):
            with torch.inference_mode():
                self.cache(self.tier())[1].forward(self.tokens)
            for name in os.listdir(self.dir):
                os.unlink(os.path.join(self.dir, name))
            model, cache = self.cache(self.tier())
            with torch.inference_mode():
                self.assertTrue(torch.equal(cache.forward(self.tokens), self.baseline()))
            self.assertEqual(model.calls, 1)

        def test_unsafe_entries_miss(self):
            for unsafe in ["symlink", "mode"]:
                with self.subTest(unsafe=unsafe):
                    for name in os.listdir(self.dir) if os.path.isdir(self.dir) else []:
                        os.unlink(os.path.join(self.dir, name))
                    with torch.inference_mode():
                        self.cache(self.tier())[1].forward(self.tokens)
                    [name] = self.files()
                    path = os.path.join(self.dir, name)
                    if unsafe == "symlink":
                        target = os.path.join(self.tmp.name, "real")
                        os.replace(path, target)
                        os.symlink(target, path)
                    else:
                        os.chmod(path, 0o644)
                    tier = self.tier()
                    if unsafe == "mode":
                        self.assertEqual(self.files(), [])  # startup scan already drops it
                        open(path, "wb").write(b"x")
                        os.chmod(path, 0o644)
                    model, cache = self.cache(tier)
                    with torch.inference_mode():
                        cache.forward(self.tokens)
                    self.assertEqual(model.calls, 1)
                    self.assertFalse(os.path.islink(path))

        def test_unsafe_directory_disables_the_tier(self):
            os.makedirs(self.dir, mode=0o700)
            os.chmod(self.dir, 0o755)
            self.assertEqual(self.tier().snapshot()["diskTier"], "disabled:permissions")
            os.chmod(self.dir, 0o700)
            link = os.path.join(self.tmp.name, "link")
            os.symlink(self.dir, link)
            tier = DiskTier(link, full_window=2, fingerprint="runtime-a")
            self.assertEqual(tier.snapshot()["diskTier"], "disabled:open")
            model, cache = self.cache(tier)
            with torch.inference_mode():
                self.assertTrue(torch.equal(cache.forward(self.tokens), self.baseline()))

        def test_partial_windows_stay_in_memory(self):
            tier = self.tier(full_window=4)
            with torch.inference_mode():
                self.cache(tier)[1].forward(self.tokens)
                self.cache(tier)[1].forward(torch.tensor([[1, 2, 3, 4]], dtype=torch.int32),
                                            attention_mask=torch.tensor([[True, True, True, False]]))
            self.assertEqual(self.files(), [])
            self.assertEqual(tier.writes, 0)

        def test_touch_is_rate_limited_to_an_hour(self):
            tier = self.tier()
            with torch.inference_mode():
                self.cache(tier)[1].forward(self.tokens)
            [name] = self.files()
            path = os.path.join(self.dir, name)
            os.utime(path, (self.now[0], self.now[0]))
            self.now[0] += 1800
            with torch.inference_mode():
                self.cache(tier)[1].forward(self.tokens)
            self.assertEqual(os.stat(path).st_mtime, 1_000_000.0)
            self.now[0] += 3600
            with torch.inference_mode():
                self.cache(tier)[1].forward(self.tokens)
            self.assertGreater(os.stat(path).st_mtime, 1_000_000.0)

        def test_capacity_evicts_oldest_and_ttl_expires(self):
            tier = self.tier()
            with torch.inference_mode():
                self.cache(tier)[1].forward(self.tokens)
            entry = tier.bytes
            self.reset()
            tier = self.tier(max_bytes=entry * 2)
            names = []
            for value in range(3):
                self.now[0] += 10
                with torch.inference_mode():
                    self.cache(tier)[1].forward(torch.tensor([[value, 9]], dtype=torch.int32))
                names.append(tier.key("ns-v1", torch.tensor([[value, 9]], dtype=torch.int32), None).hex())
            self.assertEqual(tier.bytes, entry * 2)
            self.assertEqual(set(self.files()), set(names[1:]))
            for name in self.files():
                os.utime(os.path.join(self.dir, name), (self.now[0], self.now[0]))
            self.now[0] += 8 * 24 * 3600
            self.assertEqual(self.tier().bytes, 0)
            self.assertEqual(self.files(), [])

        def test_unwritable_directory_does_not_change_results(self):
            tier = self.tier()
            os.chmod(self.dir, 0o500)
            try:
                model, cache = self.cache(tier)
                with torch.inference_mode():
                    self.assertTrue(torch.equal(cache.forward(self.tokens), self.baseline()))
                self.assertEqual(cache.snapshot()["disk_errors"], 1)
            finally:
                os.chmod(self.dir, 0o700)

        def test_disk_errors_are_classified(self):
            for error, raised in [(CooperativeScanTimeout("t"), CooperativeScanTimeout),
                                  (ScanInterrupted("i"), ScanInterrupted),
                                  (RuntimeError("r"), RuntimeError),
                                  (OSError("o"), None), (ValueError("v"), None)]:
                with self.subTest(error=type(error).__name__):
                    tier = self.tier()

                    def fail(*_):
                        raise error
                    tier.get = fail
                    model, cache = self.cache(tier)
                    with torch.inference_mode():
                        if raised is None:
                            cache.forward(self.tokens)
                            self.assertEqual(cache.snapshot()["disk_errors"], 1)
                            self.assertEqual(model.calls, 1)
                        else:
                            with self.assertRaises(raised):
                                cache.forward(self.tokens)

        def test_disk_work_never_reads_the_deadline_clock(self):
            tier = self.tier()
            ticks, inside = [], []
            model = Model().eval()
            cache = ExactWindowLogitsCache(model, namespace="ns-v1", disk=tier,
                                           clock=lambda: ticks.append(bool(inside)) or 0.0)
            for name in ["get", "put"]:
                original = getattr(tier, name)

                def spy(*args, original=original):
                    inside.append(1)
                    try:
                        return original(*args)
                    finally:
                        inside.pop()
                setattr(tier, name, spy)
            cache.begin_scan(100)
            with torch.inference_mode():
                cache.forward(self.tokens)
            self.assertTrue(ticks)
            self.assertNotIn(True, ticks)

        def test_runtime_fingerprint_is_stable_in_and_across_processes(self):
            import subprocess
            import sys
            probe = ("import importlib.util, sys\n"
                     "spec = importlib.util.spec_from_file_location('c', sys.argv[1])\n"
                     "c = importlib.util.module_from_spec(spec); spec.loader.exec_module(c)\n"
                     "print(c.runtime_fingerprint())\n")
            here = runtime_fingerprint()
            self.assertEqual(here, runtime_fingerprint())
            other = subprocess.run([sys.executable, "-B", "-c", probe, __file__],
                                   capture_output=True, text=True, check=True).stdout.strip()
            self.assertEqual(here, other)

    loader = unittest.defaultTestLoader
    suite = unittest.TestSuite([loader.loadTestsFromTestCase(CacheTests), loader.loadTestsFromTestCase(DiskTests)])
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return result.wasSuccessful()


if __name__ == "__main__":
    import sys
    if sys.argv[1:] != ["--self-test"]:
        raise SystemExit("usage: opf-window-cache.py --self-test")
    raise SystemExit(0 if self_test() else 1)
