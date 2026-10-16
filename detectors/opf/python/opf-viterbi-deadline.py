# SPDX-License-Identifier: Apache-2.0
# Derived from openai/privacy-filter opf/_core/decoding.py (ViterbiCRFDecoder.decode) at commit f7f00ca7fb869683eb732c010299d901457f19c3
# (Apache License 2.0, see licenses/Apache-2.0.txt).
# Modified by ccshield: see the docstrings below for what changed.
import torch

CHECK_EVERY = 256


def deadline_decode(check_deadline):
    """Build ViterbiCRFDecoder.decode with the upstream torch ops in the upstream order.

    Only two things differ: the sequential forward and backtrack loops check the scan deadline every
    CHECK_EVERY steps, and scores that are not finite raise instead of silently falling back to argmax.
    """

    def decode(self, token_logprobs):
        if token_logprobs.ndim != 2:
            raise ValueError("token_logprobs must have shape [seq_len, num_classes]")

        seq_len, num_classes = token_logprobs.shape
        if seq_len == 0:
            return []

        device = token_logprobs.device
        dtype = token_logprobs.dtype
        if self._start_scores.device == device and self._start_scores.dtype == dtype:
            start_scores = self._start_scores
            end_scores = self._end_scores
            transition_scores = self._transition_scores
        else:
            device_index = device.index if device.index is not None else -1
            cache_key = (device.type, device_index, dtype)
            cached_scores = self._score_cache.get(cache_key)
            if cached_scores is None:
                cached_scores = (
                    self._start_scores.to(device=device, dtype=dtype),
                    self._end_scores.to(device=device, dtype=dtype),
                    self._transition_scores.to(device=device, dtype=dtype),
                )
                self._score_cache[cache_key] = cached_scores
            start_scores, end_scores, transition_scores = cached_scores

        scores = token_logprobs[0] + start_scores
        backpointers = torch.empty((seq_len - 1, num_classes), device=device, dtype=torch.int64)

        for idx in range(1, seq_len):
            if idx % CHECK_EVERY == 0:
                check_deadline()
            transitions = scores.unsqueeze(1) + transition_scores
            best_scores, best_paths = transitions.max(dim=0)
            scores = best_scores + token_logprobs[idx]
            backpointers[idx - 1] = best_paths

        if not torch.isfinite(scores).any():
            raise ValueError("viterbi scores are not finite")

        scores = scores + end_scores
        last_label = scores.argmax()
        path = torch.empty((seq_len,), device=device, dtype=torch.int64)
        path[-1] = last_label
        for idx in range(seq_len - 2, -1, -1):
            if idx % CHECK_EVERY == 0:
                check_deadline()
            last_label = backpointers[idx, last_label]
            path[idx] = last_label
        return path.tolist()

    return decode


def install(decoder_class, check_deadline):
    """Swap in the deadline-aware decode; the returned counter lets the warm-up prove it is reached."""
    calls = [0]
    decode = deadline_decode(check_deadline)

    def counted(self, token_logprobs):
        calls[0] += 1
        return decode(self, token_logprobs)

    decoder_class.decode = counted
    return calls


def self_test(opf_source, checkpoint):
    """Prove path equality against the pinned upstream decoder with real torch and the real label space."""
    import os
    import sys
    # The pinned source tree is digest-attested; bytecode written into it would refuse every later start.
    sys.dont_write_bytecode = True
    sys.path.insert(0, os.path.dirname(os.path.realpath(opf_source)))
    from opf._common.label_space import resolve_checkpoint_label_space
    from opf._core.decoding import ViterbiCRFDecoder, build_sequence_decoder
    from opf._core.sequence_labeling import build_label_info

    _, _, class_names = resolve_checkpoint_label_space(checkpoint)
    label_info = build_label_info(class_names)
    decoder, _ = build_sequence_decoder(decode_mode="viterbi", label_info=label_info,
                                        viterbi_calibration_path=None, checkpoint_dir=checkpoint)
    original = ViterbiCRFDecoder.decode
    checks = [0]

    def count():
        checks[0] += 1

    patched = deadline_decode(count)
    num_classes = len(label_info.token_to_span_label)
    background = int(label_info.background_token_label)
    generator = torch.Generator().manual_seed(20261006)
    random = torch.log_softmax(torch.randn(3000, num_classes, generator=generator) * 4, dim=-1)
    # Integer scores tie constantly, which pins max/argmax tie-breaking to upstream's.
    ties = torch.randint(-3, 1, (3000, num_classes), generator=generator).float()
    flat = torch.zeros(700, num_classes)
    blocked = random.clone()
    mask = torch.rand(3000, num_classes, generator=generator) < 0.3
    mask[:, background] = False
    blocked[mask] = float("-inf")
    cases = [random, ties, flat, blocked, random[:1], random[:2], ties[:CHECK_EVERY], ties[:CHECK_EVERY + 1]]
    for index, case in enumerate(cases):
        if patched(decoder, case) != original(decoder, case):
            print(f"case {index}: path differs from upstream")
            return False
    if checks[0] == 0:
        print("deadline checks never ran")
        return False

    class Expired(Exception):
        pass

    def expire():
        raise Expired()

    try:
        deadline_decode(expire)(decoder, random)
        print("expired deadline did not stop the decode")
        return False
    except Expired:
        pass
    poisoned = random.clone()
    poisoned[:, :] = float("nan")
    try:
        patched(decoder, poisoned)
        print("non-finite scores did not raise")
        return False
    except ValueError:
        pass
    print(f"ok: {len(cases)} cases, {checks[0]} deadline checks, {num_classes} classes")
    return True


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 4 or sys.argv[1] != "--self-test":
        raise SystemExit("usage: opf-viterbi-deadline.py --self-test <opf-source> <checkpoint>")
    raise SystemExit(0 if self_test(sys.argv[2], sys.argv[3]) else 1)
