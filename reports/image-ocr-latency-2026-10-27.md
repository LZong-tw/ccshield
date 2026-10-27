# Image OCR latency and memory (P7b)

Measured 2026-10-27 TW on Apple M2, 16 GB, macOS 27.0.1. Branch
`feat/image-ocr-native`, worker compiled from `shield-image/image-worker.swift`
into a temp directory. OPF ran from the live install's
`subscription/assets-provision.json` (version `opf-1-client-exempt`). That
install was only read; nothing was written there. HOME was a temp directory.

Inputs are `shield-image/readiness.png` (640×160: zh-Hant, en-US, one email)
resized with `sips`, so every size has the same three text regions. These are
not real screenshots. Dense screenshots produce more regions and will take
longer.

## Startup

| Step | Time |
| --- | --- |
| Worker probe (includes Vision warm-up) | 379 ms in this run; the readiness work earlier the same day measured ~30 s on a cold first recognition |
| OPF filter start (checkpoint attest + model load) | 46.2 s |

The warm-up figure varies a lot. When the system has run Vision recently, the
probe is fast. The plan's ~30 s R3 delay is the cold case and still stands.

## Per image (ms, three runs each)

| Input | Bytes | OCR | OPF scan of OCR text | Mask + re-encode | Worker RSS after |
| --- | --- | --- | --- | --- | --- |
| 640×160 PNG | 18,946 | 249 / 69 / 65 | 1574 / 17 / 21 | 6 / 9 / 3 | 61 MB |
| 1280×320 PNG | 71,335 | 91 / 85 / 84 | 19 / 19 / 19 | 12 / 13 / 12 | 91 MB |
| 1920×480 PNG | 126,053 | 240 / 87 / 87 | 16 / 16 / 16 | 21 / 21 / 20 | 146 MB |
| 1920×480 JPEG | 71,887 | 86 / 87 / 82 | 17 / 16 / 17 | 15 / 14 / 14 | 190 MB |
| 3000×750 PNG | 280,746 | 159 / 148 / 156 | 16 / 18 / 18 | 55 / 69 / 69 | 285 MB |

The first OPF scan (1.57 s) is model warm-up. After that, each image adds
about 0.1–0.25 s when warm. The OCR and OPF stages dominate. Gitleaks was not
part of this run; its scan timeout is 2 s per call.

## Worker memory

A follow-up run of 30 OCR + mask passes at 3000×750 sampled RSS every 5
images: 308, 379, 392, 403, 415, 426 MB. Ten 640×160 passes then brought it
down to 177 MB.

[INFERENCE] This looks like allocator high-water rather than an unbounded
leak, because RSS fell after smaller images. It is not proven. The worker
lives as long as the daemon, so a long session with large screenshots could
hold several hundred MB. If that turns out to matter, the options are to
recycle the worker after N images or to add an autoreleasepool per request
in Swift. Neither is implemented.

## Reproducing

Run the scripts kept outside the repo
(`/tmp/claude-501/bench/{bench,leak}.mjs`) with HOME set to a temp directory
and `LIVE` pointing at the ccshield data root. Running them needs `xcrun` and
the sandbox disabled.
