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

The first 30-image run reached ~430 MB and looked like it might keep
growing. `handle()` already ran in an autoreleasepool. The stdin chunk, the
parsed request and the base64 reply were outside it, and each of those is
image-sized. `482f9b3` wraps every loop iteration in its own pool.

240 OCR + mask passes over 8 mixed inputs (640 to 3600 px wide, PNG and
JPEG), RSS in MB sampled every 10 images, same order for both builds:

| Build | Start | 10 | 50 | 100 | 150 | 200 | 240 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Before (`482f9b3~` source) | 51 | 277 | 375 | 398 | 448 | 461 | 461 |
| After (`482f9b3`) | 51 | 219 | 319 | 308 | 303 | 301 | 283 |

Full curve after the fix: 219 260 252 277 319 279 208 270 263 308 284 223
214 309 303 268 224 231 275 301 261 211 271 283. It moves inside 208–319 MB
with no trend; the second half peaks lower (309) than the first (319).
Before the fix it climbed to 461 MB and was still rising.

Outcome: **RSS levels off**, so the worker is not recycled after N images.

## Synthetic corpus eval

`tools/image-eval.mjs` renders `test/fixtures/image-corpus/` into a temp
directory and runs every case through the real inspector: Vision, Gitleaks,
and the named privacy worker. "Masked and re-OCR clean" means OCR on the
output image no longer reads the sensitive text. Every number here is
**synthetic only**: drawn text with known ground truth, not user screenshots.

### Regex worker

Privacy detector: `regex-v1`. Gitleaks 8.30.1. Synthetic only.

| Case | Truth | Detected | Masked and re-OCR clean | Kept text readable | Outcome |
| --- | --- | --- | --- | --- | --- |
| english.png | email | email | yes | yes | forwarded masked |
| chinese.png | email, person | email | yes | yes | forwarded masked (mismatch) |
| rotated.png | email | email | yes | yes | forwarded masked |
| exif.jpg | email | email | yes | yes | forwarded masked |
| alpha.png | email | email | yes | yes | forwarded masked |
| dark.png | email | email | yes | yes | forwarded masked |
| ui-12.png | email | email | yes | yes | forwarded masked |
| ui-11.png | email | none | **no** | yes | forwarded, normalized only (mismatch) |
| card.png | credit-card | credit-card | yes | yes | forwarded masked |
| secret.png | secret | secret | – | – | blocked |
| clean.png | none | none | – | yes | forwarded, normalized only |
| empty.png | none | none | – | – | forwarded, normalized only |
| animated.gif | refuse | – | – | – | rejected |
| animated.png | refuse | – | – | – | rejected |
| animated.webp | refuse | – | – | – | rejected |
| corrupt.png | refuse | – | – | – | rejected |
| oversized.png | refuse | – | – | – | rejected |

Precision 9/9 = 1.00. Recall 9/11 = 0.82. Masking verified 8/9 = 0.89. Refusals 5/5 = 1.00.

| k | Runs | p50 ms | p95 ms | Max ms | Worker RSS MB | Privacy RSS MB |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | 20 | 136 | 156 | 171 | 114 | 47 |
| 3 | 20 | 407 | 455 | 470 | 120 | 48 |
| 8 | 20 | 1148 | 1266 | 1683 | 119 | 48 |

### OPF (live install, read-only)

Privacy detector: `opf-1-client-exempt`. Gitleaks 8.30.1. Synthetic only.
Label mapping for scoring: `private_email` = `email`, `private_person` = `person`, `private_phone` = `phone`, `private_address` = `address`, `account_number` = `credit-card`.

| Case | Truth | Detected | Masked and re-OCR clean | Kept text readable | Outcome |
| --- | --- | --- | --- | --- | --- |
| english.png | email | email | yes | yes | forwarded masked |
| chinese.png | email, person | person, email | yes | yes | forwarded masked |
| rotated.png | email | email | yes | yes | forwarded masked |
| exif.jpg | email | email | yes | yes | forwarded masked |
| alpha.png | email | email | yes | yes | forwarded masked |
| dark.png | email | email | yes | yes | forwarded masked |
| ui-12.png | email | email | yes | yes | forwarded masked |
| ui-11.png | email | email, person | yes | yes | forwarded masked (mismatch) |
| card.png | credit-card | credit-card, private_date | yes | yes | forwarded masked (mismatch) |
| secret.png | secret | secret | – | – | blocked |
| clean.png | none | none | – | yes | forwarded, normalized only |
| empty.png | none | none | – | – | forwarded, normalized only |
| animated.gif | refuse | – | – | – | rejected |
| animated.png | refuse | – | – | – | rejected |
| animated.webp | refuse | – | – | – | rejected |
| corrupt.png | refuse | – | – | – | rejected |
| oversized.png | refuse | – | – | – | rejected |

Precision 11/13 = 0.85. Recall 11/11 = 1.00. Masking verified 9/9 = 1.00. Refusals 5/5 = 1.00.

| k | Runs | p50 ms | p95 ms | Max ms | Worker RSS MB | Privacy RSS MB |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | 20 | 163 | 196 | 200 | 111 | 2164 |
| 3 | 20 | 502 | 523 | 536 | 116 | 2165 |
| 8 | 20 | 1382 | 1595 | 1895 | 114 | 2165 |

Privacy RSS is the privacy worker's whole process tree. For OPF that is the
Node adapter (~54 MB) plus the Python model process (~1.8–2.1 GB). The first
version of this table counted only the adapter.

### Findings

- **A secret on its own OCR line was missed (fixed, `c9bbae1`).** Regions
  were joined with `"\n"`, which detectors read JSON-escaped as `\n`. The `n`
  touched the next region and defeated Gitleaks' leading `\b`, so the AWS
  key in `secret.png` passed. The separator is now `"\n "`.
  [INFERENCE] Text requests reach Gitleaks as the same JSON-escaped body, so
  a key that starts right after a newline in a pasted text message probably
  has the same miss. Since confirmed with real Gitleaks and fixed for every
  request on ccshield `fix/text-newline-boundary` (`ef9558a`).
- **Truncated images were forwarded (fixed, `c9bbae1`).** ImageIO decoded half
  a PNG and reported it complete. The inspector now checks each container's
  end marker before the worker sees the bytes. Side effect: a JPEG with data
  after its FFD9 marker (some cameras append some) is now refused. The user
  accepted this as fail-closed (2026-10-27).
- **11 px UI text with the regex worker.** Vision reads `ann.wu@ example.net`
  with a space, so the regex email rule misses it and the email leaves
  unmasked. OPF catches it. Known limitation of the regex worker, accepted by
  the user (2026-10-27); the native test keeps this case as a `todo`.
- **OPF false positives.** `Expires 08/29` on the card image is labelled
  `private_date` and masked. At 11 px, OPF also labels part of the email as a
  person. Both cost readability, not privacy. Accepted by the user (2026-10-27).
- **The EXIF case was first rendered wrong.** That was a fixture error, not a
  worker error: the renderer used orientation 6 for a rotation that needs 8.
  The worker applies EXIF correctly.

## Reproducing

```bash
HOME=<temp> CCSHIELD_NATIVE_IMAGE=1 node --test test/shield-image-native.test.mjs
HOME=<temp> node tools/image-eval.mjs <workdir> [<assets-provision.json>]
```

The single-image timings above came from scratch scripts kept outside the
repo. Both commands need `xcrun` and Vision, so run them outside the sandbox.
