Third-party license texts for bundled files.

- `Apache-2.0.txt` — byte-identical copy of upstream `openai/privacy-filter`
  `LICENSE` (sha256 `c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4`).
  Covers the helpers classified as derived below. Each carries a header
  naming the upstream file and commit and a "Modified by ccshield" notice
  (Apache-2.0 §4(b)). Upstream ships no NOTICE file, so §4(d) adds nothing.

Original helpers are MIT (the repository license) with no extra header.
Nothing upstream is MPL-2.0. The privacy-filter weights and tokenizer on
Hugging Face (`openai/privacy-filter`) are Apache-2.0; they are downloaded,
not bundled.

## Python helper classification (Task 0, 2026-10-16)

Upstream `openai/privacy-filter` at `f7f00ca7fb869683eb732c010299d901457f19c3`
is Apache-2.0. Each helper was diffed function by function against upstream
`opf/` at that commit.

| Helper | Classification | Basis |
| --- | --- | --- |
| `opf-cpu-grouped.py` | derived from upstream `opf/_model/model.py` (Apache-2.0) | reimplements `MLPBlock.forward` (top-k routing, softmax weights, SwiGLU experts) for grouped CPU execution; 4 of 58 lines identical |
| `opf-mmap-weights.py` | original (MIT) | own safetensors header parser and mmap views; 1 of 42 lines identical (an import) |
| `opf-window-cache.py` | original (MIT) | logits cache and scan deadline; 0 of 129 lines identical |
| `opf-viterbi-deadline.py` | derived from upstream `opf/_core/decoding.py` (Apache-2.0) | copies `ViterbiCRFDecoder.decode` and adds a deadline check; 22 of 67 lines identical |
