Third-party license texts for bundled subtrees.

Reserved for the MPL-2.0 (OPF-derived files) and Apache-2.0
(`opf-viterbi-deadline.py`) subtrees that arrive with the detector assets.
Nothing is bundled here yet.

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

The license section above still says MPL-2.0; Task 3 corrects it.
