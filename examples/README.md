# Examples

Fixtures used by the docs, the demo, and the end-to-end tests.

| Directory | Purpose |
|---|---|
| `vulnerable/` | Every rule family fires at least once (planted issues are annotated inline). `cairn scan examples/vulnerable` exits 1. |
| `clean/` | The well-configured counterpart; the false-positive regression fixture. Must always produce **zero** findings. |
| `policy/` | A commented `.cairn.yaml` showing the policy-as-code surface. |

Try it:

```bash
cairn scan examples/vulnerable            # ranked findings, trade-offs, $ estimates
cairn scan examples/clean                 # "no findings. Clean."
cairn scan examples/vulnerable \
  --config examples/policy/.cairn.yaml   # same scan under an org policy
```
