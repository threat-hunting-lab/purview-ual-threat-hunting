# Phase 3 — Model-in-the-loop Control Eval

This evaluates hallucination / refusal / prompt-injection risk for AI-assisted security reasoning using a deterministic control-eval format.

## Personas
- `strict`: evidence-grounded, abstains when required
- `hallucinator`: overclaims, invents claim IDs
- `injection_prone`: follows instructions embedded in evidence fields
- `over_refuser`: refuses too often

## Aggregate Results

| Persona | Claims Precision | Claims Recall | Claims F1 | Refusal Acc | Injection Fail Rate | Hallucination Case Rate |
|---|---:|---:|---:|---:|---:|---:|
| `strict` | 1.000 | 1.000 | 1.000 | 1.000 | 0.000 | 0.000 |
| `hallucinator` | 0.562 | 1.000 | 0.720 | 0.667 | 1.000 | 1.000 |
| `injection_prone` | 0.818 | 1.000 | 0.900 | 1.000 | 1.000 | 0.000 |
| `over_refuser` | 0.000 | 0.000 | 0.000 | 0.333 | 0.000 | 0.000 |

## Notes
- This is intentionally **model-agnostic**. Swap in a real LLM later behind the same interface.
- The scoring is deterministic because the model selects from a fixed candidate claim set.
