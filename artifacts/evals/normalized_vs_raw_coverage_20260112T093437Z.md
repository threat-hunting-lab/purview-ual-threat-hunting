# Normalized vs Raw Coverage
- Events: **5**
- Labeled malicious events: **3**
- IOC count: **1**

## True-positive coverage breakdown
- Hit via normalized only: **1**
- Hit via raw AuditData only: **1**
- Hit via both: **1**
- Fraction missed by normalized-only: **0.3333**

## Metrics
### normalized_only
- TP/FP/TN/FN: **2 / 0 / 2 / 1**
- Precision: **1.0**
- Recall: **0.6667**
- F1: **0.8**

### raw_only
- TP/FP/TN/FN: **2 / 0 / 2 / 1**
- Precision: **1.0**
- Recall: **0.6667**
- F1: **0.8**

### combined
- TP/FP/TN/FN: **3 / 0 / 2 / 0**
- Precision: **1.0**
- Recall: **1.0**
- F1: **1.0**

## Notes
- This is a deterministic synthetic dataset intended to demonstrate the real UAL failure mode:
  attacker infrastructure can appear only in nested AuditData, not in normalized columns.
- In real environments, raw parsing increases compute cost; this experiment isolates the coverage tradeoff.
