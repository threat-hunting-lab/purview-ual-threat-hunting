# Rarity Threshold Sensitivity

This experiment stress-tests a simple rarity heuristic:
> flag events if their source IP appears **≤ threshold** times in the dataset.

Two synthetic tenants are generated with the **same attacker behavior** but different benign baselines.

## Tenant A (low benign IP diversity)
- Events: **403** | Malicious: **3**
- Benign unique IPs: **35**

| threshold (count ≤ t) | precision | recall | f1 | alert_rate | TP | FP | TN | FN |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 | 0.0 | 0.0 | 0.0 | 0.0 | 0 | 0 | 400 | 3 |
| 2 | 0.0 | 0.0 | 0.0 | 0.0 | 0 | 0 | 400 | 3 |
| 3 | 1.0 | 1.0 | 1.0 | 0.0074 | 3 | 0 | 400 | 0 |
| 4 | 1.0 | 1.0 | 1.0 | 0.0074 | 3 | 0 | 400 | 0 |
| 5 | 0.0196 | 1.0 | 0.0385 | 0.3797 | 3 | 150 | 250 | 0 |
| 6 | 0.0196 | 1.0 | 0.0385 | 0.3797 | 3 | 150 | 250 | 0 |

**Best (by F1) in Tenant A:** thr≤3 | P=1.0 R=1.0 F1=1.0 | TP/FP/TN/FN=3/0/400/0 | alert_rate=0.0074

## Tenant B (high benign IP diversity / drift)
- Events: **603** | Malicious: **3**
- Benign unique IPs: **235**

| threshold (count ≤ t) | precision | recall | f1 | alert_rate | TP | FP | TN | FN |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 | 0.0 | 0.0 | 0.0 | 0.3317 | 0 | 200 | 400 | 3 |
| 2 | 0.0 | 0.0 | 0.0 | 0.3317 | 0 | 200 | 400 | 3 |
| 3 | 0.0148 | 1.0 | 0.0291 | 0.3367 | 3 | 200 | 400 | 0 |
| 4 | 0.0148 | 1.0 | 0.0291 | 0.3367 | 3 | 200 | 400 | 0 |
| 5 | 0.0085 | 1.0 | 0.0169 | 0.5854 | 3 | 350 | 250 | 0 |
| 6 | 0.0085 | 1.0 | 0.0169 | 0.5854 | 3 | 350 | 250 | 0 |

**Best (by F1) in Tenant B:** thr≤3 | P=0.0148 R=1.0 F1=0.0291 | TP/FP/TN/FN=3/200/400/0 | alert_rate=0.3367

## Cross-apply the “best” threshold (shows brittleness)
- Tenant B using Tenant A’s best threshold: **thr≤3 | P=0.0148 R=1.0 F1=0.0291 | TP/FP/TN/FN=3/200/400/0 | alert_rate=0.3367**
- Tenant A using Tenant B’s best threshold: **thr≤3 | P=1.0 R=1.0 F1=1.0 | TP/FP/TN/FN=3/0/400/0 | alert_rate=0.0074**

## Notes
- This is a deterministic synthetic experiment designed to isolate a real failure mode:
  rarity-based heuristics can become unreliable under baseline drift (e.g., VPN churn, remote work, ISP diversity).
- In an AI-assisted pipeline, this can produce overconfident narratives from noisy alert floods or hide attacker activity
  behind environment-dependent thresholds.
