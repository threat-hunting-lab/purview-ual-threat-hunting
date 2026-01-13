# Purview UAL Threat Hunting Toolkit

Focused Python utilities for threat hunting within **Microsoft Purview Unified Audit Logs (UAL)** at scale.

Designed for environments where:
- UAL exports contain **hundreds of thousands to millions of records**
- Suspicious activity may be buried in nested **`AuditData` JSON**
- Analysts need **repeatable, explainable heuristics** (not black-box verdicts)

The scripts emphasize **signal reduction, rarity analysis, defensive safety**, and (Phase 2) **evaluation of failure modes** relevant to AI-assisted security.

---

## Why This Exists

Microsoft Purview UAL data presents several challenges in real investigations:
- High-volume CSV exports that exceed SIEM-friendly sizes
- Critical security actions mixed with benign noise
- IP indicators that appear inconsistently across normalized and raw fields
- Nested JSON (`AuditData`) that often contains the only copy of attacker infrastructure

This toolkit was built to:
- Reduce audit log noise deterministically
- Surface rare, external, and high-risk behavior
- Correlate IOC data safely across both structured and raw audit fields
- Operate on large datasets without exhausting memory

---

## Included Scripts (Tier-1)

| Script | Purpose |
|------|--------|
| `ual_critical_plus_rarity.py` | Surfaces critical UAL operations and augments them with IP rarity + externality heuristics |
| `ual_targeted_rare_hunts.py` | Detects high-risk operations performed from rare external IPs |
| `ual_spray_bruteforce.py` | Identifies password spraying / brute-force patterns using time and IP/user distribution |
| `ual_login_ioc_hits.py` | Matches IOC IPs against normalized login fields |
| `ual_ioc_hits_from_raw.py` | Deep IOC sweep across nested `AuditData` JSON when normalized fields are insufficient |

---

## Why Two IOC Scripts?

This distinction is intentional and reflects real-world UAL behavior:

- **`ual_login_ioc_hits.py`**  
  Fast, low-cost IOC matching against normalized IP fields. Use this when login telemetry is clean and well-structured.

- **`ual_ioc_hits_from_raw.py`**  
  Deep inspection of raw `AuditData` JSON. Required when attacker IPs appear only in nested or non-standard fields.

Separating these avoids unnecessary JSON parsing overhead while preserving coverage.

---

## Phase 2 — Evaluation & Robustness (AI-Security Relevant)

This repo also includes an **evaluation harness** focused on how simple heuristics fail under:
- **Coverage gaps** (normalized-only telemetry missing key fields)
- **Baseline drift** (tenant differences / VPN churn)
- **Baseline pollution** (indicators common globally but rare in sensitive operations)

This matters for AI-assisted security because any LLM-based summarization/triage inherits upstream brittleness and can produce confident narratives from biased alert streams unless uncertainty and coverage are explicit.

- Evaluation overview: `evals/README.md`
- Canonical artifacts (sample outputs): `artifacts/evals/`

**Key experiments (Phase 2):**
- Normalized vs Raw Coverage: `artifacts/evals/normalized_vs_raw_coverage_20260112T093437Z.md`
- Rarity Threshold Sensitivity: `artifacts/evals/rarity_threshold_sensitivity_20260112T093440Z.md`
- Conditional Rarity Mitigation: `artifacts/evals/conditional_rarity_mitigation_20260112T101004Z.md`

## Phase 3 — Model-in-the-Loop Control Eval (LLM Safety Harness)

Phase 3 adds a **deterministic evaluation harness** for AI-assisted security workflows: given a UAL-style evidence bundle and a finite set of candidate claims, a model must select **only** claims supported by evidence, **refuse** when evidence is insufficient, and **ignore prompt-injection** attempts embedded in the data.

This is designed to measure (and prevent) the exact failure modes that break real-world deployments:
- **Hallucination**: selecting unsupported claims (false positives)
- **Under-calling**: missing supported claims (false negatives)
- **Over-refusal**: refusing when evidence is sufficient
- **Prompt injection**: following malicious instructions inside "logs"

**Phase 3 experiment:**
- Model-in-loop control eval (claim support + refusal + injection):  
  `evals/experiments/model_in_loop_control_eval.py`

**Canonical Phase 3 artifact (sample output):**
- `artifacts/evals/model_in_loop_control_eval_20260112T105045Z.md`

Run it from repo root:
```bash
python -m evals.experiments.model_in_loop_control_eval --out artifacts/evals
```

Note: the experiment writes both `.md` and `.json`. Some JSON artifacts may be excluded by `.gitignore`; the `.md` is intended as the reviewer-facing canonical summary.

---

## Installation

Python 3.9+ recommended.

```bash
python -m venv .venv
# Windows PowerShell:
# .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Quickstart Examples (Tier-1)

```bash
python -m ual.scripts.ual_critical_plus_rarity --input ual.csv --slim

python -m ual.scripts.ual_targeted_rare_hunts --input ual.csv --slim

python -m ual.scripts.ual_login_ioc_hits \
  --input ual.csv \
  --iocs ioc_ips.example.txt \
  --slim

python -m ual.scripts.ual_ioc_hits_from_raw \
  --input ual.csv \
  --iocs ioc_ips.example.txt \
  --slim
```

## Quickstart (Reproduce Phase 2 Evals)

From the repo root:

```bash
python -m evals.experiments.normalized_vs_raw_coverage --out artifacts/evals
python -m evals.experiments.rarity_threshold_sensitivity --out artifacts/evals
python -m evals.experiments.conditional_rarity_mitigation --out artifacts/evals
```

Artifacts are written to `artifacts/evals/` as both:
- `.md` (human-readable)
- `.json` (machine-readable)

## Output

Tier-1 script outputs are written to the `outputs/` directory by default.

Phase 2 evaluation artifacts are written to `artifacts/evals/`.

## Repo Layout

Typical layout (paths may vary slightly by branch):

- `ual/scripts/` — Tier-1 hunting scripts (CLI entrypoints)
- `evals/` — evaluation harness + experiments
- `artifacts/evals/` — committed example outputs (md/json)
- `outputs/` — local runtime outputs (often gitignored)

## OPSEC & Safety

- No tenant-specific field names are hardcoded
- No proprietary schemas or identifiers are included
- Example IOC and CIDR files are intentionally non-sensitive
- Scripts expect sanitized exports prior to public use

This repository is intended for **defensive research and detection engineering only**.

## Limitations

- Heuristic-based: results require analyst judgment
- IP rarity thresholds are environment-dependent
- Not a verdict engine — findings are investigative leads
- Assumes UAL export integrity and timestamp accuracy
- Evaluation artifacts illustrate failure modes, not universal performance guarantees

## License

MIT License
