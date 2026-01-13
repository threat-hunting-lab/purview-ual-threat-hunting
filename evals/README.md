# Evaluation Harness for UAL Threat Hunting Heuristics

## Purpose

This directory contains an **evaluation and failure-mode analysis layer** for the UAL Tier-1 threat hunting toolkit.

The core UAL scripts are intentionally heuristic-based and deterministic. They surface investigative leads rather than verdicts.  
This evaluation harness exists to answer a different question:

> *When do these heuristics fail, how brittle are they under realistic conditions, and how should those limitations be understood before using AI-assisted reasoning on top of them?*

This work is motivated by the observation that **AI systems are often most dangerous when they are confidently wrong**, especially when operating over incomplete, noisy, or adversary-influenced security telemetry.

Example: a model may confidently summarize "no evidence of compromise" when the relevant fields were never present in the normalized schema.

---

## Quickstart (Reproduce the Artifacts)

From the repo root:

```bash
python -m evals.experiments.normalized_vs_raw_coverage --out artifacts/evals
python -m evals.experiments.rarity_threshold_sensitivity --out artifacts/evals
python -m evals.experiments.conditional_rarity_mitigation --out artifacts/evals
python -m evals.experiments.model_in_loop_control_eval --out artifacts/evals
```

Artifacts are written to `artifacts/evals/` as:
- `.md` (human-readable, reviewer-facing)
- `.json` (machine-readable; may be excluded from git in some repos via `.gitignore`)

## Why Evaluation Matters for AI-Assisted Security

In many environments, AI models are increasingly used to:
- Summarize security incidents
- Prioritize alerts
- Cluster events into narratives
- Suggest likely attacker behavior

However, these models inherit all upstream data weaknesses:
- Missing fields
- Inconsistent normalization
- Rare-event bias
- Stale or noisy indicators
- Imperfect analyst labels

Before placing any model "in the loop," it is critical to understand:
- What information is being lost
- Which heuristics are fragile
- Where confidence is unjustified

This evaluation layer treats security telemetry as adversary-influenced input, not ground truth.

## Scope and Design Principles

This evaluation harness is intentionally:
- **Model-agnostic where possible** (LLMs are optional, not required)
- **Deterministic and reproducible**
- **Focused on falsification, not optimization**
- **Grounded in real UAL behavior, not toy datasets**

The goal is not to maximize detection rates, but to characterize failure modes that would mislead downstream automation or AI-assisted analysis.

## Threat Model and Assumptions

### Assumptions

- UAL exports are structurally valid but may be incomplete
- Timestamps and event ordering are mostly accurate
- Analyst labels (when present) are noisy and imperfect
- Attackers may deliberately exploit logging blind spots

### Explicit Non-Assumptions

- Normalized fields are complete or authoritative
- Rarity implies maliciousness
- Absence of evidence implies benign behavior
- Labels represent ground truth

## Experiments

### 1. Normalized vs Raw Coverage

**Question:**  
How often does normalized UAL telemetry miss attacker infrastructure that is only present in raw AuditData fields?

**Why this matters:**  
AI systems frequently operate over normalized schemas. If normalization silently drops critical context, models may hallucinate explanations or over-generalize benign behavior.

**Outputs:**
- `artifacts/evals/normalized_vs_raw_coverage_20260112T093437Z.md`
- `artifacts/evals/normalized_vs_raw_coverage_20260112T093437Z.json`

### 2. Rarity Threshold Sensitivity

**Question:**  
How stable are IP rarity heuristics under changing baseline noise, tenant size, and IP diversity?

**Why this matters:**  
Static rarity thresholds often look reasonable in small datasets but collapse under scale or drift, producing misleading "rare" signals.

**Outputs:**
- `artifacts/evals/rarity_threshold_sensitivity_20260112T093440Z.md`
- `artifacts/evals/rarity_threshold_sensitivity_20260112T093440Z.json`

### 3. Conditional Rarity Mitigation (Operation-Conditioned)

**Question:**  
When an attacker IP becomes common globally (baseline pollution / shared VPN egress), can global rarity miss sensitive admin abuse — and does operation-conditioned rarity mitigate that?

**Why this matters:**  
Global rarity can fail when an indicator is frequent in high-volume operations (e.g., logins), even if it is rare where it matters (e.g., mailbox permission changes). This is a classic upstream brittleness problem: downstream AI triage/summarization inherits whatever the detector does (including blind spots).

**Method (high level):**
- Evaluate only a sensitive operation (Add-MailboxPermission)
- Inject benign "cover traffic" so the attacker IP is common globally
- Compare:
  - **Global rarity:** `count(ip) ≤ t`
  - **Conditional rarity:** `count(operation, ip) ≤ t`

**Outputs:**
- `artifacts/evals/conditional_rarity_mitigation_20260112T101004Z.md`
- `artifacts/evals/conditional_rarity_mitigation_20260112T101004Z.json`

### 4. Model-in-the-Loop Control Eval (Hallucination / Refusal / Injection)

**Question:**  
If an LLM is used to summarize or triage UAL-style evidence, can we score whether it:
- selects only evidence-supported claims (no hallucinations),
- refuses when evidence is insufficient,
- ignores prompt-injection attempts embedded in "logs"?

**Why this matters:**  
In AI-assisted security, the most dangerous failure mode is confidently wrong output over incomplete or adversary-influenced telemetry. This experiment treats model output like a detector: it must make constrained, auditable selections under explicit rules.

**Method (high level):**

Each case contains:
- `evidence[]` (UAL-style snippets)
- `candidate_claims{}` (the only allowed claims)
- `supported_claim_ids[]` (ground-truth supported claims)

The model returns `supported_claim_ids` and is scored via a confusion matrix over the claim set.

Additional labels track injection presence and whether refusal is required.

**Outputs:**
- `artifacts/evals/model_in_loop_control_eval_20260112T105045Z.md`
- (Optional/generated) `artifacts/evals/model_in_loop_control_eval_20260112T105045Z.json`

## Metrics and Interpretation

Metrics are intentionally simple and interpretable:
- Precision / Recall / F1
- Alert rate (proxy for operational triage load)
- Coverage deltas
- Stability under perturbation

These metrics are diagnostic, not absolute performance scores.

A "good" result is not high recall — it is **predictable degradation under known stressors**.

## Limitations

- This harness does not attempt to infer attacker intent
- Synthetic data cannot capture all real-world edge cases
- Results are environment-dependent by design
- This is not a replacement for analyst judgment

## Next Steps

Planned extensions include:
- Calibrated abstention: penalize "confidently wrong" more heavily than uncertainty
- More adversarial cases: conflicting evidence, poisoned fields, partial telemetry, and injection variants
- Label-noise stress test: inject controlled label corruption to quantify metric instability under weak supervision
- Extending datasets to additional telemetry sources

## Summary

This evaluation harness exists to make uncertainty explicit.

Before asking AI systems to reason about security events, we must first understand where the data lies, where heuristics break, and where confidence is unwarranted.

This work treats evaluation as a safety mechanism — not an afterthought.
