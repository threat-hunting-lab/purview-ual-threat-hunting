# Evaluation Harness for UAL Threat Hunting Heuristics

## Purpose

This directory contains an **evaluation and failure-mode analysis layer** for the UAL Tier-1 threat hunting toolkit.

The core UAL scripts are intentionally heuristic-based and deterministic. They surface investigative leads rather than verdicts.  
This evaluation harness exists to answer a different question:

> *When do these heuristics fail, how brittle are they under realistic conditions, and how should those limitations be understood before using AI-assisted reasoning on top of them?*

This work is motivated by the observation that **AI systems are often most dangerous when they are confidently wrong**, especially when operating over incomplete, noisy, or adversary-influenced security telemetry.

---

## Why Evaluation Matters for AI-Assisted Security

In many environments, AI models are increasingly used to:
- summarize security incidents,
- prioritize alerts,
- cluster events into narratives,
- or suggest likely attacker behavior.

However, these models inherit **all upstream data weaknesses**:
- missing fields,
- inconsistent normalization,
- rare-event bias,
- stale or noisy indicators,
- and imperfect analyst labels.

Before placing any model “in the loop,” it is critical to understand:
- what information is being lost,
- which heuristics are fragile,
- and where confidence is unjustified.

This evaluation layer treats **security telemetry as adversary-influenced input**, not ground truth.

---

## Scope and Design Principles

This evaluation harness is intentionally:
- **Model-agnostic** (no LLMs required)
- **Deterministic and reproducible**
- **Focused on falsification**, not optimization
- **Grounded in real UAL behavior**, not toy datasets

The goal is not to maximize detection rates, but to **characterize failure modes** that would mislead downstream automation or AI-assisted analysis.

---

## Threat Model and Assumptions

### Assumptions
- UAL exports are structurally valid but may be incomplete
- Timestamps and event ordering are mostly accurate
- Analyst labels (when present) are noisy and imperfect
- Attackers may deliberately exploit logging blind spots

### Non-Assumptions
- Normalized fields are complete or authoritative
- Rarity implies maliciousness
- Absence of evidence implies benign behavior
- Labels represent ground truth

---

## Experiments

### 1. Normalized vs Raw Coverage

**Question:**  
How often does normalized UAL telemetry miss attacker infrastructure that is only present in raw `AuditData` fields?

**Why this matters:**  
AI systems frequently operate over normalized schemas. If normalization silently drops critical context, models may hallucinate explanations or over-generalize benign behavior.

**Method:**  
- Generate or sample UAL-like events where IP indicators appear inconsistently
- Compare detection coverage using:
  - normalized fields only
  - deep inspection of raw JSON
- Measure recall deltas and compute cost tradeoffs

**Failure Mode Exposed:**  
False confidence due to silent information loss.

---

### 2. Rarity Threshold Sensitivity

**Question:**  
How stable are IP rarity heuristics under changing baseline noise, tenant size, and IP diversity?

**Why this matters:**  
Static rarity thresholds often look reasonable in small datasets but collapse under scale or drift, producing misleading “rare” signals.

**Method:**  
- Vary baseline distributions and event volumes
- Sweep rarity thresholds
- Measure precision/recall degradation

**Failure Mode Exposed:**  
Brittle heuristics that appear robust in one environment but fail in another.

---

### 3. Label Noise Stability

**Question:**  
How sensitive are heuristic outcomes to imperfect or noisy analyst labels?

**Why this matters:**  
AI models trained or evaluated on noisy labels may overfit spurious patterns or reinforce incorrect assumptions.

**Method:**  
- Inject controlled label noise
- Observe stability of heuristic conclusions
- Track variance under increasing corruption

**Failure Mode Exposed:**  
Over-reliance on weak supervision.

---

## Metrics and Interpretation

Metrics are intentionally simple and interpretable:
- Precision / Recall
- Coverage deltas
- Stability under perturbation

These metrics are **diagnostic**, not absolute performance scores.

A “good” result is not high recall — it is **predictable degradation** under known stressors.

---

## Limitations

- This harness does not attempt to infer attacker intent
- Synthetic data cannot capture all real-world edge cases
- Results are environment-dependent by design
- This is not a replacement for analyst judgment

---

## Next Steps

Planned extensions include:
- Introducing model-in-the-loop summarization with explicit confidence bounds
- Evaluating hallucination risk when telemetry is incomplete
- Testing refusal behavior when evidence is insufficient
- Extending datasets to additional telemetry sources

---

## Summary

This evaluation harness exists to make uncertainty explicit.

Before asking AI systems to reason about security events, we must first understand **where the data lies, where heuristics break, and where confidence is unwarranted**.

This work treats evaluation as a safety mechanism — not an afterthought.
