# Conditional Rarity Mitigation (Operation-Conditioned)

This experiment compares two rarity heuristics **evaluated only on a sensitive admin operation**:

- **Global rarity**: flag admin-op events if `count(ip) ≤ t` over the full dataset
- **Conditional rarity**: flag admin-op events if `count(operation, ip) ≤ t`

Attacker behavior is held constant; only benign baseline diversity (login churn) shifts.

## Why scope evaluation to admin-only?
High-volume operations like logins can have extreme benign diversity (VPN/mobile churn). If a rarity heuristic is applied globally without context, benign one-offs can dominate alert volume. Scoping the evaluation to a sensitive operation (e.g., mailbox permission changes) ensures we measure whether conditioning actually improves signal quality where it matters.

## Tenant A (lower login churn)
- Best global: **thr≤3 | P=1.0 R=1.0 F1=1.0 | TP/FP/TN/FN=3/0/48/0 | alert_rate=0.0588**
- Best conditional: **thr≤3 | P=1.0 R=1.0 F1=1.0 | TP/FP/TN/FN=3/0/48/0 | alert_rate=0.0588**

## Tenant B (high login churn / many benign one-offs)
- Best global: **thr≤3 | P=1.0 R=1.0 F1=1.0 | TP/FP/TN/FN=3/0/48/0 | alert_rate=0.0588**
- Best conditional: **thr≤3 | P=1.0 R=1.0 F1=1.0 | TP/FP/TN/FN=3/0/48/0 | alert_rate=0.0588**

## Interpretation
- If **global** precision/alert_rate degrades in Tenant B (while attacker behavior is unchanged), this demonstrates
  distribution-shift brittleness caused by environment-dependent baselines.
- If **conditional** maintains materially better precision/alert_rate in Tenant B, this demonstrates a practical
  mitigation: measure rarity *within operation context* and scope evaluation to sensitive actions.

This is directly relevant to AI-assisted security: models that summarize or prioritize alerts inherit upstream
brittleness and may produce confident narratives from noise unless baselines are conditioned and scoped.
