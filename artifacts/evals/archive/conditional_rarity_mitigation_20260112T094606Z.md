# Conditional Rarity Mitigation (Operation-Conditioned)

This experiment compares two rarity heuristics:

- **Global rarity**: flag if `count(ip) ≤ t`
- **Conditional rarity**: flag if `count(operation, ip) ≤ t`

Attacker behavior is held constant; only benign baseline diversity shifts.

## Expected failure mode
Global rarity collapses under environments with high benign IP churn (e.g., VPN/mobile/remote work),
because many benign IPs become 'rare' by count.

Conditional rarity mitigates this by measuring rarity *within the operation context*.

## Tenant A (lower login churn)
- Best global: **thr≤3 | P=0.1304 R=1.0 F1=0.2308 | TP/FP/TN/FN=3/20/348/0 | alert_rate=0.062**
- Best conditional: **thr≤3 | P=0.1304 R=1.0 F1=0.2308 | TP/FP/TN/FN=3/20/348/0 | alert_rate=0.062**

## Tenant B (high login churn / many benign one-offs)
- Best global: **thr≤3 | P=0.0074 R=1.0 F1=0.0148 | TP/FP/TN/FN=3/400/348/0 | alert_rate=0.5366**
- Best conditional: **thr≤3 | P=0.0074 R=1.0 F1=0.0148 | TP/FP/TN/FN=3/400/348/0 | alert_rate=0.5366**

## Interpretation
- If **global** alert_rate/FP spikes in Tenant B while attacker behavior is unchanged, that demonstrates
  distribution-shift brittleness.
- If **conditional** maintains materially better precision/alert_rate in Tenant B, it demonstrates
  a practical mitigation without adding AI.

This is directly relevant to AI-assisted security: models that summarize or prioritize alerts inherit
upstream brittleness and may produce confident narratives from noise floods unless baselines are conditioned.
