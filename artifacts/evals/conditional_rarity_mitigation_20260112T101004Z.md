# Conditional Rarity Mitigation (Operation-Conditioned)

We evaluate rarity **only on a sensitive admin operation** (`Add-MailboxPermission`).

- **Global rarity** decision: flag if `count(ip) ≤ t` over the full dataset
- **Conditional rarity** decision: flag if `count(operation, ip) ≤ t`

## Why this scenario matters
To demonstrate the benefit of conditioning, the attacker IP is made **common globally** by injecting
benign login 'cover traffic' from the same IP (simulating shared VPN egress / common infrastructure).
Global rarity can then miss admin abuse because the IP no longer looks rare globally.

## Tenant A (lower login churn)
- Best global: **thr≤1 | P=0.0 R=0.0 F1=0.0 | TP/FP/TN/FN=0/0/48/3 | alert_rate=0.0**
- Best conditional: **thr≤3 | P=1.0 R=1.0 F1=1.0 | TP/FP/TN/FN=3/0/48/0 | alert_rate=0.0588**
- At thr≤3 global: **thr≤3 | P=0.0 R=0.0 F1=0.0 | TP/FP/TN/FN=0/0/48/3 | alert_rate=0.0**
- At thr≤3 conditional: **thr≤3 | P=1.0 R=1.0 F1=1.0 | TP/FP/TN/FN=3/0/48/0 | alert_rate=0.0588**

## Tenant B (high login churn)
- Best global: **thr≤1 | P=0.0 R=0.0 F1=0.0 | TP/FP/TN/FN=0/0/48/3 | alert_rate=0.0**
- Best conditional: **thr≤3 | P=1.0 R=1.0 F1=1.0 | TP/FP/TN/FN=3/0/48/0 | alert_rate=0.0588**
- At thr≤3 global: **thr≤3 | P=0.0 R=0.0 F1=0.0 | TP/FP/TN/FN=0/0/48/3 | alert_rate=0.0**
- At thr≤3 conditional: **thr≤3 | P=1.0 R=1.0 F1=1.0 | TP/FP/TN/FN=3/0/48/0 | alert_rate=0.0588**

## Interpretation
- If the attacker IP is common globally, **global rarity** can yield FN (low recall) even when the admin operation is rare.
- **Conditional rarity** preserves detection by measuring rarity inside the admin-operation context.
This illustrates a practical mitigation against baseline pollution and is directly relevant to AI-assisted triage: upstream
brittleness can cause models to confidently summarize incomplete/biased alert streams.
