# Purview UAL Threat Hunting Toolkit

Focused Python utilities for threat hunting within **Microsoft Purview Unified Audit Logs (UAL)** at scale.

Designed for environments where:
- UAL exports contain **hundreds of thousands to millions of records**
- Suspicious activity may be buried in nested **`AuditData` JSON**
- Analysts need **repeatable, explainable heuristics** (not black-box verdicts)

The scripts emphasize **signal reduction, rarity analysis, and defensive safety**.

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

## Included Scripts (Tier-1)

| Script | Purpose |
|------|--------|
| `ual_critical_plus_rarity.py` | Surfaces critical UAL operations and augments them with IP rarity + externality heuristics |
| `ual_targeted_rare_hunts.py` | Detects high-risk operations performed from rare external IPs |
| `ual_spray_bruteforce.py` | Identifies password spraying / brute-force patterns using time and IP/user distribution |
| `ual_login_ioc_hits.py` | Matches IOC IPs against normalized login fields |
| `ual_ioc_hits_from_raw.py` | Deep IOC sweep across nested `AuditData` JSON when normalized fields are insufficient |

## Why Two IOC Scripts?

This distinction is intentional and reflects real-world UAL behavior:

- **`ual_login_ioc_hits.py`**  
  Fast, low-cost IOC matching against normalized IP fields. Use this when login telemetry is clean and well-structured.

- **`ual_ioc_hits_from_raw.py`**  
  Deep inspection of raw `AuditData` JSON. Required when attacker IPs appear only in nested or non-standard fields.

Separating these avoids unnecessary JSON parsing overhead while preserving coverage.

## Installation

Python 3.9+ recommended.

```bash
python -m venv .venv
# Windows PowerShell:
# .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Quickstart Examples

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

## Output

Outputs are written to the `outputs/` directory by default.

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

## License

MIT License
