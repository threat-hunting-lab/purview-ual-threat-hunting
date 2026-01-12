from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from random import Random
from typing import Any, Dict, List, Tuple

from evals.metrics import confusion_from_bools


@dataclass(frozen=True)
class OpEvent:
    event_id: str
    operation: str
    src_ip: str
    label_is_malicious: bool


def ip_counts_global(events: List[OpEvent]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for e in events:
        counts[e.src_ip] = counts.get(e.src_ip, 0) + 1
    return counts


def ip_counts_by_operation(events: List[OpEvent]) -> Dict[Tuple[str, str], int]:
    """
    Counts (operation, ip) so we can compute rarity *within* an operation.
    """
    counts: Dict[Tuple[str, str], int] = {}
    for e in events:
        k = (e.operation, e.src_ip)
        counts[k] = counts.get(k, 0) + 1
    return counts


def _ip(octet: int, base: str) -> str:
    return f"{base}.{octet}"


def make_tenant_events(
    *,
    tenant_name: str,
    seed: int,
    attacker_ip: str,
    attacker_events: int,
    login_hot_ip_count: int,
    login_hot_events_per_ip: int,
    login_unique_oneoffs: int,
    admin_benign_ip_count: int,
    admin_benign_events_per_ip: int,
) -> List[OpEvent]:
    """
    Two operations:
      - UserLoggedIn: high volume, high diversity in Tenant B (simulates VPN/mobile churn)
      - Add-MailboxPermission: lower volume, tighter baseline (more meaningful rarity context)

    Attacker activity occurs in Add-MailboxPermission (sensitive op), held constant across tenants.
    """
    rng = Random(seed)
    events: List[OpEvent] = []
    eid = 0

    OP_LOGIN = "UserLoggedIn"
    OP_ADMIN = "Add-MailboxPermission"

    # Login: hot benign IPs (repeat a lot)
    login_hot_ips = [_ip(i + 1, "198.51.100") for i in range(login_hot_ip_count)]
    for ip in login_hot_ips:
        for _ in range(login_hot_events_per_ip):
            eid += 1
            events.append(OpEvent(f"{tenant_name}-E{eid}", OP_LOGIN, ip, False))

    # Login: unique benign one-offs (drift/noise)
    # These are the main cause of global rarity false positives.
    oneoff_start = 200
    for i in range(login_unique_oneoffs):
        ip = _ip(oneoff_start + i, "198.51.100")
        eid += 1
        events.append(OpEvent(f"{tenant_name}-E{eid}", OP_LOGIN, ip, False))

    # Admin op: small stable benign set (e.g., known admin networks / jump hosts)
    admin_ips = [_ip(50 + i, "192.0.2") for i in range(admin_benign_ip_count)]
    for ip in admin_ips:
        for _ in range(admin_benign_events_per_ip):
            eid += 1
            events.append(OpEvent(f"{tenant_name}-E{eid}", OP_ADMIN, ip, False))

    # Attacker events on admin op (held constant)
    for _ in range(attacker_events):
        eid += 1
        events.append(OpEvent(f"{tenant_name}-E{eid}", OP_ADMIN, attacker_ip, True))

    rng.shuffle(events)
    return events


def sweep_thresholds(
    *,
    events: List[OpEvent],
    max_threshold: int,
) -> Dict[str, List[Dict[str, Any]]]:
    """
    Compare:
      - global rarity: count(ip) <= t
      - conditional rarity: count(operation, ip) <= t
    """
    y_true = [e.label_is_malicious for e in events]

    g_counts = ip_counts_global(events)
    c_counts = ip_counts_by_operation(events)

    global_rows: List[Dict[str, Any]] = []
    conditional_rows: List[Dict[str, Any]] = []

    for t in range(1, max_threshold + 1):
        # Global
        y_pred_g = [(g_counts[e.src_ip] <= t) for e in events]
        mg = confusion_from_bools(y_true, y_pred_g)
        alert_rate_g = sum(y_pred_g) / len(y_pred_g) if y_pred_g else 0.0
        global_rows.append(
            {
                "threshold_count_leq": t,
                "tp": mg.tp, "fp": mg.fp, "tn": mg.tn, "fn": mg.fn,
                "precision": round(mg.precision, 4),
                "recall": round(mg.recall, 4),
                "f1": round(mg.f1, 4),
                "alert_rate": round(alert_rate_g, 4),
            }
        )

        # Conditional (within operation)
        y_pred_c = [(c_counts[(e.operation, e.src_ip)] <= t) for e in events]
        mc = confusion_from_bools(y_true, y_pred_c)
        alert_rate_c = sum(y_pred_c) / len(y_pred_c) if y_pred_c else 0.0
        conditional_rows.append(
            {
                "threshold_count_leq": t,
                "tp": mc.tp, "fp": mc.fp, "tn": mc.tn, "fn": mc.fn,
                "precision": round(mc.precision, 4),
                "recall": round(mc.recall, 4),
                "f1": round(mc.f1, 4),
                "alert_rate": round(alert_rate_c, 4),
            }
        )

    return {"global": global_rows, "conditional": conditional_rows}


def best_by_f1(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    # Prefer higher recall, then lower alert rate, then smaller threshold
    def key(r: Dict[str, Any]) -> Tuple[float, float, float, float]:
        return (r["f1"], r["recall"], -r["alert_rate"], -r["threshold_count_leq"])
    return max(rows, key=key)


def write_outputs(result: Dict[str, Any], out_dir: Path) -> Tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    json_path = out_dir / f"conditional_rarity_mitigation_{ts}.json"
    md_path = out_dir / f"conditional_rarity_mitigation_{ts}.md"

    json_path.write_text(json.dumps(result, indent=2), encoding="utf-8")

    def fmt_row(r: Dict[str, Any]) -> str:
        return (
            f"thr≤{r['threshold_count_leq']} | "
            f"P={r['precision']} R={r['recall']} F1={r['f1']} | "
            f"TP/FP/TN/FN={r['tp']}/{r['fp']}/{r['tn']}/{r['fn']} | "
            f"alert_rate={r['alert_rate']}"
        )

    a = result["tenant_a"]
    b = result["tenant_b"]

    best_a_g = a["best"]["global"]
    best_a_c = a["best"]["conditional"]
    best_b_g = b["best"]["global"]
    best_b_c = b["best"]["conditional"]

    md = []
    md.append("# Conditional Rarity Mitigation (Operation-Conditioned)\n\n")
    md.append("This experiment compares two rarity heuristics:\n\n")
    md.append("- **Global rarity**: flag if `count(ip) ≤ t`\n")
    md.append("- **Conditional rarity**: flag if `count(operation, ip) ≤ t`\n\n")
    md.append("Attacker behavior is held constant; only benign baseline diversity shifts.\n\n")

    md.append("## Expected failure mode\n")
    md.append(
        "Global rarity collapses under environments with high benign IP churn (e.g., VPN/mobile/remote work),\n"
        "because many benign IPs become 'rare' by count.\n\n"
        "Conditional rarity mitigates this by measuring rarity *within the operation context*.\n\n"
    )

    md.append("## Tenant A (lower login churn)\n")
    md.append(f"- Best global: **{fmt_row(best_a_g)}**\n")
    md.append(f"- Best conditional: **{fmt_row(best_a_c)}**\n\n")

    md.append("## Tenant B (high login churn / many benign one-offs)\n")
    md.append(f"- Best global: **{fmt_row(best_b_g)}**\n")
    md.append(f"- Best conditional: **{fmt_row(best_b_c)}**\n\n")

    md.append("## Interpretation\n")
    md.append(
        "- If **global** alert_rate/FP spikes in Tenant B while attacker behavior is unchanged, that demonstrates\n"
        "  distribution-shift brittleness.\n"
        "- If **conditional** maintains materially better precision/alert_rate in Tenant B, it demonstrates\n"
        "  a practical mitigation without adding AI.\n\n"
        "This is directly relevant to AI-assisted security: models that summarize or prioritize alerts inherit\n"
        "upstream brittleness and may produce confident narratives from noise floods unless baselines are conditioned.\n"
    )

    md_path.write_text("".join(md), encoding="utf-8")
    return json_path, md_path


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Eval: conditional rarity mitigation (per-operation rarity)")
    p.add_argument("--out", default="artifacts/evals", help="Output directory (default: artifacts/evals)")
    p.add_argument("--seed", type=int, default=11)
    p.add_argument("--max-threshold", type=int, default=6)

    p.add_argument("--attacker-ip", default="203.0.113.10")
    p.add_argument("--attacker-events", type=int, default=3)

    # Tenant A: lower churn
    p.add_argument("--a-login-oneoffs", type=int, default=20)

    # Tenant B: higher churn
    p.add_argument("--b-login-oneoffs", type=int, default=400)

    # Shared baseline for both tenants
    p.add_argument("--login-hot-ips", type=int, default=5)
    p.add_argument("--login-hot-events", type=int, default=60)

    p.add_argument("--admin-benign-ips", type=int, default=6)
    p.add_argument("--admin-benign-events", type=int, default=8)

    return p.parse_args()


def main() -> None:
    args = parse_args()

    tenant_a_events = make_tenant_events(
        tenant_name="TenantA",
        seed=args.seed,
        attacker_ip=args.attacker_ip,
        attacker_events=args.attacker_events,
        login_hot_ip_count=args.login_hot_ips,
        login_hot_events_per_ip=args.login_hot_events,
        login_unique_oneoffs=args.a_login_oneoffs,
        admin_benign_ip_count=args.admin_benign_ips,
        admin_benign_events_per_ip=args.admin_benign_events,
    )

    tenant_b_events = make_tenant_events(
        tenant_name="TenantB",
        seed=args.seed + 1,
        attacker_ip=args.attacker_ip,
        attacker_events=args.attacker_events,
        login_hot_ip_count=args.login_hot_ips,
        login_hot_events_per_ip=args.login_hot_events,
        login_unique_oneoffs=args.b_login_oneoffs,
        admin_benign_ip_count=args.admin_benign_ips,
        admin_benign_events_per_ip=args.admin_benign_events,
    )

    a = sweep_thresholds(events=tenant_a_events, max_threshold=args.max_threshold)
    b = sweep_thresholds(events=tenant_b_events, max_threshold=args.max_threshold)

    result = {
        "meta": {
            "experiment": "conditional_rarity_mitigation",
            "seed": args.seed,
            "max_threshold_swept": args.max_threshold,
            "attacker_ip": args.attacker_ip,
            "attacker_events": args.attacker_events,
            "tenant_a_login_oneoffs": args.a_login_oneoffs,
            "tenant_b_login_oneoffs": args.b_login_oneoffs,
        },
        "tenant_a": {
            "best": {
                "global": best_by_f1(a["global"]),
                "conditional": best_by_f1(a["conditional"]),
            },
            "sweep": a,
        },
        "tenant_b": {
            "best": {
                "global": best_by_f1(b["global"]),
                "conditional": best_by_f1(b["conditional"]),
            },
            "sweep": b,
        },
    }

    out_dir = Path(args.out)
    json_path, md_path = write_outputs(result, out_dir=out_dir)
    print(f"[OK] Wrote: {json_path}")
    print(f"[OK] Wrote: {md_path}")


if __name__ == "__main__":
    main()
