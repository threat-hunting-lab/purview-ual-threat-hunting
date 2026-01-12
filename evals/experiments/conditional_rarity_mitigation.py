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


OP_LOGIN = "UserLoggedIn"
OP_ADMIN = "Add-MailboxPermission"


def ip_counts_global(events: List[OpEvent]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for e in events:
        counts[e.src_ip] = counts.get(e.src_ip, 0) + 1
    return counts


def ip_counts_by_operation(events: List[OpEvent]) -> Dict[Tuple[str, str], int]:
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
    attacker_login_cover_events: int,
    login_hot_ip_count: int,
    login_hot_events_per_ip: int,
    login_unique_oneoffs: int,
    admin_benign_ip_count: int,
    admin_benign_events_per_ip: int,
) -> List[OpEvent]:
    """
    Two operations:
      - UserLoggedIn: high volume; Tenant B has many one-off benign IPs (churn)
      - Add-MailboxPermission: lower volume; attacker acts here

    Key knob:
      attacker_login_cover_events:
        Adds BENIGN login events using attacker_ip. This simulates the attacker using
        infrastructure that is common globally (e.g., shared VPN egress), which breaks
        global rarity but not operation-conditioned rarity.
    """
    rng = Random(seed)
    events: List[OpEvent] = []
    eid = 0

    # Login: hot benign IPs (repeat a lot)
    login_hot_ips = [_ip(i + 1, "198.51.100") for i in range(login_hot_ip_count)]
    for ip in login_hot_ips:
        for _ in range(login_hot_events_per_ip):
            eid += 1
            events.append(OpEvent(f"{tenant_name}-E{eid}", OP_LOGIN, ip, False))

    # Login: attacker_ip "cover traffic" (BENIGN) to make attacker_ip common globally
    for _ in range(attacker_login_cover_events):
        eid += 1
        events.append(OpEvent(f"{tenant_name}-E{eid}", OP_LOGIN, attacker_ip, False))

    # Login: unique benign one-offs (drift/noise)
    oneoff_start = 200
    for i in range(login_unique_oneoffs):
        ip = _ip(oneoff_start + i, "198.51.100")
        eid += 1
        events.append(OpEvent(f"{tenant_name}-E{eid}", OP_LOGIN, ip, False))

    # Admin op: small stable benign set (e.g., jump hosts)
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


def sweep_thresholds_on_admin_only(
    *,
    events: List[OpEvent],
    max_threshold: int,
    admin_operation: str = OP_ADMIN,
) -> Dict[str, List[Dict[str, Any]]]:
    """
    Evaluate ONLY on admin_operation events, but use:
      - global rarity decision: global_count(ip) <= t (computed over ALL events)
      - conditional rarity decision: op_count(operation, ip) <= t
    """
    admin_events = [e for e in events if e.operation == admin_operation]
    y_true = [e.label_is_malicious for e in admin_events]

    g_counts = ip_counts_global(events)
    c_counts = ip_counts_by_operation(events)

    global_rows: List[Dict[str, Any]] = []
    conditional_rows: List[Dict[str, Any]] = []

    for t in range(1, max_threshold + 1):
        # Global rarity applied to admin events (decision uses global count)
        y_pred_g = [(g_counts[e.src_ip] <= t) for e in admin_events]
        mg = confusion_from_bools(y_true, y_pred_g)
        alert_rate_g = sum(y_pred_g) / len(y_pred_g) if y_pred_g else 0.0
        global_rows.append(
            {
                "threshold_count_leq": t,
                "tp": mg.tp,
                "fp": mg.fp,
                "tn": mg.tn,
                "fn": mg.fn,
                "precision": round(mg.precision, 4),
                "recall": round(mg.recall, 4),
                "f1": round(mg.f1, 4),
                "alert_rate": round(alert_rate_g, 4),
            }
        )

        # Conditional rarity within the admin operation
        y_pred_c = [(c_counts[(e.operation, e.src_ip)] <= t) for e in admin_events]
        mc = confusion_from_bools(y_true, y_pred_c)
        alert_rate_c = sum(y_pred_c) / len(y_pred_c) if y_pred_c else 0.0
        conditional_rows.append(
            {
                "threshold_count_leq": t,
                "tp": mc.tp,
                "fp": mc.fp,
                "tn": mc.tn,
                "fn": mc.fn,
                "precision": round(mc.precision, 4),
                "recall": round(mc.recall, 4),
                "f1": round(mc.f1, 4),
                "alert_rate": round(alert_rate_c, 4),
            }
        )

    return {"global": global_rows, "conditional": conditional_rows}


def best_by_f1(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    # Prefer higher recall, then lower alert rate, then smaller threshold.
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

    def row_at(rows: List[Dict[str, Any]], thr: int) -> Dict[str, Any]:
        for r in rows:
            if r["threshold_count_leq"] == thr:
                return r
        return rows[0]

    a = result["tenant_a"]
    b = result["tenant_b"]

    best_a_g = a["best"]["global"]
    best_a_c = a["best"]["conditional"]
    best_b_g = b["best"]["global"]
    best_b_c = b["best"]["conditional"]

    # Highlight a fixed threshold (3) since attacker_events default = 3
    a_g_thr3 = row_at(a["sweep"]["global"], 3)
    a_c_thr3 = row_at(a["sweep"]["conditional"], 3)
    b_g_thr3 = row_at(b["sweep"]["global"], 3)
    b_c_thr3 = row_at(b["sweep"]["conditional"], 3)

    md: List[str] = []
    md.append("# Conditional Rarity Mitigation (Operation-Conditioned)\n\n")
    md.append("We evaluate rarity **only on a sensitive admin operation** (`Add-MailboxPermission`).\n\n")
    md.append("- **Global rarity** decision: flag if `count(ip) ≤ t` over the full dataset\n")
    md.append("- **Conditional rarity** decision: flag if `count(operation, ip) ≤ t`\n\n")
    md.append("## Why this scenario matters\n")
    md.append(
        "To demonstrate the benefit of conditioning, the attacker IP is made **common globally** by injecting\n"
        "benign login 'cover traffic' from the same IP (simulating shared VPN egress / common infrastructure).\n"
        "Global rarity can then miss admin abuse because the IP no longer looks rare globally.\n\n"
    )

    md.append("## Tenant A (lower login churn)\n")
    md.append(f"- Best global: **{fmt_row(best_a_g)}**\n")
    md.append(f"- Best conditional: **{fmt_row(best_a_c)}**\n")
    md.append(f"- At thr≤3 global: **{fmt_row(a_g_thr3)}**\n")
    md.append(f"- At thr≤3 conditional: **{fmt_row(a_c_thr3)}**\n\n")

    md.append("## Tenant B (high login churn)\n")
    md.append(f"- Best global: **{fmt_row(best_b_g)}**\n")
    md.append(f"- Best conditional: **{fmt_row(best_b_c)}**\n")
    md.append(f"- At thr≤3 global: **{fmt_row(b_g_thr3)}**\n")
    md.append(f"- At thr≤3 conditional: **{fmt_row(b_c_thr3)}**\n\n")

    md.append("## Interpretation\n")
    md.append(
        "- If the attacker IP is common globally, **global rarity** can yield FN (low recall) even when the admin operation is rare.\n"
        "- **Conditional rarity** preserves detection by measuring rarity inside the admin-operation context.\n"
        "This illustrates a practical mitigation against baseline pollution and is directly relevant to AI-assisted triage: upstream\n"
        "brittleness can cause models to confidently summarize incomplete/biased alert streams.\n"
    )

    md_path.write_text("".join(md), encoding="utf-8")
    return json_path, md_path


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Eval: conditional rarity mitigation (per-operation baseline)")
    p.add_argument("--out", default="artifacts/evals", help="Output directory (default: artifacts/evals)")
    p.add_argument("--seed", type=int, default=11)
    p.add_argument("--max-threshold", type=int, default=6)

    p.add_argument("--attacker-ip", default="203.0.113.10")
    p.add_argument("--attacker-events", type=int, default=3)

    # Critical knob: make attacker_ip common in logins (benign "cover traffic")
    p.add_argument("--attacker-login-cover-events", type=int, default=50)

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
        attacker_login_cover_events=args.attacker_login_cover_events,
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
        attacker_login_cover_events=args.attacker_login_cover_events,
        login_hot_ip_count=args.login_hot_ips,
        login_hot_events_per_ip=args.login_hot_events,
        login_unique_oneoffs=args.b_login_oneoffs,
        admin_benign_ip_count=args.admin_benign_ips,
        admin_benign_events_per_ip=args.admin_benign_events,
    )

    a = sweep_thresholds_on_admin_only(events=tenant_a_events, max_threshold=args.max_threshold)
    b = sweep_thresholds_on_admin_only(events=tenant_b_events, max_threshold=args.max_threshold)

    result = {
        "meta": {
            "experiment": "conditional_rarity_mitigation",
            "seed": args.seed,
            "max_threshold_swept": args.max_threshold,
            "attacker_ip": args.attacker_ip,
            "attacker_events": args.attacker_events,
            "attacker_login_cover_events": args.attacker_login_cover_events,
            "tenant_a_login_oneoffs": args.a_login_oneoffs,
            "tenant_b_login_oneoffs": args.b_login_oneoffs,
            "evaluation_scoped_to_operation": OP_ADMIN,
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
