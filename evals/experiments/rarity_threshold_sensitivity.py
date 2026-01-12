from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from random import Random
from typing import Any, Dict, List, Optional, Tuple

from evals.metrics import confusion_from_bools


@dataclass(frozen=True)
class IPEvent:
    event_id: str
    src_ip: str
    label_is_malicious: bool


def _ip(octet: int, base: str) -> str:
    # base like "198.51.100" or "203.0.113"
    return f"{base}.{octet}"


def make_tenant_events(
    *,
    tenant_name: str,
    seed: int,
    attacker_ip: str,
    attacker_events: int,
    hot_ip_count: int,
    hot_events_per_ip: int,
    cold_ip_count: int,
    cold_events_per_ip: int,
    extra_unique_cold_ips: int,
) -> List[IPEvent]:
    """
    Builds a deterministic synthetic dataset that mimics a common rarity heuristic pitfall:

    - Attacker IP appears a small number of times (rare)
    - There are some "hot" benign IPs that appear many times (normal in large tenants)
    - The key shift: some tenants also have MANY one-off benign IPs (VPNs, mobile, NAT churn, etc.)
      which can make rarity-based heuristics explode with false positives.

    extra_unique_cold_ips controls "how diverse the baseline is".
    """
    rng = Random(seed)
    events: List[IPEvent] = []
    eid = 0

    # Hot benign IPs (repeat a lot)
    hot_ips = [_ip(i + 1, "198.51.100") for i in range(hot_ip_count)]
    for ip in hot_ips:
        for _ in range(hot_events_per_ip):
            eid += 1
            events.append(IPEvent(event_id=f"{tenant_name}-E{eid}", src_ip=ip, label_is_malicious=False))

    # Cold benign IPs (repeat a little)
    cold_ips = [_ip(i + 50, "198.51.100") for i in range(cold_ip_count)]
    for ip in cold_ips:
        for _ in range(cold_events_per_ip):
            eid += 1
            events.append(IPEvent(event_id=f"{tenant_name}-E{eid}", src_ip=ip, label_is_malicious=False))

    # Extra unique benign IPs (each appears once) -> drift/noise amplifier
    # These simulate environments with high IP churn (remote work, VPN egress pools, mobile ISPs, etc.)
    unique_pool_start = 150
    unique_ips = [_ip(unique_pool_start + i, "198.51.100") for i in range(extra_unique_cold_ips)]
    for ip in unique_ips:
        eid += 1
        events.append(IPEvent(event_id=f"{tenant_name}-E{eid}", src_ip=ip, label_is_malicious=False))

    # Attacker events (rare by count)
    for _ in range(attacker_events):
        eid += 1
        events.append(IPEvent(event_id=f"{tenant_name}-E{eid}", src_ip=attacker_ip, label_is_malicious=True))

    # Shuffle deterministically so ordering doesn’t leak structure
    rng.shuffle(events)
    return events


def ip_counts(events: List[IPEvent]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for e in events:
        counts[e.src_ip] = counts.get(e.src_ip, 0) + 1
    return counts


def sweep_rarity_thresholds(
    *,
    events: List[IPEvent],
    max_threshold: int,
) -> List[Dict[str, Any]]:
    """
    Rarity heuristic: flag events if their src_ip appears <= threshold times in the dataset.
    Sweep thresholds and record metrics.
    """
    counts = ip_counts(events)
    y_true = [e.label_is_malicious for e in events]

    rows: List[Dict[str, Any]] = []
    for t in range(1, max_threshold + 1):
        y_pred = [(counts[e.src_ip] <= t) for e in events]
        m = confusion_from_bools(y_true, y_pred)

        alert_rate = sum(y_pred) / len(y_pred) if y_pred else 0.0

        rows.append(
            {
                "threshold_count_leq": t,
                "tp": m.tp,
                "fp": m.fp,
                "tn": m.tn,
                "fn": m.fn,
                "precision": round(m.precision, 4),
                "recall": round(m.recall, 4),
                "f1": round(m.f1, 4),
                "alert_rate": round(alert_rate, 4),
            }
        )
    return rows


def best_by_f1(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    # Deterministic tie-breakers: prefer higher recall, then lower alert_rate, then smaller threshold.
    def key(r: Dict[str, Any]) -> Tuple[float, float, float, float]:
        return (r["f1"], r["recall"], -r["alert_rate"], -r["threshold_count_leq"])

    return max(rows, key=key)


def summarize_comparison(
    *,
    tenant_a_rows: List[Dict[str, Any]],
    tenant_b_rows: List[Dict[str, Any]],
) -> Dict[str, Any]:
    best_a = best_by_f1(tenant_a_rows)
    best_b = best_by_f1(tenant_b_rows)

    # Apply Tenant A's "best" threshold to Tenant B, and vice versa, to show brittleness.
    thr_a = best_a["threshold_count_leq"]
    thr_b = best_b["threshold_count_leq"]

    def row_for(rows: List[Dict[str, Any]], thr: int) -> Dict[str, Any]:
        for r in rows:
            if r["threshold_count_leq"] == thr:
                return r
        raise ValueError("threshold not found")

    b_using_a = row_for(tenant_b_rows, thr_a)
    a_using_b = row_for(tenant_a_rows, thr_b)

    return {
        "best_thresholds": {
            "tenant_a_best_by_f1": best_a,
            "tenant_b_best_by_f1": best_b,
        },
        "cross_apply": {
            "tenant_b_using_tenant_a_best_threshold": b_using_a,
            "tenant_a_using_tenant_b_best_threshold": a_using_b,
        },
        "interpretation": (
            "A fixed rarity threshold can look excellent in one baseline distribution and collapse in another "
            "when benign IP diversity changes. This is a distribution-shift brittleness problem: precision can "
            "drop sharply as alert volume explodes, even when attacker behavior is unchanged."
        ),
    }


def write_outputs(result: Dict[str, Any], out_dir: Path) -> Tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    json_path = out_dir / f"rarity_threshold_sensitivity_{ts}.json"
    md_path = out_dir / f"rarity_threshold_sensitivity_{ts}.md"

    json_path.write_text(json.dumps(result, indent=2), encoding="utf-8")

    a = result["tenant_a"]
    b = result["tenant_b"]
    comp = result["comparison"]

    best_a = comp["best_thresholds"]["tenant_a_best_by_f1"]
    best_b = comp["best_thresholds"]["tenant_b_best_by_f1"]
    b_using_a = comp["cross_apply"]["tenant_b_using_tenant_a_best_threshold"]
    a_using_b = comp["cross_apply"]["tenant_a_using_tenant_b_best_threshold"]

    def fmt_row(r: Dict[str, Any]) -> str:
        return (
            f"thr≤{r['threshold_count_leq']} | "
            f"P={r['precision']} R={r['recall']} F1={r['f1']} | "
            f"TP/FP/TN/FN={r['tp']}/{r['fp']}/{r['tn']}/{r['fn']} | "
            f"alert_rate={r['alert_rate']}"
        )

    # Show a small slice (first 6 thresholds) to keep markdown readable
    def small_table(rows: List[Dict[str, Any]], n: int = 6) -> str:
        lines = []
        lines.append("| threshold (count ≤ t) | precision | recall | f1 | alert_rate | TP | FP | TN | FN |")
        lines.append("|---:|---:|---:|---:|---:|---:|---:|---:|---:|")
        for r in rows[:n]:
            lines.append(
                f"| {r['threshold_count_leq']} | {r['precision']} | {r['recall']} | {r['f1']} | {r['alert_rate']} "
                f"| {r['tp']} | {r['fp']} | {r['tn']} | {r['fn']} |"
            )
        return "\n".join(lines)

    md = []
    md.append("# Rarity Threshold Sensitivity\n\n")
    md.append("This experiment stress-tests a simple rarity heuristic:\n")
    md.append("> flag events if their source IP appears **≤ threshold** times in the dataset.\n\n")
    md.append("Two synthetic tenants are generated with the **same attacker behavior** but different benign baselines.\n\n")

    md.append("## Tenant A (low benign IP diversity)\n")
    md.append(f"- Events: **{a['summary']['n_events']}** | Malicious: **{a['summary']['n_malicious']}**\n")
    md.append(f"- Benign unique IPs: **{a['summary']['n_benign_unique_ips']}**\n\n")
    md.append(small_table(a["sweep"]))
    md.append("\n\n")
    md.append(f"**Best (by F1) in Tenant A:** {fmt_row(best_a)}\n\n")

    md.append("## Tenant B (high benign IP diversity / drift)\n")
    md.append(f"- Events: **{b['summary']['n_events']}** | Malicious: **{b['summary']['n_malicious']}**\n")
    md.append(f"- Benign unique IPs: **{b['summary']['n_benign_unique_ips']}**\n\n")
    md.append(small_table(b["sweep"]))
    md.append("\n\n")
    md.append(f"**Best (by F1) in Tenant B:** {fmt_row(best_b)}\n\n")

    md.append("## Cross-apply the “best” threshold (shows brittleness)\n")
    md.append(f"- Tenant B using Tenant A’s best threshold: **{fmt_row(b_using_a)}**\n")
    md.append(f"- Tenant A using Tenant B’s best threshold: **{fmt_row(a_using_b)}**\n\n")

    md.append("## Notes\n")
    md.append(
        "- This is a deterministic synthetic experiment designed to isolate a real failure mode:\n"
        "  rarity-based heuristics can become unreliable under baseline drift (e.g., VPN churn, remote work, ISP diversity).\n"
        "- In an AI-assisted pipeline, this can produce overconfident narratives from noisy alert floods or hide attacker activity\n"
        "  behind environment-dependent thresholds.\n"
    )

    md_path.write_text("".join(md), encoding="utf-8")
    return json_path, md_path


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Eval: rarity threshold sensitivity under baseline drift")
    p.add_argument("--out", default="outputs/evals", help="Output directory for eval artifacts (default: outputs/evals)")
    p.add_argument("--seed", type=int, default=7, help="Deterministic RNG seed (default: 7)")
    p.add_argument("--max-threshold", type=int, default=6, help="Max rarity threshold to sweep (default: 6)")

    # Attacker settings (same for both tenants)
    p.add_argument("--attacker-ip", default="203.0.113.10", help="Attacker IP (default: 203.0.113.10)")
    p.add_argument("--attacker-events", type=int, default=3, help="Number of attacker events (default: 3)")

    # Tenant A baseline
    p.add_argument("--a-hot-ips", type=int, default=5)
    p.add_argument("--a-hot-events", type=int, default=50)
    p.add_argument("--a-cold-ips", type=int, default=30)
    p.add_argument("--a-cold-events", type=int, default=5)
    p.add_argument("--a-extra-unique", type=int, default=0, help="Extra one-off benign IPs in Tenant A (default: 0)")

    # Tenant B baseline (high diversity)
    p.add_argument("--b-hot-ips", type=int, default=5)
    p.add_argument("--b-hot-events", type=int, default=50)
    p.add_argument("--b-cold-ips", type=int, default=30)
    p.add_argument("--b-cold-events", type=int, default=5)
    p.add_argument("--b-extra-unique", type=int, default=200, help="Extra one-off benign IPs in Tenant B (default: 200)")

    return p.parse_args()


def main() -> None:
    args = parse_args()

    # Build tenants with same attacker but different benign baselines
    tenant_a_events = make_tenant_events(
        tenant_name="TenantA",
        seed=args.seed,
        attacker_ip=args.attacker_ip,
        attacker_events=args.attacker_events,
        hot_ip_count=args.a_hot_ips,
        hot_events_per_ip=args.a_hot_events,
        cold_ip_count=args.a_cold_ips,
        cold_events_per_ip=args.a_cold_events,
        extra_unique_cold_ips=args.a_extra_unique,
    )

    tenant_b_events = make_tenant_events(
        tenant_name="TenantB",
        seed=args.seed + 1,
        attacker_ip=args.attacker_ip,
        attacker_events=args.attacker_events,
        hot_ip_count=args.b_hot_ips,
        hot_events_per_ip=args.b_hot_events,
        cold_ip_count=args.b_cold_ips,
        cold_events_per_ip=args.b_cold_events,
        extra_unique_cold_ips=args.b_extra_unique,
    )

    a_rows = sweep_rarity_thresholds(events=tenant_a_events, max_threshold=args.max_threshold)
    b_rows = sweep_rarity_thresholds(events=tenant_b_events, max_threshold=args.max_threshold)

    a_counts = ip_counts(tenant_a_events)
    b_counts = ip_counts(tenant_b_events)

    result = {
        "meta": {
            "experiment": "rarity_threshold_sensitivity",
            "seed": args.seed,
            "attacker_ip": args.attacker_ip,
            "attacker_events": args.attacker_events,
            "max_threshold_swept": args.max_threshold,
        },
        "tenant_a": {
            "summary": {
                "n_events": len(tenant_a_events),
                "n_malicious": sum(e.label_is_malicious for e in tenant_a_events),
                "n_benign_unique_ips": len({ip for ip, c in a_counts.items() if ip != args.attacker_ip}),
            },
            "sweep": a_rows,
        },
        "tenant_b": {
            "summary": {
                "n_events": len(tenant_b_events),
                "n_malicious": sum(e.label_is_malicious for e in tenant_b_events),
                "n_benign_unique_ips": len({ip for ip, c in b_counts.items() if ip != args.attacker_ip}),
            },
            "sweep": b_rows,
        },
        "comparison": summarize_comparison(tenant_a_rows=a_rows, tenant_b_rows=b_rows),
    }

    out_dir = Path(args.out)
    json_path, md_path = write_outputs(result, out_dir=out_dir)
    print(f"[OK] Wrote: {json_path}")
    print(f"[OK] Wrote: {md_path}")


if __name__ == "__main__":
    main()
