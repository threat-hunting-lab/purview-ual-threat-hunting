from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from evals.metrics import confusion_from_bools, coverage_delta


# ----------------------------
# Synthetic UAL-like event model
# ----------------------------

@dataclass(frozen=True)
class Event:
    """
    Minimal event schema for evaluating 'normalized vs raw' IOC coverage.

    - normalized_ip: simulates a normalized column like ClientIP / IPAddress / etc.
    - auditdata: simulates nested JSON where attacker infra may actually appear
    - label_is_malicious: ground truth for whether this event contains an IOC we care about
    """
    event_id: str
    operation: str
    normalized_ip: Optional[str]
    auditdata: Dict[str, Any]
    label_is_malicious: bool


def _extract_ips_from_raw(auditdata: Dict[str, Any]) -> Set[str]:
    """
    Extremely conservative raw extractor: only returns strings that look like IPv4.
    We keep it simple on purpose: the goal is coverage, not perfect parsing.
    """
    ips: Set[str] = set()

    def walk(obj: Any) -> None:
        if isinstance(obj, dict):
            for v in obj.values():
                walk(v)
        elif isinstance(obj, list):
            for v in obj:
                walk(v)
        elif isinstance(obj, str):
            s = obj.strip()
            # Minimal IPv4 check (no regex, deterministic, fast)
            parts = s.split(".")
            if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
                ips.add(s)

    walk(auditdata)
    return ips


def _make_synthetic_events(iocs: Set[str]) -> List[Event]:
    """
    Creates a small deterministic dataset that mirrors the real UAL failure mode:
    attacker infra sometimes appears only in raw AuditData and not in normalized fields.
    """
    # IOC chosen for demo; these should be non-sensitive test IPs
    # (You can replace with TEST-NET ranges if you want)
    ioc_a = next(iter(iocs)) if iocs else "203.0.113.10"  # TEST-NET-3 example

    return [
        # Hit via normalized only (raw does not include)
        Event(
            event_id="E1",
            operation="UserLoggedIn",
            normalized_ip=ioc_a,
            auditdata={"UserAgent": "Mozilla/5.0", "Note": "no ip here"},
            label_is_malicious=True,
        ),
        # Hit via raw only (normalized missing)
        Event(
            event_id="E2",
            operation="Add-MailboxPermission",
            normalized_ip=None,
            auditdata={"Actor": {"IP": ioc_a}, "Nested": {"Metadata": ["x", "y"]}},
            label_is_malicious=True,
        ),
        # Hit via both
        Event(
            event_id="E3",
            operation="Update-ConditionalAccessPolicy",
            normalized_ip=ioc_a,
            auditdata={"ClientIP": ioc_a, "Context": {"foo": "bar"}},
            label_is_malicious=True,
        ),
        # True negative (benign)
        Event(
            event_id="E4",
            operation="FileAccessed",
            normalized_ip="192.0.2.44",  # TEST-NET-1 example
            auditdata={"ClientIP": "192.0.2.44"},
            label_is_malicious=False,
        ),
        # False-positive trap: raw contains IP but not an IOC
        Event(
            event_id="E5",
            operation="SearchQueryPerformed",
            normalized_ip=None,
            auditdata={"SomeIP": "198.51.100.22"},  # TEST-NET-2
            label_is_malicious=False,
        ),
    ]


def evaluate(events: List[Event], iocs: Set[str]) -> Dict[str, Any]:
    """
    Compare two strategies:
      A) Normalized-only IOC matching
      B) Raw-only IOC matching (deep parse of AuditData)
      C) Combined (normalized OR raw)

    Produces:
      - confusion matrices for each
      - coverage analysis: what would be missed if you trusted only normalized fields
    """
    y_true: List[bool] = [e.label_is_malicious for e in events]

    pred_norm: List[bool] = []
    pred_raw: List[bool] = []
    pred_combined: List[bool] = []

    # For coverage breakdown among true positives
    hit_norm_only = hit_raw_only = hit_both = 0

    for e in events:
        norm_hit = (e.normalized_ip is not None) and (e.normalized_ip in iocs)
        raw_ips = _extract_ips_from_raw(e.auditdata)
        raw_hit = any(ip in iocs for ip in raw_ips)

        pred_norm.append(norm_hit)
        pred_raw.append(raw_hit)
        pred_combined.append(norm_hit or raw_hit)

        # Coverage breakdown only for true-positive labels
        if e.label_is_malicious:
            if norm_hit and raw_hit:
                hit_both += 1
            elif norm_hit and (not raw_hit):
                hit_norm_only += 1
            elif (not norm_hit) and raw_hit:
                hit_raw_only += 1
            else:
                # Malicious label but neither hit: should not happen in this synthetic set,
                # but in real data this represents missed coverage entirely.
                pass

    m_norm = confusion_from_bools(y_true, pred_norm)
    m_raw = confusion_from_bools(y_true, pred_raw)
    m_combined = confusion_from_bools(y_true, pred_combined)

    pct_raw_only, pct_norm_only = coverage_delta(hit_norm_only, hit_raw_only, hit_both)

    return {
        "summary": {
            "n_events": len(events),
            "n_malicious_labels": sum(y_true),
            "ioc_count": len(iocs),
            "coverage_true_positive": {
                "hit_norm_only": hit_norm_only,
                "hit_raw_only": hit_raw_only,
                "hit_both": hit_both,
                "pct_raw_only_of_total_hits": round(pct_raw_only, 4),
                "pct_norm_only_of_total_hits": round(pct_norm_only, 4),
                "interpretation": (
                    "pct_raw_only_of_total_hits approximates how many IOC-bearing events "
                    "would be missed if you only trusted normalized fields."
                ),
            },
        },
        "metrics": {
            "normalized_only": {
                "tp": m_norm.tp, "fp": m_norm.fp, "tn": m_norm.tn, "fn": m_norm.fn,
                "precision": round(m_norm.precision, 4),
                "recall": round(m_norm.recall, 4),
                "f1": round(m_norm.f1, 4),
            },
            "raw_only": {
                "tp": m_raw.tp, "fp": m_raw.fp, "tn": m_raw.tn, "fn": m_raw.fn,
                "precision": round(m_raw.precision, 4),
                "recall": round(m_raw.recall, 4),
                "f1": round(m_raw.f1, 4),
            },
            "combined": {
                "tp": m_combined.tp, "fp": m_combined.fp, "tn": m_combined.tn, "fn": m_combined.fn,
                "precision": round(m_combined.precision, 4),
                "recall": round(m_combined.recall, 4),
                "f1": round(m_combined.f1, 4),
            },
        },
    }


def write_outputs(result: Dict[str, Any], out_dir: Path) -> Tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)

    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    json_path = out_dir / f"normalized_vs_raw_coverage_{ts}.json"
    md_path = out_dir / f"normalized_vs_raw_coverage_{ts}.md"

    json_path.write_text(json.dumps(result, indent=2), encoding="utf-8")

    # Markdown summary (reviewer-friendly)
    s = result["summary"]
    cov = s["coverage_true_positive"]
    m = result["metrics"]

    md = []
    md.append("# Normalized vs Raw Coverage\n")
    md.append(f"- Events: **{s['n_events']}**\n")
    md.append(f"- Labeled malicious events: **{s['n_malicious_labels']}**\n")
    md.append(f"- IOC count: **{s['ioc_count']}**\n\n")

    md.append("## True-positive coverage breakdown\n")
    md.append(f"- Hit via normalized only: **{cov['hit_norm_only']}**\n")
    md.append(f"- Hit via raw AuditData only: **{cov['hit_raw_only']}**\n")
    md.append(f"- Hit via both: **{cov['hit_both']}**\n")
    md.append(f"- Fraction missed by normalized-only: **{cov['pct_raw_only_of_total_hits']}**\n\n")

    md.append("## Metrics\n")
    for name in ["normalized_only", "raw_only", "combined"]:
        mm = m[name]
        md.append(f"### {name}\n")
        md.append(f"- TP/FP/TN/FN: **{mm['tp']} / {mm['fp']} / {mm['tn']} / {mm['fn']}**\n")
        md.append(f"- Precision: **{mm['precision']}**\n")
        md.append(f"- Recall: **{mm['recall']}**\n")
        md.append(f"- F1: **{mm['f1']}**\n\n")

    md.append("## Notes\n")
    md.append(
        "- This is a deterministic synthetic dataset intended to demonstrate the real UAL failure mode:\n"
        "  attacker infrastructure can appear only in nested AuditData, not in normalized columns.\n"
        "- In real environments, raw parsing increases compute cost; this experiment isolates the coverage tradeoff.\n"
    )

    md_path.write_text("".join(md), encoding="utf-8")
    return json_path, md_path


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Eval: normalized vs raw IOC coverage")
    p.add_argument(
        "--out",
        default="outputs/evals",
        help="Output directory for eval artifacts (default: outputs/evals)",
    )
    p.add_argument(
        "--iocs",
        default="203.0.113.10",
        help="Comma-separated IOC IPs for the synthetic dataset (default: 203.0.113.10)",
    )
    return p.parse_args()


def main() -> None:
    args = parse_args()
    iocs = {s.strip() for s in args.iocs.split(",") if s.strip()}

    events = _make_synthetic_events(iocs=iocs)
    result = evaluate(events=events, iocs=iocs)

    out_dir = Path(args.out)
    json_path, md_path = write_outputs(result, out_dir=out_dir)

    print(f"[OK] Wrote: {json_path}")
    print(f"[OK] Wrote: {md_path}")


if __name__ == "__main__":
    main()
