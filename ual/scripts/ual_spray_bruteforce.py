from __future__ import annotations

import argparse
import math
import time
from pathlib import Path
from typing import Dict, Any, Set

import pandas as pd

from ual.utils.ip_utils import load_trusted_networks, is_trusted_ip, normalize_ip
from ual.utils.io_utils import read_csv_in_chunks, default_outputs_dir, ensure_columns
from ual.utils.ual_schema import IP_CANDIDATES


# Sign-in operation names used in your UAL (adjust if needed)
LOGIN_SUCCESS_OPS = {"UserLoggedIn"}
LOGIN_FAILURE_OPS = {"UserLoginFailed"}

# Defaults (can be overridden via CLI)
DEFAULT_CHUNKSIZE = 500_000
DEFAULT_MIN_FAILS_PER_IP = 20
DEFAULT_MIN_FAILED_USERS = 5

SLIM_IP_SUMMARY_COLUMNS = [
    "IP",
    "TotalFailures",
    "TotalSuccesses",
    "DistinctFailedUsers",
    "DistinctSuccessUsers",
    "CompromisedUserCandidates",
]

SLIM_EVENT_COLUMNS = [
    "CreationDate",
    "UserId",
    "Operation",
    "SuspiciousIP",
    "Outcome",
]


def parse_args():
    p = argparse.ArgumentParser(
        description=(
            "Spray/bruteforce heuristic: find external IPs with many failed sign-ins "
            "targeting multiple users, and at least one success against a previously failed user."
        )
    )
    p.add_argument("--input", required=True, help="Path to UAL CSV export")
    p.add_argument(
        "--trusted-cidrs",
        default="trusted_cidrs.txt",
        help="Optional path to trusted CIDRs file (default: trusted_cidrs.txt; if missing, safe defaults are used).",
    )
    p.add_argument(
        "--out-ip-summary",
        default=None,
        help="Output CSV path for IP summary (default: <repo>/outputs/ual_spray_candidates_ips.csv)",
    )
    p.add_argument(
        "--out-events",
        default=None,
        help="Output CSV path for matched events (default: <repo>/outputs/ual_spray_candidates_events.csv)",
    )
    p.add_argument("--chunksize", type=int, default=DEFAULT_CHUNKSIZE, help=f"CSV chunksize (default: {DEFAULT_CHUNKSIZE})")
    p.add_argument(
        "--min-fails-per-ip",
        type=int,
        default=DEFAULT_MIN_FAILS_PER_IP,
        help=f"At least this many failed attempts from an IP (default: {DEFAULT_MIN_FAILS_PER_IP})",
    )
    p.add_argument(
        "--min-failed-users",
        type=int,
        default=DEFAULT_MIN_FAILED_USERS,
        help=f"At least this many distinct failed users per IP (default: {DEFAULT_MIN_FAILED_USERS})",
    )
    p.add_argument(
        "--slim",
        action="store_true",
        help="Write curated, deterministic output columns (recommended for public toolkit)",
    )
    return p.parse_args()


def safe_str(v) -> str:
    if v is None:
        return ""
    if isinstance(v, float) and math.isnan(v):
        return ""
    return str(v)


def pick_ip(rec: Dict[str, Any]) -> str:
    """
    Pick best IP from known fields, normalized (handles IPv4:port, [IPv6]:port).
    """
    for col in IP_CANDIDATES + ["AuditData.ClientIP", "AuditData.ClientIPAddress"]:
        if col not in rec:
            continue
        ip = normalize_ip(safe_str(rec.get(col)).strip())
        if ip:
            return ip
    return ""


def get_operation(rec: Dict[str, Any]) -> str:
    op1 = safe_str(rec.get("Operation")).strip()
    op2 = safe_str(rec.get("AuditData.Operation")).strip()
    return op1 if op1 else op2


def first_pass_build_stats(
    input_path: Path,
    chunksize: int,
    trusted_nets,
    min_fails_per_ip: int,
    min_failed_users: int,
):
    """
    Build stats per external IP:
      - fail count
      - success count
      - failed users set (capped)
      - success users set (capped)
    Then select candidate IPs meeting spray/brute heuristics.
    """
    ip_stats: Dict[str, Dict[str, Any]] = {}
    total_rows = 0
    chunk_idx = 0

    # Cap user set sizes to keep memory bounded.
    # We only need to know if >= min_failed_users and overlap exists.
    cap_failed = min_failed_users + 50  # generous cap; prevents runaway memory
    cap_success = min_failed_users + 50

    for chunk in read_csv_in_chunks(input_path, chunksize=chunksize):
        chunk_idx += 1
        total_rows += len(chunk)

        ensure_columns(
            chunk,
            ["Operation", "AuditData.Operation", "IP_Normalized", "AuditData.ClientIP", "AuditData.ClientIPAddress", "UserId"],
        )

        for rec in chunk.to_dict(orient="records"):
            op = get_operation(rec)
            if op not in LOGIN_SUCCESS_OPS and op not in LOGIN_FAILURE_OPS:
                continue

            user = safe_str(rec.get("UserId")).strip()
            if not user:
                continue

            ip = pick_ip(rec)
            if not ip:
                continue

            # Focus on external sources
            if is_trusted_ip(ip, trusted_nets):
                continue

            s = ip_stats.setdefault(
                ip,
                {
                    "fail_count": 0,
                    "success_count": 0,
                    "failed_users": set(),
                    "success_users": set(),
                },
            )

            if op in LOGIN_FAILURE_OPS:
                s["fail_count"] += 1
                if len(s["failed_users"]) < cap_failed:
                    s["failed_users"].add(user)
            else:
                s["success_count"] += 1
                if len(s["success_users"]) < cap_success:
                    s["success_users"].add(user)

        print(f"[*] First pass - chunk {chunk_idx}, total rows: {total_rows}", flush=True)

    # Decide which IPs look like spray/brute candidates
    spray_ips: Dict[str, Dict[str, Any]] = {}
    for ip, s in ip_stats.items():
        if s["fail_count"] < min_fails_per_ip:
            continue
        if len(s["failed_users"]) < min_failed_users:
            continue

        overlap = s["failed_users"].intersection(s["success_users"])
        if not overlap:
            continue

        spray_ips[ip] = {
            "fail_count": s["fail_count"],
            "success_count": s["success_count"],
            "failed_users": s["failed_users"],
            "success_users": s["success_users"],
            "compromised_candidates": overlap,
        }

    return spray_ips, total_rows


def write_ip_summary(spray_ips: Dict[str, Dict[str, Any]], out_path: Path, slim: bool) -> int:
    if not spray_ips:
        return 0

    rows = []
    for ip, s in spray_ips.items():
        rows.append(
            {
                "IP": ip,
                "TotalFailures": s["fail_count"],
                "TotalSuccesses": s["success_count"],
                "DistinctFailedUsers": len(s["failed_users"]),
                "DistinctSuccessUsers": len(s["success_users"]),
                "CompromisedUserCandidates": ",".join(sorted(s["compromised_candidates"])),
            }
        )

    df = pd.DataFrame(rows).sort_values(
        ["DistinctFailedUsers", "TotalFailures", "TotalSuccesses"],
        ascending=[False, False, False],
    )

    if slim:
        for c in SLIM_IP_SUMMARY_COLUMNS:
            if c not in df.columns:
                df[c] = ""
        df = df[SLIM_IP_SUMMARY_COLUMNS]

    df.to_csv(out_path, index=False)
    return len(df)


def second_pass_dump_events(
    input_path: Path,
    chunksize: int,
    spray_ips: Dict[str, Dict[str, Any]],
    out_path: Path,
    slim: bool,
) -> int:
    if not spray_ips:
        return 0

    suspicious_ips: Set[str] = set(spray_ips.keys())
    first_write = True
    total_events = 0
    chunk_idx = 0

    for chunk in read_csv_in_chunks(input_path, chunksize=chunksize):
        chunk_idx += 1

        ensure_columns(
            chunk,
            ["Operation", "AuditData.Operation", "IP_Normalized", "AuditData.ClientIP", "AuditData.ClientIPAddress", "UserId", "CreationDate"],
        )

        out_rows = []

        for rec in chunk.to_dict(orient="records"):
            op = get_operation(rec)
            if op not in LOGIN_SUCCESS_OPS and op not in LOGIN_FAILURE_OPS:
                continue

            ip = pick_ip(rec)
            if ip not in suspicious_ips:
                continue

            rec["SuspiciousIP"] = ip
            rec["Outcome"] = "Success" if op in LOGIN_SUCCESS_OPS else "Fail"
            out_rows.append(rec)

        if out_rows:
            df = pd.DataFrame(out_rows)

            if slim:
                for c in SLIM_EVENT_COLUMNS:
                    if c not in df.columns:
                        df[c] = ""
                df = df[SLIM_EVENT_COLUMNS]

            mode = "w" if first_write else "a"
            header = first_write
            df.to_csv(out_path, index=False, mode=mode, header=header)
            first_write = False
            total_events += len(df)
            print(f"[+] Second pass - chunk {chunk_idx}, wrote {len(df)} events (total {total_events})", flush=True)
        else:
            print(f"[-] Second pass - chunk {chunk_idx}, 0 events (total {total_events})", flush=True)

    return total_events


def main():
    args = parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        raise FileNotFoundError(f"Input not found: {input_path}")

    out_dir = default_outputs_dir(__file__)
    out_ip_summary = Path(args.out_ip_summary) if args.out_ip_summary else out_dir / "ual_spray_candidates_ips.csv"
    out_events = Path(args.out_events) if args.out_events else out_dir / "ual_spray_candidates_events.csv"

    trusted_nets = load_trusted_networks(args.trusted_cidrs)

    print(f"[+] Input: {input_path}")
    print(f"[+] Output (IP summary): {out_ip_summary}")
    print(f"[+] Output (events): {out_events}")
    print(f"[+] Trusted CIDRs file: {args.trusted_cidrs} (if missing, safe defaults are used)")
    print(
        f"[+] chunksize={args.chunksize} min_fails_per_ip={args.min_fails_per_ip} "
        f"min_failed_users={args.min_failed_users} slim={args.slim}"
    )

    t0 = time.time()

    spray_ips, total_rows = first_pass_build_stats(
        input_path=input_path,
        chunksize=args.chunksize,
        trusted_nets=trusted_nets,
        min_fails_per_ip=args.min_fails_per_ip,
        min_failed_users=args.min_failed_users,
    )

    num_ips = write_ip_summary(spray_ips, out_ip_summary, args.slim)
    events_written = second_pass_dump_events(input_path, args.chunksize, spray_ips, out_events, args.slim)

    t1 = time.time()
    print(f"\n[=] Scanned {total_rows:,} rows in {t1 - t0:.1f}s.")

    if not spray_ips:
        print("[=] No strong spray/brute patterns found with current thresholds.")
    else:
        print(f"[=] Identified {num_ips} suspicious IPs. Summary: {out_ip_summary}")
        print(f"[=] Wrote {events_written} related sign-in events to {out_events}")


if __name__ == "__main__":
    main()
