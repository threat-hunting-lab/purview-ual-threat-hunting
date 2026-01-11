from __future__ import annotations

import argparse
import math
import time
from pathlib import Path
from typing import Dict, Any, Set, List

import pandas as pd

from ual.utils.ip_utils import normalize_ip
from ual.utils.io_utils import read_csv_in_chunks, default_outputs_dir, ensure_columns
from ual.utils.ual_schema import IP_CANDIDATES


DEFAULT_CHUNKSIZE = 500_000

# Deterministic/minimal output for public toolkit
SLIM_COLUMNS = [
    "CreationDate",
    "UserId",
    "Operation",
    "SuspiciousIP",
    "MatchedColumn",
]


def parse_args():
    p = argparse.ArgumentParser(
        description="Find login-related UAL rows where any client/actor IP matches an IOC IP list."
    )
    p.add_argument("--input", required=True, help="Path to UAL CSV export (login-focused or full export)")
    p.add_argument(
        "--iocs",
        required=True,
        help="Path to IOC IP list file (one IP per line; comments with # allowed). CIDRs not supported here.",
    )
    p.add_argument(
        "--out",
        default=None,
        help="Output CSV path (default: <repo>/outputs/ual_login_ioc_hits.csv)",
    )
    p.add_argument("--chunksize", type=int, default=DEFAULT_CHUNKSIZE, help=f"CSV chunksize (default: {DEFAULT_CHUNKSIZE})")
    p.add_argument(
        "--slim",
        action="store_true",
        help="Write a curated, deterministic set of output columns",
    )
    return p.parse_args()


def safe_str(v) -> str:
    if v is None:
        return ""
    if isinstance(v, float) and math.isnan(v):
        return ""
    return str(v)


def load_iocs(path: Path) -> Set[str]:
    if not path.exists():
        raise FileNotFoundError(f"IOC file not found: {path}")

    iocs: Set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        raw = line.strip()
        if not raw or raw.startswith("#"):
            continue
        norm = normalize_ip(raw)
        if norm:
            iocs.add(norm)

    if not iocs:
        raise ValueError("IOC file loaded but no usable IPs found.")
    print(f"[+] Loaded {len(iocs)} IOC IPs.")
    return iocs


def candidate_ip_columns() -> List[str]:
    """
    Cover common UAL fields plus the specific login-focused fields you used previously.
    """
    extra = [
        "AuditData.ClientIP",
        "AuditData.ActorIpAddress",
        "AuditData.ClientIPAddress",
        "AuditData.ActorIPAddress",
    ]
    # De-dup while preserving order
    seen = set()
    cols = []
    for c in (IP_CANDIDATES + extra):
        if c not in seen:
            cols.append(c)
            seen.add(c)
    return cols


def main():
    args = parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        raise FileNotFoundError(f"Input not found: {input_path}")

    ioc_path = Path(args.iocs)
    ioc_ips = load_iocs(ioc_path)

    out_dir = default_outputs_dir(__file__)
    out_path = Path(args.out) if args.out else out_dir / "ual_login_ioc_hits.csv"

    print(f"[+] Input: {input_path}")
    print(f"[+] IOC list: {ioc_path}")
    print(f"[+] Output: {out_path}")
    print(f"[+] chunksize={args.chunksize} slim={args.slim}")

    cols = candidate_ip_columns()

    first_write = True
    total_rows = 0
    total_hits = 0
    chunk_idx = 0
    start = time.time()

    for chunk in read_csv_in_chunks(input_path, chunksize=args.chunksize):
        chunk_idx += 1
        rows = len(chunk)
        total_rows += rows

        # Ensure candidate IP columns exist
        ensure_columns(chunk, cols + ["CreationDate", "UserId", "Operation", "AuditData.Operation"])

        # normalize each candidate column into a temp norm column
        norm_cols = []
        for c in cols:
            nc = f"{c}__norm"
            chunk[nc] = chunk[c].map(safe_str).map(normalize_ip)
            norm_cols.append(nc)

        # Build a mask: any normalized col matches an IOC
        mask = False
        for nc in norm_cols:
            mask = mask | chunk[nc].isin(ioc_ips)

        hits = chunk[mask].copy()

        if not hits.empty:
            # Pick the first matching IP column per row (deterministic)
            matched_ip = []
            matched_col = []
            for _, r in hits.iterrows():
                found_ip = ""
                found_col = ""
                for c in cols:
                    nc = f"{c}__norm"
                    v = safe_str(r.get(nc))
                    if v and v in ioc_ips:
                        found_ip = v
                        found_col = c
                        break
                matched_ip.append(found_ip)
                matched_col.append(found_col)

            hits["SuspiciousIP"] = matched_ip
            hits["MatchedColumn"] = matched_col

            # Normalize operation: prefer Operation then fallback AuditData.Operation
            if "Operation" in hits.columns and "AuditData.Operation" in hits.columns:
                hits["Operation"] = hits["Operation"].fillna("").astype(str).str.strip()
                hits["AuditData.Operation"] = hits["AuditData.Operation"].fillna("").astype(str).str.strip()
                hits["Operation"] = hits["Operation"].where(hits["Operation"] != "", hits["AuditData.Operation"])

            if args.slim:
                for c in SLIM_COLUMNS:
                    if c not in hits.columns:
                        hits[c] = ""
                hits = hits[SLIM_COLUMNS]

            mode = "w" if first_write else "a"
            header = first_write
            hits.to_csv(out_path, index=False, mode=mode, header=header)
            first_write = False

            hits_in_chunk = len(hits)
            total_hits += hits_in_chunk
            print(f"[+] Chunk {chunk_idx}: {rows} rows, {hits_in_chunk} hits (total hits: {total_hits})", flush=True)
        else:
            print(f"[-] Chunk {chunk_idx}: {rows} rows, 0 hits (total scanned: {total_rows})", flush=True)

    elapsed = time.time() - start
    print(f"\n[=] Finished. Scanned {total_rows:,} rows in {elapsed:.1f}s.")
    if total_hits:
        print(f"[=] FOUND {total_hits:,} matching rows. Saved to {out_path}")
    else:
        print("[=] No matches found with current IOC list.")


if __name__ == "__main__":
    main()
