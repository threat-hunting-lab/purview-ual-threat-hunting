from __future__ import annotations

import argparse
import json
import math
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

import pandas as pd

from ual.utils.ip_utils import normalize_ip
from ual.utils.io_utils import read_csv_in_chunks, default_outputs_dir, ensure_columns


DEFAULT_CHUNKSIZE = 250_000

SLIM_COLUMNS = [
    "CreationDate",
    "UserId",
    "Operation",
    "SuspiciousIP",
    "MatchedPath",
    "MatchedValueType",
]


def parse_args():
    p = argparse.ArgumentParser(
        description=(
            "Deep IOC sweep: parse raw AuditData JSON and match IOC IPs anywhere in nested fields. "
            "Use this when IPs may not be surfaced in normalized columns."
        )
    )
    p.add_argument("--input", required=True, help="Path to UAL CSV export (must include AuditData column)")
    p.add_argument(
        "--iocs",
        required=True,
        help="Path to IOC IP list file (one IP per line; comments with # allowed). CIDRs not supported here.",
    )
    p.add_argument(
        "--out",
        default=None,
        help="Output CSV path (default: <repo>/outputs/ual_ioc_hits_from_raw.csv)",
    )
    p.add_argument("--chunksize", type=int, default=DEFAULT_CHUNKSIZE, help=f"CSV chunksize (default: {DEFAULT_CHUNKSIZE})")
    p.add_argument(
        "--slim",
        action="store_true",
        help="Write curated, deterministic output columns",
    )
    p.add_argument(
        "--max-hits-per-row",
        type=int,
        default=3,
        help="Cap how many matches we record per row (prevents huge output if a record contains many repeated IPs).",
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


def try_parse_json(s: str) -> Optional[Any]:
    s = s.strip()
    if not s:
        return None
    try:
        return json.loads(s)
    except Exception:
        return None


def iter_leaf_values(obj: Any, path: str = "$") -> Iterable[Tuple[str, Any]]:
    """
    Yield (path, value) for leaf values in nested dict/list JSON.
    """
    if isinstance(obj, dict):
        for k, v in obj.items():
            k_str = safe_str(k)
            new_path = f"{path}.{k_str}" if k_str else path
            yield from iter_leaf_values(v, new_path)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from iter_leaf_values(v, f"{path}[{i}]")
    else:
        # leaf
        yield (path, obj)


def extract_ioc_hits_from_auditdata(audit_obj: Any, iocs: Set[str], max_hits: int) -> List[Tuple[str, str, str]]:
    """
    Returns list of (ioc_ip, matched_path, matched_type).
    - matched_type is a simple label: str/int/float/bool/null/other
    """
    hits: List[Tuple[str, str, str]] = []
    if audit_obj is None:
        return hits

    for pth, val in iter_leaf_values(audit_obj):
        if len(hits) >= max_hits:
            break

        # Most likely IP appearance is as strings; but we safely stringify
        if isinstance(val, str):
            candidate = normalize_ip(val.strip())
        else:
            candidate = normalize_ip(safe_str(val).strip())

        if candidate and candidate in iocs:
            vtype = type(val).__name__ if val is not None else "null"
            hits.append((candidate, pth, vtype))

    return hits


def main():
    args = parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        raise FileNotFoundError(f"Input not found: {input_path}")

    ioc_path = Path(args.iocs)
    ioc_ips = load_iocs(ioc_path)

    out_dir = default_outputs_dir(__file__)
    out_path = Path(args.out) if args.out else out_dir / "ual_ioc_hits_from_raw.csv"

    print(f"[+] Input: {input_path}")
    print(f"[+] IOC list: {ioc_path}")
    print(f"[+] Output: {out_path}")
    print(f"[+] chunksize={args.chunksize} slim={args.slim} max_hits_per_row={args.max_hits_per_row}")

    first_write = True
    total_rows = 0
    total_hits = 0
    chunk_idx = 0
    start = time.time()

    for chunk in read_csv_in_chunks(input_path, chunksize=args.chunksize):
        chunk_idx += 1
        rows = len(chunk)
        total_rows += rows

        ensure_columns(chunk, ["CreationDate", "UserId", "Operation", "AuditData", "AuditData.Operation"])

        out_rows: List[Dict[str, Any]] = []

        # Work row-wise because we parse JSON per row
        for rec in chunk.to_dict(orient="records"):
            audit_raw = safe_str(rec.get("AuditData"))
            audit_obj = try_parse_json(audit_raw)

            hits = extract_ioc_hits_from_auditdata(audit_obj, ioc_ips, max_hits=args.max_hits_per_row)
            if not hits:
                continue

            # Normalize operation: prefer Operation then fallback AuditData.Operation
            op = safe_str(rec.get("Operation")).strip()
            if not op:
                op = safe_str(rec.get("AuditData.Operation")).strip()

            base = {
                "CreationDate": rec.get("CreationDate", ""),
                "UserId": rec.get("UserId", ""),
                "Operation": op,
            }

            # One output row per match (capped by max_hits_per_row)
            for ioc_ip, matched_path, matched_type in hits:
                r = dict(base)
                r["SuspiciousIP"] = ioc_ip
                r["MatchedPath"] = matched_path
                r["MatchedValueType"] = matched_type
                out_rows.append(r)

        if out_rows:
            df = pd.DataFrame(out_rows)

            if args.slim:
                for c in SLIM_COLUMNS:
                    if c not in df.columns:
                        df[c] = ""
                df = df[SLIM_COLUMNS]

            mode = "w" if first_write else "a"
            header = first_write
            df.to_csv(out_path, index=False, mode=mode, header=header)
            first_write = False

            total_hits += len(df)
            print(f"[+] Chunk {chunk_idx}: {rows} rows, {len(df)} matches (total matches: {total_hits})", flush=True)
        else:
            print(f"[-] Chunk {chunk_idx}: {rows} rows, 0 matches (total scanned: {total_rows})", flush=True)

    elapsed = time.time() - start
    print(f"\n[=] Finished. Scanned {total_rows:,} rows in {elapsed:.1f}s.")
    if total_hits:
        print(f"[=] FOUND {total_hits:,} matches. Saved to {out_path}")
    else:
        print("[=] No matches found inside AuditData with current IOC list.")


if __name__ == "__main__":
    main()
