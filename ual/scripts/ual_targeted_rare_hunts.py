from __future__ import annotations

import argparse
import math
import time
from pathlib import Path
from typing import Dict, Any

import pandas as pd

from ual.utils.ip_utils import load_trusted_networks, is_trusted_ip, normalize_ip
from ual.utils.io_utils import read_csv_in_chunks, default_outputs_dir, ensure_columns
from ual.utils.ual_schema import IP_CANDIDATES


# === CATEGORY DEFINITIONS ===

MAILBOX_RULE_OPS = {
    "New-InboxRule",
    "Set-InboxRule",
    "Remove-InboxRule",
    "Enable-InboxRule",
    "Disable-InboxRule",
    "UpdateInboxRules",
    "Add-MailboxPermission",
    "Add-RecipientPermission",
    "Remove-RecipientPermission",
    "Set-Mailbox",
    "AddFolderPermissions",
    "ModifyFolderPermissions",
    "RemoveFolderPermissions",
    "MailItemsAccessed",
    "SendAs",
    "SendOnBehalf",
}

ROLE_CHANGE_OPS = {
    "PIMRoleAssigned",
    "Add member to role.",
    "Remove member from role.",
    "Add owner to group.",
    "Remove owner from group.",
}

APP_CONSENT_OPS = {
    "Add service principal.",
    "Update service principal.",
    "Add app role assignment to service principal.",
    "Add application.",
    "Delete application.",
    # Fix/normalize encoding artifact variants:
    "Update application – Certificates and secrets management",
    "Update application - Certificates and secrets management",
    "Update application.",
    "Consent to application.",
}

SEARCH_EXPORT_OPS = {
    "SearchQueryPerformed",
    "ExportArtifactDownload",
    "Get-ComplianceSearchAction",
    "Search-Mailbox",
    "GetActionsForAllExports",
    "GetSingleActionForExport",
    "GetActionsForSearch",
}

ALL_SENSITIVE = MAILBOX_RULE_OPS | ROLE_CHANGE_OPS | APP_CONSENT_OPS | SEARCH_EXPORT_OPS

DEFAULT_RARE_MAX_EVENTS = 20
DEFAULT_RARE_MAX_USERS = 2

SLIM_COLUMNS = [
    "CreationDate",
    "UserId",
    "Operation",
    "SuspiciousIP",
    "HuntCategory",
    "IP_TotalEvents",
    "IP_DistinctUsers",
    "IP_IsRareExternal",
]


def parse_args():
    p = argparse.ArgumentParser(
        description=(
            "Targeted hunt: keep only sensitive operations when they originate from rare, external IPs "
            "(rarity is computed across the dataset)."
        )
    )
    p.add_argument("--input", required=True, help="Path to UAL CSV export")
    p.add_argument(
        "--trusted-cidrs",
        default="trusted_cidrs.txt",
        help="Optional path to trusted CIDRs file (default: trusted_cidrs.txt; if missing, safe defaults are used).",
    )
    p.add_argument(
        "--out",
        default=None,
        help="Output CSV path (default: <repo>/outputs/ual_targeted_rare_hunts.csv)",
    )
    p.add_argument("--chunksize", type=int, default=500_000, help="CSV chunksize (default: 500000)")
    p.add_argument("--rare-max-events", type=int, default=DEFAULT_RARE_MAX_EVENTS, help="IP total events <= N")
    p.add_argument("--rare-max-users", type=int, default=DEFAULT_RARE_MAX_USERS, help="IP distinct users <= N")
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


def normalize_operation(op: str) -> str:
    """
    Guard against CSV encoding artifacts (mojibake) by forcing a consistent representation.
    We keep this intentionally light to avoid altering legitimate op names.
    """
    op = safe_str(op).strip()
    if not op:
        return ""
    # Common mojibake fix for the en-dash in "Certificates and secrets management"
    op = op.replace("Ã¢â‚¬â€œ", "–")
    return op


def pick_ip(rec: Dict[str, Any]) -> str:
    for col in IP_CANDIDATES + ["AuditData.ClientIP", "AuditData.ClientIPAddress"]:
        if col not in rec:
            continue
        ip = normalize_ip(safe_str(rec.get(col)).strip())
        if ip:
            return ip
    return ""


def get_operation(rec: Dict[str, Any]) -> str:
    op1 = normalize_operation(rec.get("Operation"))
    op2 = normalize_operation(rec.get("AuditData.Operation"))
    return op1 if op1 else op2


def classify_category(op: str) -> str:
    if op in MAILBOX_RULE_OPS:
        return "MailboxRule/PermsFromRareExternalIP"
    if op in ROLE_CHANGE_OPS:
        return "RoleChangeFromRareExternalIP"
    if op in APP_CONSENT_OPS:
        return "App/SPN/ConsentFromRareExternalIP"
    if op in SEARCH_EXPORT_OPS:
        return "Search/ExportFromRareExternalIP"
    return ""


def first_pass_build_ip_flags(
    input_path: Path,
    chunksize: int,
    trusted_nets,
    rare_max_events: int,
    rare_max_users: int,
):
    """
    Build per-IP stats for EXTERNAL IPs only, then derive a rarity flag.
    """
    ip_stats: Dict[str, Dict[str, Any]] = {}  # ip -> {"count": int, "users": set()}
    total_rows = 0
    chunk_idx = 0

    for chunk in read_csv_in_chunks(input_path, chunksize=chunksize):
        chunk_idx += 1
        total_rows += len(chunk)

        ensure_columns(
            chunk,
            ["UserId", "Operation", "AuditData.Operation", "IP_Normalized", "AuditData.ClientIP", "AuditData.ClientIPAddress"],
        )

        for rec in chunk.to_dict(orient="records"):
            ip = pick_ip(rec)
            if not ip:
                continue
            # Only track external IPs
            if is_trusted_ip(ip, trusted_nets):
                continue

            user = safe_str(rec.get("UserId")).strip()
            if not user:
                continue

            s = ip_stats.setdefault(ip, {"count": 0, "users": set()})
            s["count"] += 1

            # Memory-safe cap: once distinct users exceed rare_max_users, rarity-by-user is false
            if len(s["users"]) <= rare_max_users:
                s["users"].add(user)

        print(f"[*] First pass: chunk {chunk_idx}, total rows {total_rows}", flush=True)

    ip_flags: Dict[str, Dict[str, Any]] = {}
    for ip, s in ip_stats.items():
        rare = s["count"] <= rare_max_events and len(s["users"]) <= rare_max_users
        ip_flags[ip] = {"count": s["count"], "users": len(s["users"]), "is_rare": rare}

    print(f"[=] First pass complete. Rows={total_rows:,} External IPs={len(ip_stats):,} Rare External IPs={sum(1 for v in ip_flags.values() if v['is_rare']):,}")
    return ip_flags


def second_pass_collect(
    input_path: Path,
    chunksize: int,
    trusted_nets,
    ip_flags: Dict[str, Dict[str, Any]],
    out_path: Path,
    slim: bool,
):
    first_write = True
    total_flagged = 0
    chunk_idx = 0

    for chunk in read_csv_in_chunks(input_path, chunksize=chunksize):
        chunk_idx += 1

        ensure_columns(
            chunk,
            [
                "UserId",
                "CreationDate",
                "Operation",
                "AuditData.Operation",
                "IP_Normalized",
                "AuditData.ClientIP",
                "AuditData.ClientIPAddress",
            ],
        )

        out_rows = []

        for rec in chunk.to_dict(orient="records"):
            op = get_operation(rec)
            if not op or op not in ALL_SENSITIVE:
                continue

            ip = pick_ip(rec)
            if not ip:
                continue

            # external + rare only
            if is_trusted_ip(ip, trusted_nets):
                continue

            ip_info = ip_flags.get(ip)
            if not ip_info or not ip_info.get("is_rare", False):
                continue

            category = classify_category(op)
            if not category:
                continue

            rec["SuspiciousIP"] = ip
            rec["HuntCategory"] = category
            rec["IP_TotalEvents"] = ip_info["count"]
            rec["IP_DistinctUsers"] = ip_info["users"]
            rec["IP_IsRareExternal"] = "yes"
            out_rows.append(rec)

        if out_rows:
            df = pd.DataFrame(out_rows)

            if slim:
                for c in SLIM_COLUMNS:
                    if c not in df.columns:
                        df[c] = ""
                df = df[SLIM_COLUMNS]

            mode = "w" if first_write else "a"
            header = first_write
            df.to_csv(out_path, index=False, mode=mode, header=header)

            first_write = False
            total_flagged += len(df)
            print(f"[+] Second pass: chunk {chunk_idx}, wrote {len(df)} (total {total_flagged})", flush=True)
        else:
            print(f"[-] Second pass: chunk {chunk_idx}, wrote 0 (total {total_flagged})", flush=True)

    return total_flagged


def main():
    args = parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        raise FileNotFoundError(f"Input not found: {input_path}")

    out_dir = default_outputs_dir(__file__)
    out_path = Path(args.out) if args.out else out_dir / "ual_targeted_rare_hunts.csv"

    trusted_nets = load_trusted_networks(args.trusted_cidrs)

    print(f"[+] Input: {input_path}")
    print(f"[+] Output: {out_path}")
    print(f"[+] Trusted CIDRs file: {args.trusted_cidrs} (if missing, safe defaults are used)")
    print(
        f"[+] chunksize={args.chunksize} rare_max_events={args.rare_max_events} "
        f"rare_max_users={args.rare_max_users} slim={args.slim}"
    )

    t0 = time.time()
    ip_flags = first_pass_build_ip_flags(
        input_path=input_path,
        chunksize=args.chunksize,
        trusted_nets=trusted_nets,
        rare_max_events=args.rare_max_events,
        rare_max_users=args.rare_max_users,
    )

    total_flagged = second_pass_collect(
        input_path=input_path,
        chunksize=args.chunksize,
        trusted_nets=trusted_nets,
        ip_flags=ip_flags,
        out_path=out_path,
        slim=args.slim,
    )
    t1 = time.time()

    print(f"[=] Finished in {t1 - t0:.1f}s.")
    if total_flagged:
        print(f"[=] Wrote {total_flagged:,} rows to {out_path}")
    else:
        print("[=] No targeted rare-IP sensitive ops with current thresholds.")


if __name__ == "__main__":
    main()
