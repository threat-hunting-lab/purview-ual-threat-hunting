from __future__ import annotations

import argparse
import math
from pathlib import Path
from typing import Dict, Any

import pandas as pd

from ual.utils.ip_utils import load_trusted_networks, is_trusted_ip, normalize_ip
from ual.utils.io_utils import read_csv_in_chunks, default_outputs_dir, ensure_columns
from ual.utils.ual_schema import IP_CANDIDATES


# --- Critical ops: ALWAYS capture, no rarity required ---

CRIT_PRIV_ROLE = {
    "PIMRoleAssigned",
    "Add member to role.",
    "Remove member from role.",
    "Add owner to group.",
    "Remove owner from group.",
}

CRIT_MAILBOX = {
    "New-InboxRule",
    "Set-InboxRule",
    "Remove-InboxRule",
    "Enable-InboxRule",
    "Disable-InboxRule",
    "UpdateInboxRules",
    "Add-MailboxPermission",
    "Add-RecipientPermission",
    "Remove-RecipientPermission",
    "MailItemsAccessed",
    "SendAs",
    "SendOnBehalf",
}

CRIT_APP = {
    "Add service principal.",
    "Add app role assignment to service principal.",
    "Add application.",
    "Consent to application.",
}

CRIT_SEARCH_EXPORT = {
    "Search-Mailbox",
    "ExportArtifactDownload",
}

CRIT_CONFIG = {
    "Set-ConditionalAccessPolicy",
    "Set-AdminAuditLogConfig",
    "Install-AdminAuditLogConfig",
    "SharingPolicyChanged",
    "SiteCollectionAdminAdded",
    "SiteCollectionAdminRemoved",
}

CRITICAL_OPS = CRIT_PRIV_ROLE | CRIT_MAILBOX | CRIT_APP | CRIT_SEARCH_EXPORT | CRIT_CONFIG


# --- High ops: ONLY include when IP is external + rare ---

HIGH_USER_GROUP = {
    "Add user.",
    "Delete user.",
    "Update user.",
    "Disable account.",
    "Reset user password.",
    "Change user password.",
    "Add group.",
    "Delete group.",
    "Update group.",
    "Add member to group.",
    "Remove member from group.",
}

HIGH_FILES = {
    "FileDownloaded",
    "FileAccessed",
    "FileDeleted",
    "SharingLinkCreated",
    "SharingLinkUpdated",
    "SharingLinkDeleted",
}

HIGH_SIGNIN = {
    "UserLoggedIn",
    "UserLoginFailed",
}

# Rarity thresholds (defaults)
DEFAULT_RARE_MAX_EVENTS = 20
DEFAULT_RARE_MAX_USERS = 2

# Deterministic/safe output columns for public usage
SLIM_COLUMNS = [
    "CreationDate",
    "UserId",
    "Operation",
    "SuspiciousIP",
    "Category",
    "IP_TotalEvents",
    "IP_DistinctUsers",
    "IP_IsRareExternal",
]


def parse_args():
    p = argparse.ArgumentParser(
        description=(
            "Keep critical UAL operations always, and retain other suspicious "
            "operations only when sourced from rare, external IPs."
        )
    )
    p.add_argument("--input", required=True, help="Path to UAL CSV export")
    p.add_argument(
        "--trusted-cidrs",
        default="trusted_cidrs.txt",
        help="Optional path to trusted CIDRs file (default: trusted_cidrs.txt; if missing, safe defaults are used).",
    )
    p.add_argument(
        "--slim",
        action="store_true",
        help="Write a curated, deterministic set of output columns",
    )
    p.add_argument(
        "--out",
        default=None,
        help="Output CSV path (default: <repo>/outputs/ual_critical_plus_rarity.csv)",
    )
    p.add_argument("--chunksize", type=int, default=500_000, help="CSV chunksize (default: 500000)")
    p.add_argument("--rare-max-events", type=int, default=DEFAULT_RARE_MAX_EVENTS, help="IP total events <= N")
    p.add_argument("--rare-max-users", type=int, default=DEFAULT_RARE_MAX_USERS, help="IP distinct users <= N")
    return p.parse_args()


def safe_str(v) -> str:
    if v is None:
        return ""
    if isinstance(v, float) and math.isnan(v):
        return ""
    return str(v)


def pick_ip(rec: Dict[str, Any]) -> str:
    # Try known candidates; normalize so :port and [IPv6]:port don't break grouping.
    for col in IP_CANDIDATES + ["AuditData.ClientIP", "AuditData.ClientIPAddress"]:
        if col not in rec:
            continue
        ip = normalize_ip(safe_str(rec.get(col)).strip())
        if ip:
            return ip
    return ""


def get_op(rec: Dict[str, Any]) -> str:
    op1 = safe_str(rec.get("Operation")).strip()
    op2 = safe_str(rec.get("AuditData.Operation")).strip()
    return op1 if op1 else op2


def classify_category(op: str) -> str:
    if op in CRIT_PRIV_ROLE:
        return "PrivilegedRoleChange"
    if op in CRIT_MAILBOX:
        return "MailboxRulesOrPerms"
    if op in CRIT_APP:
        return "App/SPN/OAuth"
    if op in CRIT_SEARCH_EXPORT:
        return "Search/Export"
    if op in CRIT_CONFIG:
        return "SecurityConfigChange"
    if op in HIGH_USER_GROUP:
        return "UserOrGroupChange"
    if op in HIGH_FILES:
        return "FileOrSharing"
    if op in HIGH_SIGNIN:
        return "SignIn"
    return ""


def build_ip_flags(input_path: Path, chunksize: int, rare_max_events: int, rare_max_users: int):
    # ip -> {count, users:set}
    ip_stats: Dict[str, Dict[str, Any]] = {}
    total = 0
    chunk_idx = 0

    for chunk in read_csv_in_chunks(input_path, chunksize=chunksize):
        chunk_idx += 1
        total += len(chunk)

        ensure_columns(
            chunk,
            ["UserId", "Operation", "AuditData.Operation", "IP_Normalized", "AuditData.ClientIP", "AuditData.ClientIPAddress"],
        )

        for rec in chunk.to_dict(orient="records"):
            ip = pick_ip(rec)
            user = safe_str(rec.get("UserId")).strip()
            if not ip or not user:
                continue

            s = ip_stats.setdefault(ip, {"count": 0, "users": set()})
            s["count"] += 1

            # Memory-safe cap:
            # We only need to know if distinct users exceed rare_max_users.
            # Once it's > rare_max_users, rarity by user count is already false.
            if len(s["users"]) <= rare_max_users:
                s["users"].add(user)

        print(f"[*] First pass: chunk {chunk_idx}, total rows {total}", flush=True)

    ip_flags: Dict[str, Dict[str, Any]] = {}
    for ip, s in ip_stats.items():
        rare = s["count"] <= rare_max_events and len(s["users"]) <= rare_max_users
        ip_flags[ip] = {"count": s["count"], "users": len(s["users"]), "is_rare": rare}

    return ip_flags


def main():
    args = parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        raise FileNotFoundError(f"Input not found: {input_path}")

    out_dir = default_outputs_dir(__file__)
    out_path = Path(args.out) if args.out else out_dir / "ual_critical_plus_rarity.csv"

    trusted_nets = load_trusted_networks(args.trusted_cidrs)

    print(f"[+] Input: {input_path}")
    print(f"[+] Output: {out_path}")
    print(f"[+] Trusted CIDRs file: {args.trusted_cidrs} (if missing, safe defaults are used)")
    print(
        f"[+] chunksize={args.chunksize} rare_max_events={args.rare_max_events} rare_max_users={args.rare_max_users} slim={args.slim}"
    )

    ip_flags = build_ip_flags(input_path, args.chunksize, args.rare_max_events, args.rare_max_users)

    first_write = True
    total_flagged = 0
    chunk_idx = 0

    for chunk in read_csv_in_chunks(input_path, chunksize=args.chunksize):
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
            op = get_op(rec)
            if not op:
                continue

            cat = classify_category(op)
            if not cat:
                continue

            ip = pick_ip(rec)
            if not ip:
                continue

            ip_info = ip_flags.get(ip, {"count": 0, "users": 0, "is_rare": False})
            is_ext = not is_trusted_ip(ip, trusted_nets)
            is_rare_external = bool(ip_info["is_rare"]) and is_ext

            # Keep logic:
            # - Always keep critical ops
            # - Other ops only if rare + external
            keep = (op in CRITICAL_OPS) or is_rare_external
            if not keep:
                continue

            rec["SuspiciousIP"] = ip
            rec["Category"] = cat
            rec["IP_TotalEvents"] = ip_info["count"]
            rec["IP_DistinctUsers"] = ip_info["users"]
            rec["IP_IsRareExternal"] = "yes" if is_rare_external else "no"
            out_rows.append(rec)

        if out_rows:
            df = pd.DataFrame(out_rows)

            if args.slim:
                # Ensure slim columns exist and enforce deterministic order
                for c in SLIM_COLUMNS:
                    if c not in df.columns:
                        df[c] = ""
                df = df[SLIM_COLUMNS]

            mode = "w" if first_write else "a"
            header = first_write
            df.to_csv(out_path, index=False, mode=mode, header=header)

            first_write = False
            total_flagged += len(df)
            print(f"[+] Chunk {chunk_idx}: wrote {len(df)} (total {total_flagged})", flush=True)
        else:
            print(f"[-] Chunk {chunk_idx}: no rows kept (total {total_flagged})", flush=True)

    print(f"[=] Done. Wrote {total_flagged} rows to {out_path}")


if __name__ == "__main__":
    main()
