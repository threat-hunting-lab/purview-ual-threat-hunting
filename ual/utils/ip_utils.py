from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from typing import Iterable, Optional, Sequence


_IPV4_PORT_RE = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})$")


def normalize_ip(value: str | None) -> str:
    """
    Normalize an IP-ish string to a canonical IP string.
    Handles:
      - None/empty
      - whitespace
      - IPv4:port -> IPv4
      - [IPv6]:port -> IPv6
      - raw IPv6 (no port)
    Returns "" if it cannot be normalized to a valid IP.
    """
    if not value:
        return ""
    s = str(value).strip()
    if not s:
        return ""

    # [IPv6]:port
    if s.startswith("[") and "]" in s:
        inside = s[1 : s.index("]")]
        s = inside.strip()

    # IPv4:port
    m = _IPV4_PORT_RE.match(s)
    if m:
        s = m.group(1)

    # Sometimes logs have trailing punctuation
    s = s.strip(" ,;")

    try:
        ip = ipaddress.ip_address(s)
        return str(ip)
    except Exception:
        return ""


def parse_cidrs(lines: Iterable[str]) -> list[ipaddress._BaseNetwork]:
    nets: list[ipaddress._BaseNetwork] = []
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            nets.append(ipaddress.ip_network(line, strict=False))
        except Exception:
            # ignore bad lines; caller can validate separately if desired
            continue
    return nets


def default_trusted_networks() -> list[ipaddress._BaseNetwork]:
    """
    Public-safe defaults only (no org-specific public ranges).
    """
    return parse_cidrs(
        [
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "127.0.0.0/8",
            "169.254.0.0/16",
            "::1/128",
            "fc00::/7",
            "fe80::/10",
        ]
    )


def load_trusted_networks(
    cidr_file: str | Path | None = None,
    extra_cidrs: Optional[Sequence[str]] = None,
) -> list[ipaddress._BaseNetwork]:
    """
    Load trusted networks from a file (preferred), plus optional extra CIDRs.
    If file is missing/unset, returns public-safe defaults.
    """
    nets = default_trusted_networks()

    if cidr_file:
        p = Path(cidr_file)
        if p.exists():
            try:
                nets = parse_cidrs(p.read_text(encoding="utf-8").splitlines())
            except Exception:
                # fall back to defaults if file read fails
                pass

    if extra_cidrs:
        nets.extend(parse_cidrs(extra_cidrs))

    # de-dupe by string form
    uniq = {str(n): n for n in nets}
    return list(uniq.values())


def is_trusted_ip(ip_str: str, trusted_nets: Sequence[ipaddress._BaseNetwork]) -> bool:
    ip_norm = normalize_ip(ip_str)
    if not ip_norm:
        return False
    try:
        ip = ipaddress.ip_address(ip_norm)
    except Exception:
        return False
    for net in trusted_nets:
        try:
            if ip in net:
                return True
        except Exception:
            continue
    return False


def pick_first_present(row: dict, candidates: Sequence[str]) -> str:
    """
    Given a row-like dict, pick the first non-empty candidate value.
    """
    for c in candidates:
        v = row.get(c, "")
        if v is None:
            continue
        s = str(v).strip()
        if s:
            return s
    return ""


def pick_ip_from_row(row: dict, candidates: Sequence[str]) -> str:
    """
    Pick and normalize an IP address from a row dict using candidate columns.
    """
    raw = pick_first_present(row, candidates)
    return normalize_ip(raw)
