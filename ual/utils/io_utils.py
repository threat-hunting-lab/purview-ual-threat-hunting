from __future__ import annotations

import os
from pathlib import Path
from typing import Iterator, Optional

import pandas as pd


def ensure_dir(path: str | Path) -> Path:
    p = Path(path)
    p.mkdir(parents=True, exist_ok=True)
    return p


def project_root_from_file(file_path: str | Path, levels_up: int = 3) -> Path:
    """
    If called from ual/scripts/<script>.py, levels_up=3 lands at repo root.
    scripts -> ual -> (root)
    Adjust if your nesting differs.
    """
    p = Path(file_path).resolve()
    for _ in range(levels_up):
        p = p.parent
    return p


def default_outputs_dir(script_file: str | Path) -> Path:
    """
    Standard outputs directory at repo root: <root>/outputs
    """
    root = project_root_from_file(script_file, levels_up=3)
    out_dir = root / "outputs"
    ensure_dir(out_dir)
    return out_dir


def read_csv_in_chunks(
    csv_path: str | Path,
    chunksize: int = 100_000,
    encoding: Optional[str] = "utf-8",
) -> Iterator[pd.DataFrame]:
    """
    Chunked CSV reader with dtype=str to avoid pandas type surprises.
    """
    return pd.read_csv(
        csv_path,
        chunksize=chunksize,
        dtype=str,
        encoding=encoding,
        low_memory=False,
        on_bad_lines="skip",
    )


def safe_str(v) -> str:
    if v is None:
        return ""
    try:
        # handles pandas NaN
        if pd.isna(v):
            return ""
    except Exception:
        pass
    return str(v)


def ensure_columns(df: pd.DataFrame, columns: list[str]) -> pd.DataFrame:
    for c in columns:
        if c not in df.columns:
            df[c] = ""
    return df


def write_csv(df: pd.DataFrame, out_path: str | Path) -> None:
    out_path = Path(out_path)
    ensure_dir(out_path.parent)
    df.to_csv(out_path, index=False)
