from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Tuple


@dataclass(frozen=True)
class BinaryMetrics:
    tp: int
    fp: int
    tn: int
    fn: int

    @property
    def precision(self) -> float:
        denom = self.tp + self.fp
        return self.tp / denom if denom else 0.0

    @property
    def recall(self) -> float:
        denom = self.tp + self.fn
        return self.tp / denom if denom else 0.0

    @property
    def f1(self) -> float:
        p = self.precision
        r = self.recall
        denom = p + r
        return (2 * p * r / denom) if denom else 0.0


def confusion_from_bools(y_true: Iterable[bool], y_pred: Iterable[bool]) -> BinaryMetrics:
    tp = fp = tn = fn = 0
    for t, p in zip(y_true, y_pred):
        if t and p:
            tp += 1
        elif (not t) and p:
            fp += 1
        elif (not t) and (not p):
            tn += 1
        else:
            fn += 1
    return BinaryMetrics(tp=tp, fp=fp, tn=tn, fn=fn)


def coverage_delta(hit_norm_only: int, hit_raw_only: int, hit_both: int) -> Tuple[float, float]:
    """
    Returns:
      - pct_raw_only_of_total_hits: fraction of all hits that would be missed if you only used normalized fields
      - pct_norm_only_of_total_hits: fraction of all hits missed if you only used raw parsing (rare, but possible)
    """
    total = hit_norm_only + hit_raw_only + hit_both
    if total == 0:
        return 0.0, 0.0
    return hit_raw_only / total, hit_norm_only / total
