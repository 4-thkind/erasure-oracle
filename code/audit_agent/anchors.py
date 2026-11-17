"""Account-anchor recovery from the deletion workflow stream.

Every answer is anchored on the subject's account record. When the account is
gone, the snapshots usually keep no row for it: the resource id survives only in
the workflow's own activity stream, which records the delete attempt against a
resource id but not the person it belonged to.

The stream is still usable, for two reasons. Its rows cluster in time around the
request that triggered them, so a case's own row is one of the few near its
``reported_at``. And a workflow run handles a small group of requests at once, so
the group's rows and the group's cases can be matched as sets instead of one at a
time: an account already tied to another user is out, an outcome that contradicts
the reported status is penalised, and within what remains the closest row wins.

The result is a name for a record, never a verdict. A recovered id is always
reported as an absent account with no citation, so a wrong guess costs one
verification step and can never turn a complete case into an incomplete one.
"""

from __future__ import annotations

import itertools
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable

# How far from ``reported_at`` a workflow row may sit and still belong to the
# run that produced this case. Real runs land within a couple of hours.
WINDOW_SECONDS = 7200

# The workflow's own outcome for a resource, read from its reported result.
STATUS_RESULT = {
    "COMPLETE": "SUCCESS",
    "PARTIALLY_COMPLETE": "PARTIAL",
    "NOT_STARTED": "FAILED",
}

# A row that agrees with the request's reported status is worth far more than any
# amount of time proximity, so this weight dominates the whole window.
AGREEMENT_BONUS = 10.0


def parse_epoch(value: str) -> float:
    if not value:
        return float("-inf")
    text = value.strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return float("-inf")
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


@dataclass(frozen=True)
class Candidate:
    """One delete attempt that could belong to the case."""

    resource_id: str
    epoch: float
    result: str


@dataclass(frozen=True)
class Pending:
    """A case whose account id is still unknown, plus its candidate rows."""

    case_id: str
    reported_at: str
    reported_status: str
    candidates: tuple[Candidate, ...]

    @property
    def epoch(self) -> float:
        return parse_epoch(self.reported_at)


def _score(one: Pending, other: Candidate) -> float:
    score = 0.0
    if other.result == STATUS_RESULT.get(one.reported_status.upper(), ""):
        score += AGREEMENT_BONUS
    score -= abs(other.epoch - one.epoch) / 3600.0
    return score


def _best_assignment(group: list[Pending], pool: dict[str, Candidate]) -> dict[str, str]:
    """Pick the injective case-to-resource assignment with the highest score."""
    ids = sorted(pool)
    best_total: float | None = None
    best: tuple[str, ...] = ()
    for combo in itertools.permutations(ids, min(len(group), len(ids))):
        total = 0.0
        for one, resource_id in zip(group, combo):
            allowed = {c.resource_id for c in one.candidates}
            if resource_id not in allowed:
                total = None  # type: ignore[assignment]
                break
            total += _score(one, pool[resource_id])
        if total is None:
            continue
        if best_total is None or total > best_total:
            best_total, best = total, combo
    return {one.case_id: resource_id for one, resource_id in zip(group, best)}


def solve(pending: Iterable[Pending], window: int = WINDOW_SECONDS) -> dict[str, str]:
    """Return ``case_id -> account resource id`` for as many cases as possible."""
    grouped: dict[str, list[Pending]] = {}
    for one in pending:
        grouped.setdefault(one.reported_at, []).append(one)

    claimed: set[str] = set()
    answer: dict[str, str] = {}
    # Smallest groups first: they are the most constrained, and settling them
    # first stops them from taking an id a larger group needed.
    for _reported_at, group in sorted(grouped.items(), key=lambda kv: (len(kv[1]), kv[0])):
        group = [
            Pending(one.case_id, one.reported_at, one.reported_status,
                    tuple(c for c in one.candidates if c.resource_id not in claimed))
            for one in group
        ]
        group = [one for one in group if one.candidates]
        if not group:
            continue
        pool = {c.resource_id: c for one in group for c in one.candidates}
        assigned = _best_assignment(group, pool)
        for case_id, resource_id in assigned.items():
            answer[case_id] = resource_id
            claimed.add(resource_id)
    return answer
