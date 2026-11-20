"""Sample-set evaluation.

Reports the four things the submission contract asks for: case-level status
accuracy, step-level and field-level accuracy, and sequence accuracy.

Steps are aligned by identity first (phase, system, resource, operation, state)
and only then compared field by field. Aligning by position would charge a
correct step twice for a single ordering mistake, which tells us nothing about
which field was actually wrong.
"""

from __future__ import annotations

import csv
import json
import sys
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "code"))

from audit_agent.config import DATASET_DIR, SAMPLE_OUTPUT_FILE  # noqa: E402
from audit_agent.pipeline import AuditPipeline, load_sample_requests  # noqa: E402

STEP_FIELDS = ("step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id")
IDENTITY_FIELDS = ("phase", "system_id", "resource_id", "operation", "state")


@dataclass
class Metrics:
    cases: int = 0
    status_correct: int = 0
    expected_steps: int = 0
    produced_steps: int = 0
    aligned_steps: int = 0
    sequence_correct: int = 0
    status_errors: list = field(default_factory=list)
    field_correct: Counter = field(default_factory=Counter)
    field_total: Counter = field(default_factory=Counter)
    aligned_correct: Counter = field(default_factory=Counter)
    diffs: list = field(default_factory=list)

    @property
    def precision(self) -> float:
        return self.aligned_steps / self.produced_steps if self.produced_steps else 0.0

    @property
    def recall(self) -> float:
        return self.aligned_steps / self.expected_steps if self.expected_steps else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if p + r else 0.0

    @property
    def step_accuracy(self) -> float:
        return self.aligned_steps / max(self.expected_steps, self.produced_steps)


def load_expected(path: Path) -> dict[str, dict]:
    with path.open(encoding="utf-8", newline="") as fh:
        return {row["case_id"]: row for row in csv.DictReader(fh)}


def _identity(step: dict) -> tuple:
    return tuple(step.get(name) for name in IDENTITY_FIELDS)


def compare(expected: dict[str, dict], results: list) -> Metrics:
    metrics = Metrics()
    for result in results:
        truth = expected.get(result.case_id)
        if not truth:
            continue
        metrics.cases += 1
        want = json.loads(truth["steps_json"])
        got = result.steps
        metrics.expected_steps += len(want)
        metrics.produced_steps += len(got)

        if truth["deletion_status"] == result.status:
            metrics.status_correct += 1
        else:
            metrics.status_errors.append(
                (result.case_id, truth["deletion_status"], result.status)
            )

        if [_identity(step) for step in want] == [_identity(step) for step in got]:
            metrics.sequence_correct += 1

        # Multiset alignment on step identity.
        pool: dict[tuple, list[dict]] = {}
        for step in want:
            pool.setdefault(_identity(step), []).append(step)
        leftovers: list[dict] = []
        for step in got:
            bucket = pool.get(_identity(step))
            if bucket:
                reference = bucket.pop()
                metrics.aligned_steps += 1
                for name in STEP_FIELDS:
                    metrics.field_total[name] += 1
                    if reference.get(name) == step.get(name):
                        metrics.field_correct[name] += 1
                        metrics.aligned_correct[name] += 1
                if reference.get("evidence_id") != step.get("evidence_id"):
                    metrics.diffs.append(
                        (result.case_id, "evidence", reference["resource_id"],
                         reference.get("evidence_id"), step.get("evidence_id"))
                    )
            else:
                leftovers.append(step)

        # Every unmatched step is a full row of wrong fields.
        unmatched = leftovers + [step for bucket in pool.values() for step in bucket]
        for step in unmatched:
            for name in STEP_FIELDS:
                metrics.field_total[name] += 1
        for step in leftovers:
            if len(metrics.diffs) < 40:
                metrics.diffs.append(
                    (result.case_id, "extra", step["resource_id"], "", step["operation"])
                )
        for bucket in pool.values():
            for step in bucket:
                if len(metrics.diffs) < 40:
                    metrics.diffs.append(
                        (result.case_id, "missing", step["resource_id"], step["operation"], "")
                    )
    return metrics


def report(metrics: Metrics) -> str:
    lines = [
        f"sample cases                 : {metrics.cases}",
        f"status accuracy              : {metrics.status_correct}/{metrics.cases}"
        f"  ({metrics.status_correct / max(1, metrics.cases):.3f})",
        "",
        f"expected steps               : {metrics.expected_steps}",
        f"produced steps               : {metrics.produced_steps}",
        f"aligned steps                : {metrics.aligned_steps}",
        f"step precision               : {metrics.precision:.3f}",
        f"step recall                  : {metrics.recall:.3f}",
        f"step F1                      : {metrics.f1:.3f}",
        f"step accuracy (aligned/max)  : {metrics.step_accuracy:.3f}",
        f"sequence accuracy            : {metrics.sequence_correct}/{metrics.cases}"
        f"  ({metrics.sequence_correct / max(1, metrics.cases):.3f})",
        "",
    ]
    for name in STEP_FIELDS:
        total = metrics.field_total[name]
        if total:
            correct = metrics.field_correct[name]
            lines.append(f"field {name:<13}: {correct}/{total}  ({correct / total:.3f})")

    aligned = metrics.aligned_steps
    if aligned:
        lines.append("")
        lines.append("on aligned steps only (identity already matched):")
        for name in STEP_FIELDS:
            if name == "step_no":
                continue
            correct = metrics.aligned_correct[name]
            lines.append(f"  {name:<13}: {correct}/{aligned}  ({correct / aligned:.3f})")
    return "\n".join(lines)


def main() -> int:
    pipeline = AuditPipeline()
    requests = load_sample_requests(DATASET_DIR)
    results = pipeline.run_all(requests)
    metrics = compare(load_expected(SAMPLE_OUTPUT_FILE), results)
    print(report(metrics))
    if metrics.status_errors:
        print("\nstatus errors:")
        for case_id, want, got in metrics.status_errors:
            print(f"  {case_id}: expected {want}, produced {got}")
    print(f"\nstep differences ({len(metrics.diffs)} shown):")
    for row in metrics.diffs[:40]:
        print("  " + " | ".join(str(value) for value in row))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
