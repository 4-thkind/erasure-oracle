"""Submission validator.

`output.csv` has to satisfy the contract before it is uploaded, and most of the
contract is checkable without knowing the right answer. This script checks
shape, vocabulary, ordering, citation provenance, and policy legality.

Run from the repository root:

    python evaluation/validate_output.py [path/to/output.csv]
"""

from __future__ import annotations

import csv
import json

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "code"))

from audit_agent import evidence as ev  # noqa: E402
from audit_agent.config import DATASET_DIR, OUTPUT_PATH, OPERATION_STATE, PHASE_OF_OPERATION  # noqa: E402
from audit_agent.policy import Policy  # noqa: E402

STATUSES = {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"}
PHASES = ("FINDING", "REMEDIATION", "VERIFICATION")
STEP_FIELDS = {"step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"}
FINDING_OPS = {
    "REPORT_REMAINING_RECORD", "REPORT_EXPOSED_PII",
    "REPORT_ACTIVE_DATA_FLOW", "REPORT_RESTORE_RISK",
}
REMEDIATION_OPS = {"DISABLE_DATA_FLOW", "BLOCK_RESTORE", "DELETE_RECORD", "REDACT_RECORD", "ANONYMIZE_RECORD"}
VERIFICATION_OPS = {
    "VERIFY_RECORD_ABSENT", "VERIFY_RECORD_PRESENT", "VERIFY_RECORD_REDACTED",
    "VERIFY_RECORD_ANONYMIZED", "VERIFY_DATA_FLOW_DISABLED", "VERIFY_RESTORE_BLOCKED",
}
REMEDIATION_FOR = {
    "REPORT_REMAINING_RECORD": "DELETE_RECORD",
    "REPORT_EXPOSED_PII": None,           # REDACT or ANONYMIZE, decided by category
    "REPORT_ACTIVE_DATA_FLOW": "DISABLE_DATA_FLOW",
    "REPORT_RESTORE_RISK": "BLOCK_RESTORE",
}


def load_cases(dataset_dir: Path) -> dict[str, dict]:
    with (dataset_dir / "deletion_requests.csv").open(encoding="utf-8-sig", newline="") as fh:
        return {row["case_id"]: row for row in csv.DictReader(fh)}


def load_manifest(dataset_dir: Path) -> dict[str, str]:
    with (dataset_dir / "evidence_files.csv").open(encoding="utf-8-sig", newline="") as fh:
        return {row["file_id"]: row["captured_at"] for row in csv.DictReader(fh)}


def load_ids(dataset_dir: Path) -> set[str]:
    """Every id the contract allows as a citation."""
    ids: set[str] = set()
    for name in ("system_activity.csv", "user_audit_log.csv"):
        path = dataset_dir / name
        if not path.exists():
            continue
        with path.open(encoding="utf-8-sig", newline="") as fh:
            reader = csv.DictReader(fh)
            column = "activity_id" if "activity_id" in (reader.fieldnames or []) else "audit_id"
            for row in reader:
                if row.get(column):
                    ids.add(row[column])
    return ids


def category_of(resource_id: str, system_id: str) -> str:
    category, _ = ev.infer_category(resource_id, system_id)
    return category


def validate(path: Path, dataset_dir: Path) -> list[str]:
    errors: list[str] = []
    cases = load_cases(dataset_dir)
    manifest = load_manifest(dataset_dir)
    activity_ids = load_ids(dataset_dir)
    policy = Policy(dataset_dir / "deletion_rules.csv")

    with path.open(encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        if reader.fieldnames != ["case_id", "deletion_status", "steps_json"]:
            errors.append(f"header is {reader.fieldnames}, expected case_id,deletion_status,steps_json")
        rows = list(reader)

    if len(rows) != len(cases):
        errors.append(f"{len(rows)} rows, expected {len(cases)}")

    seen: set[str] = set()
    statuses: dict[str, int] = {}
    operations: dict[str, int] = {}
    late_citations: list[str] = []
    total_steps = 0

    for row in rows:
        case_id = row["case_id"]
        if case_id in seen:
            errors.append(f"{case_id}: duplicate row")
        seen.add(case_id)
        if case_id not in cases:
            errors.append(f"{case_id}: not in deletion_requests.csv")
            continue

        status = row["deletion_status"]
        statuses[status] = statuses.get(status, 0) + 1
        if status not in STATUSES:
            errors.append(f"{case_id}: status {status!r}")
            continue

        try:
            steps = json.loads(row["steps_json"])
        except json.JSONDecodeError as exc:
            errors.append(f"{case_id}: steps_json is not JSON ({exc})")
            continue
        if not isinstance(steps, list):
            errors.append(f"{case_id}: steps_json is not a list")
            continue

        audit_epoch = ev.iso_epoch(cases[case_id]["audit_at"])

        if status == "NOT_APPLICABLE":
            if steps:
                errors.append(f"{case_id}: NOT_APPLICABLE with {len(steps)} steps")
            continue
        if not steps:
            errors.append(f"{case_id}: {status} with no steps")
            continue

        phases = []
        keys = set()
        for position, step in enumerate(steps, start=1):
            if not isinstance(step, dict) or set(step) != STEP_FIELDS:
                errors.append(f"{case_id} step {position}: fields {sorted(step) if isinstance(step, dict) else step}")
                continue
            total_steps += 1
            operations[step["operation"]] = operations.get(step["operation"], 0) + 1

            if step["step_no"] != position:
                errors.append(f"{case_id} step {position}: step_no {step['step_no']}")
            if PHASE_OF_OPERATION.get(step["operation"]) != step["phase"]:
                errors.append(f"{case_id} step {position}: phase {step['phase']} for {step['operation']}")
            if OPERATION_STATE.get(step["operation"]) != step["state"]:
                errors.append(f"{case_id} step {position}: state {step['state']} for {step['operation']}")
            if not step["system_id"] or not step["resource_id"]:
                errors.append(f"{case_id} step {position}: empty system or resource")
            phases.append(step["phase"])
            keys.add((step["system_id"], step["resource_id"]))

            evidence_id = step["evidence_id"]
            if evidence_id:
                if evidence_id not in manifest and evidence_id not in activity_ids:
                    errors.append(f"{case_id} step {position}: citation {evidence_id} not in dataset")
                elif evidence_id in manifest:
                    captured = ev.iso_epoch(manifest[evidence_id])
                    if captured > audit_epoch:
                        # Documented last resort: the case window holds no
                        # artifact at all, so the audit is run against the
                        # earliest later artifact (see pipeline.late_window).
                        late_citations.append(
                            f"{case_id} step {position}: {evidence_id} captured after audit_at"
                        )

            if status == "COMPLETE":
                if step["phase"] != "VERIFICATION":
                    errors.append(f"{case_id} step {position}: COMPLETE carries {step['phase']}")
                if not evidence_id:
                    errors.append(f"{case_id} step {position}: COMPLETE step without citation")
            else:
                if step["phase"] == "FINDING" and not evidence_id:
                    errors.append(f"{case_id} step {position}: finding without citation")
                if step["phase"] != "FINDING" and evidence_id:
                    errors.append(f"{case_id} step {position}: future work cites {evidence_id}")

        order = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}
        if phases != sorted(phases, key=lambda name: order[name]):
            errors.append(f"{case_id}: phase order {phases}")

        if status == "INCOMPLETE":
            by_phase = {name: [s for s in steps if s["phase"] == name] for name in PHASES}
            remediated = {(s["system_id"], s["resource_id"]) for s in by_phase["REMEDIATION"]}
            checked = {(s["system_id"], s["resource_id"]) for s in by_phase["VERIFICATION"]}
            found = {(s["system_id"], s["resource_id"]) for s in by_phase["FINDING"]}
            if not remediated:
                errors.append(f"{case_id}: INCOMPLETE with no remediation")
            for key in sorted(found - remediated):
                errors.append(f"{case_id}: finding {key} has no remediation")
            for key in sorted(remediated - checked):
                errors.append(f"{case_id}: remediated {key} is never verified")
            for step in by_phase["FINDING"]:
                expected_op = REMEDIATION_FOR[step["operation"]]
                match = [
                    s for s in by_phase["REMEDIATION"]
                    if (s["system_id"], s["resource_id"]) == (step["system_id"], step["resource_id"])
                ]
                if not match:
                    continue
                if expected_op and match[0]["operation"] != expected_op:
                    errors.append(
                        f"{case_id}: {step['operation']} answered with {match[0]['operation']}"
                    )
                # Policy legality: a retained category is never deleted or redacted.
                category = category_of(step["resource_id"], step["system_id"])
                guard = policy.guard_for(category)
                if guard in {"RETAIN", "BLOCK_RESTORE"} and match[0]["operation"] in {
                    "DELETE_RECORD", "REDACT_RECORD", "ANONYMIZE_RECORD"
                }:
                    errors.append(
                        f"{case_id}: {category} guarded by {guard} is remediated with "
                        f"{match[0]['operation']}"
                    )
        else:
            for step in steps:
                if step["operation"] not in VERIFICATION_OPS:
                    errors.append(f"{case_id}: COMPLETE carries {step['operation']}")

    missing = sorted(set(cases) - seen)
    if missing:
        errors.append(f"{len(missing)} cases missing, first: {missing[:5]}")

    print(f"rows                : {len(rows)}")
    print(f"case ids            : {len(seen)} unique / {len(cases)} requested")
    print(f"steps               : {total_steps}")
    for name in sorted(statuses):
        print(f"status {name:<15}: {statuses[name]}")
    print("operations:")
    for name in sorted(operations):
        print(f"  {name:<26}: {operations[name]}")
    print(f"errors              : {len(errors)}")
    for line in errors[:40]:
        print("  " + line)
    if late_citations:
        print(f"late-window fallback citations: {len(late_citations)} (documented)")
        for line in late_citations[:10]:
            print("  " + line)
    return errors


def main(argv: list[str]) -> int:
    path = Path(argv[1]) if len(argv) > 1 else OUTPUT_PATH
    errors = validate(path, DATASET_DIR)
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
