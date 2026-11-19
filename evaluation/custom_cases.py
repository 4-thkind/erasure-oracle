"""Participant-authored evaluation cases.

The supplied sample set is the tuning signal, so it is a biased measure: every
rule in the agent was eventually shaped by it. These five cases are written
from scratch against the problem statement only. They build a small standalone
dataset in a temporary directory, run the real pipeline over it, and assert the
exact ordered answer.

Coverage map:

    custom_01  historical email resolution, tombstone redaction, retained audit
               record, disabled connector, blocked restore -> COMPLETE
    custom_02  every finding and remediation operation in one case, including
               flow and restore ordering -> INCOMPLETE
    custom_03  access request that mentions no deletion at all -> NOT_APPLICABLE
    custom_04  an artifact captured after audit_at contradicts the state that
               was true at audit_at -> answer must stay COMPLETE
    custom_05  primary store deleted, regional replica still holding the
               profile -> replication drift -> INCOMPLETE

Run from the repository root:

    python evaluation/custom_cases.py
"""

from __future__ import annotations

import csv
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "code"))

from audit_agent.evidence import iso_epoch  # noqa: E402
from audit_agent.pipeline import AuditPipeline  # noqa: E402

RULES = """rule_id,data_category,condition,required_action
rule_01,USER_PROFILE,Always,DELETE
rule_02,SECONDARY_IDENTIFIER,Always,DELETE
rule_03,SEARCH_INDEX_ENTRY,Always,DELETE
rule_04,CACHE_ENTRY,Always,DELETE
rule_05,SUPPORT_MESSAGE,"Conversation contains shared customer, agent, or order context that must be retained",REDACT
rule_06,SUPPORT_ATTACHMENT,Attachment belongs only to the deletion subject,DELETE
rule_07,ANALYTICS_PROFILE,Record is still attributable to a user,ANONYMIZE
rule_08,PRODUCT_TELEMETRY,Record is still attributable to a user,ANONYMIZE
rule_09,USER_EXPORT,Always,DELETE
rule_10,MARKETING_PROFILE,Always,DELETE
rule_11,EMAIL_DELIVERY_LOG,Log contains a user email address,REDACT
rule_12,SECURITY_AUDIT_LOG,Record is within the supplied retention period,RETAIN
rule_13,LEGAL_HOLD_RECORD,A supplied legal hold is active,RETAIN
rule_14,BACKUP_ARCHIVE,Restore access can be blocked,RETAIN
rule_15,ACCOUNT_TOMBSTONE,Account is deleted and only a stable internal user_id is needed to preserve references to retained records,REDACT
"""

IDENTITIES = """user_id,name,email,phone,email_hash,updated_at
user_9101,Nora Whitfield,nora.whitfield@example.com,+1 202 555 0147,{h1},2026-06-01T00:00:00Z
user_9102,Priya Raman,priya.raman@example.com,+91 98450 22118,{h2},2026-06-02T00:00:00Z
user_9103,Tomas Berger,tomas.berger@example.com,+49 30 5557 2210,{h3},2026-06-03T00:00:00Z
user_9104,Aiko Tanaka,aiko.tanaka@example.com,+81 3 5555 0182,{h4},2026-06-04T00:00:00Z
user_9105,Hana Ito,hana.ito@example.com,+81 6 5555 0273,{h5},2026-06-05T00:00:00Z
"""

HISTORY = """audit_id,user_id,event_time,field_name,old_value,new_value
audit_c01,user_9101,2025-02-03T10:00:00Z,email,nora.olsen@example.com,nora.whitfield@example.com
"""


def _hash(token: str) -> str:
    import hashlib

    return hashlib.sha256(token.encode("utf-8")).hexdigest()


REQUESTS = [
    {
        "case_id": "custom_01",
        "email": "nora.olsen@example.com",
        "requested_at": "2026-07-08T08:00:00Z",
        "reported_status": "COMPLETE",
        "reported_at": "2026-07-11T09:00:00Z",
        "audit_at": "2026-07-12T00:00:00Z",
        "request_text": "Please delete my account and everything linked to me.",
    },
    {
        "case_id": "custom_02",
        "email": "priya.raman@example.com",
        "requested_at": "2026-07-16T08:00:00Z",
        "reported_status": "COMPLETE",
        "reported_at": "2026-07-18T09:00:00Z",
        "audit_at": "2026-07-20T00:00:00Z",
        "request_text": "I want my personal data erased from your systems.",
    },
    {
        "case_id": "custom_03",
        "email": "tomas.berger@example.com",
        "requested_at": "2026-07-17T08:00:00Z",
        "reported_status": "NOT_STARTED",
        "reported_at": "2026-07-17T09:00:00Z",
        "audit_at": "2026-07-19T00:00:00Z",
        "request_text": "Please send me a copy of everything you hold about me so I can review it.",
    },
    {
        "case_id": "custom_04",
        "email": "aiko.tanaka@example.com",
        "requested_at": "2026-07-18T08:00:00Z",
        "reported_status": "COMPLETE",
        "reported_at": "2026-07-20T09:00:00Z",
        "audit_at": "2026-07-21T00:00:00Z",
        "request_text": "Bitte loeschen Sie mein Konto und meine personenbezogenen Daten.",
    },
    {
        "case_id": "custom_05",
        "email": "hana.ito@example.com",
        "requested_at": "2026-07-17T08:00:00Z",
        "reported_status": "COMPLETE",
        "reported_at": "2026-07-19T09:00:00Z",
        "audit_at": "2026-07-22T00:00:00Z",
        "request_text": "Please close my account and remove my personal data.",
    },
]


def _snapshot_bundle(captured_at: str, snapshots: list[dict]) -> str:
    return json.dumps(
        {"captured_at": captured_at, "snapshots": snapshots}, indent=2
    )


def build_dataset(root: Path) -> dict[str, list[tuple]]:
    """Write the fixture and return the expected step list per case."""
    evidence = root / "evidence"
    evidence.mkdir(parents=True, exist_ok=True)

    files: dict[str, tuple[str, str]] = {}

    # ---- custom_01 ----------------------------------------------------
    files["evidence_c01"] = (
        "evidence/bundle_custom_01.json",
        _snapshot_bundle(
            "2026-07-10T09:00:00Z",
            [
                {
                    "data_store": "account_service",
                    "collection": "customer_profiles",
                    "records": [
                        {
                            "resource_id": "account_9101",
                            "user_id": "user_9101",
                            "deleted_at": "2026-07-05T00:00:00Z",
                        }
                    ],
                },
                {
                    "data_store": "identity_service",
                    "collection": "deleted_customer_references",
                    "records": [
                        {"resource_id": "tombstone_9101", "subject_reference": "user_9101"}
                    ],
                },
                {
                    "data_store": "security_service",
                    "collection": "security_audit_records",
                    "records": [
                        {
                            "resource_id": "audit_record_9101",
                            "subject_reference": "user_9101",
                            "event": "ACCOUNT_DELETED",
                        }
                    ],
                },
                {
                    "data_store": "integration_service",
                    "collection": "connector_subscriptions",
                    "records": [
                        {"resource_id": "data_flow_9101", "user_id": "user_9101", "enabled": False}
                    ],
                },
                {
                    "data_store": "backup_service",
                    "collection": "backup_restore_entries",
                    "records": [
                        {
                            "resource_id": "backup_9101",
                            "user_id": "user_9101",
                            "restore_allowed": False,
                        }
                    ],
                },
            ],
        ),
    )

    # ---- custom_02 ----------------------------------------------------
    files["evidence_c02"] = (
        "evidence/bundle_custom_02.json",
        _snapshot_bundle(
            "2026-07-18T12:00:00Z",
            [
                {
                    "data_store": "account_service",
                    "collection": "customer_profiles",
                    "records": [{"resource_id": "account_9102", "user_id": "user_9102"}],
                },
                {
                    "data_store": "search_service",
                    "collection": "search_documents",
                    "records": [
                        {
                            "resource_id": "search_9102",
                            "document": {
                                "email": "priya.raman@example.com",
                                "title": "replacement order confirmation",
                            },
                        }
                    ],
                },
                {
                    "data_store": "support_platform",
                    "collection": "support_tickets",
                    "records": [
                        {
                            "resource_id": "support_9102",
                            "ticket": {
                                "requester_email": "priya.raman@example.com",
                                "body": "Where is my parcel?",
                            },
                        }
                    ],
                },
                {
                    "data_store": "analytics_platform",
                    "collection": "customer_analytics_profiles",
                    "records": [
                        {
                            "resource_id": "analytics_9102",
                            "user_id": "user_9102",
                            "email": "priya.raman@example.com",
                        }
                    ],
                },
                {
                    "data_store": "integration_service",
                    "collection": "connector_subscriptions",
                    "records": [
                        {"resource_id": "data_flow_9102", "user_id": "user_9102", "enabled": True}
                    ],
                },
                {
                    "data_store": "backup_service",
                    "collection": "backup_restore_entries",
                    "records": [
                        {
                            "resource_id": "backup_9102",
                            "user_id": "user_9102",
                            "restore_allowed": True,
                        }
                    ],
                },
                {
                    "data_store": "security_service",
                    "collection": "security_audit_records",
                    "records": [
                        {"resource_id": "audit_record_9102", "subject_reference": "user_9102"}
                    ],
                },
            ],
        ),
    )

    # ---- custom_03 needs no evidence at all -----------------------------

    # ---- custom_04 ----------------------------------------------------
    files["evidence_c04a"] = (
        "evidence/bundle_custom_04a.json",
        _snapshot_bundle(
            "2026-07-19T06:00:00Z",
            [
                {
                    "data_store": "account_service",
                    "collection": "customer_profiles",
                    "records": [{"resource_id": "account_9104", "user_id": "user_9104"}],
                },
                {
                    "data_store": "analytics_platform",
                    "collection": "customer_analytics_profiles",
                    "records": [
                        {
                            "resource_id": "analytics_9104",
                            "user_id": "user_9104",
                            "session_count": 12,
                        }
                    ],
                },
                {
                    "data_store": "security_service",
                    "collection": "security_audit_records",
                    "records": [
                        {"resource_id": "audit_record_9104", "subject_reference": "user_9104"}
                    ],
                },
            ],
        ),
    )
    # Captured after audit_at: it may not decide the answer for custom_04.
    files["evidence_c04b"] = (
        "evidence/bundle_custom_04b.json",
        _snapshot_bundle(
            "2026-07-25T06:00:00Z",
            [
                {
                    "data_store": "analytics_platform",
                    "collection": "customer_analytics_profiles",
                    "records": [
                        {
                            "resource_id": "analytics_9104",
                            "user_id": "user_9104",
                            "email": "aiko.tanaka@example.com",
                        }
                    ],
                },
                {
                    "data_store": "support_platform",
                    "collection": "support_tickets",
                    "records": [
                        {
                            "resource_id": "support_9104",
                            "ticket": {"requester_email": "aiko.tanaka@example.com"},
                        }
                    ],
                },
            ],
        ),
    )

    # ---- custom_05: primary deleted, regional replica drifted ----------
    files["evidence_c05a"] = (
        "evidence/primary_custom_05.sql",
        "-- Captured at: 2026-07-18T00:00:00Z\n"
        "CREATE TABLE customer_profiles ("
        "resource_id TEXT, user_id TEXT, email TEXT, name TEXT, updated_at TEXT);\n"
        "INSERT INTO customer_profiles VALUES "
        "('account_9105', 'user_9105', NULL, NULL, '2026-07-12T00:00:00Z');\n",
    )
    files["evidence_c05b"] = (
        "evidence/regional_replica_custom_05.sql",
        "-- Captured at: 2026-07-20T00:00:00Z\n"
        "CREATE TABLE customer_profiles_replica ("
        "resource_id TEXT, user_id TEXT, email TEXT, name TEXT, updated_at TEXT);\n"
        "INSERT INTO customer_profiles_replica VALUES "
        "('account_9105', 'user_9105', 'hana.ito@example.com', 'Hana Ito', "
        "'2026-07-14T00:00:00Z');\n",
    )

    captured = {
        "evidence_c01": "2026-07-10T09:00:00Z",
        "evidence_c02": "2026-07-18T12:00:00Z",
        "evidence_c04a": "2026-07-19T06:00:00Z",
        "evidence_c04b": "2026-07-25T06:00:00Z",
        "evidence_c05a": "2026-07-18T00:00:00Z",
        "evidence_c05b": "2026-07-20T00:00:00Z",
    }

    for file_id, (rel_path, body) in files.items():
        (root / rel_path).write_text(body, encoding="utf-8")

    with (root / "evidence_files.csv").open("w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh, lineterminator="\n")
        writer.writerow(["file_id", "file_path", "origin", "captured_at"])
        for file_id in sorted(files):
            writer.writerow([file_id, files[file_id][0], "custom_fixture", captured[file_id]])

    with (root / "user_identities.csv").open("w", encoding="utf-8", newline="") as fh:
        fh.write(
            IDENTITIES.format(
                h1=_hash("nora.whitfield@example.com"),
                h2=_hash("priya.raman@example.com"),
                h3=_hash("tomas.berger@example.com"),
                h4=_hash("aiko.tanaka@example.com"),
                h5=_hash("hana.ito@example.com"),
            )
        )

    (root / "user_audit_log.csv").write_text(HISTORY, encoding="utf-8")
    (root / "deletion_rules.csv").write_text(RULES, encoding="utf-8")

    with (root / "deletion_requests.csv").open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(
            fh,
            fieldnames=[
                "case_id", "email", "requested_at", "reported_status",
                "reported_at", "audit_at", "request_text",
            ],
            lineterminator="\n",
        )
        writer.writeheader()
        writer.writerows(REQUESTS)

    return expectations()


def expectations() -> dict[str, list[tuple]]:
    """The ordered answer each case must produce."""

    def step(phase, system, resource, operation, state, evidence):
        return (phase, system, resource, operation, state, evidence)

    return {
        # Account record gone, tombstone keeps only the stable reference, audit
        # record retained, connector off, backups not restorable.
        "custom_01": [
            step("VERIFICATION", "account_service", "account_9101",
                 "VERIFY_RECORD_ABSENT", "ABSENT", "evidence_c01"),
            step("VERIFICATION", "security_service", "audit_record_9101",
                 "VERIFY_RECORD_PRESENT", "PRESENT", "evidence_c01"),
            step("VERIFICATION", "identity_service", "tombstone_9101",
                 "VERIFY_RECORD_REDACTED", "REDACTED", "evidence_c01"),
            step("VERIFICATION", "integration_service", "data_flow_9101",
                 "VERIFY_DATA_FLOW_DISABLED", "DISABLED", "evidence_c01"),
            step("VERIFICATION", "backup_service", "backup_9101",
                 "VERIFY_RESTORE_BLOCKED", "BLOCKED", "evidence_c01"),
        ],
        # Every finding kind present, remediation ordered by the operation
        # table so flows stop and restores are blocked before records change.
        "custom_02": [
            step("FINDING", "search_service", "search_9102",
                 "REPORT_REMAINING_RECORD", "PRESENT", "evidence_c02"),
            step("FINDING", "analytics_platform", "analytics_9102",
                 "REPORT_EXPOSED_PII", "PRESENT", "evidence_c02"),
            step("FINDING", "support_platform", "support_9102",
                 "REPORT_EXPOSED_PII", "PRESENT", "evidence_c02"),
            step("FINDING", "integration_service", "data_flow_9102",
                 "REPORT_ACTIVE_DATA_FLOW", "ACTIVE", "evidence_c02"),
            step("FINDING", "backup_service", "backup_9102",
                 "REPORT_RESTORE_RISK", "ACTIVE", "evidence_c02"),
            step("REMEDIATION", "integration_service", "data_flow_9102",
                 "DISABLE_DATA_FLOW", "DISABLED", ""),
            step("REMEDIATION", "backup_service", "backup_9102",
                 "BLOCK_RESTORE", "BLOCKED", ""),
            step("REMEDIATION", "search_service", "search_9102",
                 "DELETE_RECORD", "ABSENT", ""),
            step("REMEDIATION", "support_platform", "support_9102",
                 "REDACT_RECORD", "REDACTED", ""),
            step("REMEDIATION", "analytics_platform", "analytics_9102",
                 "ANONYMIZE_RECORD", "ANONYMIZED", ""),
            step("VERIFICATION", "account_service", "account_9102",
                 "VERIFY_RECORD_ABSENT", "ABSENT", ""),
            step("VERIFICATION", "search_service", "search_9102",
                 "VERIFY_RECORD_ABSENT", "ABSENT", ""),
            step("VERIFICATION", "security_service", "audit_record_9102",
                 "VERIFY_RECORD_PRESENT", "PRESENT", ""),
            step("VERIFICATION", "support_platform", "support_9102",
                 "VERIFY_RECORD_REDACTED", "REDACTED", ""),
            step("VERIFICATION", "analytics_platform", "analytics_9102",
                 "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED", ""),
            step("VERIFICATION", "integration_service", "data_flow_9102",
                 "VERIFY_DATA_FLOW_DISABLED", "DISABLED", ""),
            step("VERIFICATION", "backup_service", "backup_9102",
                 "VERIFY_RESTORE_BLOCKED", "BLOCKED", ""),
        ],
        "custom_03": [],
        # The late bundle shows a fresh analytics email and a support ticket.
        # Neither existed at audit_at, so both must be ignored.
        "custom_04": [
            step("VERIFICATION", "account_service", "account_9104",
                 "VERIFY_RECORD_ABSENT", "ABSENT", "evidence_c04a"),
            step("VERIFICATION", "security_service", "audit_record_9104",
                 "VERIFY_RECORD_PRESENT", "PRESENT", "evidence_c04a"),
            step("VERIFICATION", "analytics_platform", "analytics_9104",
                 "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED", "evidence_c04a"),
        ],
        # Newest copy of the account record wins: the replica still carries the
        # profile, so the deletion is not complete.
        "custom_05": [
            step("FINDING", "account_service", "account_9105",
                 "REPORT_REMAINING_RECORD", "PRESENT", "evidence_c05b"),
            step("REMEDIATION", "account_service", "account_9105",
                 "DELETE_RECORD", "ABSENT", ""),
            step("VERIFICATION", "account_service", "account_9105",
                 "VERIFY_RECORD_ABSENT", "ABSENT", ""),
        ],
    }


def run(root: Path) -> tuple[dict[str, str], dict[str, list[tuple]], dict[str, list[dict]]]:
    expected = build_dataset(root)
    pipeline = AuditPipeline(dataset_dir=root)
    results = pipeline.run_all()
    statuses: dict[str, str] = {}
    steps: dict[str, list[tuple]] = {}
    raw: dict[str, list[dict]] = {}
    for result in results:
        statuses[result.case_id] = result.status
        steps[result.case_id] = [
            (
                step["phase"], step["system_id"], step["resource_id"],
                step["operation"], step["state"], step["evidence_id"],
            )
            for step in result.steps
        ]
        raw[result.case_id] = result.steps
    return statuses, steps, raw


def main() -> int:
    failures: list[str] = []
    with tempfile.TemporaryDirectory(prefix="ghost_custom_") as tmp:
        statuses, steps, raw = run(Path(tmp))

    expected = expectations()
    expected_status = {
        "custom_01": "COMPLETE",
        "custom_02": "INCOMPLETE",
        "custom_03": "NOT_APPLICABLE",
        "custom_04": "COMPLETE",
        "custom_05": "INCOMPLETE",
    }
    audit_at = {case["case_id"]: case["audit_at"] for case in REQUESTS}

    for case_id in sorted(expected):
        got_status = statuses.get(case_id, "<missing>")
        if got_status != expected_status[case_id]:
            failures.append(
                f"{case_id}: status {got_status}, expected {expected_status[case_id]}"
            )

        got_steps = steps.get(case_id, [])
        want_steps = expected[case_id]
        if got_steps != want_steps:
            failures.append(f"{case_id}: step list differs from the expected plan")
            for index in range(max(len(got_steps), len(want_steps))):
                got = got_steps[index] if index < len(got_steps) else None
                want = want_steps[index] if index < len(want_steps) else None
                if got != want:
                    failures.append(f"    {index + 1}: got {got} want {want}")

        # Structural invariants that hold for every answer, not just these.
        rows = raw.get(case_id, [])
        for position, row in enumerate(rows, start=1):
            if row["step_no"] != position:
                failures.append(f"{case_id}: step_no {row['step_no']} at position {position}")
            if row["evidence_id"] and iso_epoch(
                _capture(row["evidence_id"])
            ) > iso_epoch(audit_at[case_id]):
                failures.append(
                    f"{case_id}: {row['resource_id']} cites evidence captured after audit_at"
                )
        phases = [row["phase"] for row in rows]
        order = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}
        if phases != sorted(phases, key=lambda name: order[name]):
            failures.append(f"{case_id}: phases are not FINDING, REMEDIATION, VERIFICATION")

    print("participant-authored cases")
    print("--------------------------")
    for case_id in sorted(expected):
        wanted = expected_status[case_id]
        got = statuses.get(case_id, "<missing>")
        marker = "PASS" if got == wanted and steps.get(case_id) == expected[case_id] else "FAIL"
        print(
            f"  {case_id:<10} {marker}  status={got:<14} "
            f"steps={len(steps.get(case_id, []))} expected={len(expected[case_id])}"
        )

    if failures:
        print("\nfailures:")
        for line in failures:
            print("  " + line)
        return 1
    print("\nall participant-authored cases pass")
    return 0


CAPTURED = {
    "evidence_c01": "2026-07-10T09:00:00Z",
    "evidence_c02": "2026-07-18T12:00:00Z",
    "evidence_c04a": "2026-07-19T06:00:00Z",
    "evidence_c04b": "2026-07-25T06:00:00Z",
    "evidence_c05a": "2026-07-18T00:00:00Z",
    "evidence_c05b": "2026-07-20T00:00:00Z",
}


def _capture(file_id: str) -> str:
    return CAPTURED.get(file_id, "")


if __name__ == "__main__":
    raise SystemExit(main())
