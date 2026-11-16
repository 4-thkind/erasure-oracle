"""Repository layout and tunable constants."""

from __future__ import annotations

import os
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DATASET_DIR = REPO_ROOT / "dataset"
EVIDENCE_DIR = DATASET_DIR / "evidence"
OUTPUT_PATH = REPO_ROOT / "output.csv"
EVALUATION_DIR = Path(__file__).resolve().parents[2] / "evaluation"

REQUEST_FILE = DATASET_DIR / "deletion_requests.csv"
SAMPLE_REQUEST_FILE = DATASET_DIR / "sample_deletion_requests.csv"
SAMPLE_OUTPUT_FILE = DATASET_DIR / "sample_output.csv"
IDENTITY_FILE = DATASET_DIR / "user_identities.csv"
AUDIT_LOG_FILE = DATASET_DIR / "user_audit_log.csv"
ACTIVITY_FILE = DATASET_DIR / "system_activity.csv"
RULES_FILE = DATASET_DIR / "deletion_rules.csv"
EVIDENCE_MANIFEST = DATASET_DIR / "evidence_files.csv"

OUTPUT_COLUMNS = ("case_id", "deletion_status", "steps_json")

# Statuses
COMPLETE = "COMPLETE"
INCOMPLETE = "INCOMPLETE"
NOT_APPLICABLE = "NOT_APPLICABLE"

# Phases, in emission order.
PHASE_ORDER = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}

# Operation order taken verbatim from the problem statement tables.
OPERATION_ORDER = {
    "REPORT_REMAINING_RECORD": 0,
    "REPORT_EXPOSED_PII": 1,
    "REPORT_ACTIVE_DATA_FLOW": 2,
    "REPORT_RESTORE_RISK": 3,
    "DISABLE_DATA_FLOW": 0,
    "BLOCK_RESTORE": 1,
    "DELETE_RECORD": 2,
    "REDACT_RECORD": 3,
    "ANONYMIZE_RECORD": 4,
    "VERIFY_RECORD_ABSENT": 0,
    "VERIFY_RECORD_PRESENT": 1,
    "VERIFY_RECORD_REDACTED": 2,
    "VERIFY_RECORD_ANONYMIZED": 3,
    "VERIFY_DATA_FLOW_DISABLED": 4,
    "VERIFY_RESTORE_BLOCKED": 5,
}

OPERATION_STATE = {
    "REPORT_REMAINING_RECORD": "PRESENT",
    "REPORT_EXPOSED_PII": "PRESENT",
    "REPORT_ACTIVE_DATA_FLOW": "ACTIVE",
    "REPORT_RESTORE_RISK": "ACTIVE",
    "DISABLE_DATA_FLOW": "DISABLED",
    "BLOCK_RESTORE": "BLOCKED",
    "DELETE_RECORD": "ABSENT",
    "REDACT_RECORD": "REDACTED",
    "ANONYMIZE_RECORD": "ANONYMIZED",
    "VERIFY_RECORD_ABSENT": "ABSENT",
    "VERIFY_RECORD_PRESENT": "PRESENT",
    "VERIFY_RECORD_REDACTED": "REDACTED",
    "VERIFY_RECORD_ANONYMIZED": "ANONYMIZED",
    "VERIFY_DATA_FLOW_DISABLED": "DISABLED",
    "VERIFY_RESTORE_BLOCKED": "BLOCKED",
}

PHASE_OF_OPERATION = {
    "REPORT_REMAINING_RECORD": "FINDING",
    "REPORT_EXPOSED_PII": "FINDING",
    "REPORT_ACTIVE_DATA_FLOW": "FINDING",
    "REPORT_RESTORE_RISK": "FINDING",
    "DISABLE_DATA_FLOW": "REMEDIATION",
    "BLOCK_RESTORE": "REMEDIATION",
    "DELETE_RECORD": "REMEDIATION",
    "REDACT_RECORD": "REMEDIATION",
    "ANONYMIZE_RECORD": "REMEDIATION",
    "VERIFY_RECORD_ABSENT": "VERIFICATION",
    "VERIFY_RECORD_PRESENT": "VERIFICATION",
    "VERIFY_RECORD_REDACTED": "VERIFICATION",
    "VERIFY_RECORD_ANONYMIZED": "VERIFICATION",
    "VERIFY_DATA_FLOW_DISABLED": "VERIFICATION",
    "VERIFY_RESTORE_BLOCKED": "VERIFICATION",
}

# Optional model assistant. Absent configuration is a supported state: the
# deterministic auditor still produces a complete answer.
MODEL_PROVIDER = os.environ.get("AUDIT_MODEL_PROVIDER", "").strip()
MODEL_NAME = os.environ.get("AUDIT_MODEL_NAME", "").strip()
MODEL_API_KEY = os.environ.get("AUDIT_MODEL_API_KEY", "").strip()
MODEL_BASE_URL = os.environ.get("AUDIT_MODEL_BASE_URL", "").strip()
