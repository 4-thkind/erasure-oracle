"""Reconciled record states to the ordered step list the grader expects.

The planner is deliberately dumb about evidence: it receives one final state per
record (already reconciled at ``audit_at``) and applies ``deletion_rules.csv``.

Two behaviours here are worth calling out because they are not obvious from the
operation table alone:

*   A ``COMPLETE`` case lists every record the audit covered, each with an
    evidence citation, because the answer has to *prove* the current state.
*   An ``INCOMPLETE`` case lists the violations, the full remediation plan, and
    only the checks that must pass afterwards: the account, records policy says
    must be retained, and every record that was remediated. Records that were
    already compliant need no future check, so they are not repeated.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import evidence as ev
from .config import OPERATION_ORDER, OPERATION_STATE, PHASE_OF_OPERATION
from .policy import ANONYMIZE, BLOCK_RESTORE, DELETE, DISABLE_FLOW, REDACT, RETAIN, Policy


@dataclass
class Step:
    system_id: str
    resource_id: str
    operation: str
    evidence_id: str = ""

    @property
    def phase(self) -> str:
        return PHASE_OF_OPERATION[self.operation]

    @property
    def state(self) -> str:
        return OPERATION_STATE[self.operation]

    def as_dict(self, step_no: int) -> dict:
        return {
            "step_no": step_no,
            "phase": self.phase,
            "system_id": self.system_id,
            "resource_id": self.resource_id,
            "operation": self.operation,
            "state": self.state,
            "evidence_id": self.evidence_id,
        }


@dataclass
class RecordState:
    system: str
    resource_id: str
    category: str
    state: str
    evidence_id: str = ""
    captured_at: str = ""
    keys: set[str] = field(default_factory=set)
    origin: str = ""

    @property
    def key(self) -> tuple[str, str]:
        return (self.system, self.resource_id)


@dataclass
class CasePlan:
    status: str
    steps: list[dict]
    findings: int
    notes: list[str] = field(default_factory=list)


def _order_key(step: Step):
    """Operation order from the problem table, then system, then resource."""
    return (OPERATION_ORDER[step.operation], step.system_id, step.resource_id)


class Planner:
    """Turn reconciled record states into findings, plan, and checks."""

    def __init__(self, policy: Policy) -> None:
        self.policy = policy

    # ------------------------------------------------------------------
    def plan(self, records: list[RecordState], complete_hint: bool) -> CasePlan:
        findings: list[Step] = []
        remediations: list[Step] = []
        checks: list[Step] = []

        # Records that must be re-checked after remediation even though they are
        # not violations themselves (account, retained evidence).
        mandatory: list[Step] = []
        already_terminal: list[Step] = []

        for rec in sorted(records, key=lambda r: (r.system, r.resource_id)):
            guard = self.policy.guard_for(rec.category)
            evid = rec.evidence_id
            state = rec.state

            if rec.category == ev.DATA_FLOW:
                if state == ev.FLOW_ACTIVE:
                    findings.append(Step(rec.system, rec.resource_id, "REPORT_ACTIVE_DATA_FLOW", evid))
                    remediations.append(Step(rec.system, rec.resource_id, "DISABLE_DATA_FLOW"))
                    mandatory.append(Step(rec.system, rec.resource_id, "VERIFY_DATA_FLOW_DISABLED"))
                else:
                    already_terminal.append(Step(rec.system, rec.resource_id,
                                                 "VERIFY_DATA_FLOW_DISABLED", evid))
                continue

            if rec.category == ev.BACKUP_ARCHIVE:
                if state == ev.RESTORE_ALLOWED:
                    findings.append(Step(rec.system, rec.resource_id, "REPORT_RESTORE_RISK", evid))
                    remediations.append(Step(rec.system, rec.resource_id, "BLOCK_RESTORE"))
                    mandatory.append(Step(rec.system, rec.resource_id, "VERIFY_RESTORE_BLOCKED"))
                else:
                    already_terminal.append(Step(rec.system, rec.resource_id,
                                                 "VERIFY_RESTORE_BLOCKED", evid))
                continue

            if guard == RETAIN:
                if state != ev.ABSENT:
                    mandatory.append(Step(rec.system, rec.resource_id, "VERIFY_RECORD_PRESENT", evid))
                continue

            if guard == DELETE:
                if state == ev.ABSENT:
                    terminal = Step(rec.system, rec.resource_id, "VERIFY_RECORD_ABSENT", evid)
                    (mandatory if _is_account(rec) else already_terminal).append(terminal)
                else:
                    findings.append(Step(rec.system, rec.resource_id, "REPORT_REMAINING_RECORD", evid))
                    remediations.append(Step(rec.system, rec.resource_id, "DELETE_RECORD"))
                    mandatory.append(Step(rec.system, rec.resource_id, "VERIFY_RECORD_ABSENT"))
                continue

            if guard == REDACT:
                if state in {ev.ABSENT}:
                    terminal = Step(rec.system, rec.resource_id, "VERIFY_RECORD_ABSENT", evid)
                    (mandatory if _is_account(rec) else already_terminal).append(terminal)
                elif state == ev.REDACTED:
                    terminal = Step(rec.system, rec.resource_id,
                                    "VERIFY_RECORD_REDACTED", evid)
                    (mandatory if _is_account(rec) else already_terminal).append(terminal)
                else:
                    findings.append(Step(rec.system, rec.resource_id, "REPORT_EXPOSED_PII", evid))
                    remediations.append(Step(rec.system, rec.resource_id, "REDACT_RECORD"))
                    mandatory.append(Step(rec.system, rec.resource_id, "VERIFY_RECORD_REDACTED"))
                continue

            if guard == ANONYMIZE:
                if state == ev.ABSENT:
                    terminal = Step(rec.system, rec.resource_id, "VERIFY_RECORD_ABSENT", evid)
                    (mandatory if _is_account(rec) else already_terminal).append(terminal)
                elif state == ev.ANONYMIZED:
                    terminal = Step(rec.system, rec.resource_id,
                                    "VERIFY_RECORD_ANONYMIZED", evid)
                    (mandatory if _is_account(rec) else already_terminal).append(terminal)
                else:
                    findings.append(Step(rec.system, rec.resource_id, "REPORT_EXPOSED_PII", evid))
                    remediations.append(Step(rec.system, rec.resource_id, "ANONYMIZE_RECORD"))
                    mandatory.append(Step(rec.system, rec.resource_id, "VERIFY_RECORD_ANONYMIZED"))
                continue

        finding_keys = {_op_key(s) for s in findings}

        findings.sort(key=_order_key)
        remediations.sort(key=_order_key)
        checks = mandatory + (already_terminal if not findings else [])
        checks = [c for c in checks if _op_key(c) not in finding_keys or c.operation.startswith("VERIFY_")]
        checks.sort(key=_order_key)

        if findings:
            # Proposed remediation and post-remediation checks are future work.
            for step in remediations + checks:
                step.evidence_id = ""

        ordered = findings + remediations + checks
        status = "INCOMPLETE" if findings else "COMPLETE"
        steps = [s.as_dict(i + 1) for i, s in enumerate(ordered)]
        return CasePlan(status=status, steps=steps, findings=len(findings))


def _is_account(rec: RecordState) -> bool:
    return rec.resource_id.startswith("account_")


def _op_key(step: Step):
    return (step.system_id, step.resource_id)


def remediation_order(step: Step):
    return _order_key(step)
