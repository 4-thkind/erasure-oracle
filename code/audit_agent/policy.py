"""Policy layer: ``deletion_rules.csv`` expressed as executable rules.

The CSV is the participant-facing contract, so it is loaded and honoured at run
time rather than being duplicated as magic strings.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path

from . import evidence as ev

DELETE = "DELETE"
REDACT = "REDACT"
ANONYMIZE = "ANONYMIZE"
RETAIN = "RETAIN"
BLOCK_RESTORE = "BLOCK_RESTORE"
DISABLE_FLOW = "DISABLE_FLOW"

# Guard action implied by each rule row, keyed by rule id. The mapping is the
# mechanical reading of `required_action` plus the category semantics; it is
# kept explicit so the report can justify every decision.
RULE_TO_GUARD = {
    DELETE: DELETE,
    REDACT: REDACT,
    ANONYMIZE: ANONYMIZE,
    RETAIN: RETAIN,
}

# Fallback guard action per category. Used when the CSV is unavailable.
CATEGORY_GUARD = {
    ev.USER_PROFILE: DELETE,
    ev.SECONDARY_IDENTIFIER: DELETE,
    ev.SEARCH_INDEX_ENTRY: DELETE,
    ev.CACHE_ENTRY: DELETE,
    ev.SUPPORT_MESSAGE: REDACT,
    ev.SUPPORT_ATTACHMENT: DELETE,
    ev.ANALYTICS_PROFILE: ANONYMIZE,
    ev.PRODUCT_TELEMETRY: ANONYMIZE,
    ev.USER_EXPORT: DELETE,
    ev.MARKETING_PROFILE: DELETE,
    ev.EMAIL_DELIVERY_LOG: REDACT,
    ev.SECURITY_AUDIT_LOG: RETAIN,
    ev.LEGAL_HOLD_RECORD: RETAIN,
    ev.BACKUP_ARCHIVE: BLOCK_RESTORE,
    ev.ACCOUNT_TOMBSTONE: REDACT,
    ev.DATA_FLOW: DISABLE_FLOW,
}

# Ordering hint: a copy is remediated before the source it was derived from so a
# sync cannot resurrect it during the cleanup window.
DOWNSTREAM_FIRST = {
    "search_service": 0,
    "cache_service": 0,
    "analytics_platform": 1,
    "support_platform": 1,
    "export_service": 1,
    "email_delivery_service": 1,
    "marketing_platform": 1,
    "account_service": 2,
    "identity_service": 3,
    "security_service": 4,
    "legal_service": 4,
}


@dataclass(frozen=True)
class Rule:
    rule_id: str
    category: str
    condition: str
    action: str

    @property
    def guard(self) -> str:
        return RULE_TO_GUARD.get(self.action.upper(), self.action.upper())


class Policy:
    def __init__(self, rules_path: Path | None) -> None:
        self.rules: list[Rule] = []
        if rules_path and rules_path.exists():
            with rules_path.open(encoding="utf-8-sig", newline="") as fh:
                for row in csv.DictReader(fh):
                    self.rules.append(
                        Rule(
                            rule_id=row["rule_id"].strip(),
                            category=row["data_category"].strip().upper(),
                            condition=row["condition"].strip(),
                            action=row["required_action"].strip().upper(),
                        )
                    )
        self.by_category = {r.category: r for r in self.rules}

    def guard_for(self, category: str) -> str:
        rule = self.by_category.get(category)
        if rule:
            return rule.guard
        return CATEGORY_GUARD.get(category, DELETE)

    def rule_id_for(self, category: str) -> str:
        rule = self.by_category.get(category)
        return rule.rule_id if rule else ""

    def is_retained(self, category: str) -> bool:
        return self.guard_for(category) in {RETAIN, BLOCK_RESTORE}

    def compliant(self, category: str, state: str) -> bool:
        """True when an observed state already satisfies the policy.

        Used to decide whether a record discovered late can still be listed: a
        compliant record only needs a check, so it may be named without a
        citation. A violation always needs one, so it cannot.
        """
        if state == ev.ABSENT:
            return True
        if category == ev.DATA_FLOW:
            return state == ev.FLOW_DISABLED
        if category == ev.BACKUP_ARCHIVE:
            return state == ev.RESTORE_BLOCKED
        guard = self.guard_for(category)
        if guard == DELETE:
            return False
        if guard == REDACT:
            return state == ev.REDACTED
        if guard == ANONYMIZE:
            return state == ev.ANONYMIZED
        if guard == RETAIN:
            return state == ev.PRESENT
        return False
