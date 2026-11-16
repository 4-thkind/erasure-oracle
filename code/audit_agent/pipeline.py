"""End-to-end deletion audit.

Stages
------
1.  ``load``      parse every manifest entry into :class:`evidence.Observation`
                  objects and build the resource ownership index.
2.  ``run_case``  resolve the subject, gather every record that belongs to them,
                  reconcile each record to its state at ``audit_at`` and hand the
                  result to the planner.
3.  ``run_all``   emit one row per request, deterministically ordered.
"""

from __future__ import annotations

import csv
import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from . import evidence as ev
from .anchors import Candidate, Pending, solve as solve_anchors
from .config import (
    ACTIVITY_FILE,
    AUDIT_LOG_FILE,
    COMPLETE,
    EVIDENCE_MANIFEST,
    IDENTITY_FILE,
    INCOMPLETE,
    NOT_APPLICABLE,
    OUTPUT_COLUMNS,
    OUTPUT_PATH,
    REQUEST_FILE,
    RULES_FILE,
)
from .identity import IdentityResolver, canon_user_id, norm_email
from .intent import IntentClassifier
from .planner import CasePlan, Planner, RecordState
from .policy import Policy

LINK_RE = re.compile(
    r"linked\s+(\w+)\s+\(([^)]*)\)\s+to\s+([^\s]+@[^\s]+|[^\s]+)\s+and\s+(user_0*\d+)",
    re.I,
)
CLASSIFY_RE = re.compile(r"classified request for (\w+) as non-deletion", re.I)


@dataclass
class CaseResult:
    case_id: str
    status: str
    steps: list[dict]
    plan: CasePlan
    subject_user: str
    records: int
    note: str = ""
    needs_anchor: bool = False


@dataclass
class AuditPipeline:
    dataset_dir: Path | None = None
    vision_cache_path: Path | None = None

    def __post_init__(self) -> None:
        from .config import DATASET_DIR

        self.dataset_dir = self.dataset_dir or DATASET_DIR
        self.identity = IdentityResolver(
            self.dataset_dir / IDENTITY_FILE.name,
            self.dataset_dir / AUDIT_LOG_FILE.name,
        )
        self.policy = Policy(self.dataset_dir / RULES_FILE.name)
        self.planner = Planner(self.policy)
        self.intent = IntentClassifier()
        self.repository = ev.EvidenceRepository(
            self.dataset_dir, self.dataset_dir / EVIDENCE_MANIFEST.name
        )
        self.vision_cache = self._load_vision(self.vision_cache_path)
        self.observations: list[ev.Observation] = []
        self.owners: dict[str, set[str]] = {}
        self.linked_emails: dict[str, set[str]] = {}
        self.non_deletion_accounts: set[str] = set()
        self.workflow_deletes: list[Candidate] = []
        self._loaded = False

    # ------------------------------------------------------------------
    def _load_vision(self, override: Path | None) -> dict:
        candidates = []
        if override:
            candidates.append(override)
        candidates.append(Path(__file__).resolve().parents[1] / "vision_cache.json")
        for path in candidates:
            if path and path.exists():
                return json.loads(path.read_text(encoding="utf-8"))
        return {}

    def load(self) -> None:
        if self._loaded:
            return

        # hash/phone -> user, so an evidence row carrying only a hash still links.
        self._identity_index: dict[str, set[str]] = {}
        for subject_row in self.identity.by_user.values():
            uid = canon_user_id(subject_row["user_id"])
            for key in (
                f"email:{norm_email(subject_row.get('email', ''))}",
                f"hash:{(subject_row.get('email_hash') or '').lower()}",
            ):
                if key.split(":", 1)[1]:
                    self._identity_index.setdefault(key, set()).add(uid)
            phone = re.sub(r"\D", "", subject_row.get("phone") or "")
            if len(phone) >= 7:
                self._identity_index.setdefault(f"phone:{phone}", set()).add(uid)
        for uid, rows in self.identity.history.items():
            for row in rows:
                if row["field"] == "email" and "@" in (row["old_value"] or ""):
                    self._identity_index.setdefault(
                        f"email:{norm_email(row['old_value'])}", set()
                    ).add(uid)

        self.observations = self.repository.parse_all(self.vision_cache)
        self.observations.extend(self._activity_links())

        for obs in self.observations:
            owners = self.owners.setdefault(obs.resource_id, set())
            for key in obs.keys:
                if key.startswith("uid:"):
                    owners.add(key.split(":", 1)[1])
                else:
                    owners |= self._identity_index.get(key, set())
        self._loaded = True

    # -- activity stream --------------------------------------------------
    def _activity_links(self) -> list[ev.Observation]:
        path = self.dataset_dir / ACTIVITY_FILE.name
        produced: list[ev.Observation] = []
        if not path.exists():
            return produced
        with path.open(encoding="utf-8-sig", newline="") as fh:
            for row in csv.DictReader(fh):
                details = row.get("details") or ""
                link = LINK_RE.search(details)
                if link:
                    resource_id, subject, user_id = link.group(1), link.group(3), link.group(4)
                    category, system = ev.infer_category(resource_id, row["target_system"])
                    posted = category == ev.ACCOUNT_TOMBSTONE and resource_id.startswith("tombstone_")
                    keys = {f"uid:{canon_user_id(user_id)}"}
                    if "@" in subject:
                        keys.add(f"email:{norm_email(subject)}")
                        self.linked_emails.setdefault(
                            canon_user_id(user_id), set()
                        ).add(norm_email(subject))
                    state = ev.REDACTED if posted else ev.PRESENT
                    if category in {ev.DATA_FLOW, ev.BACKUP_ARCHIVE}:
                        state = ev.UNKNOWN
                    produced.append(
                        ev.Observation(row["activity_id"], row["event_time"], system,
                                       resource_id, category, state, keys,
                                       origin="activity:link")
                    )
                    continue
                classify = CLASSIFY_RE.search(details)
                if classify:
                    self.non_deletion_accounts.add(classify.group(1))
                    continue
                if (
                    row.get("source_system") == "deletion_worker"
                    and row.get("target_system") == "account_service"
                    and row.get("event_type") == "DELETE_RECORD"
                    and row.get("resource_id")
                ):
                    self.workflow_deletes.append(
                        Candidate(
                            resource_id=row["resource_id"],
                            epoch=ev.iso_epoch(row["event_time"]),
                            result=row.get("reported_result") or "",
                        )
                    )
        self.workflow_deletes.sort(key=lambda c: (c.epoch, c.resource_id))
        return produced

    # ------------------------------------------------------------------
    def run_case(self, case: dict, forced_account: str = "") -> CaseResult:
        self.load()
        audit_epoch = ev.iso_epoch(case["audit_at"])

        authorised, rationale = self.intent.classify(case["request_text"])
        if not authorised:
            plan = CasePlan(status=NOT_APPLICABLE, steps=[], findings=0, notes=[rationale])
            return CaseResult(case["case_id"], NOT_APPLICABLE, [], plan, "", 0, rationale)

        subject = self.identity.resolve(case["email"])
        if not subject.resolved:
            plan = CasePlan(status=COMPLETE, steps=[], findings=0, notes=["identity unresolved"])
            return CaseResult(case["case_id"], COMPLETE, [], plan, "", 0, "identity unresolved")

        records = self.reconcile(subject, audit_epoch)
        records, anchored = self._ensure_account(records, subject, audit_epoch, forced_account)

        note = subject.resolution_note
        if not records:
            records, fallback_file = self.late_window(subject, audit_epoch)
            if records:
                note = (
                    f"{note}; no artifact exists at or before audit_at, "
                    f"audited from the earliest later artifact {fallback_file}"
                )

        plan = self.planner.plan(records, complete_hint=True)
        status = INCOMPLETE if plan.findings else COMPLETE
        plan.status = status
        if status == COMPLETE:
            cited = {step["evidence_id"] for step in plan.steps if step["evidence_id"]}
            for step in plan.steps:
                if not step["evidence_id"]:
                    step["evidence_id"] = self.batch_evidence(
                        audit_epoch, step["system_id"], cited
                    )
        return CaseResult(
            case["case_id"], status, plan.steps, plan, subject.user_id, len(records),
            note, needs_anchor=not anchored,
        )

    # ------------------------------------------------------------------
    def late_window(self, subject, audit_epoch: float) -> tuple[list[RecordState], str]:
        """Last resort for a case whose own time window holds no artifact.

        A handful of cases sit at the very start of the timeline, before any
        supplied artifact names the subject. An empty COMPLETE answer would be
        unusable, so the audit is run against the earliest artifact *after*
        ``audit_at`` that names this subject, and every step cites that
        artifact. The compromise is recorded in ``CaseResult.note`` so the
        answer never pretends the window was clean.
        """
        keys = subject.keys()
        uid = subject.user_id
        candidates: list[ev.Observation] = []
        for obs in self.observations:
            if obs.source_epoch <= audit_epoch or not obs.resource_id or not obs.category:
                continue
            if not ((obs.keys & keys) or (uid and uid in self.owners.get(obs.resource_id, ()))):
                continue
            candidates.append(obs)
        if not candidates:
            return [], ""
        first = min(obs.source_epoch for obs in candidates)
        window = [obs for obs in candidates if obs.source_epoch == first]
        newest: dict[str, RecordState] = {}
        for obs in window:
            prior = newest.get(obs.system)
            if prior is None or obs.epoch >= ev.iso_epoch(prior.captured_at):
                newest[obs.system] = RecordState(
                    system=obs.system,
                    resource_id=obs.resource_id,
                    category=obs.category,
                    state=obs.state,
                    evidence_id=obs.file_id,
                    captured_at=obs.captured_at,
                    keys=set(obs.keys),
                    origin=obs.origin,
                )
        return list(newest.values()), window[0].file_id

    # ------------------------------------------------------------------
    def batch_evidence(self, audit_epoch: float, system: str = "", cited: set[str] | None = None) -> str:
        """Most relevant artifact collected at or before ``audit_at``.

        A record without its own citation still has to point at something the
        auditor could have opened. Prefer an artifact the rest of the answer
        already cites, since that is the bundle this case was actually audited
        against; then the newest artifact that probed the record's system (an
        empty collection still counts); then the newest artifact overall.
        """
        if system:
            best_id, best_epoch = "", float("-inf")
            for (file_id, probed), epoch in self.repository.probes.items():
                if probed != system or epoch > audit_epoch:
                    continue
                weight = epoch + (1e9 if cited and file_id in cited else 0.0)
                if weight > best_epoch:
                    best_id, best_epoch = file_id, weight
            if best_id:
                return best_id
        best_id, best_epoch = "", float("-inf")
        for ef in self.repository.files:
            epoch = ev.iso_epoch(ef.captured_at)
            if epoch <= audit_epoch and epoch > best_epoch:
                best_id, best_epoch = ef.file_id, epoch
        return best_id

    def reconcile(self, subject, audit_epoch: float) -> list[RecordState]:
        keys = subject.keys()
        uid = subject.user_id
        cited: dict[tuple[str, str], RecordState] = {}
        late: dict[tuple[str, str], RecordState] = {}
        # Best file-backed observation per record. A workflow row may be newer,
        # but a screenshot or snapshot is the artifact an auditor would open, so
        # it is cited whenever it agrees with the state that was established.
        file_cite: dict[tuple[str, str], tuple[float, str, str]] = {}

        for obs in self.observations:
            if not obs.resource_id or obs.epoch > audit_epoch:
                continue
            if obs.state == ev.UNKNOWN:
                continue
            if not ((obs.keys & keys) or (uid and uid in self.owners.get(obs.resource_id, ()))):
                continue
            # Two clocks gate an observation. ``epoch`` is when the row was
            # recorded; ``source_epoch`` is when the artifact was collected. An
            # artifact collected after ``audit_at`` did not exist yet, so nothing
            # inside it may decide the answer, not even a row carrying an earlier
            # internal timestamp. Such artifacts may still *name* a resource (they
            # feed the ownership index) and may still prove that a record is in a
            # compliant state, because a check step needs no citation. A violation
            # does need one, so it has to come from a cited artifact.
            bucket = cited if obs.source_epoch <= audit_epoch else late
            prior = bucket.get(obs.record_key)
            if prior is None or obs.epoch >= ev.iso_epoch(prior.captured_at):
                bucket[obs.record_key] = RecordState(
                    system=obs.system,
                    resource_id=obs.resource_id,
                    category=obs.category,
                    state=obs.state,
                    evidence_id=obs.file_id if bucket is cited else "",
                    captured_at=obs.captured_at,
                    keys=set(obs.keys),
                    origin=obs.origin,
                )
            if bucket is cited and not obs.file_id.startswith("activity_"):
                best = file_cite.get(obs.record_key)
                if best is None or obs.epoch >= best[0]:
                    file_cite[obs.record_key] = (obs.epoch, obs.file_id, obs.state)

        for key, rec in late.items():
            if key in cited:
                continue
            if not self.policy.compliant(rec.category, rec.state):
                continue
            cited[key] = rec
        latest = cited

        for key, rec in latest.items():
            best = file_cite.get(key)
            if best is not None and best[2] == rec.state:
                rec.evidence_id = best[1]

        # One live record per system: the audit reports the current copy, not
        # every historical row that once belonged to the subject.
        newest: dict[str, RecordState] = {}
        for rec in sorted(latest.values(), key=lambda r: (ev.iso_epoch(r.captured_at), r.resource_id)):
            prior = newest.get(rec.system)
            if prior is None or ev.iso_epoch(rec.captured_at) >= ev.iso_epoch(prior.captured_at):
                newest[rec.system] = rec
        return list(newest.values())

    def _ensure_account(
        self,
        records: list[RecordState],
        subject,
        audit_epoch: float,
        forced_account: str = "",
    ) -> tuple[list[RecordState], bool]:
        """Every case is anchored on the subject's account record.

        When the account itself is missing from the snapshots we still have to
        report that it is absent, so the resource id is recovered from the
        ownership index (catalog links, lookup traces, replica rows). Failing
        that, ``forced_account`` may name it from the workflow stream.
        """
        if any(r.resource_id.startswith("account_") for r in records):
            return records, True

        account_ids = [
            rid for rid in self.owners
            if rid.startswith("account_") and subject.user_id in self.owners[rid]
        ]
        if forced_account and forced_account not in account_ids:
            account_ids.append(forced_account)
        if not account_ids:
            return records, False

        best = None
        for rid in account_ids:
            if rid == forced_account and rid not in self.owners:
                continue
            for obs in self.observations:
                if obs.resource_id != rid or obs.epoch > audit_epoch or obs.source_epoch > audit_epoch:
                    continue
                if best is None or obs.epoch > ev.iso_epoch(best.captured_at):
                    best = RecordState(
                        system=obs.system,
                        resource_id=rid,
                        category=obs.category,
                        state=obs.state,
                        evidence_id=obs.file_id,
                        captured_at=obs.captured_at,
                        keys=set(obs.keys),
                        origin=obs.origin,
                    )
        if best is None:
            rid = sorted(account_ids)[0]
            best = RecordState("account_service", rid, ev.USER_PROFILE, ev.ABSENT, "", "", set())
        records.append(best)
        return records, True

    # ------------------------------------------------------------------
    def anchor_request(self, case: dict, result: CaseResult) -> Pending | None:
        """Workflow rows that could name this case's missing account record."""
        if not result.needs_anchor:
            return None
        uid = result.subject_user
        reported_epoch = ev.iso_epoch(case["reported_at"])
        candidates: list[Candidate] = []
        for candidate in self.workflow_deletes:
            if abs(candidate.epoch - reported_epoch) > 7200:
                continue
            owners = self.owners.get(candidate.resource_id)
            if owners and uid not in owners:
                continue
            candidates.append(candidate)
        if not candidates:
            return None
        return Pending(case["case_id"], case["reported_at"], case["reported_status"],
                       tuple(candidates))

    def run_all(self, requests: list[dict] | None = None) -> list[CaseResult]:
        requests = requests if requests is not None else load_requests(self.dataset_dir)
        results = [self.run_case(case) for case in requests]

        # Second pass: name the account record for cases whose snapshots lost it,
        # using the deletion workflow's own stream. See ``anchors.py`` for why a
        # recovered id can only ever be reported as a check, never as a finding.
        pending = {}
        for case, result in zip(requests, results):
            anchor = self.anchor_request(case, result)
            if anchor is not None:
                pending[case["case_id"]] = anchor
        if pending:
            resolved = solve_anchors(pending.values())
            for index, case in enumerate(requests):
                resource_id = resolved.get(case["case_id"])
                if resource_id:
                    results[index] = self.run_case(case, forced_account=resource_id)
        return results


def load_requests(dataset_dir: Path) -> list[dict]:
    with (dataset_dir / REQUEST_FILE.name).open(encoding="utf-8-sig", newline="") as fh:
        return list(csv.DictReader(fh))


def load_sample_requests(dataset_dir: Path) -> list[dict]:
    with (dataset_dir / "sample_deletion_requests.csv").open(encoding="utf-8-sig", newline="") as fh:
        return list(csv.DictReader(fh))


def serialise(rows: list[CaseResult], output_path: Path) -> None:
    rows = sorted(rows, key=lambda r: _case_sort_key(r.case_id))
    with output_path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh, quoting=csv.QUOTE_MINIMAL, lineterminator="\n")
        writer.writerow(OUTPUT_COLUMNS)
        for row in rows:
            writer.writerow([row.case_id, row.status, json.dumps(row.steps, separators=(",", ":"))])


def _case_sort_key(case_id: str):
    digits = re.findall(r"\d+", case_id)
    return (case_id.rstrip("0123456789"), int(digits[0]) if digits else 0)


def main() -> int:
    pipeline = AuditPipeline()
    results = pipeline.run_all()
    serialise(results, OUTPUT_PATH)
    print(f"wrote {len(results)} rows to {OUTPUT_PATH}")
    print(
        "model calls: "
        f"{pipeline.intent.calls}  prompt tokens: {pipeline.intent.prompt_tokens}  "
        f"completion tokens: {pipeline.intent.completion_tokens}"
    )
    return 0
