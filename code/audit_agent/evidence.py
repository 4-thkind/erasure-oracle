"""Evidence normalisation.

Every supplied artifact is reduced to a stream of :class:`Observation` objects:

    (evidence file, capture time, system, resource, policy category, state, identity keys)

Only facts are extracted. No verdicts are attached here; the planner applies
``deletion_rules.csv`` on top of these observations. The same record can be
observed more than once (primary database, replica, read-back trace, export),
which is exactly how replication drift is discovered.
"""

from __future__ import annotations

import csv
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from .identity import canon_user_id, norm_email, norm_hash, norm_name, norm_phone

# ---------------------------------------------------------------- vocabulary

ABSENT = "ABSENT"
PRESENT = "PRESENT"
REDACTED = "REDACTED"
ANONYMIZED = "ANONYMIZED"
FLOW_ACTIVE = "FLOW_ACTIVE"
FLOW_DISABLED = "FLOW_DISABLED"
RESTORE_ALLOWED = "RESTORE_ALLOWED"
RESTORE_BLOCKED = "RESTORE_BLOCKED"
# A row can tie a resource to a person without saying anything about the state
# of that resource. Activity link rows for connectors and backups are exactly
# that: they prove ownership, not whether a flow runs or a restore is possible.
UNKNOWN = "UNKNOWN"

# data categories from deletion_rules.csv
USER_PROFILE = "USER_PROFILE"
SECONDARY_IDENTIFIER = "SECONDARY_IDENTIFIER"
SEARCH_INDEX_ENTRY = "SEARCH_INDEX_ENTRY"
CACHE_ENTRY = "CACHE_ENTRY"
SUPPORT_MESSAGE = "SUPPORT_MESSAGE"
SUPPORT_ATTACHMENT = "SUPPORT_ATTACHMENT"
ANALYTICS_PROFILE = "ANALYTICS_PROFILE"
PRODUCT_TELEMETRY = "PRODUCT_TELEMETRY"
USER_EXPORT = "USER_EXPORT"
MARKETING_PROFILE = "MARKETING_PROFILE"
EMAIL_DELIVERY_LOG = "EMAIL_DELIVERY_LOG"
SECURITY_AUDIT_LOG = "SECURITY_AUDIT_LOG"
LEGAL_HOLD_RECORD = "LEGAL_HOLD_RECORD"
BACKUP_ARCHIVE = "BACKUP_ARCHIVE"
ACCOUNT_TOMBSTONE = "ACCOUNT_TOMBSTONE"
DATA_FLOW = "DATA_FLOW"

PREFIX_CATEGORY = {
    "account": (USER_PROFILE, "account_service"),
    "search": (SEARCH_INDEX_ENTRY, "search_service"),
    "analytics": (ANALYTICS_PROFILE, "analytics_platform"),
    "support": (SUPPORT_MESSAGE, "support_platform"),
    "export": (USER_EXPORT, "export_service"),
    "data_flow": (DATA_FLOW, "integration_service"),
    "backup": (BACKUP_ARCHIVE, "backup_service"),
    "audit_record": (SECURITY_AUDIT_LOG, "security_service"),
    "tombstone": (ACCOUNT_TOMBSTONE, "identity_service"),
    "cache": (CACHE_ENTRY, "cache_service"),
    "email_delivery": (EMAIL_DELIVERY_LOG, "email_delivery_service"),
    "marketing": (MARKETING_PROFILE, "marketing_platform"),
    "legal_hold": (LEGAL_HOLD_RECORD, "legal_service"),
}

SYSTEM_CATEGORY = {
    "account_service": USER_PROFILE,
    "search_service": SEARCH_INDEX_ENTRY,
    "analytics_platform": ANALYTICS_PROFILE,
    "support_platform": SUPPORT_MESSAGE,
    "export_service": USER_EXPORT,
    "integration_service": DATA_FLOW,
    "backup_service": BACKUP_ARCHIVE,
    "security_service": SECURITY_AUDIT_LOG,
    "identity_service": ACCOUNT_TOMBSTONE,
    "cache_service": CACHE_ENTRY,
    "email_delivery_service": EMAIL_DELIVERY_LOG,
    "marketing_platform": MARKETING_PROFILE,
    "legal_service": LEGAL_HOLD_RECORD,
}

# Longest first: ``audit_record_`` has to win over ``audit_``-like short forms.
PREFIX_ORDER = sorted(PREFIX_CATEGORY, key=len, reverse=True)

# `result`/status vocabulary used by the compact handover style tables.
RESULT_STATE = {
    "FOUND": PRESENT,
    "PRESENT": PRESENT,
    "IDENTIFIABLE": PRESENT,
    "NOT_FOUND": ABSENT,
    "ABSENT": ABSENT,
    "MISSING": ABSENT,
    "DELETED": ABSENT,
    "REDACTED": REDACTED,
    "ANONYMIZED": ANONYMIZED,
    "ACTIVE": FLOW_ACTIVE,
    "ENABLED": FLOW_ACTIVE,
    "DISABLED": FLOW_DISABLED,
    "BLOCKED": RESTORE_BLOCKED,
    "RESTORE_BLOCKED": RESTORE_BLOCKED,
    "RESTORE_ALLOWED": RESTORE_ALLOWED,
}

IDENTITY_FIELD_ALIASES = {
    "email": "email",
    "customer_email": "email",
    "owner_email": "email",
    "requester_email": "email",
    "contact_email": "email",
    "subject_email": "email",
    "lookup_key": "identifier",
    "match_key": "identifier",
    "correlation_key": "identifier",
    "scan_key": "identifier",
    "subject_key": "identifier",
    "subject_reference": "subject",
    "customer_reference": "user",
    "user_id": "user",
    "subject_ref": "user",
    "phone": "phone",
    "owner_phone": "phone",
    "requester_phone": "phone",
    "customer_phone": "phone",
    "email_hash": "hash",
    "name": "name",
    "full_name": "name",
    "display_name": "name",
    "requester_name": "name",
}

PII_IDENTITY_FIELDS = ("name", "email", "phone", "email_hash")


class ObservationError(RuntimeError):
    pass


@dataclass
class Observation:
    file_id: str
    captured_at: str
    system: str
    resource_id: str
    category: str
    state: str
    keys: set[str] = field(default_factory=set)
    origin: str = ""
    note: str = ""
    source_captured_at: str = ""

    @property
    def epoch(self) -> float:
        return iso_epoch(self.captured_at)

    @property
    def source_epoch(self) -> float:
        return iso_epoch(self.source_captured_at) if self.source_captured_at else self.epoch

    @property
    def record_key(self) -> tuple[str, str]:
        return (self.system, self.resource_id)


def iso_epoch(value: str) -> float:
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


def add_identity(keys: set[str], field_name: str, value: str) -> None:
    """Turn a raw field value into a normalised, collision-safe match key."""
    if value in (None, ""):
        return
    value = str(value).strip()
    if not value:
        return
    kind = IDENTITY_FIELD_ALIASES.get(field_name, field_name)
    if kind == "email":
        if "@" in value:
            keys.add(f"email:{norm_email(value)}")
        else:
            # correlation keys are occasionally opaque hashes
            if re.fullmatch(r"[0-9a-f]{64}", value.lower()):
                keys.add(f"hash:{norm_hash(value)}")
    elif kind in {"user", "subject", "identifier"}:
        if "@" in value:
            keys.add(f"email:{norm_email(value)}")
        elif re.fullmatch(r"user_0*\d+", value.strip()):
            keys.add(f"uid:{canon_user_id(value)}")
        elif re.fullmatch(r"[0-9a-f]{64}", value.strip().lower()):
            keys.add(f"hash:{norm_hash(value)}")
        elif kind == "identifier":
            return  # opaque ids such as trace handles are not identities
        else:
            keys.add(f"name:{norm_name(value)}")
    elif kind == "phone":
        digits = norm_phone(value)
        if len(digits) >= 7:
            keys.add(f"phone:{digits}")
    elif kind == "hash":
        keys.add(f"hash:{norm_hash(value)}")
    elif kind == "name":
        keys.add(f"name:{norm_name(value)}")


def identity_keys_from_record(record: dict, extra_fields=()) -> set[str]:
    """Collect identity keys from a record, including nested payloads.

    Snapshot rows wrap the interesting fields one or two levels down
    (``{"document": {...}}``, ``{"profile": {...}}``), so the walk has to
    recurse instead of only reading the top level.
    """
    keys: set[str] = set()
    aliases = set(IDENTITY_FIELD_ALIASES) | set(extra_fields)

    def walk(node, depth: int) -> None:
        if depth > 3:
            return
        if isinstance(node, dict):
            for field_name, value in node.items():
                if field_name in aliases:
                    add_identity(keys, field_name, value)
                elif isinstance(value, (dict, list)):
                    walk(value, depth + 1)
        elif isinstance(node, list):
            for item in node:
                walk(item, depth + 1)

    walk(record, 0)
    return keys


def has_pii(keys: set[str]) -> bool:
    return any(k.split(":", 1)[0] in {"email", "phone", "hash", "name"} for k in keys)


def has_direct_pii(keys: set[str]) -> bool:
    return any(k.startswith(("email:", "phone:", "hash:", "name:")) for k in keys)


def _prefix_of(resource_id: str) -> str:
    """Longest known prefix, so ``audit_record_4`` is not read as ``audit``.

    Splitting on the first underscore is wrong for every multi-word prefix in
    ``PREFIX_CATEGORY`` (``audit_record``, ``data_flow``, ``email_delivery``,
    ``legal_hold``). Those records only classified correctly when the artifact
    happened to pass a system name; a PDF page or a header-less row did not.
    """
    rid = (resource_id or "").lower()
    for prefix in PREFIX_ORDER:
        if rid.startswith(prefix + "_"):
            return prefix
    return ""


def infer_category(resource_id: str, system: str, declared: str = "") -> tuple[str, str]:
    if declared and declared.upper() in set(SYSTEM_CATEGORY.values()) | {SUPPORT_ATTACHMENT, SECONDARY_IDENTIFIER, PRODUCT_TELEMETRY, DATA_FLOW}:
        return declared.upper(), system or SYSTEM_CATEGORY.get(system, "")
    prefix = _prefix_of(resource_id)
    if prefix in PREFIX_CATEGORY:
        cat, sysname = PREFIX_CATEGORY[prefix]
        return cat, system or sysname
    if system in SYSTEM_CATEGORY:
        return SYSTEM_CATEGORY[system], system
    return "", system


def normalise_state(raw: str, category: str) -> str:
    state = RESULT_STATE.get((raw or "").strip().upper(), (raw or "").strip().upper())
    if state == FLOW_ACTIVE and category == BACKUP_ARCHIVE:
        return RESTORE_ALLOWED
    if state == PRESENT and category == BACKUP_ARCHIVE:
        return RESTORE_ALLOWED
    return state


# ------------------------------------------------------------------ KV logs

KV_RE = re.compile(r'([A-Za-z_][A-Za-z0-9_]*)=("([^"]*)"|\'([^\']*)\'|([^\s,\]]+))')


def parse_kv_line(line: str) -> tuple[dict, dict]:
    """Split a log line into unkeyed context and key=value pairs.

    Supports every dialect present in the corpus: ``k=v``, ``k="v"``,
    ``"k":"v"`` (JSON-ish), ``k: v`` (bracket logs) and the escaped variant
    ``event=\\"x\\"`` used by cloud runtime exports.
    """
    line = line.replace('\\"', '"').replace("\\'", "'")
    fields: dict[str, str] = {}
    for m in KV_RE.finditer(line):
        value = m.group(3) if m.group(3) is not None else (
            m.group(4) if m.group(4) is not None else m.group(5)
        )
        fields[m.group(1).strip().lower()] = (value or "").strip()

    # JSON-ish dialect: "k":"v"
    for m in re.finditer(r'"([A-Za-z_][A-Za-z0-9_]*)":\s*"([^"]*)"', line):
        fields.setdefault(m.group(1).lower(), m.group(2))
    # bracket dialect: k: "v"
    for m in re.finditer(r'([A-Za-z_][A-Za-z0-9_]*):\s*"([^"]*)"', line):
        fields.setdefault(m.group(1).lower(), m.group(2))
    return fields, {}


TIMESTAMP_RE = re.compile(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)")


def line_timestamp(line: str) -> str:
    m = TIMESTAMP_RE.search(line)
    if not m:
        return ""
    value = m.group(1)
    if not value.endswith("Z"):
        value += "Z"
    return value


# ---------------------------------------------------------------- SQL parser

CREATE_RE = re.compile(r"CREATE TABLE (\w+)\s*\((.*?)\);", re.S)
INSERT_RE = re.compile(r"INSERT INTO [\"']?(\w+)[\"']?\s+VALUES\s*\((.*?)\);", re.S)


def split_sql_values(blob: str) -> list[str]:
    out: list[str] = []
    buf: list[str] = []
    in_str = False
    depth = 0
    i = 0
    while i < len(blob):
        ch = blob[i]
        if in_str:
            if ch == "'" and i + 1 < len(blob) and blob[i + 1] == "'":
                buf.append("'")
                i += 2
                continue
            if ch == "'":
                in_str = False
            else:
                buf.append(ch)
            i += 1
            continue
        if ch == "'":
            in_str = True
            i += 1
            continue
        if ch in "[{":
            depth += 1
        elif ch in "]}":
            depth -= 1
        if ch == "," and depth == 0:
            out.append("".join(buf).strip())
            buf = []
            i += 1
            continue
        buf.append(ch)
        i += 1
    if buf:
        out.append("".join(buf).strip())
    return out


def parse_sql(text: str) -> list[dict]:
    """Return [{table, columns, values}] for every INSERT statement."""
    columns: dict[str, list[str]] = {}
    for m in CREATE_RE.finditer(text):
        table = m.group(1)
        cols: list[str] = []
        for definition in split_sql_values(m.group(2)):
            name = re.match(r"\s*([A-Za-z_][A-Za-z0-9_]*)", definition)
            if name and name.group(1).upper() not in {
                "PRIMARY", "UNIQUE", "FOREIGN", "CHECK", "CONSTRAINT", "KEY",
            }:
                cols.append(name.group(1))
        columns[table] = cols

    rows: list[dict] = []
    for m in INSERT_RE.finditer(text):
        table = m.group(1)
        cols = columns.get(table, [])
        values = split_sql_values(m.group(2))
        if not cols or len(cols) != len(values):
            continue
        row = {"__table__": table}
        for col, val in zip(cols, values):
            if val.upper() == "NULL":
                row[col] = None
            else:
                row[col] = val
        rows.append(row)
    return rows


# ------------------------------------------------------- evidence repository

SNAPSHOT_TIME_RE = re.compile(r"Captured at:\s*(\S+)")


@dataclass
class EvidenceFile:
    file_id: str
    path: Path
    rel_path: str
    origin: str
    captured_at: str


class EvidenceRepository:
    def __init__(self, dataset_dir: Path, manifest_path: Path) -> None:
        self.dataset_dir = dataset_dir
        self.files: list[EvidenceFile] = []
        with manifest_path.open(encoding="utf-8-sig", newline="") as fh:
            for row in csv.DictReader(fh):
                rel = row["file_path"]
                self.files.append(
                    EvidenceFile(
                        file_id=row["file_id"],
                        path=dataset_dir / rel,
                        rel_path=rel,
                        origin=row["origin"],
                        captured_at=row["captured_at"],
                    )
                )
        self.files.sort(key=lambda f: f.file_id)
        # (file_id, system) -> latest instant at which that file probed that
        # system. Empty collections count: an empty snapshot of
        # ``account_service`` still proves that nothing was there.
        self.probes: dict[tuple[str, str], float] = {}

    def probe(self, file_id: str, system: str, epoch: float) -> None:
        key = (file_id, system)
        if epoch > self.probes.get(key, float("-inf")):
            self.probes[key] = epoch

    def parse_all(self, vision_cache: dict | None = None) -> list[Observation]:
        out: list[Observation] = []
        for ef in self.files:
            try:
                produced = self._parse_file(ef, vision_cache or {})
            except Exception as exc:  # pragma: no cover - defensive
                raise ObservationError(f"failed to parse {ef.file_id} ({ef.rel_path})") from exc
            # The manifest capture time gates every observation: an artifact
            # collected after the case's audit_at cannot decide that case, even
            # when the individual log line predates it.
            for obs in produced:
                obs.source_captured_at = ef.captured_at
                self.probe(ef.file_id, obs.system, obs.epoch)
            out.extend(produced)
        return out

    # -- dispatch ---------------------------------------------------------
    def _parse_file(self, ef: EvidenceFile, vision_cache: dict) -> list[Observation]:
        suffix = ef.path.suffix.lower()
        if suffix == ".sql":
            return self._parse_sql_file(ef)
        if suffix == ".json":
            return self._parse_json_file(ef)
        if suffix == ".log":
            return self._parse_log_file(ef)
        if suffix == ".txt":
            return self._parse_text_file(ef)
        if suffix == ".pdf":
            return self._parse_pdf_file(ef)
        if suffix in {".png", ".jpg", ".jpeg"}:
            return self._parse_image_file(ef, vision_cache)
        return []

    # -- SQL --------------------------------------------------------------
    def _parse_sql_file(self, ef: EvidenceFile) -> list[Observation]:
        text = ef.path.read_text(encoding="utf-8", errors="ignore")
        captured = ef.captured_at
        m = SNAPSHOT_TIME_RE.search(text)
        if m:
            captured = m.group(1)
        obs: list[Observation] = []
        for table in parse_sql(text):
            row = dict(table)
            name = row.pop("__table__")
            obs.extend(self._rows_to_observations(ef, captured, name, row))
        return obs

    def _rows_to_observations(self, ef: EvidenceFile, captured: str, table: str, row: dict) -> list[Observation]:
        out: list[Observation] = []

        # Replica / primary documents: nested record_json payload.
        if "record_json" in row and row["record_json"]:
            try:
                payload = json.loads(row["record_json"])
            except json.JSONDecodeError:
                payload = {}
            origin = row.get("origin_system") or ""
            resource_id = row.get("resource_id") or payload.get("resource_id") or ""
            category, system = infer_category(resource_id, origin)
            keys = identity_keys_from_record(payload)
            keys |= identity_keys_from_record(row)
            if "subject_reference" in payload:
                add_identity(keys, "subject_reference", payload["subject_reference"])
            state = self._document_state(category, payload, keys)
            out.append(Observation(ef.file_id, captured, system, resource_id, category, state, keys,
                                   origin=f"sql:{table}"))
            return out

        resource_id = row.get("resource_id") or ""
        if not resource_id:
            return out

        declared = ""
        for key in ("record_type", "data_category", "category"):
            if row.get(key):
                declared = str(row[key]).upper()
                break

        # Profile tables expose a user_id column with a real value.
        category, system = infer_category(resource_id, "", declared)
        if table.startswith("customer_profiles"):
            system = "account_service"
            category = USER_PROFILE
        elif table.startswith("search_documents"):
            system = "search_service"
            category = SEARCH_INDEX_ENTRY
        elif table.startswith("support_records"):
            system = "support_platform"
            category = SUPPORT_MESSAGE
        elif table.startswith("customer_exports"):
            system = "export_service"
            category = USER_EXPORT
        elif table.startswith("connector_subscriptions"):
            system = "integration_service"
            category = DATA_FLOW
        elif table.startswith("backup_restore_entries"):
            system = "backup_service"
            category = BACKUP_ARCHIVE
        elif table.startswith("security_audit_records"):
            system = "security_service"
            category = SECURITY_AUDIT_LOG
        elif table.startswith("customer_analytics_profiles"):
            system = "analytics_platform"
            category = ANALYTICS_PROFILE
        elif table.startswith("customer_search_documents"):
            system = "search_service"
            category = SEARCH_INDEX_ENTRY

        keys = identity_keys_from_record(row)
        state = self._structured_state(category, row, keys)
        out.append(Observation(ef.file_id, captured, system, resource_id, category, state, keys,
                               origin=f"sql:{table}"))
        return out

    def _document_state(self, category: str, payload: dict, keys: set[str]) -> str:
        if category == DATA_FLOW:
            enabled = payload.get("enabled")
            if enabled is None and "restore_allowed" in payload:
                return RESTORE_ALLOWED if _truthy(payload["restore_allowed"]) else RESTORE_BLOCKED
            return FLOW_ACTIVE if _truthy(enabled) else FLOW_DISABLED
        if category == BACKUP_ARCHIVE:
            return RESTORE_ALLOWED if _truthy(payload.get("restore_allowed")) else RESTORE_BLOCKED
        if category == ACCOUNT_TOMBSTONE:
            return REDACTED if not has_direct_pii(keys) else PRESENT
        if category in {ANALYTICS_PROFILE, PRODUCT_TELEMETRY}:
            return PRESENT if has_direct_pii(keys) else ANONYMIZED
        if category in {SECURITY_AUDIT_LOG, LEGAL_HOLD_RECORD}:
            return PRESENT
        return PRESENT if has_direct_pii(keys) else ABSENT

    def _structured_state(self, category: str, row: dict, keys: set[str]) -> str:
        if category == DATA_FLOW:
            return FLOW_ACTIVE if _truthy(row.get("enabled")) else FLOW_DISABLED
        if category == BACKUP_ARCHIVE:
            return RESTORE_ALLOWED if _truthy(row.get("restore_allowed")) else RESTORE_BLOCKED
        if category == ACCOUNT_TOMBSTONE:
            return REDACTED if not has_direct_pii(keys) else PRESENT
        if category in {ANALYTICS_PROFILE, PRODUCT_TELEMETRY}:
            return PRESENT if has_direct_pii(keys) else ANONYMIZED
        if category in {SECURITY_AUDIT_LOG, LEGAL_HOLD_RECORD}:
            return PRESENT
        if category == SUPPORT_MESSAGE:
            return PRESENT if has_direct_pii(keys) else REDACTED
        return PRESENT if has_direct_pii(keys) else ABSENT

    # -- JSON -------------------------------------------------------------
    def _parse_json_file(self, ef: EvidenceFile) -> list[Observation]:
        data = json.loads(ef.path.read_text(encoding="utf-8"))
        captured = data.get("captured_at") or data.get("exported_at") or ef.captured_at
        obs: list[Observation] = []

        # records_assurance_service snapshot bundles
        if isinstance(data.get("snapshots"), list):
            for snap in data["snapshots"]:
                store = snap.get("data_store", "")
                ts = snap.get("captured_at") or captured
                if store:
                    self.probe(ef.file_id, store, iso_epoch(ts))
                for rec in snap.get("records", []):
                    category, system = infer_category(rec.get("resource_id", ""), store)
                    if (snap.get("collection") or "").startswith("deleted_customer_references"):
                        category, system = ACCOUNT_TOMBSTONE, "identity_service"
                    keys = identity_keys_from_record(rec)
                    add_identity(keys, "subject_reference", rec.get("subject_reference", ""))
                    state = self._structured_state(category, rec, keys)
                    obs.append(Observation(ef.file_id, ts, system, rec.get("resource_id", ""),
                                           category, state, keys, origin="json:snapshot"))
            return obs

        # service_resource_export:{...service_exports...}
        if isinstance(data.get("service_exports"), dict):
            return self._parse_service_export(ef, captured, data["service_exports"])

        # flat record lists (connector configs, audit ledger, export manifest,
        # analytics report, export jobs)
        records = data.get("records")
        if isinstance(records, list):
            for rec in records:
                if not isinstance(rec, dict):
                    continue
                obs.extend(self._parse_flat_json_record(ef, captured, rec))
            return obs
        return obs

    def _parse_service_export(self, ef: EvidenceFile, captured: str, exports: dict) -> list[Observation]:
        obs: list[Observation] = []
        for system, payload in exports.items():
            self.probe(ef.file_id, system, iso_epoch(captured))
            for collection, records in payload.items():
                if not isinstance(records, list):
                    continue
                for rec in records:
                    if not isinstance(rec, dict):
                        continue
                    ts = rec.get("observed_at") or captured
                    resource_id = rec.get("resource_id", "")
                    category, sysname = infer_category(resource_id, system)
                    keys: set[str] = set()
                    state = PRESENT
                    if collection == "profile_lookups":
                        profile = rec.get("profile") or {}
                        keys = identity_keys_from_record(profile)
                        status = rec.get("status_code")
                        state = ABSENT if (not profile or status == 404) else PRESENT
                    elif collection == "restore_entries":
                        keys = identity_keys_from_record(rec)
                        state = RESTORE_ALLOWED if _truthy(rec.get("restore_allowed")) else RESTORE_BLOCKED
                    elif collection == "connectors":
                        keys = identity_keys_from_record(rec)
                        state = FLOW_ACTIVE if _truthy(rec.get("enabled")) else FLOW_DISABLED
                    elif collection == "index_queries":
                        hits = (rec.get("hits") or {}).get("documents") or []
                        for doc in hits:
                            keys |= identity_keys_from_record(doc)
                            if doc.get("resource_id"):
                                resource_id = doc["resource_id"]
                        add_identity(keys, "match_key", rec.get("query", ""))
                        state = PRESENT if has_direct_pii(keys) else ABSENT
                    elif collection == "audit_records":
                        add_identity(keys, "subject_reference", rec.get("subject_reference", ""))
                        state = PRESENT
                    elif collection == "tickets":
                        keys = identity_keys_from_record(rec)
                        state = PRESENT if has_direct_pii(keys) else REDACTED
                    elif collection == "profiles":
                        keys = identity_keys_from_record(rec)
                        state = PRESENT if has_direct_pii(keys) else ANONYMIZED
                    elif collection == "exports":
                        keys = identity_keys_from_record(rec)
                        state = PRESENT if has_direct_pii(keys) else ABSENT
                    else:
                        keys = identity_keys_from_record(rec)
                        add_identity(keys, "subject_reference", rec.get("subject_reference", ""))
                    if not resource_id:
                        continue
                    obs.append(Observation(ef.file_id, ts, sysname, resource_id, category, state, keys,
                                           origin=f"json:export:{collection}"))
        return obs

    def _parse_flat_json_record(self, ef: EvidenceFile, captured: str, rec: dict) -> list[Observation]:
        resource_id = rec.get("resource_id", "")
        if not resource_id:
            return []
        declared = (rec.get("record_type") or rec.get("data_category") or "").upper()
        system = rec.get("system", "")
        category, sysname = infer_category(resource_id, system, declared)
        keys = identity_keys_from_record(rec)

        result = rec.get("result") or rec.get("status")
        if result:
            state = normalise_state(result, category)
        elif category == ANALYTICS_PROFILE:
            state = PRESENT if has_direct_pii(keys) else ANONYMIZED
        elif category == USER_EXPORT:
            available = rec.get("download_available")
            state = PRESENT if (available is None or _truthy(available)) else ABSENT
        elif category == ACCOUNT_TOMBSTONE:
            state = PRESENT if has_direct_pii(keys) else REDACTED
        else:
            state = PRESENT if has_direct_pii(keys) else ABSENT
        ts = rec.get("recorded_at") or rec.get("created_at") or rec.get("observed_at") or captured
        return [Observation(ef.file_id, ts, sysname, resource_id, category, state, keys,
                            origin="json:record")]

    # -- logs -------------------------------------------------------------
    def _parse_log_file(self, ef: EvidenceFile) -> list[Observation]:
        text = ef.path.read_text(encoding="utf-8", errors="ignore")
        if re.search(r"event=record_lookup", text):
            return self._parse_record_lookup_log(ef, text)
        if "resource_lookup_trace" in ef.rel_path or "readback" in ef.origin:
            return self._parse_readback_log(ef, text)
        if "support_replica" in ef.rel_path:
            return self._parse_support_replica_log(ef, text)
        return self._parse_trace_log(ef, text)

    def _parse_record_lookup_log(self, ef: EvidenceFile, text: str) -> list[Observation]:
        obs: list[Observation] = []
        for line in text.splitlines():
            if "record_lookup" not in line:
                continue
            fields, _ = parse_kv_line(line)
            resource_id = fields.get("resource_id", "")
            if not resource_id:
                continue
            ts = line_timestamp(line) or ef.captured_at
            declared = (fields.get("record_type") or "").upper()
            system = fields.get("system", "")
            category, sysname = infer_category(resource_id, system, declared)
            keys = identity_keys_from_record(fields)
            state = normalise_state(fields.get("result", ""), category)
            if category == BACKUP_ARCHIVE:
                state = RESTORE_ALLOWED if state in {PRESENT, FLOW_ACTIVE} else RESTORE_BLOCKED
            elif category == DATA_FLOW:
                state = FLOW_ACTIVE if state in {PRESENT, FLOW_ACTIVE} else FLOW_DISABLED
            obs.append(Observation(ef.file_id, ts, sysname, resource_id, category, state, keys,
                                   origin="log:record_lookup"))
        return obs

    def _parse_readback_log(self, ef: EvidenceFile, text: str) -> list[Observation]:
        obs: list[Observation] = []
        pending: dict[str, set[str]] = {}
        for line in text.splitlines():
            fields, _ = parse_kv_line(line)
            event = fields.get("event", "")
            trace = fields.get("trace_id", "")
            if event.endswith("_started"):
                keys: set[str] = set()
                for alias in ("lookup_key", "match_key", "subject_ref", "scan_key", "correlation_key"):
                    add_identity(keys, alias, fields.get(alias, ""))
                if keys and trace:
                    pending.setdefault(trace, set()).update(keys)
                continue
            if not event.endswith("_completed"):
                continue
            resource_id = fields.get("resource_id", "")
            if not resource_id:
                continue
            ts = line_timestamp(line) or ef.captured_at
            category, system = infer_category(resource_id, fields.get("service", ""))

            keys = set()
            for alias in ("email", "phone", "email_hash", "customer_reference", "requester_email",
                          "requester_name", "requester_phone", "subject_reference", "owner_email",
                          "customer_email"):
                add_identity(keys, alias, fields.get(alias, ""))
            keys |= pending.get(trace, set())

            if "profile_lookup" in event:
                state = ABSENT if (fields.get("rows") == "0" or fields.get("http_status") == "404") else PRESENT
            elif "connector_config_read" in event:
                state = FLOW_ACTIVE if _truthy(fields.get("enabled")) else FLOW_DISABLED
            elif "restore_policy_read" in event:
                state = RESTORE_ALLOWED if _truthy(fields.get("restore_allowed")) else RESTORE_BLOCKED
            elif "index_query" in event:
                state = PRESENT if (fields.get("result") == "hit" or has_direct_pii(keys)) else ABSENT
            elif "analytics_profile_read" in event:
                state = PRESENT if has_direct_pii(keys) else ANONYMIZED
            elif "audit_record_read" in event:
                state = PRESENT if fields.get("rows", "1") != "0" else ABSENT
            elif "support_ticket_read" in event:
                state = PRESENT if has_direct_pii(keys) else REDACTED
            elif "export_metadata_read" in event or "export_download_check" in event:
                state = PRESENT if has_direct_pii(keys) else ABSENT
            else:
                state = PRESENT if has_direct_pii(keys) else ABSENT
            obs.append(Observation(ef.file_id, ts, system, resource_id, category, state, keys,
                                   origin="log:readback"))
        return obs

    def _parse_support_replica_log(self, ef: EvidenceFile, text: str) -> list[Observation]:
        obs: list[Observation] = []
        pending: dict[str, set[str]] = {}
        for line in text.splitlines():
            fields, _ = parse_kv_line(line)
            event = fields.get("event", "")
            trace = fields.get("trace_id", "")
            if event.endswith("_started"):
                keys: set[str] = set()
                add_identity(keys, "lookup_key", fields.get("lookup_key", ""))
                if keys and trace:
                    pending.setdefault(trace, set()).update(keys)
                continue
            if not event.endswith("_completed"):
                continue
            resource_id = fields.get("resource_id", "")
            if not resource_id:
                continue
            keys = pending.pop(trace, set())
            add_identity(keys, "lookup_key", fields.get("lookup_key", ""))
            state = PRESENT if fields.get("rows", "1") != "0" else ABSENT
            # The support replica is a *legacy contact index*: it stores lookup
            # rows, not conversation content, so the policy category is the
            # secondary identifier list, not a support message.
            obs.append(Observation(ef.file_id, line_timestamp(line) or ef.captured_at, "support_platform",
                                   resource_id, SECONDARY_IDENTIFIER, state, keys,
                                   origin="log:support_replica"))
        return obs

    TRACE_COMPLETED = {
        "profile_lookup_completed": ("account_service", USER_PROFILE),
        "index_query_completed": ("search_service", SEARCH_INDEX_ENTRY),
        "analytics_profile_read_completed": ("analytics_platform", ANALYTICS_PROFILE),
        "analytics_profile_scan_completed": ("analytics_platform", ANALYTICS_PROFILE),
        "audit_record_read_completed": ("security_service", SECURITY_AUDIT_LOG),
        "audit_record_query_completed": ("security_service", SECURITY_AUDIT_LOG),
        "connector_config_read_completed": ("integration_service", DATA_FLOW),
        "restore_policy_read_completed": ("backup_service", BACKUP_ARCHIVE),
        "export_download_check_completed": ("export_service", USER_EXPORT),
        "export_metadata_read_completed": ("export_service", USER_EXPORT),
        "contact_lookup_completed": ("analytics_platform", SECONDARY_IDENTIFIER),
        "contact_query_completed": ("support_platform", SUPPORT_MESSAGE),
        "support_ticket_read_completed": ("support_platform", SUPPORT_MESSAGE),
        "export_completed": ("export_service", USER_EXPORT),
        "connector_heartbeat": ("integration_service", DATA_FLOW),
        "analytics_identity_scan": ("analytics_platform", ANALYTICS_PROFILE),
        "analytics_profile_scan_completed": ("analytics_platform", ANALYTICS_PROFILE),
        "restore_candidate_evaluated": ("backup_service", BACKUP_ARCHIVE),
        "attachment_pii_scan": ("support_platform", SUPPORT_ATTACHMENT),
        "message_pii_scan": ("support_platform", SUPPORT_MESSAGE),
    }

    # Events whose boolean fields tell us the resulting state directly.
    FLOW_EVENTS = {"connector_config_read_completed", "connector_heartbeat"}
    RESTORE_EVENTS = {"restore_policy_read_completed", "restore_candidate_evaluated"}

    def _parse_trace_log(self, ef: EvidenceFile, text: str) -> list[Observation]:
        obs: list[Observation] = []
        pending: dict[str, set[str]] = {}
        for line in text.splitlines():
            fields, _ = parse_kv_line(line)
            event = fields.get("event", "")
            if not event:
                # bracket dialect: [service] [trace] event: k="v"
                m = re.search(r"\[(?:[a-z_]+)\]\s*\[(tr-\d+)\]\s*(\w+):", line)
                if m:
                    fields["trace_id"] = m.group(1)
                    event = m.group(2)
                    fields["event"] = event
            if not event:
                # pipe dialect: | WARN | service | tr-1 | event_name | k="v"
                m = re.search(r"\|\s*[A-Z]+\s*\|\s*[a-z_]+\s*\|\s*(tr-\d+)\s*\|\s*([a-z_0-9]+)\s*\|", line)
                if m:
                    fields["trace_id"] = m.group(1)
                    event = m.group(2)
                    fields["event"] = event
            trace = fields.get("trace_id", "")
            if event.endswith("_started"):
                keys: set[str] = set()
                for alias in ("lookup_key", "match_key", "scan_key", "subject_key", "correlation_key",
                              "subject_ref"):
                    add_identity(keys, alias, fields.get(alias, ""))
                if keys and trace:
                    pending.setdefault(trace, set()).update(keys)
                continue
            if event not in self.TRACE_COMPLETED:
                continue
            resource_id = fields.get("resource_id", "")
            if not resource_id:
                continue
            system, category = self.TRACE_COMPLETED[event]
            keys = pending.pop(trace, set())
            for alias in ("correlation_key", "email", "customer_reference", "subject_reference",
                          "requester_email", "owner_email", "customer_email", "matched_value"):
                add_identity(keys, alias, fields.get(alias, ""))
            if event in self.FLOW_EVENTS:
                state = FLOW_ACTIVE if _truthy(fields.get("enabled")) else FLOW_DISABLED
            elif event in self.RESTORE_EVENTS:
                if _truthy(fields.get("deletion_block")):
                    state = RESTORE_BLOCKED
                else:
                    state = RESTORE_ALLOWED if _truthy(fields.get("restore_allowed", "true")) else RESTORE_BLOCKED
            elif category == USER_PROFILE:
                state = ABSENT if (fields.get("rows") == "0" or fields.get("http_status") == "404") else PRESENT
            elif category == SEARCH_INDEX_ENTRY:
                state = PRESENT if (fields.get("result", "hit") != "miss" or has_direct_pii(keys)) else ABSENT
            elif category == ANALYTICS_PROFILE:
                state = PRESENT if has_direct_pii(keys) else ANONYMIZED
            elif category == SECURITY_AUDIT_LOG:
                state = PRESENT
            elif category == DATA_FLOW:
                state = FLOW_ACTIVE if _truthy(fields.get("enabled")) else FLOW_DISABLED
            elif category == BACKUP_ARCHIVE:
                state = RESTORE_ALLOWED if _truthy(fields.get("restore_allowed", "true")) else RESTORE_BLOCKED
            elif category == USER_EXPORT:
                available = fields.get("available")
                state = PRESENT if (available is None or _truthy(available)) else ABSENT
            elif category in {SUPPORT_ATTACHMENT, SECONDARY_IDENTIFIER}:
                state = PRESENT
            else:
                state = PRESENT if has_direct_pii(keys) else REDACTED
            obs.append(Observation(ef.file_id, line_timestamp(line) or ef.captured_at, system,
                                   resource_id, category, state, keys, origin="log:trace"))
        return obs

    # -- plain text handover ----------------------------------------------
    HANDOVER_RE = re.compile(
        r"\|\s*([a-z_]+)\s*\|\s*(\w+)\s*\|\s*([A-Z_]+)\s*\|\s*([A-Z_]+)\s*\|\s*(.+?)\s*$"
    )

    def _parse_text_file(self, ef: EvidenceFile) -> list[Observation]:
        text = ef.path.read_text(encoding="utf-8", errors="ignore")
        captured = ef.captured_at
        m = re.search(r"Snapshot:\s*(\S+)", text)
        if m:
            captured = m.group(1)
        obs: list[Observation] = []
        for line in text.splitlines():
            match = self.HANDOVER_RE.search(line)
            if not match:
                continue
            system, resource_id, record_type, result, subject = match.groups()
            category, sysname = infer_category(resource_id, system, record_type)
            keys: set[str] = set()
            add_identity(keys, "subject_reference", subject)
            state = normalise_state(result, category)
            obs.append(Observation(ef.file_id, captured, sysname, resource_id, category, state, keys,
                                   origin="text:handover"))
        return obs

    # -- PDF --------------------------------------------------------------
    def _parse_pdf_file(self, ef: EvidenceFile) -> list[Observation]:
        try:
            import pymupdf  # type: ignore
        except ImportError:  # pragma: no cover
            import sys

            print(
                "warning: pymupdf is not installed, PDF evidence is skipped "
                "(pip install pymupdf)",
                file=sys.stderr,
            )
            return []
        obs: list[Observation] = []
        doc = pymupdf.open(ef.path)
        text = "\n".join(page.get_text() for page in doc)
        doc.close()
        obs.extend(self._records_from_document_text(ef, text))
        return obs

    def _records_from_document_text(self, ef: EvidenceFile, text: str) -> list[Observation]:
        obs: list[Observation] = []
        text.lower()
        for m in re.finditer(r"\b(account_\d+|support_\d+|audit_record_\d+|export_\d+|search_\d+)\b", text):
            rid = m.group(1)
            category, system = infer_category(rid, "")
            window = text[max(0, m.start() - 400): m.end() + 400]
            keys: set[str] = set()
            for email in re.findall(r"[\w.+-]+@[\w.-]+\.\w+", window):
                add_identity(keys, "email", email)
            for phone in re.findall(r"\+\d[\d\s().-]{7,}\d", window):
                add_identity(keys, "phone", phone)
            for uid in re.findall(r"\buser_0*\d+\b", window):
                add_identity(keys, "user", uid)
            state = PRESENT if has_direct_pii(keys) else ABSENT
            if category == SUPPORT_MESSAGE:
                category = SUPPORT_ATTACHMENT
            obs.append(Observation(ef.file_id, ef.captured_at, system, rid, category, state, keys,
                                   origin="pdf"))
        return obs

    # -- images -----------------------------------------------------------
    def _parse_image_file(self, ef: EvidenceFile, vision_cache: dict) -> list[Observation]:
        entries = vision_cache.get(ef.file_id) or []
        obs: list[Observation] = []
        for entry in entries:
            resource_id = entry.get("resource_id", "")
            if not resource_id:
                continue
            category = entry.get("category", "")
            system = entry.get("system", "")
            category, system = infer_category(resource_id, system, category)
            keys: set[str] = set()
            for field_name, value in (entry.get("identifiers") or {}).items():
                add_identity(keys, field_name, value)
            state = entry.get("state") or (PRESENT if has_direct_pii(keys) else ABSENT)
            obs.append(Observation(ef.file_id, ef.captured_at, system, resource_id, category,
                                   state, keys, origin="image"))
        return obs


def _truthy(value) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() in {"true", "1", "yes", "y", "active", "enabled", "delivered"}
