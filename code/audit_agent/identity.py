"""Identity resolution: current snapshot plus the full historical trail.

The request email may be a *current* address or one that was replaced years
earlier. Everything the subject ever used has to become a search key, because
secondary systems keep the old spelling long after the primary service moved
on.
"""

from __future__ import annotations

import csv
import re
from dataclasses import dataclass, field
from pathlib import Path


USER_ID_RE = re.compile(r"^user_0*(\d+)$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$")


def canon_user_id(value: str) -> str:
    """``user_007`` and ``user_7`` are the same subject."""
    m = USER_ID_RE.match((value or "").strip())
    if m:
        return f"user_{int(m.group(1))}"
    return (value or "").strip()


def norm_email(value: str) -> str:
    return (value or "").strip().lower()


def norm_phone(value: str) -> str:
    """Phones are stored with wildly different punctuation; compare digits only."""
    digits = re.sub(r"\D", "", value or "")
    return digits


def norm_hash(value: str) -> str:
    return (value or "").strip().lower()


def norm_name(value: str) -> str:
    return re.sub(r"\s+", " ", (value or "").strip()).casefold()


@dataclass
class Subject:
    """Everything that can be used to recognise one person in evidence."""

    user_id: str
    current_email: str = ""
    current_name: str = ""
    emails: set[str] = field(default_factory=set)
    phones: set[str] = field(default_factory=set)
    hashes: set[str] = field(default_factory=set)
    names: set[str] = field(default_factory=set)
    resolved: bool = True
    resolution_note: str = ""

    def keys(self) -> set[str]:
        """All normalised match keys, prefixed so they never cross-match."""
        out: set[str] = set()
        if self.user_id:
            out.add(f"uid:{self.user_id}")
        for e in self.emails:
            out.add(f"email:{e}")
        for p in self.phones:
            out.add(f"phone:{p}")
        for h in self.hashes:
            out.add(f"hash:{h}")
        for n in self.names:
            if n:
                out.add(f"name:{n}")
        return out


class IdentityResolver:
    def __init__(self, identity_path: Path, audit_path: Path) -> None:
        self.current: dict[str, dict] = {}
        self.by_user: dict[str, dict] = {}
        self.email_to_user: dict[str, str] = {}
        self.history: dict[str, list[dict]] = {}
        self._load(identity_path, audit_path)

    def _load(self, identity_path: Path, audit_path: Path) -> None:
        with identity_path.open(encoding="utf-8-sig", newline="") as fh:
            for row in csv.DictReader(fh):
                uid = canon_user_id(row["user_id"])
                row["user_id"] = uid
                self.current[norm_email(row["email"])] = row
                self.by_user[uid] = row
                self.email_to_user[norm_email(row["email"])] = uid

        with audit_path.open(encoding="utf-8-sig", newline="") as fh:
            for row in csv.DictReader(fh):
                uid = canon_user_id(row["user_id"])
                if not uid:
                    continue
                self.history.setdefault(uid, []).append(
                    {
                        "audit_id": row["audit_id"],
                        "event_time": row["event_time"],
                        "field": row["field_name"],
                        "old_value": row["old_value"],
                        "new_value": row["new_value"],
                    }
                )
        for rows in self.history.values():
            rows.sort(key=lambda r: r["event_time"])

    # -- resolution -------------------------------------------------------
    def resolve(self, email: str) -> Subject:
        email = norm_email(email)
        uid = self.email_to_user.get(email)
        note = "current email"

        if uid is None:
            for candidate, rows in self.history.items():
                for row in rows:
                    if row["field"] == "email" and norm_email(row["old_value"]) == email:
                        uid = candidate
                        note = f"historical email superseded on {row['event_time']}"
                        break
                if uid:
                    break

        if uid is None:
            return Subject(user_id="", resolved=False, resolution_note="no identity match")

        subject = Subject(user_id=uid, resolved=True, resolution_note=note)
        record = self.by_user.get(uid, {})
        subject.current_email = norm_email(record.get("email", ""))
        subject.current_name = record.get("name", "")

        subject.emails.add(email)
        if subject.current_email:
            subject.emails.add(subject.current_email)
        if record.get("phone"):
            subject.phones.add(norm_phone(record["phone"]))
        if record.get("email_hash"):
            subject.hashes.add(norm_hash(record["email_hash"]))
        if record.get("name"):
            subject.names.add(norm_name(record["name"]))

        for row in self.history.get(uid, []):
            field_name = row["field"]
            if field_name == "email":
                for value in (row["old_value"], row["new_value"]):
                    if value and EMAIL_RE.match(value.strip()):
                        subject.emails.add(norm_email(value))
            elif field_name == "phone":
                for value in (row["old_value"], row["new_value"]):
                    if value:
                        digits = norm_phone(value)
                        if len(digits) >= 7:
                            subject.phones.add(digits)
            elif field_name == "email_hash":
                for value in (row["old_value"], row["new_value"]):
                    if value:
                        subject.hashes.add(norm_hash(value))
            elif field_name == "name":
                for value in (row["old_value"], row["new_value"]):
                    if value:
                        subject.names.add(norm_name(value))

        subject.emails.discard("")
        subject.phones.discard("")
        subject.hashes.discard("")
        subject.names.discard("")
        return subject
