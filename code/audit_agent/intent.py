"""Request-intent reading.

A deletion audit is only authorised if the person actually asked for deletion.
Access, correction, export, and marketing opt-out requests must return
``NOT_APPLICABLE`` even though every other field looks like a deletion case.

The deterministic matcher handles the whole corpus. The optional model
assistant is asked only about the small number of requests that arrive with
no recognisable marker in any supported language.
"""

from __future__ import annotations

import json
import os
import re
import urllib.request

from .config import MODEL_API_KEY, MODEL_BASE_URL, MODEL_NAME, MODEL_PROVIDER

# Phrases that explicitly withdraw a deletion mandate. These win over any
# deletion-sounding word in the same message.
NEGATION_PATTERNS = [
    r"not asking for deletion",
    r"not a request to (?:erase|delete)",
    r"do not close",
    r"don'?t delete",
    r"without removing any of my records",
    r"leave the account active",
    r"keep the account as it is",
    r"leave my profile and purchase history in place",
    r"want to continue using the service",
    r"remove me from marketing lists only",
    r"still need the account",
    r"still use it",
    r"leave my profile[^.]*in place",
    r"keep (?:the|my) account",
]

DELETION_MARKERS = [
    # English
    "delet", "delete", "erasure", "erase", "erased", "remov", "close my account",
    "close this account", "close the account", "closure", "wipe", "purge",
    # Romance
    "suppress", "supprim", "effac", "elimin", "exclus", "borr", "quitar", "apagar",
    "cance", "desativ", "encerr", "anul",
    # Germanic / Nordic
    "lösch", "loesch", "verwijder", "slett", "slet", "rader", "törl", "torl", "poist",
    "sil", "verwijderen", "entfern",
    # Slavic / other European
    "smaz", "usun", "usuń", "uklon", "töröl", "szünt",
    # CJK and Korean
    "削除", "退会", "閉鎖", "删除", "刪除", "注销", "註銷", "탈퇴", "삭제", "해지", "閉じ",
    # Greek / Cyrillic
    "διαγραφ", "κατάργηση", "удал", "удол",
]

# A follow-up that asks the desk to *confirm* a deletion already asked for still
# authorises the audit: the mandate is to end up with no identifiable data, and
# checking that outcome is part of honouring it.
CONFIRMATION_PATTERNS = [
    r"\bprofile is gone\b",
    r"\b(?:account|profile|data|records?|copies)\s+(?:is|are)\s+(?:gone|removed|deleted|erased|anonymi[sz]ed)\b",
    r"\bcannot identify me\b",
    r"\bcan'?t identify me\b",
    r"\bno longer identif",
    r"\bconfirm(?:ing)?\s+(?:that|the)\b[^.]{0,60}\b(?:gone|removed|deleted|erased)\b",
]

_confirmation = [re.compile(p, re.I) for p in CONFIRMATION_PATTERNS]

_negation = [re.compile(p, re.I) for p in NEGATION_PATTERNS]


def repair_mojibake(text: str) -> str:
    """Requests arrive in mixed encodings; recover what we can without a loss."""
    if not text:
        return ""
    try:
        repaired = text.encode("cp1252", "ignore").decode("utf-8", "ignore")
    except (UnicodeEncodeError, LookupError):
        return text
    if len(repaired.strip()) >= max(8, len(text.strip()) // 3):
        return repaired
    return text


class IntentClassifier:
    def __init__(self) -> None:
        self.calls = 0
        self.prompt_tokens = 0
        self.completion_tokens = 0

    def classify(self, text: str) -> tuple[bool, str]:
        """Return ``(authorises_deletion, rationale)``."""
        cleaned = repair_mojibake(text)
        lowered = cleaned.lower()

        for pattern in _negation:
            if pattern.search(lowered):
                return False, f"explicit withdrawal: {pattern.pattern}"

        if any(marker in lowered for marker in DELETION_MARKERS):
            return True, "deletion marker present"

        for pattern in _confirmation:
            if pattern.search(lowered):
                return True, "asks the desk to confirm an erasure outcome"

        # No marker in any supported language: ask the assistant, else default to
        # treating the message as a non-deletion contact.
        verdict = self._ask_model(cleaned)
        if verdict is not None:
            return verdict, "model adjudication"
        return False, "no deletion mandate found"

    # -- optional assistant --------------------------------------------------
    def _ask_model(self, text: str) -> bool | None:
        if not (MODEL_API_KEY and MODEL_NAME):
            return None
        if MODEL_PROVIDER.lower() in {"", "none", "off"}:
            return None
        base = MODEL_BASE_URL or "https://api.openai.com/v1"
        prompt = (
            "A customer sent the message below to an online shop's privacy desk. "
            "Answer with exactly one word, DELETE or OTHER. Answer DELETE only if the "
            "message authorises erasure of the customer's account or personal data.\n\n"
            f"Message:\n{text}"
        )
        body = json.dumps({
            "model": MODEL_NAME,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0,
            "max_tokens": 4,
        }).encode("utf-8")
        request = urllib.request.Request(
            f"{base.rstrip('/')}/chat/completions",
            data=body,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {MODEL_API_KEY}",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except Exception:
            return None
        usage = payload.get("usage") or {}
        self.calls += 1
        self.prompt_tokens += int(usage.get("prompt_tokens") or 0)
        self.completion_tokens += int(usage.get("completion_tokens") or 0)
        content = (payload.get("choices") or [{}])[0].get("message", {}).get("content", "")
        return "DELETE" in (content or "").upper()
