"""Shared facts and exact identifiers. Facts are evidence, never verdicts."""

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from .inputs import parse_timestamp


@dataclass(frozen=True, order=True)
class Identifier:
    kind: str
    value: str


def identifier(kind: str, value: Any) -> Identifier | None:
    if not isinstance(value, str) or not value.strip() or value.lower() in {"null", "none"}:
        return None
    value = value.strip()
    if kind in {"email", "email_hash"}: value = value.lower()
    if kind == "phone":
        value = re.sub(r"[ ()+.-]", "", value)
        if not value.isdigit(): return None
    return Identifier(kind, value)


def reference(value: Any) -> Identifier | None:
    """Only recognize full identifiers, never names/substrings/resource prefixes."""
    if not isinstance(value, str): return None
    if re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", value): return identifier("email", value)
    if re.fullmatch(r"user_[A-Za-z0-9_-]+", value): return identifier("user_id", value)
    if re.fullmatch(r"[0-9a-fA-F]{64}", value): return identifier("email_hash", value)
    if re.fullmatch(r"\+?[\d ().-]{7,}", value): return identifier("phone", value)
    return None


IDENTIFIER_KEYS = {
    "email": "email", "owner_email": "email", "requester_email": "email",
    "customer_email": "email", "phone": "phone", "owner_phone": "phone",
    "requester_phone": "phone", "email_hash": "email_hash", "user_id": "user_id",
}
REFERENCE_KEYS = {"subject_reference", "subject_ref", "customer_reference", "lookup_key",
                  "correlation_key", "match_key", "subject_key", "subject_selector",
                  "uploaded_by", "lookup_value", "matched_value",
                  "query", "owner_key", "scan_key"}


def identifiers_in(fields: Any) -> tuple[Identifier, ...]:
    result = set()
    def visit(node):
        if isinstance(node, dict):
            for key, value in node.items():
                found = identifier(IDENTIFIER_KEYS[key], value) if key in IDENTIFIER_KEYS else (
                    reference(value) if key in REFERENCE_KEYS else None)
                if found: result.add(found)
                if key in {"message_text", "message_excerpt", "page_text"} and isinstance(value, str):
                    for token in value.split():
                        item = reference(token.strip("\"'()[],;:."))
                        if item: result.add(item)
                if isinstance(value, (dict, list)): visit(value)
        elif isinstance(node, list):
            for value in node: visit(value)
    visit(fields)
    return tuple(sorted(result))


@dataclass(frozen=True)
class Fact:
    source_id: str
    location: str
    system_id: str
    resource_id: str
    identifiers: tuple[Identifier, ...]
    available_at: datetime
    observed_at: datetime
    timestamps: dict[str, str]
    fields: dict[str, Any]
    nature: str  # CLAIM, OBSERVATION, or SCOPE (never global absence)
    observed_state: str
    related_locations: tuple[str, ...] = ()

    def visible_at(self, cutoff: datetime) -> bool:
        return (self.available_at <= cutoff and self.observed_at <= cutoff
                and not self.fields.get("temporal_anomaly"))


def observed_state(fields: dict, nature: str) -> str:
    if nature != "OBSERVATION": return "UNKNOWN"
    # Only explicit readback observations establish these local states.
    if fields.get("profile", "missing") is None and fields.get("status_code") == 404:
        return "ABSENT"
    if fields.get("result") in {"NOT_FOUND", "ABSENT"}: return "ABSENT"
    if fields.get("http_status") in {404, "404"} and fields.get("rows") in {0, "0"}:
        return "ABSENT"
    if fields.get("event") == "index_query_completed" and fields.get("result") == "miss":
        return "ABSENT"
    if "hits" in fields and fields["hits"] == []: return "ABSENT"
    return "PRESENT"


def make_fact(source_id, location, system, fields, available_at, observed_at,
              *, nature="OBSERVATION", timestamps=None, related_locations=()):
    times = dict(timestamps or {})
    times["available_at"] = available_at.isoformat()
    for key in ("observed_at", "recorded_at", "updated_at", "captured_at"):
        if fields.get(key):
            parsed = parse_timestamp(fields[key])
            times[key] = fields[key]
            observed_at = max(observed_at, parsed)
    return Fact(source_id, location, system, str(fields.get("resource_id") or ""),
                identifiers_in(fields), available_at, observed_at, times, fields,
                nature, observed_state(fields, nature), tuple(related_locations))
