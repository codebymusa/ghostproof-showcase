"""Time-bounded identity assertions with explicit ownership collisions."""

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime

from .facts import Identifier, identifier
from .inputs import parse_timestamp


@dataclass(frozen=True)
class IdentityAssertion:
    user_id: str
    identifier: Identifier
    raw_value: str
    source_id: str
    location: str
    available_at: datetime
    relation: str  # SNAPSHOT, OLD_VALUE, NEW_VALUE, STABLE_REFERENCE


@dataclass(frozen=True)
class Resolution:
    status: str  # RESOLVED, AMBIGUOUS, UNRESOLVED
    candidates: tuple[str, ...]
    assertions: tuple[IdentityAssertion, ...]
    matched_sources: tuple[str, ...]
    shared_identifiers: tuple[Identifier, ...]


class IdentityIndex:
    """Collect known-by-cutoff historical identifiers, not a guessed current profile.

    A snapshot newer than cutoff is excluded in full. Audit OLD_VALUE is grounded
    at the audit event's availability, not backdated before that event. Thus a
    future snapshot/audit cannot reveal identifiers to an earlier case. Historical
    ownership persists for ghost-data search, so re-used identifiers are ambiguous.
    Names are never indexed and hashes are copied only from supplied fields.
    """

    def __init__(self, identities, audit_log):
        self.by_identifier = defaultdict(list)
        self.by_user = defaultdict(list)
        def add(user, kind, value, source, location, time, relation):
            item = identifier(kind, value)
            if item:
                assertion = IdentityAssertion(user, item, value, source, location, time, relation)
                self.by_identifier[item].append(assertion)
                self.by_user[user].append(assertion)
        for row in identities:
            user = row["user_id"]; time = parse_timestamp(row["updated_at"])
            for kind in ("user_id", "email", "phone", "email_hash"):
                add(user, kind, row[kind], user, f"user_identities.csv:user_id={user}/{kind}",
                    time, "SNAPSHOT")
        for row in audit_log:
            user = row["user_id"]; time = parse_timestamp(row["event_time"])
            add(user, "user_id", user, row["audit_id"],
                f"user_audit_log.csv:audit_id={row['audit_id']}/user_id", time, "STABLE_REFERENCE")
            if row["field_name"] in {"email", "phone", "email_hash"}:
                for key, relation in (("old_value", "OLD_VALUE"), ("new_value", "NEW_VALUE")):
                    add(user, row["field_name"], row[key], row["audit_id"],
                        f"user_audit_log.csv:audit_id={row['audit_id']}/{key}", time, relation)
        for values in self.by_user.values():
            values.sort(key=lambda a: (a.available_at, a.source_id, a.location))

    def owners(self, item: Identifier, cutoff: datetime) -> tuple[str, ...]:
        return tuple(sorted({a.user_id for a in self.by_identifier.get(item, ())
                             if a.available_at <= cutoff}))

    def resolve(self, email: str, cutoff: datetime) -> Resolution:
        item = identifier("email", email)
        candidates = self.owners(item, cutoff) if item else ()
        assertions = tuple(a for user in candidates for a in self.by_user[user]
                           if a.available_at <= cutoff)
        matches = tuple(sorted({a.source_id for a in assertions if a.identifier == item}))
        shared = tuple(sorted({a.identifier for a in assertions
                               if len(self.owners(a.identifier, cutoff)) > 1}))
        status = "RESOLVED" if len(candidates) == 1 else "AMBIGUOUS" if candidates else "UNRESOLVED"
        return Resolution(status, candidates, assertions, matches, shared)
