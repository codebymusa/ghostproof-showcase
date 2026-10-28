"""Inspectable temporal decisions for individual physical copies, never case verdicts."""

import json
from collections import defaultdict
from dataclasses import dataclass, field

from .facts import Fact


MUTATIONS = {"DELETE_RECORD", "REDACT_RECORD", "ANONYMIZE_RECORD", "SYNC_RECORD",
             "RESTORE_BACKUP", "INDEX_RECORD", "UPDATE_RECORD", "DISABLE_DATA_FLOW", "BLOCK_RESTORE"}

# A sparse readback does not revoke explicit policy metadata. PII and control
# state are deliberately excluded: never carry old exposed fields into a redaction.
POLICY_CONTEXT_FIELDS = {"retention_until", "retained_until", "hold_active",
                         "shared_context", "subject_only"}


def record_fields(fact):
    fields = fact.fields
    if isinstance(fields.get("record"), dict): return dict(fields["record"])
    if isinstance(fields.get("profile"), dict): return dict(fields["profile"])
    return dict(fields)


def physical_copy(fact):
    table = fact.fields.get("storage_table", "")
    if "replica" in table: return table
    if table: return "primary"
    return fact.fields.get("physical_copy", "unspecified")


def semantic_signature(fact):
    fields = record_fields(fact)
    keys = {"email", "phone", "email_hash", "user_id", "customer_reference", "subject_reference",
            "requester_email", "requester_phone", "requester_name", "full_name", "name",
            "message_text", "message_excerpt", "enabled", "restore_allowed", "result"}
    keys |= POLICY_CONTEXT_FIELDS
    return fact.observed_state, {k: v for k, v in fields.items() if k in keys}


def contradicts(left, right):
    a_state, a = semantic_signature(left); b_state, b = semantic_signature(right)
    if a_state != b_state: return True
    for summary_fact, detail_fact in ((left, right), (right, left)):
        summary = record_fields(summary_fact).get("result")
        details = record_fields(detail_fact)
        if summary in {"REDACTED", "ANONYMIZED"}:
            keys = {"name", "full_name", "requester_name", "email", "phone", "email_hash",
                    "owner_email", "requester_email", "requester_phone"}
            if summary == "ANONYMIZED" and not ("record_type" in details and "result" in details):
                keys |= {"user_id", "customer_reference", "subject_reference"}
            if any(details.get(k) is not None and str(details[k]).strip().lower() not in
                   {"", "null", "none", "[redacted]"} for k in keys):
                return True
    # Compare shared observed fields only; an omitted field is not a null field.
    return any(a[k] != b[k] for k in a.keys() & b.keys())


@dataclass(frozen=True)
class ResourceState:
    system_id: str
    resource_id: str
    copy_id: str
    state: str  # PRESENT, ABSENT, UNKNOWN, CONFLICT
    selected: tuple[Fact, ...]
    claims: tuple[Fact, ...]
    history: tuple[Fact, ...]
    explanation: tuple[str, ...]
    policy_context: tuple[Fact, ...] = ()
    policy_values: dict = field(default_factory=dict)


def reconstruct(facts, cutoff):
    """Filter availability/effective bounds, then compare observations within a copy.

    Claims cannot establish absence. A later unverified mutating claim makes the
    prior observed state uncertain. Simultaneous incompatible observations remain
    CONFLICT. An unspecified readback never erases an explicitly observed replica.
    """
    groups = defaultdict(list); claims = defaultdict(list)
    for fact in facts:
        if not fact.resource_id: continue
        key = (fact.system_id, fact.resource_id)
        if fact.nature == "CLAIM":
            if fact.visible_at(cutoff): claims[key].append(fact)
        elif fact.nature == "OBSERVATION":
            # Keep future/quarantined facts in explanations, never select them.
            groups[(*key, physical_copy(fact))].append(fact)
    # Future-only physical copies must not enter an earlier audit's world.
    # Keep later history for explanations only when that copy was already
    # observed at cutoff. An eligible claim can ground an unknown logical
    # resource, but cannot establish the existence of a future replica.
    groups = {key: history for key, history in groups.items()
              if any(f.visible_at(cutoff) for f in history)}
    for key in claims:
        if not any(k[:2] == key for k in groups): groups[(*key, "unspecified")] = []
    results = []
    for (system, resource, copy), history in sorted(groups.items()):
        observed = [f for f in history if f.visible_at(cutoff) and not f.fields.get("temporal_anomaly")]
        claim_rows = tuple(sorted(claims.get((system, resource), []), key=lambda f: (f.observed_at, f.location)))
        explanations = []
        future = sum(not f.visible_at(cutoff) for f in history)
        quarantined = sum(bool(f.fields.get("temporal_anomaly")) for f in history)
        if future: explanations.append(f"Excluded {future} observation(s) after availability/effective cutoff.")
        if quarantined: explanations.append(f"Quarantined {quarantined} capture/effective-time contradiction(s).")
        selected = ()
        state = "UNKNOWN"
        if observed:
            latest = max(f.observed_at for f in observed)
            selected = tuple(sorted((f for f in observed if f.observed_at == latest),
                                    key=lambda f: (f.source_id, f.location)))
            state = selected[0].observed_state
            if any(contradicts(a, b) for a in selected for b in selected): state = "CONFLICT"
            explanations.append(f"Latest visible observation for copy {copy}: {latest.isoformat()}.")
            explanations.extend(f"Selected {f.source_id} {f.location}." for f in selected)
            later_mutations = [f for f in claim_rows if f.observed_at > latest
                               and f.fields.get("event_type", f.fields.get("event")) in MUTATIONS]
            if later_mutations:
                state = "UNKNOWN"
                explanations.append("Later mutation claims lack a following readback: " +
                                    ", ".join(f.source_id for f in later_mutations))
        else:
            explanations.append("No eligible direct observation; claims/scopes cannot establish state.")
        if state == "CONFLICT": explanations.append("Simultaneous incompatible readbacks; no arbitrary winner.")
        if claim_rows: explanations.append(f"Retained {len(claim_rows)} claim(s) separately; success is not proof.")
        context = []
        policy_values = {}
        missing = POLICY_CONTEXT_FIELDS - set().union(*(record_fields(f).keys() for f in selected))
        # A record recreated after an observed absence is a new incarnation.
        # An old legal/ownership declaration is not automatically a declaration
        # about the new record, even when it reuses the same resource ID.
        reset = max((f.observed_at for f in observed
                     if f.observed_state == "ABSENT"
                     and selected and f.observed_at < selected[0].observed_at), default=None)
        # Latest explicit value wins, including null/false. Simultaneous
        # conflicting metadata is left unknown instead of arbitrarily selected.
        for field in sorted(missing):
            candidates = [f for f in observed if field in record_fields(f)
                          and (state != "PRESENT" or reset is None or f.observed_at > reset)]
            if not candidates: continue
            newest = max(f.observed_at for f in candidates)
            candidates = [f for f in candidates if f.observed_at == newest]
            if len({json.dumps(record_fields(f)[field], sort_keys=True) for f in candidates}) != 1:
                continue
            policy_values[field] = record_fields(candidates[0])[field]
            context.extend(candidates)
        context = tuple({(f.source_id, f.location): f for f in context}.values())
        results.append(ResourceState(system, resource, copy, state, selected, claim_rows,
                                     tuple(sorted(history, key=lambda f: (f.observed_at, f.location))),
                                     tuple(explanations), context, policy_values))
    return tuple(results)


def state_details(state):
    """Combine compatible simultaneous observations without erasing omitted fields."""
    merged = dict(state.policy_values)
    for fact in state.selected: merged.update(record_fields(fact))
    return merged
