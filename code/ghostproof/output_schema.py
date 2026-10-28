"""Validate submission structure and citation availability, never audit truth."""

import json
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Mapping, Sequence

from .inputs import parse_timestamp, read_csv

OUTPUT_COLUMNS = ("case_id", "deletion_status", "steps_json")
STEP_FIELDS = {
    "step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"
}
OPERATIONS = {
    "FINDING": {
        "REPORT_REMAINING_RECORD": "PRESENT",
        "REPORT_EXPOSED_PII": "PRESENT",
        "REPORT_ACTIVE_DATA_FLOW": "ACTIVE",
        "REPORT_RESTORE_RISK": "ACTIVE",
    },
    "REMEDIATION": {
        "DISABLE_DATA_FLOW": "DISABLED",
        "BLOCK_RESTORE": "BLOCKED",
        "DELETE_RECORD": "ABSENT",
        "REDACT_RECORD": "REDACTED",
        "ANONYMIZE_RECORD": "ANONYMIZED",
    },
    "VERIFICATION": {
        "VERIFY_RECORD_ABSENT": "ABSENT",
        "VERIFY_RECORD_PRESENT": "PRESENT",
        "VERIFY_RECORD_REDACTED": "REDACTED",
        "VERIFY_RECORD_ANONYMIZED": "ANONYMIZED",
        "VERIFY_DATA_FLOW_DISABLED": "DISABLED",
        "VERIFY_RESTORE_BLOCKED": "BLOCKED",
    },
}
# Insertion order above is the specification's table order, not lexical order.
PHASE_RANK = {phase: rank for rank, phase in enumerate(OPERATIONS)}
OPERATION_RANK = {
    phase: {operation: rank for rank, operation in enumerate(operations)}
    for phase, operations in OPERATIONS.items()
}
VERIFICATION_FOR = dict(zip(OPERATIONS["REMEDIATION"], (
    "VERIFY_DATA_FLOW_DISABLED", "VERIFY_RESTORE_BLOCKED", "VERIFY_RECORD_ABSENT",
    "VERIFY_RECORD_REDACTED", "VERIFY_RECORD_ANONYMIZED",
)))


class OutputError(ValueError):
    """Output violates the documented submission contract."""


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise OutputError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def validate_rows(
    rows: Sequence[Mapping[str, str]],
    requests: Sequence[Mapping[str, str]],
    evidence_times: Mapping[str, datetime],
) -> dict:
    """Check exact coverage, ordering, step vocabulary and citation cutoffs.

    Does not establish intent, identity links, evidence meaning, completeness,
    dependency safety, policy correctness, or whether a cited claim is proof.
    """
    expected = [request["case_id"] for request in requests]
    actual = [row.get("case_id") for row in rows]
    if len(set(expected)) != len(expected):
        raise OutputError("request IDs must be unique")
    if actual != sorted(expected):
        raise OutputError("output must cover every request exactly once in case_id order")
    request_by_id = {request["case_id"]: request for request in requests}
    total_steps = 0
    for row in rows:
        case_id = row["case_id"]
        if set(row) != set(OUTPUT_COLUMNS) or not all(isinstance(v, str) for v in row.values()):
            raise OutputError(f"{case_id}: exact string-valued output fields required")
        status = row["deletion_status"]
        if status not in {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"}:
            raise OutputError(f"{case_id}: invalid deletion_status")
        try:
            steps = json.loads(row["steps_json"], object_pairs_hook=_unique_object,
                               parse_constant=lambda value: (_ for _ in ()).throw(
                                   OutputError(f"non-JSON constant: {value}")))
        except (ValueError, TypeError) as exc:
            raise OutputError(f"{case_id}: invalid steps_json: {exc}") from exc
        if not isinstance(steps, list):
            raise OutputError(f"{case_id}: steps_json must be an array")
        if status == "NOT_APPLICABLE":
            if steps:
                raise OutputError(f"{case_id}: NOT_APPLICABLE requires []")
            continue
        if not steps:
            raise OutputError(f"{case_id}: authorized cases require evidence/plan steps")
        cutoff = parse_timestamp(request_by_id[case_id]["audit_at"])
        sort_keys = []
        phases = set()
        checks = set()
        actions = []
        for number, step in enumerate(steps, 1):
            prefix = f"{case_id}, step {number}"
            if not isinstance(step, dict) or set(step) != STEP_FIELDS:
                raise OutputError(f"{prefix}: exact seven step fields required")
            if type(step["step_no"]) is not int or step["step_no"] != number:
                raise OutputError(f"{prefix}: step_no must be a consecutive integer")
            if not all(isinstance(step[field], str) for field in STEP_FIELDS - {"step_no"}):
                raise OutputError(f"{prefix}: all other step fields must be strings")
            phase, operation, state = step["phase"], step["operation"], step["state"]
            if phase not in OPERATIONS or OPERATIONS[phase].get(operation) != state:
                raise OutputError(f"{prefix}: invalid phase/operation/state combination")
            if not step["system_id"].strip() or not step["resource_id"].strip():
                raise OutputError(f"{prefix}: system_id and resource_id are required")
            if status == "COMPLETE" and phase != "VERIFICATION":
                raise OutputError(f"{prefix}: COMPLETE permits verification only")
            citation = step["evidence_id"]
            needs_citation = phase == "FINDING" or status == "COMPLETE"
            if needs_citation:
                if citation not in evidence_times:
                    raise OutputError(f"{prefix}: unknown or absent evidence_id")
                if evidence_times[citation] > cutoff:
                    raise OutputError(f"{prefix}: evidence is after audit_at")
            elif citation != "":
                raise OutputError(f"{prefix}: future steps require empty evidence_id")
            phases.add(phase)
            sort_keys.append((PHASE_RANK[phase],
                              OPERATION_RANK[phase][operation],
                              step["system_id"], step["resource_id"]))
            resource = (step["system_id"], step["resource_id"])
            if phase == "VERIFICATION":
                checks.add((*resource, operation))
            elif phase == "REMEDIATION":
                actions.append((*resource, VERIFICATION_FOR[operation]))
        if sort_keys != sorted(sort_keys):
            raise OutputError(f"{case_id}: steps must follow phase/operation/system/resource order")
        if status == "INCOMPLETE" and phases != set(OPERATIONS):
            raise OutputError(f"{case_id}: INCOMPLETE requires all three phases")
        if any(action not in checks for action in actions):
            raise OutputError(f"{case_id}: remediation has no matching verification")
        total_steps += len(steps)
    return {"rows": len(rows), "steps": total_steps,
            "status_counts": dict(sorted(Counter(row["deletion_status"] for row in rows).items())),
            "validation_scope": "structure and citation availability; not audit correctness"}


def validate_output(path: Path, requests, evidence_times) -> dict:
    return validate_rows(read_csv(path, OUTPUT_COLUMNS), requests, evidence_times)
