"""Strict, read-only loading of the six production input tables.

Source field values stay as strings without normalization. Derived UTC timestamps
are separate metadata. Public samples and their answers are never read here.
"""
from __future__ import annotations

import csv
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Sequence


class InputError(ValueError):
    """The participant-facing input violates the declared input contract."""


COLUMNS: dict[str, tuple[str, ...]] = {
    "deletion_requests.csv": (
        "case_id", "email", "requested_at", "reported_status", "reported_at",
        "audit_at", "request_text",
    ),
    "user_identities.csv": (
        "user_id", "name", "email", "phone", "email_hash", "updated_at",
    ),
    "user_audit_log.csv": (
        "audit_id", "user_id", "event_time", "field_name", "old_value", "new_value",
    ),
    "system_activity.csv": (
        "activity_id", "event_time", "event_type", "source_system", "target_system",
        "resource_id", "reported_result", "details",
    ),
    "deletion_rules.csv": ("rule_id", "data_category", "condition", "required_action"),
    "evidence_files.csv": ("file_id", "file_path", "origin", "captured_at"),
}
TIMESTAMP_COLUMNS = {
    "deletion_requests.csv": ("requested_at", "reported_at", "audit_at"),
    "user_identities.csv": ("updated_at",),
    "user_audit_log.csv": ("event_time",),
    "system_activity.csv": ("event_time",),
    "deletion_rules.csv": (),
    "evidence_files.csv": ("captured_at",),
}
TIMESTAMP_PATTERN = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)"
)


@dataclass(frozen=True)
class Inputs:
    """Owned rows plus derived provenance times; never writes source files.

    The container's attributes are fixed; row lists/dictionaries remain available
    to callers for indexing. Callers should keep them as source snapshots and put
    inferred facts in separate structures.
    """

    requests: list[dict[str, str]]
    identities: list[dict[str, str]]
    audit_log: list[dict[str, str]]
    activity: list[dict[str, str]]
    rules: list[dict[str, str]]
    evidence: list[dict[str, str]]
    evidence_times: dict[str, datetime]


def parse_timestamp(text: str) -> datetime:
    """Parse an ISO-8601 timestamp with seconds and an explicit time zone.

    Return a timezone-aware UTC datetime. Reject naive or malformed timestamps
    rather than silently applying the machine's local time zone.
    """
    if not isinstance(text, str) or not TIMESTAMP_PATTERN.fullmatch(text):
        raise InputError("Expected an ISO-8601 timestamp with an explicit time zone")
    try:
        result = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if result.tzinfo is None or result.utcoffset() is None:
            raise ValueError("Missing time zone")
        return result.astimezone(timezone.utc)
    except (ValueError, OverflowError) as exc:
        raise InputError("Invalid ISO-8601 timestamp") from exc


def read_csv(
    path: Path, expected_columns: Sequence[str] | None = None,
) -> list[dict[str, str]]:
    """Read UTF-8 CSV with strict headers/row widths and unmodified field values.

    An optional exact header also enforces column order. No files are created,
    and diagnostics identify location rather than reproducing source contents.
    """
    path = Path(path)
    try:
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.reader(handle, strict=True)
            columns = next(reader, None)
            if not columns or any(not column.strip() for column in columns):
                raise InputError(f"{path.name}: missing or empty column header")
            if len(set(columns)) != len(columns):
                raise InputError(f"{path.name}: duplicate column header")
            if expected_columns is not None and columns != list(expected_columns):
                raise InputError(f"{path.name}: header does not match the required columns/order")
            result: list[dict[str, str]] = []
            for values in reader:
                if len(values) != len(columns):
                    raise InputError(
                        f"{path.name}: line {reader.line_num}: expected "
                        f"{len(columns)} columns, found {len(values)}"
                    )
                result.append(dict(zip(columns, values, strict=True)))
            return result
    except (OSError, UnicodeError, csv.Error) as exc:
        raise InputError(f"{path.name}: cannot read a valid UTF-8 CSV ({type(exc).__name__})") from exc


def _required(row: dict[str, str], fields: Sequence[str], location: str) -> None:
    for field in fields:
        if not row[field].strip():
            raise InputError(f"{location}: required field {field} is empty")


def _evidence_path(dataset_dir: Path, evidence_dir: Path, value: str) -> Path:
    """Constrain manifest paths, including resolved symlinks, to evidence/."""
    relative = PurePosixPath(value.replace("\\", "/"))
    windows = PureWindowsPath(value)
    if relative.is_absolute() or windows.drive or windows.root or ".." in relative.parts:
        raise InputError("evidence_files.csv: absolute or traversal path is prohibited")
    if not relative.parts or relative.parts[0] != "evidence":
        raise InputError("evidence_files.csv: file_path must start with evidence/")
    candidate = dataset_dir.joinpath(*relative.parts).resolve()
    if not candidate.is_relative_to(evidence_dir):
        raise InputError("evidence_files.csv: resolved path escapes dataset/evidence")
    if not candidate.is_file():
        raise InputError("evidence_files.csv: referenced evidence file is missing or not a file")
    return candidate


def load_inputs(dataset_dir: Path, *, expected_request_count: int | None = 518) -> Inputs:
    """Validate/load only allowlisted production inputs and manifest file paths.

    Set expected_request_count=None only for small synthetic test fixtures. This
    checks input integrity, not deletion intent, evidence truth or policy outcomes.
    Evidence bodies are not opened or executed. Evidence times are availability
    cutoffs, not proof that a cited item supports a particular finding.
    """
    dataset_dir = Path(dataset_dir).resolve()
    evidence_dir = (dataset_dir / "evidence").resolve()
    if not dataset_dir.is_dir():
        raise InputError("Dataset directory does not exist")
    if not evidence_dir.is_relative_to(dataset_dir) or not evidence_dir.is_dir():
        raise InputError("Evidence directory must exist inside the dataset directory")
    tables: dict[str, list[dict[str, str]]] = {}
    for name, columns in COLUMNS.items():
        source = dataset_dir / name
        if not source.resolve().is_relative_to(dataset_dir):
            raise InputError(f"{name}: resolved input path escapes the dataset directory")
        rows = read_csv(source, columns)
        seen: set[str] = set()
        primary_key = columns[0]
        for number, row in enumerate(rows, start=2):
            location = f"{name}: row {number}"
            _required(row, (primary_key,), location)
            identifier = row[primary_key]
            if identifier in seen:
                raise InputError(f"{location}: duplicate {primary_key}")
            seen.add(identifier)
            for field in TIMESTAMP_COLUMNS[name]:
                try:
                    parse_timestamp(row[field])
                except InputError as exc:
                    raise InputError(f"{location}: invalid {field}: {exc}") from exc
        tables[name] = rows

    requests = tables["deletion_requests.csv"]
    if expected_request_count is not None and len(requests) != expected_request_count:
        raise InputError(f"Expected {expected_request_count} requests; found {len(requests)}")
    for number, row in enumerate(requests, start=2):
        location = f"deletion_requests.csv: row {number}"
        _required(row, COLUMNS["deletion_requests.csv"], location)
        if row["reported_status"] not in {"COMPLETE", "PARTIALLY_COMPLETE", "NOT_STARTED"}:
            raise InputError(f"{location}: invalid reported_status")

    users = {row["user_id"] for row in tables["user_identities.csv"]}
    for number, row in enumerate(tables["user_audit_log.csv"], start=2):
        location = f"user_audit_log.csv: row {number}"
        _required(row, ("user_id", "field_name"), location)
        if row["user_id"] not in users:
            raise InputError(f"{location}: user_id does not exist in user_identities.csv")

    for number, row in enumerate(tables["deletion_rules.csv"], start=2):
        location = f"deletion_rules.csv: row {number}"
        _required(row, COLUMNS["deletion_rules.csv"], location)
        if row["required_action"] not in {"DELETE", "REDACT", "ANONYMIZE", "RETAIN"}:
            raise InputError(f"{location}: invalid required_action")

    for number, row in enumerate(tables["evidence_files.csv"], start=2):
        _required(row, COLUMNS["evidence_files.csv"], f"evidence_files.csv: row {number}")
        _evidence_path(dataset_dir, evidence_dir, row["file_path"])

    evidence_times: dict[str, datetime] = {}
    for name, key, time_column in (
        ("evidence_files.csv", "file_id", "captured_at"),
        ("system_activity.csv", "activity_id", "event_time"),
        ("user_audit_log.csv", "audit_id", "event_time"),
    ):
        for row in tables[name]:
            if row[key] in evidence_times:
                raise InputError(f"{name}: evidence ID collides across provenance namespaces")
            evidence_times[row[key]] = parse_timestamp(row[time_column])
    return Inputs(
        requests=requests,
        identities=tables["user_identities.csv"],
        audit_log=tables["user_audit_log.csv"],
        activity=tables["system_activity.csv"],
        rules=tables["deletion_rules.csv"],
        evidence=tables["evidence_files.csv"],
        evidence_times=evidence_times,
    )
