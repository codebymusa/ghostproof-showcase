"""Read-only structured adapters. Keep evidence and claims; emit coverage gaps."""

import json
import re
import sqlite3
from collections import Counter
from dataclasses import dataclass, field, replace
from datetime import datetime
from pathlib import Path

from .facts import Fact, make_fact, reference
from .inputs import parse_timestamp


@dataclass
class Coverage:
    source_id: str
    path: str
    status: str = "PARSED"
    units: int = 0
    parsed_units: int = 0
    facts: int = 0
    issues: list[str] = field(default_factory=list)


@dataclass
class EvidenceCorpus:
    facts: list[Fact]
    coverage: list[Coverage]

    def summary(self):
        return {key: sum(c.status == key for c in self.coverage)
                for key in ("PARSED", "PARTIAL", "FAILED", "PENDING")}


TABLE_SYSTEM = {
    "customer_profiles": "account_service",
    "customer_profiles_primary": "account_service",
    "customer_profiles_failover_replica": "account_service",
    "search_documents_primary": "search_service",
    "customer_search_documents": "search_service",
    "customer_analytics_profiles": "analytics_platform",
    "support_records": "support_platform",
    "customer_exports": "export_service",
    "connector_subscriptions": "integration_service",
    "backup_restore_entries": "backup_service",
    "security_audit_records": "security_service",
}
COLLECTION_SYSTEM = {
    "customer_analytics_reports": "analytics_platform", "customer_export_jobs": "export_service",
}


def parse_json(text: str, source_id: str, path: str, captured: datetime):
    root = json.loads(text)
    if not isinstance(root, dict): raise ValueError("JSON root must be an object")
    exported = parse_timestamp(root.get("exported_at", root.get("captured_at", captured.isoformat())))
    available = max(captured, exported)
    facts = []
    issues = []
    def collection(records, system, scope, pointer, time):
        if not isinstance(records, list): raise ValueError("record collection must be an array")
        # Capture scope is retained, never an inferred missing-record observation.
        facts.append(make_fact(source_id, f"{path}#{pointer}", system,
                               {"collection": scope, "record_count": len(records)}, available,
                               time or exported, nature="SCOPE", timestamps={"exported_at": exported.isoformat()}))
        for number, record in enumerate(records):
            if not isinstance(record, dict): raise ValueError("record must be an object")
            fields = dict(record)
            fields["capture_collection"] = scope
            record_times = [parse_timestamp(record[key]) for key in
                            ("observed_at", "recorded_at", "updated_at", "captured_at")
                            if record.get(key)]
            # History rows describe past events, not a fresh observation at export.
            observation = (parse_timestamp(record["recorded_at"])
                           if scope == "operational_record_history" and record.get("recorded_at")
                           else time or (max(record_times) if record_times else exported))
            for key in ("observed_at", "recorded_at", "updated_at", "captured_at"):
                if record.get(key): observation = max(observation, parse_timestamp(record[key]))
            if observation > available:
                issues.append(f"{pointer}/{number}: observation after declared capture/export")
                fields["temporal_anomaly"] = "observation after declared capture/export; quarantined"
            if not record.get("resource_id"):
                issues.append(f"{pointer}/{number}: missing resource_id")
            facts.append(make_fact(source_id, f"{path}#{pointer}/{number}",
                                   record.get("system", system), fields, available, observation,
                                   timestamps={"collection_observed_at": (time or observation).isoformat(),
                                               "exported_at": exported.isoformat()}))
    if "snapshots" in root:
        for index, snapshot in enumerate(root["snapshots"]):
            collection(snapshot["records"], snapshot["data_store"], snapshot["collection"],
                       f"/snapshots/{index}/records", parse_timestamp(snapshot["captured_at"]))
    elif "service_exports" in root:
        for system, collections in sorted(root["service_exports"].items()):
            for name, records in sorted(collections.items()):
                # Each readback row has observed_at; export time is only availability.
                collection(records, system, name, f"/service_exports/{system}/{name}",
                           None)
    elif "records" in root:
        name = root.get("collection", "records")
        system = COLLECTION_SYSTEM.get(name, root.get("source", ""))
        if not system and not all(r.get("system") for r in root["records"]):
            issues.append("collection has no grounded system")
        collection(root["records"], system, name, "/records",
                   parse_timestamp(root.get("captured_at", exported.isoformat()))
                   if "record_count" not in root else None)
        if "record_count" in root and root["record_count"] != len(root["records"]):
            issues.append("declared record_count mismatch")
    else:
        raise ValueError("unsupported JSON container")
    # Unknown roots are not interpreted by recursively guessing arbitrary keys.
    return facts, issues


def isolated_sql(text: str):
    """Import into bounded :memory: SQLite. Deny attach, extensions and file APIs."""
    connection = sqlite3.connect(":memory:")
    try:
        connection.enable_load_extension(False)
        connection.execute("PRAGMA temp_store=MEMORY")
        connection.execute("PRAGMA max_page_count=4096")
        connection.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, 8_000_000)
        connection.setlimit(sqlite3.SQLITE_LIMIT_SQL_LENGTH, 8_000_000)
        allow = {sqlite3.SQLITE_CREATE_TABLE, sqlite3.SQLITE_CREATE_INDEX,
                 sqlite3.SQLITE_INSERT, sqlite3.SQLITE_UPDATE, sqlite3.SQLITE_READ,
                 sqlite3.SQLITE_SELECT, sqlite3.SQLITE_TRANSACTION, sqlite3.SQLITE_RECURSIVE,
                 sqlite3.SQLITE_REINDEX}
        def authorize(action, first, second, db, trigger):
            if action == sqlite3.SQLITE_FUNCTION:
                return sqlite3.SQLITE_OK if second == "json_valid" else sqlite3.SQLITE_DENY
            if action == sqlite3.SQLITE_PRAGMA:
                safe = first == "foreign_keys" and second in (None, "ON", "1")
                return sqlite3.SQLITE_OK if safe else sqlite3.SQLITE_DENY
            return sqlite3.SQLITE_OK if action in allow else sqlite3.SQLITE_DENY
        connection.set_authorizer(authorize)
        ticks = 0
        def progress():
            nonlocal ticks
            ticks += 1
            return int(ticks > 2000)
        connection.set_progress_handler(progress, 1000)
        connection.executescript(text)
        connection.row_factory = sqlite3.Row
        result = {}
        tables = [r[0] for r in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
        for table in tables:
            quoted = '"' + table.replace('"', '""') + '"'
            rows = connection.execute(f"SELECT * FROM {quoted} LIMIT 100001").fetchall()
            if len(rows) > 100000: raise ValueError("SQL row limit exceeded")
            result[table] = [dict(row) for row in rows]
        return result
    finally:
        connection.close()


def parse_sql(text, source_id, path, captured):
    tables = isolated_sql(text)
    facts = []; issues = []
    declared_scope = tables.get("snapshot_scope", [])
    for table, records in sorted(tables.items()):
        system = TABLE_SYSTEM.get(table, "")
        facts.append(make_fact(source_id, f"{path}#table={table}", system,
                               {"table": table, "row_count": len(records),
                                "declared_scope": declared_scope}, captured, captured, nature="SCOPE"))
        if table == "snapshot_scope": continue
        for index, record in enumerate(records):
            fields = dict(record)
            if "record_json" in fields:
                nested = json.loads(fields["record_json"])
                if not isinstance(nested, dict): raise ValueError("record_json must be an object")
                # Retain envelope and nested fields separately (no overwrite).
                fields["record"] = nested
            fields["storage_table"] = table
            row_system = record.get("origin_system", system)
            if not row_system: issues.append(f"table={table}: unknown system mapping")
            times = [captured]
            # Row updated_at describes earlier change; capture still observes it now.
            for obj in (record, fields.get("record", {})):
                for key in ("observed_at", "recorded_at", "updated_at", "captured_at"):
                    if obj.get(key): times.append(parse_timestamp(obj[key]))
            observation = max(times)
            if observation > captured: issues.append(f"table={table}/row={index}: future row timestamp")
            facts.append(make_fact(source_id, f"{path}#table={table}/row={index}/resource={record.get('resource_id', '')}",
                                   row_system, fields, captured, observation))
    return facts, issues


KEY_VALUE = re.compile(r'([A-Za-z_][A-Za-z0-9_]*)=("(?:\\.|[^"\\])*"|[^\s]+)')
ISO_START = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))\s+(.*)$")


def key_values(text):
    result = {}
    for key, value in KEY_VALUE.findall(text):
        if value.startswith('"'): value = json.loads(value)
        elif value == "null": value = None
        elif value in {"true", "false"}: value = value == "true"
        result[key] = value
    if isinstance(result.get("message"), str):
        payload = result.pop("message")
        result["message_payload"] = payload
        result.update(key_values(payload))
    return result


READBACK_EVENTS = {
    "record_lookup", "profile_lookup_completed", "index_query_completed",
    "analytics_profile_read_completed", "analytics_profile_scan_completed",
    "message_scan_completed", "ticket_read_completed", "attachment_read_completed",
    "export_metadata_read_completed", "export_object_read_completed",
    "connector_config_read_completed", "connector_read_completed",
    "restore_policy_read_completed", "restore_access_read_completed",
    "audit_record_read_completed", "contact_query_completed",
    "contact_lookup_completed", "support_ticket_read_completed",
    "export_download_check_completed", "restore_authorization_completed",
    "analytics_profile_read", "analytics_identity_scan", "message_pii_scan",
    "attachment_pii_scan", "connector_config_loaded", "retained_order_loaded",
    "message_read", "restore_candidate_evaluated",
}


def connector_control_readback(fields):
    """Recognize control telemetry, never infer state from delivery success.

    The supplied connector heartbeat exposes the running connector's enabled
    and scheduler-registration controls. Both must be explicit booleans on a
    resource-scoped integration-service record. A generic heartbeat, last_run,
    or operation result alone remains a claim.
    """
    boolean_values = (True, False, "true", "false")
    return (fields.get("event") == "connector_heartbeat"
            and fields.get("service") == "integration_service"
            and bool(fields.get("resource_id"))
            and all(type(fields.get(k)) in (bool, str)
                    and fields[k] in boolean_values
                    for k in ("enabled", "scheduler_registered"))
            and str(fields["enabled"]).lower() == str(fields["scheduler_registered"]).lower())


def decode_log_line(line):
    match = ISO_START.match(line)
    if not match: raise ValueError("unrecognized timestamp envelope")
    stamp, payload = match.groups()
    fields = {}
    if payload.startswith("{"):
        fields = json.loads(payload)
    elif re.match(r"\[\w+\] \[", payload):
        m = re.match(r"\[(\w+)\] \[([^]]+)\] \[([^]]+)\] ([^:]+):\s*(.*)", payload)
        if not m: raise ValueError("unrecognized bracket envelope")
        level, service, trace, event, body = m.groups()
        fields = dict(key_values(body), level=level, service=service, trace_id=trace, event=event)
    elif payload.startswith("|"):
        parts = payload.split("|", 5)
        if len(parts) != 6: raise ValueError("unrecognized pipe envelope")
        _, level, service, trace, event, body = (p.strip() for p in parts)
        fields = dict(key_values(body), level=level, service=service, trace_id=trace, event=event)
    elif payload.startswith("<"):
        m = re.match(r"<\d+>1 \S+ (\S+) (\S+) - - (.*)", payload)
        if not m: raise ValueError("unrecognized syslog envelope")
        service, trace, body = m.groups()
        fields = dict(key_values(body), service=service, trace_id=trace)
    else:
        fields = key_values(payload)
        if "function" in fields: fields.setdefault("service", fields["function"])
        if "requestId" in fields: fields.setdefault("trace_id", fields["requestId"])
    if not fields.get("event"): raise ValueError("event not recognized")
    return parse_timestamp(stamp), fields


def parse_logs(text, source_id, path, captured):
    facts = []; issues = []; contexts = {}; parsed = 0
    lines = [item for item in enumerate(text.splitlines(), 1) if item[1].strip()]
    for number, line in lines:
        location = f"{path}#line={number}"
        try:
            time, fields = decode_log_line(line)
            key = (fields.get("service", ""), fields.get("trace_id", ""))
            event = fields["event"]
            related = (); timestamps = {}
            if key[1] and event.endswith("_started"):
                contexts[key] = (dict(fields), time, location)
            if key[1] and key in contexts and (event.endswith("_completed") or event in READBACK_EVENTS
                                              or connector_control_readback(fields)):
                context, start_time, start_location = contexts[key]
                if start_time <= time:
                    # Only same service/trace; no later fields leak into earlier rows.
                    fields = {**context, **fields}
                    related = (start_location,)
                    timestamps["query_started_at"] = start_time.isoformat()
            system = fields.get("system", fields.get("service", ""))
            controls = connector_control_readback(fields)
            nature = "OBSERVATION" if event in READBACK_EVENTS or controls else "CLAIM"
            if controls:
                fields["observation_basis"] = "resource-scoped connector control telemetry"
                fields["observed_fields"] = ["enabled", "scheduler_registered"]
                fields["claim_fields"] = [k for k in ("last_run", "reported_result") if k in fields]
                fields["uncertainty"] = "Control fields observed; delivery success is a claim, not proof of downstream state."
            if event.endswith("_completed") and any(token in event for token in ("read", "lookup", "query", "scan")) and event not in READBACK_EVENTS:
                issues.append(f"line={number}: unclassified readback event {event}")
            facts.append(make_fact(source_id, location, system, fields, captured, time,
                                   nature=nature, timestamps=timestamps, related_locations=related))
            parsed += 1
        except (ValueError, TypeError, KeyError):
            issues.append(f"line={number}: unsupported or malformed log entry")
    return facts, issues, len(lines), parsed


def parse_text(text, source_id, path, captured):
    facts = []; issues = []
    scoped_checks = "Snapshot:" in text and "checks completed during the shift:" in text
    readback_values = {"NOT_FOUND", "FOUND", "IDENTIFIABLE", "ANONYMIZED", "REDACTED", "ACTIVE", "DISABLED", "BLOCKED"}
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip(): continue
        if not line.startswith("- "):
            if line.startswith(("CUSTOMER PLATFORM", "Snapshot:", "Account and downstream")): continue
            issues.append(f"line={number}: unsupported text"); continue
        parts = [p.strip() for p in line[2:].split("|")]
        if len(parts) != 6:
            issues.append(f"line={number}: malformed handover row"); continue
        stamp, system, resource, category, result, subject = parts
        nature = "OBSERVATION" if scoped_checks and result in readback_values else "CLAIM"
        fields = dict(resource_id=resource, record_type=category, result=result,
                      subject_reference=subject, observation_basis="operator_readback_summary" if nature == "OBSERVATION" else "unverified_text_claim",
                      uncertainty="attested scoped readback; no raw record payload" if nature == "OBSERVATION" else "not a scoped state readback")
        facts.append(make_fact(source_id, f"{path}#line={number}", system, fields,
                               captured, parse_timestamp(stamp), nature=nature))
    return facts, issues


def activity_facts(rows):
    facts = []
    for number, row in enumerate(rows, 2):
        fields = dict(row)
        # Explicit identifiers in operational prose are links/claims, not identity merges.
        tokens = [token.strip("\"'()[],;:.") for token in row["details"].split()]
        fields["mentioned_subjects"] = [{"subject_reference": token} for token in tokens
                                        if reference(token)]
        if row["event_type"] == "LINK_RESOURCE_IDENTITY":
            alias = re.search(re.escape(row["resource_id"]) + r"\s+\(([^)]+)\)", row["details"])
            if alias: fields["resource_alias"] = alias[1]
            # Explicit catalog ownership attestation, not operation SUCCESS.
            if "belongs only to" in row["details"] and "no other subject is linked" in row["details"]:
                fields["subject_only"] = True
        time = parse_timestamp(row["event_time"])
        facts.append(make_fact(row["activity_id"], f"system_activity.csv#row={number}",
                               row["target_system"], fields, time, time, nature="CLAIM"))
    return facts


def resolve_catalog_aliases(facts):
    """Join exact business keys only through explicit participant catalog links.

    Resource numbers, filenames shared across systems and unlinked ownership are
    never guessed. Catalog claims establish relevance, not record existence.
    Availability of a mapped observation includes the catalog-link timestamp.
    """
    links = {}
    for fact in facts:
        alias = fact.fields.get("resource_alias")
        if fact.fields.get("event_type") == "LINK_RESOURCE_IDENTITY" and alias:
            links.setdefault(alias, []).append(fact)
    result = []
    for fact in facts:
        alias = fact.fields.get("resource_alias", fact.fields.get("object_name", fact.resource_id))
        candidates = links.get(alias, [])
        if fact.nature != "OBSERVATION" or not candidates:
            result.append(fact); continue
        candidates = [link for link in candidates if link.system_id == fact.system_id
                      or fact.fields.get("document_kind") == "customer_statement"]
        targets = {(link.system_id, link.resource_id) for link in candidates}
        if len(targets) != 1:
            result.append(fact); continue
        link = min(candidates, key=lambda f: (f.available_at, f.source_id))
        if (fact.system_id, fact.resource_id) == (link.system_id, link.resource_id) and not link.fields.get("subject_only"):
            result.append(fact); continue
        # No enrichment is needed for an already canonical readback, except
        # explicit subject-only ownership absent from the observation.
        fields = dict(fact.fields)
        fields["resource_id"] = link.resource_id
        fields["catalog_link"] = {"source_id": link.source_id, "location": link.location,
                                  "alias": alias, "available_at": link.available_at.isoformat()}
        if link.fields.get("subject_only") is True:
            fields.setdefault("subject_only", True)
            fields.setdefault("record_type", "SUPPORT_ATTACHMENT")
        if fact.fields.get("document_kind") == "customer_statement" and link.system_id == "export_service":
            fields["record_type"] = "USER_EXPORT"
        result.append(replace(fact, system_id=link.system_id, resource_id=link.resource_id,
                              available_at=max(fact.available_at, link.available_at), fields=fields,
                              timestamps={**fact.timestamps, "available_at": max(fact.available_at, link.available_at).isoformat(),
                                          "catalog_link_available_at": link.available_at.isoformat()},
                              related_locations=fact.related_locations + (link.location,)))
    return result


def parse_evidence(dataset: Path, manifest, activity) -> EvidenceCorpus:
    facts = activity_facts(activity)
    coverage = [Coverage("system_activity.csv", "system_activity.csv", units=len(activity),
                         parsed_units=len(activity), facts=len(facts))]
    for row in sorted(manifest, key=lambda r: r["file_id"]):
        path = dataset / row["file_path"]
        item = Coverage(row["file_id"], row["file_path"])
        coverage.append(item)
        try:
            if not path.resolve().is_relative_to((dataset / "evidence").resolve()):
                raise ValueError("evidence path escapes evidence directory")
            if path.suffix.lower() in {".pdf", ".png"}:
                from .visual_evidence import parse_visual
                parsed, issues, status = parse_visual(path, row)
                facts.extend(parsed)
                item.status, item.issues, item.facts = status, issues, len(parsed)
                item.units = item.parsed_units = len(parsed)
                continue
            if path.suffix.lower() not in {".json", ".sql", ".log", ".txt"}:
                item.status = "PENDING"
                item.issues.append("PDF/image or unsupported format: extraction pending")
                continue
            captured = parse_timestamp(row["captured_at"])
            text = path.read_text(encoding="utf-8")
            if path.suffix == ".json":
                parsed, issues = parse_json(text, row["file_id"], row["file_path"], captured)
            elif path.suffix == ".sql":
                parsed, issues = parse_sql(text, row["file_id"], row["file_path"], captured)
            elif path.suffix == ".log":
                parsed, issues, item.units, item.parsed_units = parse_logs(
                    text, row["file_id"], row["file_path"], captured)
            else:
                parsed, issues = parse_text(text, row["file_id"], row["file_path"], captured)
            # A manifest-declared logical system can ground a replica service alias.
            canonical_systems = set(TABLE_SYSTEM.values())
            if row.get("origin") in canonical_systems:
                parsed = [replace(f, system_id=row["origin"],
                                  fields={**f.fields, "physical_copy": f.system_id,
                                          "logical_system_source": "manifest.origin"})
                          if f.system_id.endswith("_replica") else f for f in parsed]
            if path.suffix != ".log":
                item.parsed_units = len(parsed)
                item.units = len(parsed) + len(issues)
            facts.extend(parsed)
            item.facts = len(parsed)
            item.issues = issues
            if issues: item.status = "PARTIAL"
        except (ValueError, TypeError, KeyError, OSError, sqlite3.Error) as exc:
            item.status = "FAILED"
            # Diagnostic is intentionally structural; never copy arbitrary source content.
            item.issues.append(f"{type(exc).__name__}: parser could not safely extract file")
    facts = resolve_catalog_aliases(facts)
    facts.sort(key=lambda f: (f.source_id, f.location))
    return EvidenceCorpus(facts, coverage)
