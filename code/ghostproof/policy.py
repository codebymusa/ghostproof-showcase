"""Supplied deletion-rule decisions, kept separate from evidence extraction."""

import re
from dataclasses import dataclass

from .facts import IDENTIFIER_KEYS, reference
from .inputs import parse_timestamp
from .state import state_details, record_fields


COLLECTION_CATEGORY = {
    "customer_profiles": "USER_PROFILE", "profile_lookups": "USER_PROFILE",
    "customer_search_documents": "SEARCH_INDEX_ENTRY", "index_queries": "SEARCH_INDEX_ENTRY",
    "customer_analytics_reports": "ANALYTICS_PROFILE", "profiles": "ANALYTICS_PROFILE",
    "support_conversations": "SUPPORT_MESSAGE", "tickets": "SUPPORT_MESSAGE",
    "ticket_attachments": "SUPPORT_ATTACHMENT", "customer_export_jobs": "USER_EXPORT",
    "exports": "USER_EXPORT", "connector_configurations": "DATA_FLOW", "connectors": "DATA_FLOW",
    "backup_catalog": "BACKUP_ARCHIVE", "restore_entries": "BACKUP_ARCHIVE",
    "security_audit_events": "SECURITY_AUDIT_LOG", "audit_records": "SECURITY_AUDIT_LOG",
    "retained_order_records": "LEGAL_HOLD_RECORD", "deleted_customer_references": "ACCOUNT_TOMBSTONE",
}
TABLE_CATEGORY = {
    "customer_profiles": "USER_PROFILE", "customer_profiles_primary": "USER_PROFILE",
    "customer_profiles_failover_replica": "USER_PROFILE", "search_documents_primary": "SEARCH_INDEX_ENTRY",
    "customer_search_documents": "SEARCH_INDEX_ENTRY", "customer_analytics_profiles": "ANALYTICS_PROFILE",
    "support_records": "SUPPORT_MESSAGE", "customer_exports": "USER_EXPORT",
    "connector_subscriptions": "DATA_FLOW", "backup_restore_entries": "BACKUP_ARCHIVE",
    "security_audit_records": "SECURITY_AUDIT_LOG",
}
SYSTEM_CATEGORY = {"account_service": "USER_PROFILE", "search_service": "SEARCH_INDEX_ENTRY",
                   "analytics_platform": "ANALYTICS_PROFILE", "integration_service": "DATA_FLOW",
                   "backup_service": "BACKUP_ARCHIVE", "security_service": "SECURITY_AUDIT_LOG",
                   "export_service": "USER_EXPORT", "marketing_platform": "MARKETING_PROFILE"}
PII_KEYS = {"name", "full_name", "requester_name", "email", "phone", "email_hash", "owner_email",
            "owner_phone", "requester_email", "requester_phone", "address", "delivery_address"}
LINK_KEYS = {"user_id", "subject_reference", "customer_reference"}


def truth(value):
    if value in (True, 1, "true", "1", "True"): return True
    if value in (False, 0, "false", "0", "False"): return False
    return None


def populated(value):
    return value is not None and str(value).strip().lower() not in {"", "null", "none", "[redacted]"}


def category_for(state):
    categories = set()
    for fact in state.selected:
        fields = record_fields(fact)
        category = fields.get("record_type")
        if not category:
            category = COLLECTION_CATEGORY.get(fact.fields.get("collection_name", fact.fields.get("capture_collection")))
        if not category: category = TABLE_CATEGORY.get(fact.fields.get("storage_table"))
        if not category:
            event = fields.get("event", "")
            if fields.get("source") == "legacy_contact_index" or event in {"contact_lookup_completed", "contact_query_completed"}:
                # A contact-index readback is not an analytics profile merely
                # because the analytics service emitted it.
                category = "SECONDARY_IDENTIFIER"
            elif event == "attachment_pii_scan": category = "SUPPORT_ATTACHMENT"
            elif event in {"message_pii_scan", "message_read", "support_ticket_read_completed"}: category = "SUPPORT_MESSAGE"
            elif fields.get("shared_context") is True and ("message_text" in fields or "ticket_id" in fields):
                category = "SUPPORT_MESSAGE"
            else: category = SYSTEM_CATEGORY.get(state.system_id)
        if category: categories.add(category)
    return next(iter(categories)) if len(categories) == 1 else "UNKNOWN"


@dataclass(frozen=True)
class PolicyDecision:
    system_id: str
    resource_id: str
    copy_id: str
    category: str
    rule_id: str
    required_action: str
    outcome: str  # SATISFIED, VIOLATION, UNKNOWN
    operation: str
    reasons: tuple[str, ...]
    evidence_ids: tuple[str, ...]


class PolicyEngine:
    def __init__(self, rules):
        self.rules = {row["data_category"]: dict(row) for row in rules}
        if len(self.rules) != len(rules): raise ValueError("duplicate policy category")

    def decide(self, state, cutoff):
        category = category_for(state)
        rule = self.rules.get(category)
        action = rule["required_action"] if rule else "DISABLE_DATA_FLOW" if category == "DATA_FLOW" else ""
        reasons = list(state.explanation)
        def result(outcome, reason, operation=""):
            return PolicyDecision(state.system_id, state.resource_id, state.copy_id, category,
                                  rule["rule_id"] if rule else "", action, outcome, operation,
                                  tuple(reasons + [reason]), tuple(sorted({f.source_id for f in state.selected})))
        if state.state in {"UNKNOWN", "CONFLICT"}:
            return result("UNKNOWN", "Current copy state is not established.")
        if category == "UNKNOWN" or not action:
            return result("UNKNOWN", "No grounded category / supplied rule; do not invent treatment.")
        fields = state_details(state)
        summary = fields.get("result")
        pii = [key for key in PII_KEYS if populated(fields.get(key))]
        # Readback query keys/subject lookup are not retained record PII.
        text = " ".join(str(fields.get(k, "")) for k in ("message_text", "message_excerpt"))
        if re.search(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}", text): pii.append("message_text/email")
        if populated(fields.get("matched_value")): pii.append("matched_value")
        if summary == "IDENTIFIABLE": pii.append("explicit_identifiable_readback")
        if category == "DATA_FLOW":
            enabled = truth(fields.get("enabled"))
            if summary in {"ACTIVE", "DISABLED"}: enabled = summary == "ACTIVE"
            if enabled is None: return result("UNKNOWN", "Health/delivery status does not establish enabled state.")
            return result("VIOLATION" if enabled else "SATISFIED", "Explicit enabled control observed.",
                          "REPORT_ACTIVE_DATA_FLOW" if enabled else "")
        if category == "BACKUP_ARCHIVE":
            allowed = truth(fields.get("restore_allowed"))
            if truth(fields.get("eligible")) is True and truth(fields.get("deletion_block")) is False:
                allowed = True
            elif truth(fields.get("deletion_block")) is True and truth(fields.get("eligible")) is not True:
                allowed = False
            if fields.get("decision") in {"allow", "deny"}: allowed = fields["decision"] == "allow"
            if summary in {"ACTIVE", "BLOCKED"}: allowed = summary == "ACTIVE"
            if state.state == "ABSENT": return result("UNKNOWN", "Archive absence alone does not prove restore paths blocked.")
            if allowed is None: return result("UNKNOWN", "Restore control / blockability is not established.")
            return result("VIOLATION" if allowed else "SATISFIED", "Retain archive; require restore access blocked.",
                          "REPORT_RESTORE_RISK" if allowed else "")
        if action == "RETAIN":
            until = fields.get("retention_until", fields.get("retained_until"))
            condition = (parse_timestamp(until) >= cutoff if until else None)
            if category == "LEGAL_HOLD_RECORD":
                condition = truth(fields.get("hold_active"))
                # A dated retained-order mandate is an explicit retention
                # condition even when the source has no redundant hold_active.
                # Explicit false/null controls are never overridden.
                if "hold_active" not in fields and until and populated(fields.get("retention_reason")):
                    condition = parse_timestamp(until) >= cutoff
                if condition is True and until: condition = parse_timestamp(until) >= cutoff
            if condition is not True:
                return result("UNKNOWN", "Retention/hold condition missing, inactive or expired; no fallback rule supplied.")
            if state.state == "ABSENT":
                return result("VIOLATION", "Required retained record is missing; no permitted recreate operation exists.")
            prohibited = [key for key in fields.get("prohibited_fields", []) if populated(fields.get(key))]
            if prohibited:
                return result("VIOLATION", "Explicit retained-record field restriction violated: " + ", ".join(prohibited),
                              "REPORT_EXPOSED_PII")
            return result("SATISFIED", "Required retained record present within supplied condition; do not delete it.")
        if category == "SUPPORT_ATTACHMENT" and fields.get("subject_only") is not True:
            return result("UNKNOWN", "Uploader identity alone does not prove subject-only attachment ownership.")
        if action == "DELETE":
            return result("SATISFIED" if state.state == "ABSENT" else "VIOLATION",
                          "Whole-record deletion required by supplied rule.",
                          "REPORT_REMAINING_RECORD" if state.state != "ABSENT" else "")
        if category == "SUPPORT_MESSAGE":
            context = fields.get("shared_context") is True or bool(re.search(r"order|agent|customer", text, re.I))
            # A typed customer-support ticket readback is conversation context;
            # it need not redundantly contain a made-up shared_context flag.
            # Generic untyped message/attachment observations do not qualify.
            context |= fields.get("event") == "support_ticket_read_completed"
            context |= (fields.get("record_type") == "SUPPORT_MESSAGE"
                        and fields.get("result") in {"IDENTIFIABLE", "REDACTED", "FOUND"}
                        and populated(fields.get("subject_reference")))
            context |= any(f.fields.get("collection_name", f.fields.get("capture_collection")) in {"support_conversations", "tickets"}
                           or f.fields.get("storage_table") == "support_records" for f in state.selected)
            if not context: return result("UNKNOWN", "Required shared conversation context is not established.")
        if state.state == "ABSENT":
            return result("VIOLATION", "Record required to remain after treatment is absent; no recreate operation supplied.")
        if action == "REDACT":
            if pii:
                return result("VIOLATION", "Prohibited record identifiers remain: " + ", ".join(sorted(pii)), "REPORT_EXPOSED_PII")
            if category == "ACCOUNT_TOMBSTONE":
                if not any(populated(fields.get(k)) for k in LINK_KEYS):
                    return result("VIOLATION", "Tombstone lost its permitted stable internal reference.")
                if not {"email", "phone", "email_hash"} <= fields.keys() or not ({"name", "full_name"} & fields.keys()):
                    return result("UNKNOWN", "Tombstone direct-identifier schema is incomplete.")
            elif summary != "REDACTED" and not (fields.get("message_text") == "[REDACTED]" or
                                                 any(k in fields for k in PII_KEYS)):
                return result("UNKNOWN", "No complete redaction observation.")
            return result("SATISFIED", "Identifiers removed while permitted reference/context remains.")
        if action == "ANONYMIZE":
            summary_only = "record_type" in fields and "result" in fields and not (PII_KEYS & fields.keys())
            links = [] if summary_only else [key for key in LINK_KEYS if populated(fields.get(key))]
            if summary == "IDENTIFIABLE" or pii or links:
                return result("VIOLATION", "Record still attributable through observed identifiers/references.", "REPORT_EXPOSED_PII")
            if summary != "ANONYMIZED" and not ({"email", "phone", "email_hash"} <= fields.keys()
                                                and any(k in fields for k in LINK_KEYS)):
                return result("UNKNOWN", "Missing linkage fields; absence of direct identifiers is not unlinkability proof.")
            return result("SATISFIED", "Observed record has no identifying link in the supplied schema.")
        return result("UNKNOWN", "Unsupported policy action.")
