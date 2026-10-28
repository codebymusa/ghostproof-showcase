"""Complete deterministic audit/planning path with explicit investigation results.

Uncertainty has no invented submission status. An internal None status remains
blank in development CSV and cannot be submitted. Proven violations can establish
INCOMPLETE while plan/coverage limitations still require investigation.
"""

from collections import defaultdict
from dataclasses import dataclass, field
from .identity import IdentityIndex
from .intent import classify_intent
from .intermediate import investigate
from .inputs import parse_timestamp
from .output_schema import OPERATIONS, PHASE_RANK, OPERATION_RANK, validate_rows
from .policy import PolicyEngine, SYSTEM_CATEGORY
from .retrieval import FactIndex


ACTION_FOR = {"REPORT_REMAINING_RECORD": "DELETE_RECORD", "REPORT_EXPOSED_PII": None,
              "REPORT_ACTIVE_DATA_FLOW": "DISABLE_DATA_FLOW", "REPORT_RESTORE_RISK": "BLOCK_RESTORE"}
VERIFY_FOR = {"DELETE": "VERIFY_RECORD_ABSENT", "REDACT": "VERIFY_RECORD_REDACTED",
              "ANONYMIZE": "VERIFY_RECORD_ANONYMIZED", "RETAIN": "VERIFY_RECORD_PRESENT",
              "DISABLE_DATA_FLOW": "VERIFY_DATA_FLOW_DISABLED"}
MISSING_PROFILE_TARGET = "No grounded account-profile verification target; final-state coverage is incomplete"


@dataclass
class AuditResult:
    case_id: str
    deletion_status: str | None
    steps: list[dict]
    intent: str
    investigation_reasons: list[str] = field(default_factory=list)
    provenance: dict = field(default_factory=dict)
    schema_errors: list[str] = field(default_factory=list)
    review_warnings: list[str] = field(default_factory=list)

    @property
    def requires_investigation(self):
        """Review includes warnings; use export_blockers for the export decision."""
        return self.deletion_status is None or bool(self.investigation_reasons or self.schema_errors or self.review_warnings)

    @property
    def export_blockers(self):
        blockers = list(self.investigation_reasons) + list(self.schema_errors)
        if self.deletion_status not in {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"}:
            blockers.insert(0, "Deletion status is unresolved or unsupported")
        return tuple(dict.fromkeys(blockers))

    @property
    def is_exportable(self):
        return not self.export_blockers

    def csv_row(self):
        import json
        return {"case_id": self.case_id, "deletion_status": self.deletion_status or "",
                "steps_json": json.dumps(self.steps, ensure_ascii=False, separators=(",", ":"))}


def step(phase, system, resource, operation, evidence=""):
    return {"step_no": 0, "phase": phase, "system_id": system, "resource_id": resource,
            "operation": operation, "state": OPERATIONS[phase][operation], "evidence_id": evidence}


def order_steps(steps):
    unique = {tuple((k, value[k]) for k in ("phase", "system_id", "resource_id", "operation", "evidence_id")): value
              for value in steps}
    values = sorted(unique.values(), key=lambda s: (PHASE_RANK[s["phase"]],
                    OPERATION_RANK[s["phase"]][s["operation"]], s["system_id"], s["resource_id"], s["evidence_id"]))
    return [dict(value, step_no=n) for n, value in enumerate(values, 1)]


def verification_operation(decision):
    if decision.category == "BACKUP_ARCHIVE": return "VERIFY_RESTORE_BLOCKED"
    return VERIFY_FOR.get(decision.required_action)


def coverage_certificate(hits, identity, keys, cutoff):
    """Require an explicit subject-scoped enumeration, never absence of hits.

    Useful for independently supplied audit inventories and synthetic fixtures.
    No certificate is fabricated for the challenge data.
    """
    for hit in hits:
        fact = hit.fact
        if fact.nature != "SCOPE" or not fact.visible_at(cutoff): continue
        fields = fact.fields
        declared = {tuple(k) for k in fields.get("covered_resources", []) if isinstance(k, (list, tuple)) and len(k) == 2}
        if fields.get("scope_complete") is True and fields.get("subject_reference") in identity.candidates and declared == keys:
            return fact
    return None


class AuditPipeline:
    def __init__(self, inputs, corpus):
        self.inputs, self.corpus = inputs, corpus
        self.identities = IdentityIndex(inputs.identities, inputs.audit_log)
        self.index = FactIndex(corpus.facts)
        self.engine = PolicyEngine(inputs.rules)

    def supplied_corpus_coverage(self, hits, cutoff):
        """Assess the supplied evidence universe, not an invented certificate.

        Every manifest entry must be processed; unresolved extraction affecting a
        linked source blocks COMPLETE. A subject-bearing document with no mapped
        resource also blocks it. Unknown external systems are outside this task's
        evidence universe and are never claimed audited.
        """
        manifest = {r["file_id"]: r for r in self.inputs.evidence}
        coverage = {c.source_id: c for c in self.corpus.coverage}
        if not manifest:
            return False, "No supplied manifest coverage; explicit enumeration required"
        linked = {h.fact.source_id for h in hits}
        for source, row in manifest.items():
            if parse_timestamp(row["captured_at"]) > cutoff: continue
            item = coverage.get(source)
            if item is None or item.status in {"FAILED", "PENDING"}:
                return False, "Supplied evidence includes an unprocessed eligible source"
            if item.status == "PARTIAL" and source in linked:
                return False, "Linked evidence extraction/semantics remains partial"
        if any(h.fact.nature == "SCOPE" and h.fact.identifiers and not h.fact.resource_id
               and h.fact.source_id in linked for h in hits):
            return False, "Subject-bearing document has an unmapped resource scope"
        return True, "All supplied sources processed; linked resource histories evaluated at cutoff"

    def predict(self, request):
        intent = classify_intent(request["request_text"])
        result = AuditResult(request["case_id"], None, [], intent.authorization)
        if intent.authorization == "NON_DELETION":
            result.deletion_status = "NOT_APPLICABLE"
            validate_rows([result.csv_row()], [request], self.inputs.evidence_times)
            return result
        if intent.authorization != "DELETE_AUDIT":
            result.investigation_reasons.extend(intent.reasons)
            return result
        identity, hits, states, decisions = investigate(request, self.identities, self.index, self.engine)
        if identity.status != "RESOLVED":
            result.investigation_reasons.append("Identity resolution is " + identity.status)
            return result
        cutoff = parse_timestamp(request["audit_at"])
        references = [h.fact for h in hits if h.basis == "RESOURCE_REFERENCE"]
        if references:
            result.provenance["RESOURCE_REFERENCES"] = [
                {**f.fields["reference_edge"], "available_at": f.available_at.isoformat(),
                 "observed_at": f.observed_at.isoformat(), "nature": f.nature,
                 "proves": "Scoped relevance / future verification target only; not current state"}
                for f in references]
            result.investigation_reasons.extend(f.fields["reference_issue"] for f in references
                                                if f.fields.get("reference_issue"))
        pairs = list(zip(states, decisions))
        if not any(d.category == "USER_PROFILE" or
                   (s.system_id == "account_service" and any(f.fields.get("reference_edge") for f in s.claims))
                   for s, d in pairs):
            result.investigation_reasons.append(MISSING_PROFILE_TARGET)
        by_resource = defaultdict(list)
        for state, decision in pairs:
            by_resource[(state.system_id, state.resource_id)].append((state, decision))
            result.provenance[f"RESOURCE:{state.system_id}/{state.resource_id}/{state.copy_id}"] = {
                "state": state.state, "category": decision.category, "rule_id": decision.rule_id,
                "required_action": decision.required_action, "policy_outcome": decision.outcome,
                "explanation": list(decision.reasons),
                "policy_context": [{"source_id": f.source_id, "location": f.location,
                                    "observed_at": f.observed_at.isoformat()}
                                   for f in state.policy_context],
                "selected": [{"source_id": f.source_id, "location": f.location,
                              "available_at": f.available_at.isoformat(), "observed_at": f.observed_at.isoformat(),
                              "nature": f.nature, "uncertainty": f.fields.get("uncertainty", ""),
                              "related_locations": list(f.related_locations),
                              "observation_basis": f.fields.get("observation_basis", ""),
                              "observed_fields": f.fields.get("observed_fields", []),
                              "claim_fields": f.fields.get("claim_fields", [])}
                             for f in state.selected],
                "catalog_links": [f.fields["catalog_link"] for f in state.selected
                                  if f.fields.get("catalog_link")],
                "claims": [{"source_id": f.source_id, "location": f.location} for f in state.claims]}
        findings = []; remediation = []; checks = []; actionable = False
        for (system, resource), copies in sorted(by_resource.items()):
            verification = set()
            violations = defaultdict(list)
            for state, decision in copies:
                op = verification_operation(decision)
                if op: verification.add(op)
                if decision.outcome == "UNKNOWN":
                    result.investigation_reasons.append(f"{system}/{resource}/{state.copy_id}: {decision.reasons[-1]}")
                elif decision.outcome == "VIOLATION":
                    if decision.operation and state.selected:
                        violations[decision.operation].append((state, decision))
                    else:
                        result.investigation_reasons.append(f"{system}/{resource}: policy violation has no permitted safe remediation operation")
                elif decision.outcome == "SATISFIED" and not op:
                    result.investigation_reasons.append(f"{system}/{resource}: no permitted final-state check")
                if state.state in {"UNKNOWN", "CONFLICT"} and not op:
                    # A claim can ground relevance, but not a finding or guessed treatment.
                    hint = SYSTEM_CATEGORY.get(system)
                    rule = self.engine.rules.get(hint, {})
                    if hint in {"DATA_FLOW", "BACKUP_ARCHIVE"}:
                        verification.add("VERIFY_DATA_FLOW_DISABLED" if hint == "DATA_FLOW" else "VERIFY_RESTORE_BLOCKED")
                    elif rule.get("required_action") in VERIFY_FOR:
                        verification.add(VERIFY_FOR[rule["required_action"]])
            for operation, violating in sorted(violations.items()):
                candidates = [f for state, decision in violating for f in state.selected if f.visible_at(cutoff)]
                if not candidates:
                    result.investigation_reasons.append(f"{system}/{resource}: no eligible finding proof")
                    continue
                proof = sorted(candidates, key=lambda f: (-f.observed_at.timestamp(), -f.available_at.timestamp(), f.source_id, f.location))[0]
                findings.append(step("FINDING", system, resource, operation, proof.source_id))
                result.provenance[f"FINDING:{system}/{resource}/{operation}"] = [
                    {"source_id": f.source_id, "location": f.location, "copy": state.copy_id}
                    for state, decision in violating for f in state.selected]
                action = ACTION_FOR[operation]
                if operation == "REPORT_EXPOSED_PII":
                    treatments = {d.required_action for state, d in violating}
                    if len(treatments) != 1 or next(iter(treatments)) not in {"REDACT", "ANONYMIZE"}:
                        result.investigation_reasons.append(f"{system}/{resource}: exposed identifiers lack an unambiguous permitted treatment")
                    else: action = "REDACT_RECORD" if "REDACT" in treatments else "ANONYMIZE_RECORD"
                if action:
                    remediation.append(step("REMEDIATION", system, resource, action)); actionable = True
            for op in sorted(verification): checks.append(step("VERIFICATION", system, resource, op))
            if not verification:
                result.investigation_reasons.append(f"{system}/{resource}: verification target cannot be inferred safely")
        known_violations = any(decision.outcome == "VIOLATION" for decision in decisions)
        if known_violations:
            result.deletion_status = "INCOMPLETE"
            # An observed violation proves INCOMPLETE independently of whether
            # an otherwise unobserved profile can be linked. Preserve that scope
            # limitation as a warning. Any unknown *grounded* resource, condition,
            # unsafe plan or schema error remains a blocking investigation reason.
            if MISSING_PROFILE_TARGET in result.investigation_reasons:
                result.investigation_reasons.remove(MISSING_PROFILE_TARGET)
                result.review_warnings.append(MISSING_PROFILE_TARGET)
                result.provenance["COVERAGE_WARNING"] = {
                    "status_basis": "Observed policy violation proves INCOMPLETE",
                    "verification_scope": "Every grounded resource with a supported required treatment",
                    "not_established": "State of an unlinked account profile; no target is invented"}
            if not actionable: result.investigation_reasons.append("No complete actionable remediation plan can be serialized")
            result.steps = order_steps(findings + remediation + checks)
        else:
            certificate = coverage_certificate(hits, identity, set(by_resource), cutoff)
            if certificate:
                result.provenance["COVERAGE"] = {"source_id": certificate.source_id, "location": certificate.location}
            corpus_covered, coverage_reason = self.supplied_corpus_coverage(hits, cutoff)
            if not certificate:
                result.provenance["COVERAGE"] = {"basis": "supplied participant evidence corpus",
                    "sufficient": corpus_covered, "explanation": coverage_reason,
                    "limitation": "Not a guarantee about unsupplied systems or records lacking any subject link"}
            profile_absent = any(state.system_id == "account_service" and state.state == "ABSENT" for state in states)
            if not states: result.investigation_reasons.append("No grounded resource observations")
            if not profile_absent: result.investigation_reasons.append("No scoped evidence proving subject profile absence")
            if not certificate and not corpus_covered: result.investigation_reasons.append(coverage_reason)
            # Preserve proven checks even when another resource keeps the case
            # unresolved. A blank development status remains non-submittable.
            proven_checks = []
            for check in checks:
                copies = by_resource[(check["system_id"], check["resource_id"])]
                satisfied = all(decision.outcome == "SATISFIED" for state, decision in copies)
                # Presence is directly testable even when a retention period
                # is missing. Keep this limited proof in an unresolved audit;
                # the UNKNOWN policy reason still forbids a COMPLETE verdict.
                presence_only = (check["operation"] == "VERIFY_RECORD_PRESENT"
                    and all(state.state == "PRESENT" and decision.required_action == "RETAIN"
                            and decision.outcome == "UNKNOWN"
                            and "Retention/hold condition" in decision.reasons[-1]
                            for state, decision in copies))
                if satisfied or presence_only:
                    if presence_only:
                        result.provenance[f"LIMITED_VERIFICATION:{check['system_id']}/{check['resource_id']}"] = {
                            "proves": "Observed availability only",
                            "does_not_prove": "Retention authorization or overall deletion compliance"}
                    candidates = [f for state, decision in by_resource[(check["system_id"], check["resource_id"])]
                                  for f in state.selected if f.visible_at(cutoff)]
                    sources = {f.source_id for f in candidates}
                    # All copy decisions have already passed. Preserve every proof
                    # in the sidecar; the schema has one citation per resource check.
                    result.provenance[f"VERIFICATION:{check['system_id']}/{check['resource_id']}/{check['operation']}"] = [
                        {"source_id": f.source_id, "location": f.location} for f in candidates]
                    if candidates:
                        check["evidence_id"] = sorted(candidates, key=lambda f: (-f.observed_at.timestamp(), f.source_id, f.location))[0].source_id
                        proven_checks.append(check)
            if not result.investigation_reasons and (certificate or corpus_covered) and profile_absent:
                result.deletion_status = "COMPLETE"
            result.steps = order_steps(proven_checks)
        self._check_dependency_order(result, hits)
        result.investigation_reasons = list(dict.fromkeys(result.investigation_reasons))
        if result.deletion_status:
            try: validate_rows([result.csv_row()], [request], self.inputs.evidence_times)
            except ValueError as exc: result.schema_errors.append(str(exc))
        return result

    def _check_dependency_order(self, result, hits):
        deletion_positions = {(s["system_id"], s["resource_id"]): n for n, s in enumerate(result.steps)
                              if s["phase"] == "REMEDIATION" and s["operation"] == "DELETE_RECORD"}
        for hit in hits:
            fields = hit.fact.fields
            edge = fields.get("reference_edge", {})
            if edge.get("status") == "LINKED":
                # The referring downstream copy depends on the pointed-to
                # source, including when its namespace was resolved separately.
                source = (edge["target_system"], edge["target_resource_id"])
                target = (edge["source_system"], edge["source_resource_id"])
            else:
                source_id = fields.get("source_resource_id")
                source_system = fields.get("source_system")
                if not source_id or not source_system: continue
                source = (source_system, source_id); target = (hit.fact.system_id, hit.fact.resource_id)
            if source in deletion_positions and target in deletion_positions and deletion_positions[source] < deletion_positions[target]:
                result.investigation_reasons.append("Dependency order conflicts with canonical serialization; destructive steps withheld for manual planning")
                result.steps = order_steps([s for s in result.steps if s["phase"] != "REMEDIATION"])
                break
