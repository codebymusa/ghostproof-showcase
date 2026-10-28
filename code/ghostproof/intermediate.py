"""Milestone 3 intermediate state/policy run. No intent or final case verdicts."""

import json
from collections import Counter, defaultdict
from pathlib import Path

from .diagnostics import verify_dataset
from .evidence import parse_evidence
from .identity import IdentityIndex
from .inputs import load_inputs, parse_timestamp
from .policy import PolicyEngine
from .retrieval import FactIndex
from .state import reconstruct


def investigate(request, identities, index, engine):
    cutoff = parse_timestamp(request["audit_at"])
    identity = identities.resolve(request["email"], cutoff)
    hits = index.retrieve(identity, cutoff, identities)
    keys = {(h.fact.system_id, h.fact.resource_id) for h in hits if h.fact.resource_id}
    # Include future history only for excluded-evidence explanations, never for linking.
    facts = [index.facts[n] for key in sorted(keys) for n in index.by_resource.get(key, ())]
    # Explicit reference edges are derived relevance claims, not observations.
    # Include them even when the grounded target has no captured history.
    facts.extend(h.fact for h in hits if h.basis == "RESOURCE_REFERENCE" and h.fact.resource_id)
    states = reconstruct(facts, cutoff)
    decisions = tuple(engine.decide(state, cutoff) for state in states)
    return identity, hits, states, decisions


def build_context(root):
    inputs = load_inputs(root / "dataset")
    corpus = parse_evidence(root / "dataset", inputs.evidence, inputs.activity)
    return inputs, corpus, IdentityIndex(inputs.identities, inputs.audit_log), FactIndex(corpus.facts), PolicyEngine(inputs.rules)


def run_intermediate(root: Path):
    before = verify_dataset(root)
    inputs, corpus, identities, index, engine = build_context(root)
    cases = []; outcomes = Counter(); categories = Counter(); state_counts = Counter()
    conflicts = []; empty = []; divergence = 0
    for request in sorted(inputs.requests, key=lambda r: r["case_id"]):
        identity, hits, states, decisions = investigate(request, identities, index, engine)
        if not hits:
            empty.append({"case_id": request["case_id"], "identity_status": identity.status,
                          "request_text": request["request_text"],
                          "note": "No visible candidates; absence is not deletion proof. Intent not automatically adjudicated."})
        copies = defaultdict(set)
        for state in states:
            state_counts[state.state] += 1
            copies[(state.system_id, state.resource_id)].add(state.state)
            if state.state == "CONFLICT": conflicts.append((request["case_id"], state.system_id, state.resource_id, state.copy_id))
        divergence += sum("PRESENT" in values and "ABSENT" in values for values in copies.values())
        for decision in decisions:
            outcomes[decision.outcome] += 1; categories[decision.category] += 1
        cases.append({"case_id": request["case_id"], "identity_status": identity.status,
                      "candidate_count": len(hits), "resources": [
            {"system_id": state.system_id, "resource_id": state.resource_id, "copy_id": state.copy_id,
             "state": state.state, "explanation": state.explanation,
             "sources": [{"source_id": f.source_id, "location": f.location,
                          "observed_at": f.observed_at.isoformat(), "available_at": f.available_at.isoformat(),
                          "fields": f.fields} for f in state.selected],
             "policy": {"category": decision.category, "rule_id": decision.rule_id,
                        "required_action": decision.required_action, "outcome": decision.outcome,
                        "operation": decision.operation, "reasons": decision.reasons}}
            for state, decision in zip(states, decisions)]})
    report = {"scope": "intermediate identities, physical-copy states and conditional policy only; no case verdicts",
              "identity_counts": dict(Counter(c["identity_status"] for c in cases)),
              "coverage": corpus.summary(), "manifest_coverage": dict(Counter(c.status for c in corpus.coverage[1:])),
              "facts": len(corpus.facts), "state_counts": dict(state_counts), "policy_counts": dict(outcomes),
              "category_counts": dict(categories), "simultaneous_conflicts": conflicts,
              "request_resource_replica_divergences": divergence,
              "requests_without_candidates": empty,
              "sources": [vars(c) for c in corpus.coverage], "cases": cases,
              "dataset_before": before, "dataset_after": verify_dataset(root),
              "application_model_calls": 0}
    out = root / "artifacts/milestone3"
    out.mkdir(parents=True, exist_ok=True)
    target = out / "intermediate.json"
    if target.is_symlink(): raise ValueError("refusing symlink output")
    target.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    summary = {key: value for key, value in report.items() if key not in {"cases", "sources", "requests_without_candidates", "simultaneous_conflicts"}}
    summary["requests_without_candidates"] = len(empty)
    summary["simultaneous_conflicts"] = len(conflicts)
    lines = ["# Milestone 3 evidence coverage and intermediate counts", "",
             "No case deletion verdicts. Counts below are request/resource/copy decisions, not unique people or accuracy.",
             "```json", json.dumps(summary, indent=2), "```", "",
             "## Every source", "", "| Source | Path | Status | Facts | Remaining limits |",
             "| --- | --- | --- | ---: | --- |"]
    for c in corpus.coverage:
        lines.append(f"| {c.source_id} | {c.path} | {c.status} | {c.facts} | {'; '.join(c.issues)} |")
    lines += ["", "## Requests with no candidate facts", "",
              "These request texts were inspected. They explicitly ask for non-deletion actions; this is a review observation,",
              "not an automated multilingual classifier or permission to skip evidence. Zero candidates never proves deletion.",
              "", "| Case | Request text |", "| --- | --- |"]
    for row in empty: lines.append(f"| {row['case_id']} | {row['request_text']} |")
    (root / "code/evaluation/milestone3_coverage.md").write_text("\n".join(lines)+"\n", encoding="utf-8")
    return summary
