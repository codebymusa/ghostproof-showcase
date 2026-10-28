"""Milestone 2 diagnostics; never writes a deletion verdict or submission CSV."""

import hashlib
import json
from collections import Counter
from dataclasses import asdict
from pathlib import Path

from .evidence import parse_evidence
from .identity import IdentityIndex
from .inputs import load_inputs, parse_timestamp, read_csv
from .retrieval import FactIndex


def verify_dataset(root):
    rows = read_csv(root / "code/evaluation/dataset_inventory.csv")
    expected = {r["path"] for r in rows}
    actual = {p.relative_to(root).as_posix() for p in (root / "dataset").rglob("*") if p.is_file()}
    if actual != expected: raise ValueError("dataset inventory file set changed")
    for row in rows:
        data = (root / row["path"]).read_bytes()
        if len(data) != int(row["size_bytes"]) or hashlib.sha256(data).hexdigest() != row["sha256"]:
            raise ValueError(f"dataset fingerprint changed: {row['path']}")
    return {"files": len(rows), "unchanged": True}


def run_diagnostics(root: Path):
    preservation = verify_dataset(root)
    inputs = load_inputs(root / "dataset")
    identities = IdentityIndex(inputs.identities, inputs.audit_log)
    corpus = parse_evidence(root / "dataset", inputs.evidence, inputs.activity)
    index = FactIndex(corpus.facts)
    rows = []; examples = []
    for request in sorted(inputs.requests, key=lambda r: r["case_id"]):
        cutoff = parse_timestamp(request["audit_at"])
        resolution = identities.resolve(request["email"], cutoff)
        hits = index.retrieve(resolution, cutoff)
        rows.append({"case_id": request["case_id"], "identity_status": resolution.status,
                     "candidates": resolution.candidates,
                     "assertion_count": len(resolution.assertions),
                     "shared_identifier_count": len(resolution.shared_identifiers),
                     "candidate_fact_count": len(hits),
                     "resource_history_hits": sum(h.basis == "RESOURCE_HISTORY" for h in hits)})
        for hit in hits:
            if len(examples) >= 12: break
            f = hit.fact
            if f.resource_id and (not examples or all(e["source_id"] != f.source_id for e in examples)):
                examples.append({"case_id": request["case_id"], "source_id": f.source_id,
                                 "location": f.location, "nature": f.nature, "basis": hit.basis,
                                 "system_id": f.system_id, "resource_id": f.resource_id,
                                 "available_at": f.available_at.isoformat(),
                                 "observed_at": f.observed_at.isoformat(),
                                 "related_locations": f.related_locations,
                                 "linked_from": hit.linked_from})
    # Count resource histories retaining differing field payloads, not adjudicated conflicts.
    variants = 0
    for key, numbers in index.by_resource.items():
        observations = [index.facts[n] for n in numbers if index.facts[n].nature == "OBSERVATION"]
        if len({json.dumps(f.fields, sort_keys=True) for f in observations}) > 1: variants += 1
    current_only = {}
    for request in inputs.requests:
        cutoff = parse_timestamp(request["audit_at"])
        current_only[request["case_id"]] = any(
            a.identifier.kind == "email" and a.raw_value.strip().lower() == request["email"].strip().lower()
            and a.relation == "SNAPSHOT" for a in identities.resolve(request["email"], cutoff).assertions)
    report = {
        "milestone": 2, "scope": "identity and evidence candidates; no deletion decisions or accuracy",
        "dataset_preservation": preservation,
        "identity_counts": {status: sum(r["identity_status"] == status for r in rows)
                            for status in ("RESOLVED", "AMBIGUOUS", "UNRESOLVED")},
        "current_snapshot_email_matches": sum(current_only.values()),
        "historical_email_required": sum(not v for v in current_only.values()),
        "requests_with_shared_identifiers": sum(bool(r["shared_identifier_count"]) for r in rows),
        "requests_with_candidate_facts": sum(bool(r["candidate_fact_count"]) for r in rows),
        "coverage_counts_including_activity_csv": corpus.summary(),
        "manifest_coverage_counts": dict(Counter(c.status for c in corpus.coverage[1:])),
        "fact_count": len(corpus.facts),
        "fact_nature_counts": dict(Counter(f.nature for f in corpus.facts)),
        "resource_histories_with_different_payloads": variants,
        "hash_consistency": {"snapshots": len(inputs.identities), "sha256_lower_email_matches": sum(
            hashlib.sha256(r["email"].strip().lower().encode()).hexdigest() == r["email_hash"]
            for r in inputs.identities), "derived_identifiers_added": 0},
        "coverage": [asdict(c) for c in corpus.coverage],
        "cases": rows, "representative_provenance": examples,
        "application_model_usage": {"calls": 0, "input_tokens": 0, "output_tokens": 0, "cost_usd": 0},
    }
    report["dataset_preservation_after"] = verify_dataset(root)
    destination = root / "artifacts/milestone2"
    destination.mkdir(parents=True, exist_ok=True)
    output = destination / "diagnostics.json"
    if output.is_symlink(): raise ValueError("refusing diagnostic symlink")
    output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    lines = ["# Milestone 2 diagnostic results", "", "Identity and candidate-evidence coverage only. No deletion verdicts or prediction accuracy.", ""]
    for key in ("identity_counts", "current_snapshot_email_matches", "historical_email_required",
                "requests_with_shared_identifiers", "requests_with_candidate_facts",
                "coverage_counts_including_activity_csv", "manifest_coverage_counts", "fact_count",
                "fact_nature_counts", "resource_histories_with_different_payloads", "hash_consistency",
                "dataset_preservation_after", "application_model_usage"):
        lines.append(f"- {key}: {json.dumps(report[key], sort_keys=True)}")
    lines += ["", "PARSED means the recognized structure was extracted; it does not mean a source's claims are true.",
              "PARTIAL includes timestamp inconsistencies or unsupported records. SCOPE rows never assert record absence.",
              "Differing payloads include replicas, updates and envelope differences; they are not a count of proven policy violations.",
              "", "## Every evidence source (plus global activity)", "", "| Source | Path | Coverage | Facts | Notes |",
              "| --- | --- | --- | ---: | --- |"]
    for c in corpus.coverage:
        lines.append(f"| {c.source_id} | {c.path} | {c.status} | {c.facts} | {'; '.join(c.issues)} |")
    lines += ["", "## Representative candidate provenance", ""]
    for item in examples:
        lines.append(f"- {item['case_id']}: {item['source_id']} `{item['location']}`; "
                     f"{item['nature']}, {item['basis']}; {item['system_id']}/{item['resource_id']}; "
                     f"observed {item['observed_at']}, available {item['available_at']}.")
    (root / "code/evaluation/milestone2_diagnostics.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return {key: value for key, value in report.items() if key not in {"coverage", "cases", "representative_provenance"}}
