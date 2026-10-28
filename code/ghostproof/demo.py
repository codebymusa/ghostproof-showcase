"""Portfolio adapter over the existing audit engine, not a second engine.

Inputs use the original six-table contract with a small fictional manifest.
Expected outcomes live only in tests. Optional explicit AI mode uses a loopback
extractor; the default remains offline. No competition-export path is used here.
"""
import hashlib
import json
from dataclasses import asdict, replace
from pathlib import Path

from .audit import AuditPipeline
from .evidence import parse_evidence, Coverage
from .facts import make_fact
from .inputs import COLUMNS, load_inputs, parse_timestamp
from .intermediate import investigate
from .state import record_fields


def fingerprint(dataset, inputs):
    paths = set(COLUMNS) | {row['file_path'] for row in inputs.evidence}
    return {name: hashlib.sha256((dataset / name).read_bytes()).hexdigest()
            for name in sorted(paths)}


def inspect_request(pipeline, request):
    result = pipeline.predict(request)
    identity, hits, states, decisions = investigate(
        request, pipeline.identities, pipeline.index, pipeline.engine)
    cutoff = parse_timestamp(request['audit_at'])
    resources = []
    for state, decision in zip(states, decisions):
        selected = {(f.source_id, f.location) for f in state.selected}
        history = { (f.source_id, f.location): f for f in state.history + state.claims }
        timeline = []
        for fact in sorted(history.values(), key=lambda f: (f.observed_at, f.available_at, f.source_id, f.location)):
            fields = record_fields(fact)
            # A compact field view; original provenance and JSON pointers remain.
            observed = {k: fields[k] for k in (
                'result', 'email', 'customer_reference', 'user_id', 'subject_reference',
                'enabled', 'scheduler_registered', 'restore_allowed', 'retention_until',
                'hold_active', 'account_status', 'event_type', 'reported_result') if k in fields}
            timeline.append({'source_id': fact.source_id, 'location': fact.location,
                'observed_at': fact.observed_at.isoformat(), 'available_at': fact.available_at.isoformat(),
                'nature': fact.nature, 'observed_state': fact.observed_state,
                'evidence_label': fact.fields.get('evidence_label', fact.nature),
                'extraction': fact.fields.get('extraction'),
                'eligible_at_audit': fact.visible_at(cutoff),
                'selected': (fact.source_id, fact.location) in selected,
                'observed_fields': observed, 'related_locations': list(fact.related_locations)})
        resources.append({'system_id': state.system_id, 'resource_id': state.resource_id,
                          'copy_id': state.copy_id, 'state': state.state,
                          'policy': asdict(decision), 'timeline': timeline})
    steps = []
    for item in result.steps:
        key = f"{item['phase']}:{item['system_id']}/{item['resource_id']}/{item['operation']}"
        proof = result.provenance.get(key, []) if item['evidence_id'] else []
        steps.append({**item, 'source_locations': [p['location'] for p in proof],
                      'future_work': not bool(item['evidence_id'])})
    return {'case_id': request['case_id'], 'request': dict(request),
        'portfolio_status': result.deletion_status or 'INSUFFICIENT_EVIDENCE',
        'engine_status': result.deletion_status, 'intent': result.intent,
        'identity': {'status': identity.status, 'user_ids': list(identity.candidates),
                     'shared_identifiers': [asdict(i) for i in identity.shared_identifiers],
                     'assertions': [{'kind': a.identifier.kind, 'value': a.identifier.value,
                                     'relation': a.relation, 'source_id': a.source_id,
                                     'location': a.location, 'available_at': a.available_at.isoformat()}
                                    for a in identity.assertions]},
        'resources': resources, 'steps': steps,
        'review_reasons': result.investigation_reasons, 'review_warnings': result.review_warnings,
        'schema_errors': result.schema_errors, 'requires_review': result.requires_investigation,
        'export_blockers': list(result.export_blockers), 'provenance': result.provenance}


def cell(value):
    return str(value).replace('|', '\\|').replace('\n', ' ')


def render_markdown(report):
    lines = ['# GhostProof — fictional audit demos', '',
        'Read-only audit and planning. No deletions executed; no paid API calls.',
        'Runtime extraction: ' + report['runtime_ai'] + '.',
        'COMPLETE is bounded to the supplied fictional corpus, not a certification of external systems.',
        'INSUFFICIENT_EVIDENCE is a portfolio presentation label for an unresolved engine status; it is not a competition CSV status.', '',
        '| Request | Portfolio result | Engine status | Review needed |',
        '| --- | --- | --- | --- |']
    for case in report['cases']:
        lines.append(f"| {case['case_id']} | {case['portfolio_status']} | {case['engine_status'] or 'unresolved'} | {case['requires_review']} |")
    for case in report['cases']:
        req, identity = case['request'], case['identity']
        lines += ['', f"## {case['case_id']} — {case['portfolio_status']}", '',
                  f"Request: {req['request_text']}", f"Supplied email: `{req['email']}`", '',
                  f"Requested at: {req['requested_at']}; audit cutoff: **{req['audit_at']}**.",
                  f"Workflow claim: {req['reported_status']} at {req['reported_at']} (not accepted as state proof).", '',
                  f"Identity: **{identity['status']}**, stable subject(s): {', '.join(identity['user_ids']) or 'none'}.", '',
                  '| Identifier | Relation | Available at | Identity source/location |',
                  '| --- | --- | --- | --- |']
        for a in identity['assertions']:
            lines.append(f"| {a['kind']}: {cell(a['value'])} | {a['relation']} | {a['available_at']} | {a['source_id']} — {a['location']} |")
        lines += ['', '### Resource states and timelines', '']
        for resource in case['resources']:
            policy = resource['policy']
            lines += [f"#### {resource['system_id']}/{resource['resource_id']} [{resource['copy_id']}]", '',
                      f"State: **{resource['state']}**; policy: {policy['category']} / {policy['required_action'] or 'unestablished'} / **{policy['outcome']}**.",
                      *['- ' + reason for reason in policy['reasons']], '',
                      '| Event/observation time | Available at | Nature / observed state | Eligible / selected | Evidence / source location | Fields |',
                      '| --- | --- | --- | --- | --- | --- |']
            for fact in resource['timeline']:
                lines.append(f"| {fact['observed_at']} | {fact['available_at']} | {fact['evidence_label']} / {fact['observed_state']} | "
                             f"{fact['eligible_at_audit']} / {fact['selected']} | {fact['source_id']} — {fact['location']} | "
                             f"{cell(json.dumps(fact['observed_fields'], ensure_ascii=False, sort_keys=True))} |")
                if fact['extraction']:
                    lines.append('  - Validated source excerpt: ' + cell(fact['extraction']['excerpt']))
        for phase, title in [('FINDING', 'Findings'), ('REMEDIATION', 'Required remediation (planned, not executed)'),
                             ('VERIFICATION', 'Verification checks')]:
            lines += ['', '### ' + title, '']
            selected = [step for step in case['steps'] if step['phase'] == phase]
            if not selected: lines.append('None supported for this phase.')
            for step in selected:
                proof = (step['evidence_id'] + ' — ' + '; '.join(step['source_locations'])) if step['evidence_id'] else 'future work; no execution evidence'
                lines.append(f"{step['step_no']}. {step['operation']} — {step['system_id']}/{step['resource_id']} → {step['state']}. {proof}")
        lines += ['', '### Missing evidence and review reasons', '']
        reasons = case['review_reasons'] + case['review_warnings'] + case['schema_errors']
        lines += ['- ' + reason for reason in reasons] or ['No unresolved conditions within this supplied corpus.']
    lines += ['', '## Run provenance', '', f"Evidence coverage: {json.dumps(report['coverage'], sort_keys=True)}.",
              'Only allowlisted input tables and manifested evidence were read; expected outcomes were not loaded.',
              'Input SHA256 fingerprints and complete resource provenance are in report.json.', '']
    if report.get('extraction_runs'):
        lines += ['## Optional extraction usage', '',
                  'Model output is a proposal. Only source-validated readbacks enter state reconstruction.',
                  'Null token/latency values mean unavailable or no new generation; they are not estimated zeros.', '',
                  '| Source | Provider / model used | Calls | Cache | Fallback | Model latency ms | Input / output tokens |',
                  '| --- | --- | --- | --- | --- | --- | --- |']
        for run in report['extraction_runs']:
            lines.append(f"| {run['source_id']} | {run['provider']} / {run['model'] or 'none'} | {run['model_calls']} | "
                         f"{run['cache_hit']} | {run['fallback_used']} | {run['latency_ms']} | {run['input_tokens']} / {run['output_tokens']} |")
            lines.append(f"- Requested: {run['requested_provider']} / {run['requested_model']}; "
                         f"returned model metadata: {run.get('returned_model') or 'unavailable'}. "
                         'On fallback, the table labels the provider of admitted facts, not the attempted model.')
            if run.get('fallback_reason'): lines.append('- Fallback reason: ' + run['fallback_reason'])
            if run['validation']['uncertainties']: lines.append('- Extraction uncertainty: ' + ', '.join(run['validation']['uncertainties']))
    return '\n'.join(lines)


def run_demo(repo_root: Path, *, dataset=None, output_dir=None, ai_config=None, unstructured_manifest=None):
    root = Path(repo_root).resolve()
    dataset = Path(dataset or root / 'demo/dataset').resolve()
    raw_output = Path(output_dir or root / ('artifacts/portfolio_demo_ai' if ai_config else 'artifacts/portfolio_demo'))
    output = raw_output.resolve()
    if raw_output.is_symlink() or any(output.is_relative_to(p) for p in (dataset, root / 'dataset')):
        raise ValueError('Demo report output must not overwrite input datasets or use a symlink')
    inputs = load_inputs(dataset, expected_request_count=None)
    before = fingerprint(dataset, inputs)
    corpus = parse_evidence(dataset, inputs.evidence, inputs.activity)
    original_inputs = inputs
    extraction_runs = []; additional_hashes = {}; additional_paths = {}
    if ai_config is not None:
        from .local_extraction import LocalExtractor, strict_json
        extractor = LocalExtractor(ai_config, root / 'artifacts/portfolio_ai/cache')
        manifest = Path(unstructured_manifest or root / 'demo/unstructured/manifest.json').resolve()
        manifest_bytes = manifest.read_bytes()
        additional_hashes['unstructured/manifest.json'] = hashlib.sha256(manifest_bytes).hexdigest()
        additional_paths['unstructured/manifest.json'] = manifest
        mounted = []; times = dict(inputs.evidence_times)
        for row in strict_json(manifest_bytes.decode('utf8'))['sources']:
            if set(row) != {'file_id', 'file_path', 'captured_at'} or not row['file_id']:
                raise ValueError('Invalid unstructured source metadata')
            path = (manifest.parent / row['file_path']).resolve()
            if not path.is_relative_to(manifest.parent) or not path.is_file() or path.suffix not in {'.txt', '.log'}:
                raise ValueError('Unstructured source must be a text/log file inside the manifest directory')
            if row['file_id'] in times: raise ValueError('Unstructured evidence ID collision')
            source = {**row, 'file_path': 'unstructured/' + row['file_path']}
            source_bytes = path.read_bytes(); text = source_bytes.decode('utf8')
            additional_hashes[source['file_path']] = hashlib.sha256(source_bytes).hexdigest()
            additional_paths[source['file_path']] = path
            facts, run = extractor.extract(text, source)
            run['source_id'] = row['file_id']; extraction_runs.append(run)
            # Uninterpreted subject-bearing text must not silently disappear
            # from the supplied-corpus completion assessment.
            accepted_lines = {f.fields['extraction']['line_no'] for f in facts}
            scope = []
            for n, line in enumerate(text.splitlines(), 1):
                if n not in accepted_lines:
                    fact = make_fact(source['file_id'], f"{source['file_path']}#line={n}/unmapped",
                                     'unstructured', {'page_text': line}, parse_timestamp(source['captured_at']),
                                     parse_timestamp(source['captured_at']), nature='SCOPE')
                    if fact.identifiers: scope.append(fact)
            partial = bool(run['validation']['uncovered_lines'] or scope or not facts)
            corpus.facts.extend(facts + scope)
            corpus.coverage.append(Coverage(source['file_id'], source['file_path'], 'PARTIAL' if partial else 'PARSED',
                units=len(text.splitlines()), parsed_units=len(facts), facts=len(facts),
                issues=run['validation']['uncertainties']))
            mounted.append({**source, 'origin': 'fictional_operator_readback'})
            times[source['file_id']] = parse_timestamp(source['captured_at'])
        inputs = replace(inputs, evidence=inputs.evidence + mounted, evidence_times=times)
    pipeline = AuditPipeline(inputs, corpus)
    report = {'format': 'ghostproof.portfolio.v1', 'fictional': True,
              'runtime_ai': 'none — deterministic offline audit engine', 'application_model_calls': 0,
              'input_sha256': before, 'coverage': corpus.summary(),
              'coverage_issues': [asdict(item) for item in corpus.coverage if item.status != 'PARSED'],
              'cases': [inspect_request(pipeline, request) for request in sorted(inputs.requests, key=lambda r: r['case_id'])]}
    if extraction_runs:
        report.update(runtime_ai='optional source-validated extraction; inspect provider/fallback per source',
                      application_model_calls=sum(run['model_calls'] for run in extraction_runs),
                      extraction_runs=extraction_runs, unstructured_sha256=additional_hashes)
    if before != fingerprint(dataset, original_inputs): raise ValueError('Demo input files changed during the run')
    if any(hashlib.sha256(path.read_bytes()).hexdigest() != additional_hashes[name] for name, path in additional_paths.items()):
        raise ValueError('Unstructured source files changed during extraction')
    markdown = render_markdown(report)
    output.mkdir(parents=True, exist_ok=True)
    for name, text in [('report.md', markdown), ('report.json', json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2) + '\n')]:
        target = output / name
        if target.is_symlink(): raise ValueError('Refusing symlink report destination')
        target.write_text(text, encoding='utf8', newline='\n')
    return report, markdown, output
