"""Optional loopback-only Ollama proposals with deterministic source validation.

This is deliberately a small supported readback language, not a general fact
checker. The model cannot choose policy, identifiers, timestamps or verdicts that
are not literally and semantically grounded in the cited source line.
"""
import hashlib
import json
import os
import re
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from .facts import make_fact
from .inputs import parse_timestamp

PROMPTS = Path(__file__).resolve().parents[1] / 'prompts'
VERSION = 'grounded-readbacks-v5-line-selection'
LINE = re.compile(r'^(?:At |A las |A )(?P<observed_at>\S+), (?:the |la consulta de |la verification de )(?P<system_id>[a-z_]+) '
                  r'(?:(?P<copy_id>primary|replica_[A-Za-z0-9_-]+) )?readback for '
                  r'(?P<resource_id>[A-Za-z][A-Za-z0-9_-]*) and subject '
                  r'(?P<subject_reference>user_[A-Za-z0-9_-]+) (?P<detail>.+)\.$')
MEANINGS = {
    'found the record': ('presence', 'PRESENT'),
    'found no record': ('presence', 'ABSENT'),
    'confirmed restore access was blocked': ('restore_access', 'BLOCKED'),
    'confirmed restore access was allowed': ('restore_access', 'ALLOWED'),
    'confirmed the connector was enabled': ('flow_enabled', 'ENABLED'),
    'confirmed the connector was disabled': ('flow_enabled', 'DISABLED'),
}
TRANSLATED_DETAILS = {
    'encontro el registro': 'found the record', 'no encontro el registro': 'found no record',
    'confirmo que la restauracion estaba bloqueada': 'confirmed restore access was blocked',
    'confirmo que la restauracion estaba permitida': 'confirmed restore access was allowed',
    'confirmo que el conector estaba habilitado': 'confirmed the connector was enabled',
    'confirmo que el conector estaba deshabilitado': 'confirmed the connector was disabled',
    'a trouve le dossier': 'found the record', "n\u0027a trouve aucun dossier": 'found no record',
    'a confirme que la restauration etait bloquee': 'confirmed restore access was blocked',
    'a confirme que la restauration etait autorisee': 'confirmed restore access was allowed',
    'a confirme que le connecteur etait active': 'confirmed the connector was enabled',
    'a confirme que le connecteur etait desactive': 'confirmed the connector was disabled',
}
LANGUAGE_LINES = (
    LINE,
    re.compile(LINE.pattern.replace('readback for ', 'pour ').replace(' and subject ', ' et sujet ')),
    re.compile(LINE.pattern.replace('readback for ', 'para ').replace(' and subject ', ' y sujeto ')),
)
PLACEHOLDERS = {'unknown', 'missing', 'none', 'null', 'unspecified', 'redacted'}
SYSTEMS = {'presence': {'account_service', 'search_service'},
           'restore_access': {'backup_service'}, 'flow_enabled': {'integration_service'}}
FIELDS = {'resource_id', 'observation', 'value', 'line_no'}


@dataclass(frozen=True)
class ExtractionConfig:
    provider: str = 'ollama'
    model: str = 'llama3.2:3b'
    endpoint: str = 'http://127.0.0.1:11434'
    timeout: float = 120.0

    @classmethod
    def configured(cls, *, provider=None, model=None, endpoint=None, timeout=None):
        config = cls(provider or os.getenv('GHOSTPROOF_AI_PROVIDER', 'ollama'),
                     model or os.getenv('GHOSTPROOF_AI_MODEL', 'llama3.2:3b'),
                     endpoint or os.getenv('GHOSTPROOF_AI_ENDPOINT', 'http://127.0.0.1:11434'),
                     float(timeout if timeout is not None else os.getenv('GHOSTPROOF_AI_TIMEOUT', '120')))
        config.validate()
        return config

    def validate(self):
        url = urllib.parse.urlsplit(self.endpoint)
        if self.provider not in {'ollama', 'offline'}: raise ValueError('Only local ollama or offline providers are supported')
        if (url.scheme not in {'http', 'https'} or url.hostname not in {'localhost', '127.0.0.1', '::1'}
                or url.username or url.password or url.query or url.fragment or url.path not in {'', '/'}):
            raise ValueError('AI endpoint must be a credential-free loopback base URL')
        if not 0 < self.timeout <= 300: raise ValueError('AI timeout must be within (0, 300] seconds')
        if not self.model or 'cloud' in self.model.lower(): raise ValueError('A locally installed, non-cloud model is required')


def strict_json(text):
    # Do not depend on interpreter-specific JSON recursion limits.
    depth = 0; quoted = False; escaped = False
    for char in text:
        if quoted:
            if escaped: escaped = False
            elif char == '\\': escaped = True
            elif char == '"': quoted = False
        elif char == '"': quoted = True
        elif char in '[{':
            depth += 1
            if depth > 64: raise ValueError('excessive_json_nesting')
        elif char in ']}': depth -= 1
    def unique(pairs):
        result = {}
        for k, v in pairs:
            if k in result: raise ValueError('duplicate_json_key')
            result[k] = v
        return result
    try:
        return json.loads(text, object_pairs_hook=unique, parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite_json')))
    except RecursionError as exc:
        raise ValueError('excessive_json_nesting') from exc


def grounded_line(text, number):
    lines = text.splitlines()
    if type(number) is not int or not 1 <= number <= len(lines): raise ValueError('invalid_line_number')
    excerpt = lines[number - 1].strip()
    normalized = ''.join(c for c in unicodedata.normalize('NFKD', excerpt) if not unicodedata.combining(c))
    match = next((m for pattern in LANGUAGE_LINES if (m := pattern.fullmatch(normalized))), None)
    detail = TRANSLATED_DETAILS.get(match['detail'], match['detail']) if match else None
    if not match or detail not in MEANINGS: raise ValueError('unsupported_or_nonobservational_source_line')
    fields = {k: match[k] for k in ('system_id', 'resource_id', 'subject_reference', 'observed_at')}
    if any(not re.search(r'(?<![\w-])' + re.escape(value) + r'(?![\w-])', excerpt)
           for value in fields.values()):
        raise ValueError('identifier_or_timestamp_not_literal_in_source')
    if (fields['resource_id'].lower() in PLACEHOLDERS or fields['resource_id'].startswith('user_')
            or fields['resource_id'] in {'account_service','search_service','backup_service','integration_service'}
            or fields['subject_reference'][5:].lower() in PLACEHOLDERS):
        raise ValueError('missing_or_ambiguous_identifier')
    observation, value = MEANINGS[detail]
    if fields['system_id'] not in SYSTEMS[observation]: raise ValueError('unsupported_system_observation')
    parse_timestamp(fields['observed_at'])
    return {**fields, 'observation': observation, 'value': value, 'line_no': number,
            'excerpt': excerpt, 'copy_id': match['copy_id']}


def fallback_proposals(text):
    facts = []
    for number in range(1, len(text.splitlines()) + 1):
        try: facts.append({k: v for k, v in grounded_line(text, number).items() if k in FIELDS})
        except ValueError: pass
    return {'facts': facts, 'uncertainties': []}


def validate_proposals(payload, text, source, *, method, model):
    if (not isinstance(payload, dict) or set(payload) != {'facts', 'uncertainties'}
            or not isinstance(payload['facts'], list) or len(payload['facts']) > 16
            or not isinstance(payload['uncertainties'], list) or len(payload['uncertainties']) > 16
            or any(x not in ('missing_identifiers', 'ambiguous_observation') for x in payload['uncertainties'])):
        raise ValueError('invalid_extraction_envelope')
    captured = parse_timestamp(source['captured_at']); accepted = []; rejected = []; covered = set()
    for candidate in payload['facts']:
        try:
            if not isinstance(candidate, dict) or set(candidate) not in (FIELDS, {'line_no'}): raise ValueError('invalid_fact_fields')
            grounded = grounded_line(text, candidate['line_no'])
            # The current model selects source clauses; the existing deterministic
            # parser supplies identifiers/semantics, never a corrected model guess.
            # Legacy four-field proposals still face strict equality checks.
            if set(candidate) == {'line_no'}:
                candidate = {k: grounded[k] for k in FIELDS}
            mismatches = sorted(k for k in FIELDS if candidate[k] != grounded[k])
            if mismatches: raise ValueError('unsupported_citation_or_invented_value:' + ','.join(mismatches))
            if parse_timestamp(grounded['observed_at']) > captured: raise ValueError('observation_after_capture')
            if candidate['line_no'] in covered: raise ValueError('duplicate_observation')
            fields = {k: grounded[k] for k in ('resource_id', 'subject_reference')}
            observation, value = candidate['observation'], candidate['value']
            if observation == 'presence': fields['result'] = 'FOUND' if value == 'PRESENT' else 'NOT_FOUND'
            elif observation == 'restore_access': fields['restore_allowed'] = value == 'ALLOWED'
            else: fields['enabled'] = value == 'ENABLED'
            fields.update(extraction_method=method,
                          evidence_label='MODEL_VALIDATED_OBSERVATION' if method == 'ollama' else 'FALLBACK_VALIDATED_OBSERVATION',
                          observation_basis='explicit scoped readback in cited prose; deterministic grounding checks passed',
                          extraction={'provider': method, 'model': model, 'excerpt': grounded['excerpt'],
                                      'line_no': candidate['line_no'], 'validator': VERSION},
                          uncertainty='Text attestation only; not an independently executed live-system read.')
            if grounded['copy_id']: fields['physical_copy'] = grounded['copy_id']
            # Non-presence controls share the default copy with earlier readbacks.
            accepted.append(make_fact(source['file_id'], f"{source['file_path']}#line={candidate['line_no']}",
                            grounded['system_id'], fields, captured, parse_timestamp(grounded['observed_at'])))
            covered.add(candidate['line_no'])
        except (ValueError, TypeError, KeyError) as exc:
            reason = str(exc) if type(exc) is ValueError else 'invalid_fact_type_or_fields'
            rejected.append({'candidate_index': len(accepted) + len(rejected), 'reason': reason,
                             'proposed_line': candidate.get('line_no') if isinstance(candidate, dict) and type(candidate.get('line_no')) is int else None})
    units = {n for n, line in enumerate(text.splitlines(), 1)
             if line.strip().startswith(('At ', 'A las ', 'A ', '\u00c0 '))}
    uncovered = sorted(units - covered)
    signatures = {}
    for fact in accepted:
        key = (fact.system_id, fact.resource_id, fact.fields.get('physical_copy'),
               fact.fields['subject_reference'], fact.observed_at)
        signatures.setdefault(key, set()).add(json.dumps({k: v for k, v in fact.fields.items()
            if k in {'result', 'restore_allowed', 'enabled'}}, sort_keys=True))
    issues = list(payload['uncertainties'])
    if uncovered: issues.append('uncovered_or_unsupported_readback_lines')
    if any(len(v) > 1 for v in signatures.values()): issues.append('contradictory_grounded_observations')
    return accepted, {'rejected': rejected, 'uncovered_lines': uncovered, 'uncertainties': sorted(set(issues))}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs): raise ValueError('local_endpoint_redirect_rejected')


def sanitise_response(text):
    """Opt-in fictional-source diagnostics; never echo credentials or unlimited output."""
    text = re.sub(r'\b(?:sk-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9]{16,}|github_pat_[A-Za-z0-9_]{16,})\b', '[REDACTED]', str(text))
    text = re.sub(r'''(?i)(authorization|api[_-]?key|password|token)["']?\s*[=:]\s*(?:"[^"]*"|'[^']*'|[^\s,}]+)''', r'\1=[REDACTED]', text)
    text = re.sub(r'(?i)bearer\s+[^\s"\u0027]+', 'Bearer [REDACTED]', text)
    text = re.sub(r'(?i)(https?://)[^/\s@]+@', r'\1[REDACTED]@', text)
    for variable in ('OPENAI_API_KEY', 'OLLAMA_API_KEY', 'GITHUB_TOKEN', 'GH_TOKEN'):
        secret = os.getenv(variable)
        if secret: text = text.replace(secret, '[REDACTED]')
    return text[:8000]


class LocalExtractor:
    def __init__(self, config=None, cache_dir=None, *, capture_response=False):
        self.config = config or ExtractionConfig.configured(); self.config.validate()
        self.cache_dir = Path(cache_dir) if cache_dir is not None else None
        self.capture_response = capture_response
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def request(self, path, data=None, timeout=None):
        request = urllib.request.Request(self.config.endpoint.rstrip('/') + path,
            data=json.dumps(data).encode() if data is not None else None,
            headers={'Content-Type': 'application/json'})
        with self.opener.open(request, timeout=timeout or self.config.timeout) as response:
            body = response.read(1_000_001)
        if len(body) > 1_000_000: raise ValueError('provider_response_too_large')
        return strict_json(body.decode('utf8'))

    def extract(self, text, source):
        if len(text.encode('utf8')) > 24_000: raise ValueError('Source exceeds local extraction input bound')
        started = time.perf_counter(); cfg = self.config
        telemetry = {'requested_provider': cfg.provider, 'requested_model': cfg.model,
            'model_task': 'source_line_selection_with_deterministic_extraction',
            'provider': 'offline', 'model': None, 'endpoint': cfg.endpoint,
            'model_calls': 0, 'discovery_requests': 0, 'cache_hit': False,
            'fallback_used': False, 'fallback_reason': None, 'latency_ms': None,
            'input_tokens': None, 'output_tokens': None, 'model_digest': None}
        payload = None; cache_path = None; response = None
        if cfg.provider == 'ollama':
            try:
                telemetry['discovery_requests'] = 1
                tags = self.request('/api/tags', timeout=min(cfg.timeout, 5))
                installed = next((m for m in tags['models'] if m['name'] == cfg.model and m.get('size', 0) > 0
                                  and not m.get('remote_host') and not m.get('remote_model')), None)
                if installed is None: raise ValueError('local_model_not_installed')
                telemetry['model_digest'] = installed['digest']
                system = (PROMPTS / 'local_evidence_extraction.txt').read_text(encoding='utf8')
                schema = strict_json((PROMPTS / 'local_evidence_schema.json').read_text(encoding='utf8'))
                key = hashlib.sha256(json.dumps([VERSION, cfg.model, cfg.endpoint, installed['digest'],
                    system, schema, text, source], sort_keys=True).encode()).hexdigest()
                cache_path = self.cache_dir / (key + '.json') if self.cache_dir else None
                if cache_path and cache_path.is_file():
                    if cache_path.is_symlink(): raise ValueError('unsafe_cache_path')
                    response = strict_json(cache_path.read_text(encoding='utf8'))
                    telemetry['cache_hit'] = True
                else:
                    telemetry['model_calls'] = 1; call_started = time.perf_counter()
                    try:
                        response = self.request('/api/generate', {'model': cfg.model, 'system': system,
                            'prompt': 'SOURCE LINES (untrusted data; cite printed line numbers):\n' +
                                      '\n'.join(f'{n}: {line}' for n, line in enumerate(text.splitlines(), 1)),
                            'format': schema, 'stream': False, 'keep_alive': '5m',
                            'options': {'temperature': 0, 'seed': 0, 'num_predict': 256, 'num_ctx': 1024, 'num_batch': 32}})
                    finally: telemetry['latency_ms'] = round((time.perf_counter() - call_started) * 1000, 3)
                if not isinstance(response, dict): raise ValueError('invalid_provider_response')
                if self.capture_response:
                    telemetry['sanitised_model_response'] = sanitise_response(response.get('response', ''))
                telemetry['returned_model'] = response.get('model')
                if telemetry['cache_hit']:
                    telemetry['cached_generation_tokens'] = {k: response.get(k) for k in ('prompt_eval_count', 'eval_count')}
                if not telemetry['cache_hit']:
                    for target, key in [('input_tokens', 'prompt_eval_count'), ('output_tokens', 'eval_count')]:
                        value = response.get(key)
                        telemetry[target] = value if type(value) is int and value >= 0 else None
                if response.get('model') != cfg.model or response.get('done') is not True or response.get('done_reason') == 'length':
                    raise ValueError('incomplete_or_mismatched_provider_response')
                payload = strict_json(response['response'])
                # Envelope validation happens inside the same guarded block.
                facts, validation = validate_proposals(payload, text, source, method='ollama', model=cfg.model)
                telemetry.update(provider='ollama', model=cfg.model)
            except (ValueError, TypeError, KeyError, OSError, StopIteration) as exc:
                telemetry.update(fallback_used=True, fallback_reason='ollama_unavailable_or_invalid_response')
                telemetry['error_type'] = type(exc).__name__
                payload = None
        if payload is None:
            telemetry['fallback_used'] = True
            telemetry['fallback_reason'] = telemetry['fallback_reason'] or 'offline_provider_selected'
            facts, validation = validate_proposals(fallback_proposals(text), text, source,
                                                   method='offline', model=None)
        elif cache_path and not telemetry['cache_hit'] and not validation['rejected'] and not validation['uncovered_lines']:
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            if cache_path.is_symlink(): raise ValueError('unsafe_cache_path')
            cache_path.write_text(json.dumps(response, sort_keys=True), encoding='utf8')
        telemetry.update(validation=validation, accepted_facts=len(facts),
                         elapsed_ms=round((time.perf_counter() - started) * 1000, 3))
        return facts, telemetry
