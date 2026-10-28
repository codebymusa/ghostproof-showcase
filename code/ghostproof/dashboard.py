"""Loopback-only read-only fictional demos, never a general file server."""
import json
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from .demo import run_demo
from .inputs import load_inputs
from .local_extraction import ExtractionConfig, strict_json

ASSETS = Path(__file__).resolve().parents[1] / 'dashboard'
STATIC = {'/': ('index.html', 'text/html; charset=utf-8'),
          '/app.js': ('app.js', 'text/javascript; charset=utf-8'),
          '/style.css': ('style.css', 'text/css; charset=utf-8')}


class BusyError(Exception):
    pass


class AIConfigurationError(Exception):
    pass


class DashboardApp:
    def __init__(self, root, *, ai_config=None, ai_timeout=60, ai_enabled=True):
        self.root = Path(root).resolve()
        # Offline startup must not depend on Ollama settings or credentials.
        self.ai_config = ai_config
        self.ai_timeout = ai_config.timeout if ai_config else ai_timeout
        self.ai_enabled = ai_enabled
        if not 0 < self.ai_timeout <= 120:
            raise ValueError('Dashboard AI timeout must be within (0, 120] seconds')
        self.lock = threading.Lock()
        inputs = load_inputs(self.root / 'demo/dataset', expected_request_count=None)
        guide = json.loads((ASSETS / 'scenarios.json').read_text(encoding='utf8'))
        self.scenarios = [{'case_id': r['case_id'], 'email': r['email'],
                           'title':guide.get(r['case_id'], {}).get('title',r['case_id']),
                           'description':guide.get(r['case_id'], {}).get('description','Inspect the supplied fictional evidence.')}
                          for r in inputs.requests]

    def audit(self, case_id, mode='offline'):
        if type(case_id) is not str or case_id not in {r['case_id'] for r in self.scenarios}:
            raise ValueError('Choose a fictional demo scenario')
        if mode not in ('offline', 'ai'):
            raise ValueError('Mode must be offline or ai')
        if mode == 'ai' and not self.ai_enabled:
            raise ValueError('AI is disabled for this showcase')
        config = None
        if mode == 'ai':
            try:
                config = self.ai_config or ExtractionConfig.configured(provider='ollama', timeout=self.ai_timeout)
                config.validate()
                if config.provider != 'ollama': raise ValueError('Local Ollama only')
            except ValueError as exc:
                raise AIConfigurationError('Local AI configuration is invalid. Offline mode remains available; no model call or verdict was produced.') from exc
        if not self.lock.acquire(blocking=False):
            raise BusyError('Another audit is running. Wait for it to finish before trying again.')
        try:
            report, _, _ = run_demo(self.root, dataset=self.root / 'demo/dataset',
                output_dir=self.root / 'artifacts/portfolio_dashboard/runs' / uuid.uuid4().hex,
                ai_config=config,
                unstructured_manifest=self.root / 'demo/unstructured/manifest.json')
            case = next(c for c in report['cases'] if c['case_id'] == case_id)
            # Explicit projection: no root paths, environment, traces or raw replies.
            runs = [{k: r.get(k) for k in ('source_id', 'requested_provider', 'requested_model',
                'provider', 'model', 'returned_model', 'model_calls', 'cache_hit', 'fallback_used',
                'fallback_reason', 'error_type', 'latency_ms', 'input_tokens', 'output_tokens',
                'cached_generation_tokens', 'accepted_facts', 'validation')} for r in report.get('extraction_runs', [])]
            return {'fictional': True, 'mode': mode, 'case': case, 'coverage': report['coverage'],
                    'coverage_issues': report['coverage_issues'], 'extraction_runs': runs,
                    'application_model_calls': report['application_model_calls']}
        finally:
            self.lock.release()


class DashboardServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, app, port=8765):
        self.app = app
        # No host override: never expose this development server to a LAN.
        super().__init__(('127.0.0.1', port), DashboardHandler)


class DashboardHandler(BaseHTTPRequestHandler):
    server_version = 'GhostProofLocal'

    def log_message(self, *args):
        pass

    def send_payload(self, status, payload, content_type='application/json; charset=utf-8'):
        body = payload if isinstance(payload, bytes) else json.dumps(payload, ensure_ascii=False).encode('utf8')
        self.send_response(status)
        for key, value in {'Content-Type': content_type, 'Content-Length': str(len(body)),
                'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff',
                'Referrer-Policy': 'no-referrer', 'X-Frame-Options': 'DENY',
                'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self'; "
                "img-src 'self' data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"}.items():
            self.send_header(key, value)
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def trusted_request(self, *, static=False):
        hosts = {f'127.0.0.1:{self.server.server_port}', f'localhost:{self.server.server_port}'}
        origin = self.headers.get('Origin')
        return (self.headers.get('Host') in hosts
                and (static or (origin is None or origin in {'http://' + host for host in hosts})
                     and self.headers.get('Sec-Fetch-Site', 'none') in {'none', 'same-origin'}))

    def do_GET(self):
        if not self.trusted_request(static=urlsplit(self.path).path in STATIC):
            return self.send_payload(403, {'error': 'Local same-origin requests only'})
        path = urlsplit(self.path)
        if path.query or path.fragment:
            return self.send_payload(404, {'error': 'Not found'})
        if path.path == '/api/scenarios':
            return self.send_payload(200, {'scenarios': self.server.app.scenarios,
                'ai_timeout_seconds': self.server.app.ai_timeout,
                'ai_enabled': self.server.app.ai_enabled})
        if path.path in STATIC:
            filename, content_type = STATIC[path.path]
            return self.send_payload(200, (ASSETS / filename).read_bytes(), content_type)
        self.send_payload(404, {'error': 'Not found'})

    def do_POST(self):
        if not self.trusted_request():
            return self.send_payload(403, {'error': 'Local same-origin requests only'})
        if self.path != '/api/audit':
            return self.send_payload(404, {'error': 'Not found'})
        if self.headers.get('Content-Type', '').split(';')[0].strip() != 'application/json':
            return self.send_payload(415, {'error': 'JSON request required'})
        try:
            length = int(self.headers.get('Content-Length', '0'))
            if not 0 < length <= 1024 or self.headers.get('Transfer-Encoding'):
                return self.send_payload(413, {'error': 'Invalid request size'})
            self.connection.settimeout(10)
            payload = strict_json(self.rfile.read(length).decode('utf8'))
            if not isinstance(payload, dict) or set(payload) != {'case_id', 'mode'}:
                raise ValueError('Unexpected request fields')
            if not isinstance(payload['mode'], str):
                raise ValueError('Invalid mode')
            self.send_payload(200, self.server.app.audit(payload['case_id'], payload['mode']))
        except BusyError as exc:
            self.send_payload(409, {'error': str(exc)})
        except AIConfigurationError as exc:
            self.send_payload(503, {'error': str(exc)})
        except (ValueError, TypeError):
            self.send_payload(400, {'error': 'Invalid scenario, mode or request format'})
        except Exception:
            self.send_payload(500, {'error': 'The audit could not finish. No verdict was produced. Check fixture integrity and retry offline.'})


def serve_dashboard(root, *, port=8765, ai_timeout=60, offline_only=False):
    if not 1 <= port <= 65535:
        raise ValueError('Dashboard port must be between 1 and 65535')
    server = DashboardServer(DashboardApp(root, ai_timeout=ai_timeout, ai_enabled=not offline_only), port)
    print(f'GhostProof fictional audit dashboard: http://127.0.0.1:{server.server_port}', flush=True)
    print('Loopback only. Offline by default. Read-only plans; Ctrl+C to stop.', flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
