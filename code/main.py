"""Local fictional showcase adapter. No competition or paid-provider commands."""
import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'code'))


def main():
    parser = argparse.ArgumentParser(description='GhostProof fictional local showcase')
    commands = parser.add_subparsers(dest='command', required=True)
    dashboard = commands.add_parser('dashboard', help='loopback-only read-only dashboard')
    dashboard.add_argument('--port', type=int, default=8765)
    dashboard.add_argument('--offline-only', action='store_true', help='reject AI requests on the backend')
    dashboard.add_argument('--ai-timeout', type=float, default=60)
    demo = commands.add_parser('demo', help='audit the fixed fictional scenarios')
    demo.add_argument('--ai', action='store_true', help='add fictional handover and enable optional extraction')
    demo.add_argument('--provider', choices=('ollama', 'offline'))
    demo.add_argument('--model')
    demo.add_argument('--endpoint')
    demo.add_argument('--timeout', type=float)
    args = parser.parse_args()
    try:
        if args.command == 'dashboard':
            from ghostproof.dashboard import serve_dashboard
            serve_dashboard(ROOT, port=args.port, ai_timeout=args.ai_timeout, offline_only=args.offline_only)
        else:
            from ghostproof.demo import run_demo
            config = None
            if args.ai:
                from ghostproof.local_extraction import ExtractionConfig
                config = ExtractionConfig.configured(provider=args.provider, model=args.model,
                    endpoint=args.endpoint, timeout=args.timeout)
            elif any(v is not None for v in (args.provider, args.model, args.endpoint, args.timeout)):
                raise ValueError('Extraction options require --ai')
            _, markdown, _ = run_demo(ROOT, ai_config=config)
            print(markdown)
        return 0
    except (ValueError, OSError):
        # Do not echo configuration, credentials, root paths or raw tracebacks.
        print('GhostProof could not run. Check local settings and try offline.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
