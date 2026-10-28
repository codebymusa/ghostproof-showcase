# GhostProof

**An evidence-first deletion audit prototype for privacy operations and data engineers.**

A deletion worker's success message does not prove every copy is gone. GhostProof
links historical identities, reconstructs resource state at an audit cutoff and
explains remaining data, recreation paths and the verification still needed.

This MIT-licensed portfolio release contains only independently fictional demo
inputs and the reviewed engine. It is local, read-only and not a legal adviser,
compliance certification or service connected to real customer systems.

## Clone and run offline

Requires Python 3.11+ and a modern browser. No pip packages, credentials, Ollama,
frontend build or paid services are needed for the default offline mode.

```console
git clone https://github.com/codebymusa/ghostproof-showcase.git
cd ghostproof-showcase
python -X utf8 -B code/main.py dashboard --offline-only
```

Open **http://127.0.0.1:8765**. Stop with Ctrl+C. The server always binds to
localhost; `--offline-only` disables AI on the backend as well as in the UI.
Nothing is uploaded or deleted. Remediation is a proposed plan, not execution.

For a terminal report:

```console
python -X utf8 -B code/main.py demo
```

Reports are written to local ignored `artifacts/`. They are not served by the app.

## Three fictional walkthroughs

1. **Mira / retained records:** COMPLETE within the supplied corpus. Eight checks
   cover absent profile data, privacy-safe retained records and controlled flows.
2. **Talin / the old-email trail:** INCOMPLETE. An old email links to a surviving
   search copy and enabled connector. Follow the evidence citation and inspect
   disable-before-delete remediation, then verification of all relevant resources.
3. **Niva / conflicting readbacks:** INSUFFICIENT_EVIDENCE. Conflicting search
   observations and missing restore controls prevent a supported verdict. A clean
   later capture is displayed but excluded from the earlier audit cutoff.

These are real pipeline results, not scenario-name lookups. Expected outcomes live
only in tests. The original competition dataset, answers, evaluations, private
logs/traces and history are not distributed. The fictional policy is not law.
Condition prose describes supported typed checks; it is not an arbitrary
natural-language policy interpreter. Missing observations do not prove absence.

## Architecture

```text
request + identity history + manifested evidence + explicit policy
  -> grounded identifiers / resource references
  -> facts with source location, observation time and availability
  -> per-resource/per-copy state at audit cutoff (claims kept separate)
  -> deterministic policy, findings, ordered proposed actions and verification
  -> terminal report / local dashboard
```

The model never chooses the audit verdict. Unresolved cases remain visible.
COMPLETE is bounded to the supplied fictional corpus, not unsupplied systems.
PDF/image parsing is outside this small release: such inputs remain PENDING.

## Optional local Ollama integration

Offline is the default and performs **zero inference calls**. Optional AI mode
adds a separate fictional operator note; it is a different evidence corpus.
With Ollama and the model already installed locally, run:

```console
python -X utf8 -B code/main.py demo --ai --model llama3.2:3b --timeout 60
```

No weights are downloaded automatically. Ollama selects source lines, then strict
deterministic extraction validates literal identifiers, timestamps and observations.
Unsupported proposals are rejected. Missing service/malformed output uses labelled
offline fallback; valid empty replies remain evidence gaps. Cache hits are labelled
and revalidated; unknown token counts remain unavailable rather than zero.
Fallback success is not model success. No general AI accuracy advantage is claimed.

For deterministic extraction of the additional note without any model:

```console
python -X utf8 -B code/main.py demo --ai --provider offline
```

CLI settings: `--provider`, `--model`, `--endpoint`, `--timeout`; corresponding
`GHOSTPROOF_AI_*` environment settings also work. Endpoints must be credential-free
loopback URLs. Dashboard AI is opt-in: restart without `--offline-only`, choose
Local AI-assisted, and configure model/endpoint on the server. Its generation
timeout is bounded by `--ai-timeout` (default 60, maximum 120 seconds).

This bounded readback grammar is not general multilingual understanding, robust
prompt-injection defence or authentication of source truth. A supplied attestation
is not an independently executed production query. No hosted inference is provided.

## Tests

```console
python -X utf8 -B -m unittest discover -s tests -q
```

The 11 release tests cover actual fictional outcomes, citations/planning,
insufficient evidence/cutoffs, real HTTP integration, offline AI rejection, explicit
fallback and rejected citations. Fake model replies test validation only. A real
refused-loopback discovery test verifies fallback; neither is a live model-quality
evaluation. Offline demo and tests require no pre-existing model cache or API key.

## Licence and external components

Copyright (c) 2026 Musa Mashaba. Released under the [MIT License](LICENSE).
The MIT grant covers this release's owned code and fictional material; it does not
relicense external runtimes or model weights. No Python/Ollama/pypdf implementation,
model weights or other vendored library is bundled. No additional third-party
redistribution notice was identified as required for this source-only payload.

If you install optional external software/models, review their own terms:
[Python](https://docs.python.org/3/license.html),
[Ollama MIT](https://github.com/ollama/ollama/blob/main/LICENSE),
[Llama 3.2 agreement](https://github.com/meta-llama/llama-models/blob/main/models/llama3_2/LICENSE).
Distribution of those materials or offering a model-containing service is a
separate scope with its own obligations. No vendor endorsement is implied.
