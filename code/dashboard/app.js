'use strict';
const $ = id => document.getElementById(id);
const form = $('audit-form');
let aiTimeout = 60;
const scenarioGuide = new Map();
function scenarioHelp() {
  $('scenario-help').textContent = scenarioGuide.get($('scenario').value)?.description || 'Each request and every source is fictional.';
}

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) node.setAttribute(key, value);
  for (const child of children.flat(Infinity)) {
    if (child !== null && child !== undefined) node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}
const human = text => String(text || 'unavailable').replaceAll('_', ' ').toLowerCase();
function time(value) {
  if (!value || Number.isNaN(Date.parse(value))) return 'Unavailable';
  return new Intl.DateTimeFormat('en-GB', {dateStyle:'medium', timeStyle:'short', timeZone:'UTC'}).format(new Date(value)) + ' UTC';
}
const detail = (title, value) => el('div', {class:'data-item'}, el('dt', {}, title), el('dd', {}, value));
const notice = (text, kind = '') => el('div', {class:'notice ' + kind}, text);
const empty = text => el('p', {class:'empty'}, text);
const technical = (title, value) => el('details', {}, el('summary', {}, title), el('pre', {}, JSON.stringify(value, null, 2)));
function list(items) { return el('ul', {class:'review-list'}, items.map(item => el('li', {}, item))); }
function table(headers, rows) {
  const head = el('thead', {}, el('tr', {}, headers.map(h => el('th', {scope:'col'}, h))));
  const body = el('tbody', {}, rows.map(row => el('tr', {}, row.map(cell => el('td', {}, cell)))));
  return el('div', {class:'table-wrap', role:'region', 'aria-label': headers.join(', '), tabindex:'0'},
    el('table', {}, head, body));
}
function modeHelp() {
  $('mode-help').textContent = $('mode').value === 'ai'
    ? `Adds the fictional operator note. Tries local Ollama (up to ${aiTimeout}s generation); cache or offline fallback is labelled. No paid calls.`
    : 'Deterministic baseline. No network or model calls. The additional operator note is not loaded.';
}
function evidenceLabel(fact) {
  if (fact.evidence_label === 'MODEL_VALIDATED_OBSERVATION') return 'Model-selected source line → deterministic fact extraction';
  if (fact.evidence_label === 'FALLBACK_VALIDATED_OBSERVATION') return 'Offline deterministic extraction • not a model observation';
  if (fact.nature === 'CLAIM') return 'Operational claim • not proof of resulting state';
  if (fact.nature === 'SCOPE') return 'Unmapped scope • unresolved evidence';
  return 'Direct / structured observation • deterministic parsing';
}
function render(data) {
  const c = data.case, req = c.request;
  const verdictText = {
    COMPLETE: ['Deletion complete', 'Every linked resource meets its required final state within the supplied fictional evidence corpus. This does not certify unsupplied systems.'],
    INCOMPLETE: ['Deletion incomplete', 'The engine found supported policy violations or recreation risks. Follow the proposed order below, then verify every required final state.'],
    INSUFFICIENT_EVIDENCE: ['Insufficient evidence', 'No supported deletion verdict. Conflicting or missing observations prevent a confident decision. Proven checks remain visible; uncertainty is not a finding of completion.'],
    NOT_APPLICABLE: ['Deletion not authorised', 'This request does not authorise deletion. No deletion remediation is proposed.']
  };
  const [heading, description] = verdictText[c.portfolio_status] || ['Review required', 'The engine could not establish a supported verdict.'];
  const verdict = $('verdict');
  verdict.className = 'verdict ' + ({INCOMPLETE:'incomplete', INSUFFICIENT_EVIDENCE:'insufficient'}[c.portfolio_status] || '');
  verdict.replaceChildren(el('p', {class:'eyebrow'}, `AUDIT RESULT / ${c.case_id}`),
    el('h2', {id:'verdict-title'}, heading), el('span', {class:'pill neutral'}, c.portfolio_status), el('p', {}, description));
  if (c.requires_review) verdict.append(list(c.review_reasons.length ? c.review_reasons : c.review_warnings));
  $('metrics').replaceChildren(...[
    ['Linked resource copies', c.resources.length], ['Evidence-backed steps', c.steps.filter(s => s.evidence_id).length],
    ['Proposed future steps', c.steps.filter(s => !s.evidence_id).length]
  ].map(([label,value]) => el('div', {class:'metric'}, el('span', {}, label), el('strong', {}, value))));

  $('request-content').replaceChildren(el('p', {class:'request-text'}, req.request_text),
    el('dl', {class:'data-grid'}, detail('Request email',req.email), detail('Identity resolution', c.identity.status),
      detail('Stable subject', c.identity.user_ids.join(', ') || 'Unresolved'), detail('Audit cutoff', time(req.audit_at)),
      detail('Requested', time(req.requested_at)), detail('Workflow claim — not state proof', `${req.reported_status} at ${time(req.reported_at)}`)),
    el('h3', {}, 'Current & historical identity links'),
    table(['Identifier','Relation','Available','Source / location'], c.identity.assertions.map(a => [
      `${a.kind}: ${a.value}`, a.relation, time(a.available_at), `${a.source_id} · ${a.location}`])));
  if (c.identity.shared_identifiers.length) $('request-content').append(notice('Shared identifiers require explicit ownership checks.'), technical('Shared identifier details', c.identity.shared_identifiers));

  const events = c.resources.flatMap(r => r.timeline.map(f => ({...f, resource:r.resource_id, system:r.system_id, copy:r.copy_id})));
  events.sort((a,b) => Date.parse(a.observed_at)-Date.parse(b.observed_at) || Date.parse(a.available_at)-Date.parse(b.available_at) || a.resource.localeCompare(b.resource));
  $('timeline').replaceChildren(events.length ? el('ol', {class:'timeline'}, events.map(f => {
    const item = el('li', {id:`evidence-${events.indexOf(f)}`, class:'timeline-item' + (f.eligible_at_audit ? '' : ' excluded')},
      el('div', {class:'time-line'}, el('span', {}, `Observed / effective: ${time(f.observed_at)}`), el('span', {}, `Available: ${time(f.available_at)}`)),
      el('span', {class:'event-label' + (f.nature === 'CLAIM' ? ' claim-label' : '')}, evidenceLabel(f)),
      el('p', {class:'event-title'}, `${f.system} / ${f.resource} [${f.copy}]`),
      el('p', {class:'event-fields'}, f.nature === 'CLAIM' ? 'Result remains a claim, not a confirmed record state.' : `Observed record presence: ${f.observed_state}. ${f.selected ? 'Selected in state reconstruction.' : 'Historical or superseded observation.'}`),
      el('code', {class:'citation'}, `${f.source_id} · ${f.location}`));
    const controls = Object.entries(f.observed_fields).filter(([key]) => ['result','enabled','scheduler_registered','restore_allowed','account_status','retention_until','hold_active','reported_result'].includes(key));
    if (controls.length) item.append(el('p', {class:'event-fields'}, controls.map(([k,v]) => `${k}: ${JSON.stringify(v)}`).join(' · ')));
    if (!f.eligible_at_audit) item.append(el('p', {class:'excluded-label'}, 'EXCLUDED FROM DECISION — outside audit cutoff / temporal eligibility.'));
    if (f.extraction) item.append(el('blockquote', {class:'excerpt'}, f.extraction.excerpt),
      el('p', {class:'small'}, `Source line ${f.extraction.line_no}; ${f.extraction.provider} / ${f.extraction.model || 'no model'}. Text attestation, not an independently executed live-system query.`));
    item.append(technical('Observed fields & linked source locations', {fields:f.observed_fields, related_locations:f.related_locations}));
    return item;
  })) : empty('No linked observations. Missing evidence is not proof of absence.'));
  $('resource-states').replaceChildren(el('div', {class:'resource-grid'}, c.resources.map(r => el('article', {class:'resource'},
    el('h4', {}, `${r.system_id} / ${r.resource_id} [${r.copy_id}]`), el('span', {class:'pill neutral'}, r.state),
    el('p', {}, `${r.policy.category} · ${r.policy.required_action || 'Unestablished policy'} · ${r.policy.outcome}`),
    ...r.policy.reasons.map(reason => el('p', {}, reason))))));

  $('steps').replaceChildren(...[['FINDING','Findings'],['REMEDIATION','Proposed remediation'],['VERIFICATION','Verification checks']].map(([phase,title]) => {
    const steps = c.steps.filter(s => s.phase === phase);
    function citation(s) {
      const matches = events.filter(f => f.source_id === s.evidence_id && f.resource === s.resource_id && f.system === s.system_id);
      const proof = matches.find(f => s.source_locations.includes(f.location)) || matches.find(f => f.eligible_at_audit && f.selected);
      return el('div', {}, el('code', {class:'citation'}, `${s.evidence_id} · ${s.source_locations.join('; ') || 'Source location unavailable'}`),
        proof ? el('a', {href:`#evidence-${events.indexOf(proof)}`, class:'evidence-link'}, 'Locate cited evidence in timeline') : null);
    }
    return el('div', {}, el('h3', {}, title), steps.length ? el('ol', {class:'step-list'}, steps.map(s =>
      el('li', {class:'step'}, el('span', {class:'step-no', 'aria-label':`Step ${s.step_no}`}, s.step_no), el('div', {},
        el('strong', {}, human(s.operation)), el('p', {}, `${s.system_id} / ${s.resource_id} → ${s.state}`),
        s.evidence_id ? citation(s)
          : el('p', {class:'small'}, 'Future work only · no execution evidence · not performed')))))
      : empty(phase === 'FINDING' ? 'No supported findings reported.' : 'No supported steps in this phase.'));
  }));
  const reasons = [...c.review_reasons, ...c.review_warnings, ...c.schema_errors];
  $('review-content').replaceChildren(reasons.length ? list(reasons) : notice('No unresolved conditions within the supplied fictional corpus.', 'good'));
  if (c.export_blockers.length) $('review-content').append(technical('Internal engine review / export blockers', c.export_blockers));
  if (data.coverage_issues.length) $('review-content').append(technical('Shared fictional-corpus coverage gaps (not all apply to this subject)', data.coverage_issues));
  renderExtraction(data);
  $('welcome').hidden = true; $('result').hidden = false;
  verdict.focus();
}
function renderExtraction(data) {
  const target = $('extraction-content'); target.replaceChildren();
  if (!data.extraction_runs.length) {
    target.append(notice('OFFLINE BASELINE · deterministic extraction and policy · zero model calls.', 'good'),
      el('p', {class:'small'}, 'No Ollama request, no model cache, no operator-note fallback. Only the original fictional baseline evidence is loaded.'));
    return;
  }
  target.append(el('p', {class:'section-intro'}, 'AI mode adds the fictional operator handover to the shared corpus. Its facts may not concern the selected subject. Policy decisions remain deterministic.'));
  for (const run of data.extraction_runs) {
    const status = run.fallback_used ? 'OFFLINE FALLBACK — no successful model extraction for this source'
      : !run.accepted_facts ? 'OLLAMA RESPONSE — no source-supported facts accepted'
      : run.cache_hit ? 'OLLAMA CACHE — revalidated selection, no new generation'
      : run.provider === 'ollama' ? 'OLLAMA GENERATION — proposals independently validated'
      : 'Extraction provider unavailable';
    const m = value => value === null || value === undefined ? 'Unavailable / no new generation' : String(value);
    const block = el('article', {class:'extraction-run'}, notice(status, run.fallback_used || !run.accepted_facts ? '' : 'good'),
      el('h3', {}, run.source_id), el('dl', {class:'data-grid'},
        detail('Requested provider / model', `${run.requested_provider} / ${run.requested_model}`),
        detail('Provider of admitted facts', `${run.provider} / ${run.model || 'no model'}`),
        detail('New generation attempts', run.model_calls), detail('Cache hit / fallback', `${run.cache_hit} / ${run.fallback_used}`),
        detail('Accepted facts (shared corpus)', run.accepted_facts), detail('Generation latency (ms)', m(run.latency_ms)),
        detail('New input / output tokens', `${m(run.input_tokens)} / ${m(run.output_tokens)}`)));
    if (run.fallback_used) block.append(el('p', {class:'small'}, `Reason: ${run.fallback_reason}; ${run.error_type || 'offline extraction'}. Fallback success is not model success.`));
    const v = run.validation || {};
    if (v.uncertainties?.length) block.append(el('h3', {}, 'Uncertainty'), list(v.uncertainties));
    if (v.rejected?.length) block.append(notice(`${v.rejected.length} unsupported or duplicate proposal(s) rejected. They do not enter the audit.`), technical('Validation failures', v.rejected));
    if (v.uncovered_lines?.length) block.append(notice(`Uncovered source lines: ${v.uncovered_lines.join(', ')}. Missing extraction remains a coverage gap.`));
    if (run.cached_generation_tokens) block.append(technical('Historical cached tokens — not counted as new usage', run.cached_generation_tokens));
    target.append(block);
  }
  target.append(el('p', {class:'small'}, 'Text-supported observations are not authenticated queries. The small model may select claims or instructions; deterministic grounding must reject them.'));
}
form.addEventListener('submit', async event => {
  event.preventDefault();
  $('error').hidden = true; $('result').hidden = true; $('welcome').hidden = true;
  const body = {case_id:$('scenario').value, mode:$('mode').value};
  for (const id of ['run-audit','scenario','mode']) $(id).disabled = true;
  $('main').setAttribute('aria-busy','true');
  $('progress').textContent = body.mode === 'ai' ? 'Checking local Ollama and validating evidence. This may take a minute…' : 'Running the deterministic audit engine…';
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), (aiTimeout + 30) * 1000);
  try {
    const response = await fetch('/api/audit', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body), signal:controller.signal});
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Audit request failed. No new verdict was produced.');
    render(data);
    $('progress').textContent = `Audit finished: ${human(data.case.portfolio_status)}. ${data.application_model_calls} new model generation attempt(s).`;
  } catch (error) {
    $('error').textContent = error.name === 'AbortError' ? 'Browser wait timed out. No new verdict is shown. The local audit may still be running; wait before retrying.' : error.message;
    $('error').hidden = false; $('error').focus(); $('progress').textContent = 'Audit not displayed. No new verdict was produced for this view.';
  } finally {
    clearTimeout(timer); $('main').setAttribute('aria-busy','false');
    for (const id of ['run-audit','scenario','mode']) $(id).disabled = false;
  }
});
$('mode').addEventListener('change', modeHelp);
$('scenario').addEventListener('change', scenarioHelp);
(async () => {
  try {
    const response = await fetch('/api/scenarios');
    if (!response.ok) throw new Error('Could not load the local fictional scenarios.');
    const data = await response.json(); aiTimeout = data.ai_timeout_seconds;
    data.scenarios.forEach(s => scenarioGuide.set(s.case_id,s));
    if (!data.ai_enabled) {
      const option = $('mode').querySelector('option[value="ai"]');
      option.disabled = true; option.textContent = 'Local AI (disabled for showcase)';
    }
    $('ai-availability').textContent = data.ai_enabled
      ? 'AI is optional: it runs only on this server, with an installed Ollama model. Service failure uses labelled fallback; invalid settings show an error.'
      : 'Offline-only showcase. AI requests are disabled on the server; no Ollama, credentials or paid services are needed.';
    $('scenario-count').textContent = String(data.scenarios.length).padStart(2, '0');
    $('scenario').replaceChildren(...data.scenarios.map(s => el('option', {value:s.case_id}, s.title || `${s.case_id} · ${s.email}`)));
    $('scenario').disabled = false; $('run-audit').disabled = false;
    $('progress').textContent = 'Ready. Start with Mira, then compare Talin and Niva.'; modeHelp(); scenarioHelp();
  } catch (error) {
    $('error').textContent = error.message; $('error').hidden = false; $('progress').textContent = 'Unable to load demo fixtures.';
  }
})();
