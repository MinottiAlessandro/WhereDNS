const $ = (selector, parent = document) => parent.querySelector(selector);
const $$ = (selector, parent = document) => [...parent.querySelectorAll(selector)];
const escapeHTML = value => String(value ?? '').replace(/[&<>'"]/g, char => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[char]));
const safeToken = value => String(value || 'normal').toLowerCase().replace(/[^a-z0-9-]/g, '') || 'normal';
const finiteNumber = value => Number.isFinite(Number(value)) ? Number(value) : 0;

let attacks = [];
let flowSerial = 0;
const flowModels = new Map();

$$('.nav-link').forEach(button => button.addEventListener('click', () => showView(button.dataset.view)));

function showView(name) {
  if (!$(`#view-${CSS.escape(name)}`)) name = 'query';
  $$('.nav-link').forEach(button => button.classList.toggle('active', button.dataset.view === name));
  $$('.view').forEach(view => view.classList.toggle('active', view.id === `view-${name}`));
  history.replaceState(null, '', `#${name}`);
}

function options() {
  return {
    name: $('#domain').value.trim(), type: $('#qtype').value,
    server: $('#resolver').value.trim(), transport: $('#transport').value,
    use_cache: $('#cache').checked, dnssec: $('#dnssec').checked,
    recursion_desired: true, checking_disabled: false, edns_size: 1232
  };
}

$('#transport').addEventListener('change', event => {
  const placeholders = {udp: 'system default', tcp: 'system default', dot: 'resolver.example:853', doh: 'https://resolver.example/dns-query'};
  $('#resolver').placeholder = placeholders[event.target.value];
});

$('#query-form').addEventListener('submit', event => {
  event.preventDefault();
  runQuery(false);
});
$('#trace-button').addEventListener('click', () => runQuery(true));

async function runQuery(trace) {
  const state = $('#query-state');
  const result = $('#result');
  state.className = 'state-panel loading';
  state.innerHTML = `<div class="empty-mark">⌁</div><h2>${trace ? 'Walking from the root…' : 'Waiting for the resolver…'}</h2><p>Each network exchange has a bounded timeout.</p>`;
  result.classList.add('hidden');
  try {
    const payload = options();
    if (trace) payload.recursion_desired = false;
    const response = await fetch(trace ? '/api/trace' : '/api/query', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(payload)});
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Query failed');
    state.classList.add('hidden');
    result.classList.remove('hidden');
    result.innerHTML = trace ? renderTrace(data, payload) : renderResult(data, payload);
  } catch (error) {
    state.className = 'state-panel';
    state.innerHTML = `<div class="empty-mark">!</div><h2>Query did not complete</h2><p>${escapeHTML(error.message)}</p>`;
  }
}

function renderResult(data, request) {
  const allRecords = data.records || [];
  const records = allRecords.length ? allRecords.map(record => `<tr>
    <td><span class="section-tag">${escapeHTML(record.section)}</span></td><td><code>${escapeHTML(record.name)}</code></td>
    <td>${finiteNumber(record.ttl)}s</td><td><strong>${escapeHTML(record.type)}</strong></td><td><code>${escapeHTML(record.data)}</code><br><small>${escapeHTML(record.explanation)}</small></td>
  </tr>`).join('') : '<tr><td colspan="5">No records in the response sections.</td></tr>';
  const warnings = (data.warnings || []).map(warning => `<div class="warning">${escapeHTML(warning)}</div>`).join('');
  const explanations = (data.explanations || []).map(item => `<li><strong>${escapeHTML(item.subject)}</strong><span>${escapeHTML(item.text)}</span></li>`).join('');
  const flags = (data.flags || []).map(flag => `<span class="flag ${flag.enabled ? 'on' : ''}" title="${escapeHTML(flag.explanation)}">${escapeHTML(flag.code)}</span>`).join('');
  const cache = data.from_cache ? '<span class="badge">cache hit</span>' : '<span class="badge warn">network</span>';
  const dnssec = data.dnssec || {status: 'unknown', explanation: 'No DNSSEC evidence was returned.'};
  const wire = data.wire || {};
  return `<div class="summary-strip">
    <div class="summary-cell"><small>Question</small><strong>${escapeHTML(data.question?.name)} ${escapeHTML(data.question?.type)}</strong></div>
    <div class="summary-cell"><small>Status</small><strong>${escapeHTML(data.rcode)}</strong></div>
    <div class="summary-cell"><small>Source</small><strong>${cache}</strong></div>
    <div class="summary-cell"><small>Duration</small><strong>${finiteNumber(data.duration_ms).toFixed(2)} ms</strong></div>
    <div class="summary-cell"><small>Response</small><strong>${finiteNumber(wire.response_bytes)} bytes</strong></div>
  </div>
  ${renderFlowPanel(queryFlow(data, request))}
  <div class="result-grid">
    <div class="panel"><h2>Resource records</h2><table class="record-table"><thead><tr><th>Section</th><th>Name</th><th>TTL</th><th>Type</th><th>Data & meaning</th></tr></thead><tbody>${records}</tbody></table>
      <details><summary>Raw DNS wire message</summary><h3>Query · ${finiteNumber(wire.query_bytes)} bytes</h3><pre>${escapeHTML(wire.query_hex)}</pre><h3>Response · ${finiteNumber(wire.response_bytes)} bytes</h3><pre>${escapeHTML(wire.response_hex)}</pre></details>
    </div>
    <aside><div class="panel"><h2>Protocol reading</h2><div class="flag-row">${flags}</div><h3>DNSSEC · ${escapeHTML(dnssec.status)}</h3><p>${escapeHTML(dnssec.explanation)}</p>${warnings}<ul class="explain-list">${explanations}</ul></div></aside>
  </div>`;
}

function queryFlow(data, request) {
  const question = `${data.question?.name || request.name} ${data.question?.type || request.type}`;
  const records = data.records || [];
  const sections = ['answer', 'authority', 'additional'].map(section => {
    const count = records.filter(record => String(record.section).toLowerCase() === section).length;
    return `${section} ${count}`;
  }).join(' · ');
  const actors = [
    flowActor('learner', 'You', 'started the interrogation', 'user'),
    flowActor('tool', 'WhereDNS', 'built and explained the packet', 'tool')
  ];
  if (request.use_cache) actors.push(flowActor('cache', 'WhereDNS cache', data.from_cache ? 'answered this query' : 'checked before network', 'cache'));
  actors.push(flowActor('resolver', 'DNS resolver', data.from_cache ? `${data.server}; not contacted this run` : `${data.server} via ${data.transport}`, 'resolver'));

  const events = [flowEvent('learner', 'tool', `Ask ${question}`, `WhereDNS normalized the name, selected ${request.transport.toUpperCase()}, requested EDNS size ${request.edns_size}, and ${request.dnssec ? 'set' : 'did not set'} the DNSSEC OK bit.`, 'normal')];
  if (request.use_cache) {
    events.push(flowEvent('tool', 'cache', 'Lookup exact cache key', 'The key includes name, type, resolver, transport, DNSSEC/recursion/checking settings, and EDNS size.', 'normal'));
    events.push(flowEvent('cache', 'tool', data.from_cache ? 'Fresh cached response' : 'Cache miss', data.from_cache ? 'TTL-aware wire data was found locally, so no DNS server was contacted for this run.' : 'No fresh matching entry existed, so resolution continued over the selected transport.', data.from_cache ? 'cache' : 'warning'));
  }
  if (!data.from_cache) {
    events.push(flowEvent('tool', 'resolver', `${finiteNumber(data.wire?.query_bytes)}-byte DNS question`, `The recursive-desired flag was ${request.recursion_desired ? 'set' : 'clear'}. The resolver may use its own independent cache; WhereDNS cannot observe the resolver's internal upstream path in a single recursive exchange.`, 'normal'));
    events.push(flowEvent('resolver', 'tool', `${data.rcode} · ${finiteNumber(data.wire?.response_bytes)} bytes`, `${records.length} records returned (${sections}) in ${finiteNumber(data.duration_ms).toFixed(2)} ms using ${data.transport}.`, data.rcode === 'NOERROR' ? 'response' : 'warning'));
    if (request.use_cache && data.cache_expires) {
      events.push(flowEvent('tool', 'cache', 'Store until TTL expiry', `WhereDNS stored the wire response until ${new Date(data.cache_expires).toLocaleString()}.`, 'cache'));
    }
  }
  events.push(flowEvent('tool', 'learner', `Explain ${data.rcode}`, `Flags, DNSSEC evidence, record sections, timing, cache state, and raw bytes are displayed below the graph.`, 'response'));
  return {
    title: 'What happened during this interrogation',
    caption: data.from_cache
      ? 'This run stopped at the local WhereDNS cache. The upstream resolver shown at the right was not contacted.'
      : 'This is the observable client-to-resolver exchange. A recursive response does not expose the resolver’s internal root/TLD/authority work; use “Trace from root” to observe those hops directly.',
    actors, events
  };
}

function renderTrace(trace, request) {
  const steps = trace.steps || [];
  const stepCards = steps.map(step => `<article class="trace-step"><span class="step-number">${finiteNumber(step.number)}</span><div><strong>${escapeHTML(step.role)}</strong><small>${escapeHTML(step.server)}</small><small>${escapeHTML(step.address)}</small></div><div><strong>${escapeHTML(step.event)}</strong><small>${escapeHTML(step.explanation)}</small><small>${finiteNumber(step.duration_ms).toFixed(2)} ms · ${(step.records || []).length} records · ${step.from_cache ? 'WhereDNS cache' : escapeHTML(step.transport || 'udp')}</small></div></article>`).join('');
  return `<div class="summary-strip"><div class="summary-cell"><small>Iterative question</small><strong>${escapeHTML(trace.name)} ${escapeHTML(trace.type)}</strong></div><div class="summary-cell"><small>Outcome</small><strong>${trace.complete ? 'complete' : 'partial'}</strong></div><div class="summary-cell"><small>Hops</small><strong>${steps.length}</strong></div><div class="summary-cell"><small>Duration</small><strong>${finiteNumber(trace.duration_ms).toFixed(2)} ms</strong></div><div class="summary-cell"><small>Cache</small><strong>${request.use_cache ? 'allowed' : 'bypassed'}</strong></div></div>${renderFlowPanel(traceFlow(trace))}<div class="panel spaced-panel"><h2>Delegation path</h2><div class="trace-path">${stepCards}</div></div>`;
}

function traceFlow(trace) {
  const actors = [
    flowActor('learner', 'You', 'requested an iterative trace', 'user'),
    flowActor('tool', 'WhereDNS', 'acts as the iterative resolver', 'tool')
  ];
  const actorIDs = new Map();
  const hasCache = (trace.steps || []).some(step => step.from_cache);
  if (hasCache) actors.push(flowActor('cache', 'WhereDNS cache', 'held a prior direct response', 'cache'));
  for (const step of trace.steps || []) {
    if (step.from_cache) continue;
    const key = `${step.server}|${step.address}`;
    if (actorIDs.has(key)) continue;
    const id = `server-${actorIDs.size + 1}`;
    actorIDs.set(key, id);
    actors.push(flowActor(id, step.server || step.address, `${step.role} · ${step.address}`, 'infrastructure'));
  }

  const events = [flowEvent('learner', 'tool', `Trace ${trace.name} ${trace.type}`, 'WhereDNS starts with a built-in root hint and sends recursion-desired = false.', 'normal')];
  for (const step of trace.steps || []) {
    if (step.from_cache) {
      events.push(flowEvent('tool', 'cache', `Hop ${step.number}: lookup ${step.role}`, `The direct response originally associated with ${step.server} (${step.address}) was found in the explicit WhereDNS cache.`, 'cache'));
      events.push(flowEvent('cache', 'tool', `${step.rcode} · ${step.event}`, `${step.explanation} No packet was sent to that server in this run.`, step.rcode === 'NOERROR' ? 'cache' : 'warning'));
      continue;
    }
    const actorID = actorIDs.get(`${step.server}|${step.address}`);
    events.push(flowEvent('tool', actorID, `Hop ${step.number}: ${step.question}`, `Direct ${step.transport || 'udp'} query to the ${step.role} server at ${step.address}; recursion was not requested.`, 'normal'));
    events.push(flowEvent(actorID, 'tool', `${step.rcode} · ${step.event}`, `${step.explanation} Returned ${(step.records || []).length} records and ${finiteNumber(step.response_bytes)} bytes in ${finiteNumber(step.duration_ms).toFixed(2)} ms.`, step.rcode === 'NOERROR' ? 'response' : 'warning'));
  }
  events.push(flowEvent('tool', 'learner', trace.complete ? 'Trace complete' : 'Partial trace', trace.complete ? 'The final answer, negative result, or terminal NODATA state was reached.' : 'The displayed exchanges completed, but the hierarchy walk did not reach a terminal answer.', trace.complete ? 'response' : 'warning'));
  return {
    title: 'Observed delegation sequence',
    caption: 'WhereDNS contacts each server itself. The root server does not contact the TLD, and the TLD does not contact the authoritative server—the referrals tell WhereDNS where to send its next question.',
    actors, events
  };
}

function flowActor(id, label, role, kind) {
  return {id, label, role, kind};
}

function flowEvent(from, to, label, detail, kind) {
  return {from, to, label, detail, kind};
}

function renderFlowPanel(rawModel) {
  const model = normalizeFlow(rawModel);
  if (!model.actors.length || !model.events.length) return '';
  const id = `flow-${++flowSerial}`;
  flowModels.set(id, model);
  const first = eventReading(model, 0);
  return `<section class="flow-panel" data-flow-id="${id}">
    <div class="flow-heading"><div><p class="eyebrow">Interactive sequence</p><h2>${escapeHTML(model.title)}</h2><p>${escapeHTML(model.caption)}</p></div><div class="flow-legend" aria-label="Diagram legend"><span class="legend-normal">exchange</span><span class="legend-warning">trust boundary</span><span class="legend-malicious">attack path</span><span class="legend-defense">defense</span></div></div>
    <div class="flow-scroll" tabindex="0" aria-label="Scrollable sequence diagram">${renderFlowSVG(id, model)}</div>
    <div class="flow-reader">
      <div class="flow-event-nav" aria-label="Sequence events">${model.events.map((item, index) => `<button type="button" class="flow-event-button ${index === 0 ? 'active' : ''}" data-flow-event-index="${index}" aria-label="Show step ${index + 1}"><span>${index + 1}</span>${escapeHTML(item.label)}</button>`).join('')}</div>
      <article class="flow-inspector" aria-live="polite"><div class="flow-step-controls"><button type="button" data-flow-move="-1" aria-label="Previous step">←</button><strong>Step <span data-flow-position>1</span> / ${model.events.length}</strong><button type="button" data-flow-move="1" aria-label="Next step">→</button></div><div data-flow-reading>${first}</div></article>
    </div>
  </section>`;
}

function normalizeFlow(model = {}) {
  const actors = Array.isArray(model.actors) ? model.actors.filter(actor => actor && actor.id) : [];
  const actorIDs = new Set(actors.map(actor => actor.id));
  const events = Array.isArray(model.events) ? model.events.filter(item => item && actorIDs.has(item.from) && actorIDs.has(item.to)) : [];
  return {title: model.title || 'Sequence visualization', caption: model.caption || '', actors, events};
}

function renderFlowSVG(id, model) {
  const width = Math.max(920, 130 + model.actors.length * 175);
  const rowHeight = 78;
  const startY = 136;
  const height = startY + model.events.length * rowHeight + 30;
  const margin = 75;
  const spacing = model.actors.length > 1 ? (width - margin * 2) / (model.actors.length - 1) : 0;
  const positions = new Map(model.actors.map((actor, index) => [actor.id, margin + index * spacing]));
  const kinds = ['normal', 'response', 'cache', 'warning', 'malicious', 'defense'];
  const markers = kinds.map(kind => `<marker id="${id}-arrow-${kind}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path class="flow-marker ${kind}" d="M 0 0 L 10 5 L 0 10 z"></path></marker>`).join('');
  const lanes = model.actors.map(actor => {
    const x = positions.get(actor.id);
    const label = wrapWords(actor.label, 19, 2);
    const role = truncate(actor.role, 22);
    return `<g class="flow-node ${safeToken(actor.kind)}"><line class="flow-lane-line" x1="${x}" y1="88" x2="${x}" y2="${height - 15}"></line><rect x="${x - 72}" y="16" width="144" height="70" rx="12"></rect>${svgTextLines(label, x, 42, 'flow-node-title')}<text class="flow-node-role" x="${x}" y="72">${escapeHTML(role)}</text><title>${escapeHTML(`${actor.label}: ${actor.role}`)}</title></g>`;
  }).join('');
  const eventEdges = model.events.map((item, index) => {
    const x1 = positions.get(item.from);
    const x2 = positions.get(item.to);
    const y = startY + index * rowHeight;
    const kind = kinds.includes(item.kind) ? item.kind : 'normal';
    const label = truncate(item.label, 38);
    const labelWidth = Math.min(250, Math.max(108, label.length * 6.7 + 22));
    const middle = x1 === x2 ? x1 + 48 : (x1 + x2) / 2;
    const path = x1 === x2
      ? `M ${x1} ${y} C ${x1 + 76} ${y - 30}, ${x1 + 76} ${y + 30}, ${x1} ${y + 24}`
      : `M ${x1} ${y} L ${x2} ${y}`;
    const numberX = x1 === x2 ? x1 + 12 : x1 + Math.sign(x2 - x1) * 18;
    return `<g class="flow-event ${kind} ${index === 0 ? 'active' : ''}" data-flow-event-index="${index}" tabindex="0" role="button" aria-label="Step ${index + 1}: ${escapeHTML(item.label)}"><path class="flow-edge-hit" d="${path}"></path><path class="flow-edge-path" d="${path}" marker-end="url(#${id}-arrow-${kind})"></path><circle class="flow-event-number" cx="${numberX}" cy="${y}" r="12"></circle><text class="flow-event-number-text" x="${numberX}" y="${y + 4}">${index + 1}</text><rect class="flow-event-label-bg" x="${middle - labelWidth / 2}" y="${y - 27}" width="${labelWidth}" height="23" rx="11"></rect><text class="flow-event-label" x="${middle}" y="${y - 11}">${escapeHTML(label)}</text><title>${escapeHTML(`${item.label}. ${item.detail}`)}</title></g>`;
  }).join('');
  return `<svg class="flow-svg" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}" role="img" aria-labelledby="${id}-svg-title ${id}-svg-desc"><title id="${id}-svg-title">${escapeHTML(model.title)}</title><desc id="${id}-svg-desc">${escapeHTML(model.caption)} Select a numbered event for its explanation.</desc><defs>${markers}</defs>${lanes}${eventEdges}</svg>`;
}

function wrapWords(value, maxLength, maxLines) {
  const words = String(value || '').split(/\s+/);
  const lines = [];
  for (const word of words) {
    const candidate = lines.length ? `${lines[lines.length - 1]} ${word}` : word;
    if (!lines.length || candidate.length > maxLength) lines.push(word);
    else lines[lines.length - 1] = candidate;
  }
  if (lines.length > maxLines) {
    const clipped = lines.slice(0, maxLines);
    clipped[maxLines - 1] = truncate(clipped[maxLines - 1], maxLength - 1);
    return clipped;
  }
  return lines;
}

function truncate(value, maxLength) {
  const text = String(value || '');
  return text.length > maxLength ? `${text.slice(0, Math.max(1, maxLength - 1))}…` : text;
}

function svgTextLines(lines, x, y, className) {
  const firstY = y - ((lines.length - 1) * 8);
  return `<text class="${className}" x="${x}" y="${firstY}">${lines.map((line, index) => `<tspan x="${x}" dy="${index ? 16 : 0}">${escapeHTML(line)}</tspan>`).join('')}</text>`;
}

function eventReading(model, index) {
  const item = model.events[index];
  const actors = new Map(model.actors.map(actor => [actor.id, actor]));
  const from = actors.get(item.from);
  const to = actors.get(item.to);
  return `<p class="flow-route"><span>${escapeHTML(from.label)}</span><b>→</b><span>${escapeHTML(to.label)}</span><em class="event-kind ${safeToken(item.kind)}">${escapeHTML(item.kind || 'exchange')}</em></p><h3>${escapeHTML(item.label)}</h3><p>${escapeHTML(item.detail)}</p>`;
}

function selectFlowEvent(panel, requestedIndex) {
  const model = flowModels.get(panel.dataset.flowId);
  if (!model) return;
  const index = Math.max(0, Math.min(model.events.length - 1, requestedIndex));
  panel.dataset.activeEvent = String(index);
  $$('[data-flow-event-index]', panel).forEach(node => {
    const active = Number(node.dataset.flowEventIndex) === index;
    node.classList.toggle('active', active);
    if (node.matches('button')) node.setAttribute('aria-current', active ? 'step' : 'false');
  });
  $('[data-flow-position]', panel).textContent = String(index + 1);
  $('[data-flow-reading]', panel).innerHTML = eventReading(model, index);
}

async function loadCurriculum() {
  const [attackData, labs, topics] = await Promise.all(['/api/attacks','/api/labs','/api/topics'].map(async url => {
    const response = await fetch(url);
    if (!response.ok) throw new Error(`${url} returned HTTP ${response.status}`);
    return response.json();
  }));
  attacks = attackData;
  renderAttacks(attacks);
  $('#lab-grid').innerHTML = labs.map(lab => card(lab.attack, lab.title, lab.objective, 'Run safe lab', 'lab', lab.id, lab.mode)).join('');
  $('#topic-grid').innerHTML = topics.map((topic, index) => `<article class="topic"><span class="topic-number">${String(index + 1).padStart(2,'0')}</span><div><h2>${escapeHTML(topic.title)}</h2></div><div><p>${escapeHTML(topic.summary)}</p><div class="chips">${topic.concepts.map(concept => `<span class="chip">${escapeHTML(concept)}</span>`).join('')}</div>${topic.try.map(command => `<code class="command">$ ${escapeHTML(command)}</code>`).join('')}</div></article>`).join('');
}

function card(kicker, title, text, action, actionType, id, side = '') {
  return `<article class="info-card" data-card-id="${escapeHTML(id)}"><div class="card-kicker"><span>${escapeHTML(kicker)}</span><span class="risk-${safeToken(side)}">${escapeHTML(side)}</span></div><h2>${escapeHTML(title)}</h2><p>${escapeHTML(text)}</p><button class="card-action" data-action="${escapeHTML(actionType)}" data-id="${escapeHTML(id)}">${escapeHTML(action)} →</button></article>`;
}

function renderAttacks(items) {
  $('#attack-count').textContent = `${items.length} attack families`;
  $('#attack-grid').innerHTML = items.map(attack => card(attack.category, attack.name, attack.summary, 'Visualize attack', 'attack', attack.id, attack.risk)).join('');
}

$('#attack-search').addEventListener('input', event => {
  const term = event.target.value.toLowerCase();
  const fields = attack => [attack.name, attack.category, attack.risk, attack.summary, ...(attack.mechanism || []), ...(attack.signals || []), ...(attack.defenses || [])].join(' ').toLowerCase();
  renderAttacks(attacks.filter(attack => fields(attack).includes(term)));
});

function showAttack(id) {
  const attack = attacks.find(item => item.id === id);
  if (!attack) return;
  $$('.info-card').forEach(node => node.classList.toggle('selected', node.dataset.cardId === id));
  const section = $('#attack-detail');
  section.classList.remove('hidden');
  const list = (title, items) => `<div><h3>${title}</h3><ul>${(items || []).map(item => `<li>${escapeHTML(item)}</li>`).join('')}</ul></div>`;
  section.innerHTML = `<div class="lesson-title"><div><p class="eyebrow">${escapeHTML(attack.category)} · ${escapeHTML(attack.risk)} risk</p><h2>${escapeHTML(attack.name)}</h2></div><p>${escapeHTML(attack.summary)}</p></div>${renderFlowPanel(attack.flow)}<div class="lesson-columns">${list('Prerequisites', attack.prerequisites)}${list('How it works', attack.mechanism)}${list('Observable signals', attack.signals)}${list('Defenses', attack.defenses)}</div><div class="warning">${escapeHTML(attack.ethics)}</div>`;
  section.scrollIntoView({behavior: 'smooth', block: 'start'});
}

async function runLab(id) {
  const response = await fetch(`/api/labs/${encodeURIComponent(id)}`, {method: 'POST', headers: {'Content-Type':'application/json'}, body: '{}'});
  const run = await response.json();
  if (!response.ok) throw new Error(run.error || 'Lab failed');
  const section = $('#lab-result');
  const matchingAttack = attacks.find(attack => attack.lab_scenario === id && attack.flow);
  const flow = matchingAttack ? renderFlowPanel(matchingAttack.flow) : '';
  section.classList.remove('hidden');
  section.innerHTML = `<p class="eyebrow">${escapeHTML(run.scenario.mode)}</p><h2>${escapeHTML(run.scenario.title)}</h2><p>${escapeHTML(run.scenario.objective)}</p><div class="warning">Safety: ${escapeHTML(run.scenario.safety)}</div>${flow}<div class="timeline">${run.scenario.steps.map(step => `<article><h3>${step.number}. ${escapeHTML(step.actor)} — ${escapeHTML(step.action)}</h3><p><strong>${escapeHTML(step.result)}</strong> ${escapeHTML(step.explanation)}</p></article>`).join('')}</div><h3>Check your model</h3><ul class="explain-list">${run.student_checks.map(check => `<li><strong>${escapeHTML(check.question)}</strong><span>${escapeHTML(check.answer)}</span></li>`).join('')}</ul>`;
  section.scrollIntoView({behavior: 'smooth', block: 'start'});
}

document.addEventListener('click', event => {
  const cardButton = event.target.closest('.card-action');
  if (cardButton) {
    if (cardButton.dataset.action === 'attack') showAttack(cardButton.dataset.id);
    if (cardButton.dataset.action === 'lab') runLab(cardButton.dataset.id).catch(error => console.error('Lab failed', error));
    return;
  }
  const eventNode = event.target.closest('[data-flow-event-index]');
  if (eventNode) {
    const panel = eventNode.closest('.flow-panel');
    selectFlowEvent(panel, Number(eventNode.dataset.flowEventIndex));
    return;
  }
  const moveButton = event.target.closest('[data-flow-move]');
  if (moveButton) {
    const panel = moveButton.closest('.flow-panel');
    const current = Number(panel.dataset.activeEvent || 0);
    selectFlowEvent(panel, current + Number(moveButton.dataset.flowMove));
  }
});

document.addEventListener('keydown', event => {
  const eventNode = event.target.closest('svg [data-flow-event-index]');
  if (!eventNode || !['Enter', ' '].includes(event.key)) return;
  event.preventDefault();
  selectFlowEvent(eventNode.closest('.flow-panel'), Number(eventNode.dataset.flowEventIndex));
});

loadCurriculum().catch(error => console.error('Could not load curriculum', error));
showView(location.hash.slice(1) || 'query');
