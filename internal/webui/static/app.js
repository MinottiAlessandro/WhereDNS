const $ = (selector, parent = document) => parent.querySelector(selector);
const $$ = (selector, parent = document) => [...parent.querySelectorAll(selector)];
const escapeHTML = value => String(value ?? '').replace(/[&<>'"]/g, char => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[char]));

let attacks = [];

$$('.nav-link').forEach(button => button.addEventListener('click', () => showView(button.dataset.view)));

function showView(name) {
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
    result.innerHTML = trace ? renderTrace(data) : renderResult(data);
  } catch (error) {
    state.className = 'state-panel';
    state.innerHTML = `<div class="empty-mark">!</div><h2>Query did not complete</h2><p>${escapeHTML(error.message)}</p>`;
  }
}

function renderResult(data) {
  const records = data.records.length ? data.records.map(record => `<tr>
    <td><span class="section-tag">${escapeHTML(record.section)}</span></td><td><code>${escapeHTML(record.name)}</code></td>
    <td>${record.ttl}s</td><td><strong>${escapeHTML(record.type)}</strong></td><td><code>${escapeHTML(record.data)}</code><br><small>${escapeHTML(record.explanation)}</small></td>
  </tr>`).join('') : '<tr><td colspan="5">No records in the response sections.</td></tr>';
  const warnings = (data.warnings || []).map(warning => `<div class="warning">${escapeHTML(warning)}</div>`).join('');
  const explanations = data.explanations.map(item => `<li><strong>${escapeHTML(item.subject)}</strong><span>${escapeHTML(item.text)}</span></li>`).join('');
  const flags = data.flags.map(flag => `<span class="flag ${flag.enabled ? 'on' : ''}" title="${escapeHTML(flag.explanation)}">${flag.code}</span>`).join('');
  const cache = data.from_cache ? '<span class="badge">cache hit</span>' : '<span class="badge warn">network</span>';
  return `<div class="summary-strip">
    <div class="summary-cell"><small>Question</small><strong>${escapeHTML(data.question.name)} ${escapeHTML(data.question.type)}</strong></div>
    <div class="summary-cell"><small>Status</small><strong>${escapeHTML(data.rcode)}</strong></div>
    <div class="summary-cell"><small>Source</small><strong>${cache}</strong></div>
    <div class="summary-cell"><small>Duration</small><strong>${data.duration_ms.toFixed(2)} ms</strong></div>
    <div class="summary-cell"><small>Response</small><strong>${data.wire.response_bytes} bytes</strong></div>
  </div>
  <div class="result-grid">
    <div class="panel"><h2>Resource records</h2><table class="record-table"><thead><tr><th>Section</th><th>Name</th><th>TTL</th><th>Type</th><th>Data & meaning</th></tr></thead><tbody>${records}</tbody></table>
      <details><summary>Raw DNS wire message</summary><h3>Query · ${data.wire.query_bytes} bytes</h3><pre>${escapeHTML(data.wire.query_hex)}</pre><h3>Response · ${data.wire.response_bytes} bytes</h3><pre>${escapeHTML(data.wire.response_hex)}</pre></details>
    </div>
    <aside><div class="panel"><h2>Protocol reading</h2><div class="flag-row">${flags}</div><h3>DNSSEC · ${escapeHTML(data.dnssec.status)}</h3><p>${escapeHTML(data.dnssec.explanation)}</p>${warnings}<ul class="explain-list">${explanations}</ul></div></aside>
  </div>`;
}

function renderTrace(trace) {
  const steps = trace.steps.map(step => `<article class="trace-step"><span class="step-number">${step.number}</span><div><strong>${escapeHTML(step.role)}</strong><small>${escapeHTML(step.server)}</small><small>${escapeHTML(step.address)}</small></div><div><strong>${escapeHTML(step.event)}</strong><small>${escapeHTML(step.explanation)}</small><small>${step.duration_ms.toFixed(2)} ms · ${step.records.length} records</small></div></article>`).join('');
  return `<div class="summary-strip"><div class="summary-cell"><small>Iterative question</small><strong>${escapeHTML(trace.name)} ${escapeHTML(trace.type)}</strong></div><div class="summary-cell"><small>Outcome</small><strong>${trace.complete ? 'complete' : 'partial'}</strong></div><div class="summary-cell"><small>Hops</small><strong>${trace.steps.length}</strong></div><div class="summary-cell"><small>Duration</small><strong>${trace.duration_ms.toFixed(2)} ms</strong></div><div class="summary-cell"><small>Cache</small><strong>${$('#cache').checked ? 'allowed' : 'bypassed'}</strong></div></div><div class="panel spaced-panel"><h2>Delegation path</h2><div class="trace-path">${steps}</div></div>`;
}

async function loadCurriculum() {
  const [attackData, labs, topics] = await Promise.all(['/api/attacks','/api/labs','/api/topics'].map(url => fetch(url).then(response => response.json())));
  attacks = attackData;
  renderAttacks(attacks);
  $('#lab-grid').innerHTML = labs.map(lab => card(lab.attack, lab.title, lab.objective, 'Run safe lab', 'lab', lab.id, lab.mode)).join('');
  $('#topic-grid').innerHTML = topics.map((topic, index) => `<article class="topic"><span class="topic-number">${String(index + 1).padStart(2,'0')}</span><div><h2>${escapeHTML(topic.title)}</h2></div><div><p>${escapeHTML(topic.summary)}</p><div class="chips">${topic.concepts.map(concept => `<span class="chip">${escapeHTML(concept)}</span>`).join('')}</div>${topic.try.map(command => `<code class="command">$ ${escapeHTML(command)}</code>`).join('')}</div></article>`).join('');
}

function card(kicker, title, text, action, actionType, id, side = '') {
  return `<article class="info-card"><div class="card-kicker"><span>${escapeHTML(kicker)}</span><span>${escapeHTML(side)}</span></div><h2>${escapeHTML(title)}</h2><p>${escapeHTML(text)}</p><button class="card-action" data-action="${escapeHTML(actionType)}" data-id="${escapeHTML(id)}">${escapeHTML(action)} →</button></article>`;
}

function renderAttacks(items) {
  $('#attack-count').textContent = `${items.length} attack families`;
  $('#attack-grid').innerHTML = items.map(attack => card(attack.category, attack.name, attack.summary, 'Inspect attack', 'attack', attack.id, attack.risk)).join('');
}

$('#attack-search').addEventListener('input', event => {
  const term = event.target.value.toLowerCase();
  renderAttacks(attacks.filter(attack => JSON.stringify(attack).toLowerCase().includes(term)));
});

function showAttack(id) {
  const attack = attacks.find(item => item.id === id);
  const cardNode = $(`button[data-action="attack"][data-id="${CSS.escape(id)}"]`).closest('.info-card');
  const open = $('.lesson-detail', cardNode);
  $$('.info-card .lesson-detail').forEach(node => node.remove());
  if (open) return;
  cardNode.insertAdjacentHTML('beforeend', `<section class="lesson-detail"><h3>How it works</h3><ul>${attack.mechanism.map(item => `<li>${escapeHTML(item)}</li>`).join('')}</ul><h3>Observable signals</h3><ul>${attack.signals.map(item => `<li>${escapeHTML(item)}</li>`).join('')}</ul><h3>Defenses</h3><ul>${attack.defenses.map(item => `<li>${escapeHTML(item)}</li>`).join('')}</ul><div class="warning">${escapeHTML(attack.ethics)}</div></section>`);
}

async function runLab(id) {
  const response = await fetch(`/api/labs/${id}`, {method: 'POST', headers: {'Content-Type':'application/json'}, body: '{}'});
  const run = await response.json();
  const section = $('#lab-result');
  section.classList.remove('hidden');
  section.innerHTML = `<p class="eyebrow">${escapeHTML(run.scenario.mode)}</p><h2>${escapeHTML(run.scenario.title)}</h2><p>${escapeHTML(run.scenario.objective)}</p><div class="warning">Safety: ${escapeHTML(run.scenario.safety)}</div><div class="timeline">${run.scenario.steps.map(step => `<article><h3>${step.number}. ${escapeHTML(step.actor)} — ${escapeHTML(step.action)}</h3><p><strong>${escapeHTML(step.result)}</strong> ${escapeHTML(step.explanation)}</p></article>`).join('')}</div><h3>Check your model</h3><ul class="explain-list">${run.student_checks.map(check => `<li><strong>${escapeHTML(check.question)}</strong><span>${escapeHTML(check.answer)}</span></li>`).join('')}</ul>`;
  section.scrollIntoView({behavior: 'smooth', block: 'start'});
}

document.addEventListener('click', event => {
  const button = event.target.closest('.card-action');
  if (!button) return;
  if (button.dataset.action === 'attack') showAttack(button.dataset.id);
  if (button.dataset.action === 'lab') runLab(button.dataset.id);
});

loadCurriculum().catch(error => console.error('Could not load curriculum', error));
showView(location.hash.slice(1) || 'query');
