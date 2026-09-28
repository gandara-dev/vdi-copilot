import { analyze, matchedTerms, redactionSummary, validateRules } from './lib/analyzer.js';

const MAX_FILE_BYTES = 2_000_000;
const TOKEN_PATTERN = /<(?:IP|HOST|EMAIL|SID|USER|REDACTED)>/g;

const $ = (selector) => document.querySelector(selector);
const state = { rules: [], incidents: [], evidence: [], result: null };

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function uniqueSource(name) {
  const base = name.trim() || 'pasted.log';
  const taken = new Set(state.evidence.map((item) => item.source));
  if (!taken.has(base)) return base;
  let index = 2;
  while (taken.has(`${base} (${index})`)) index += 1;
  return `${base} (${index})`;
}

function formatBytes(text) {
  const bytes = new TextEncoder().encode(text).length;
  return bytes < 1024 ? `${bytes} B` : `${(bytes / 1024).toFixed(1)} KB`;
}

// ---------------------------------------------------------------- evidence

function renderSources() {
  const list = $('#sources');
  if (!state.evidence.length) {
    list.innerHTML = '<li class="empty">No evidence yet. Pick an incident, paste text, or open files.</li>';
  } else {
    list.innerHTML = state.evidence.map((item, index) => `
      <li><code>${escapeHtml(item.source)}</code><span class="size">${formatBytes(item.text)}</span>
      <button type="button" data-remove="${index}" aria-label="Remove ${escapeHtml(item.source)}">Remove</button></li>`).join('');
  }
  $('#analyze').disabled = state.evidence.length === 0;
}

function renderIncidents() {
  const titles = Object.fromEntries(state.rules.map((rule) => [rule.id, rule.title]));
  $('#incidents').innerHTML = state.incidents.map((incident) => `
    <button type="button" class="incident" data-incident="${escapeHtml(incident.id)}">
      <strong>${escapeHtml(incident.id.replace(/-/g, ' '))}</strong>
      <span>${escapeHtml(incident.expected.map((id) => titles[id] || id).join('; '))}</span>
    </button>`).join('');
}

function renderRules() {
  const terms = (label, values) => values.length
    ? `<div class="terms"><strong>${label}:</strong> ${values.map((value) => `<span>${escapeHtml(value)}</span>`).join(' ')}</div>` : '';
  $('#rules').innerHTML = state.rules.map((rule) => `
    <div class="rule">
      <div><span class="badge ${escapeHtml(rule.severity)}">${escapeHtml(rule.severity)}</span><strong>${escapeHtml(rule.title)}</strong></div>
      <div><code>${escapeHtml(rule.id)}</code> · confidence ${escapeHtml(rule.confidence)}</div>
      ${terms('all', rule.all)}${terms('any', rule.any)}${terms('none', rule.none)}
    </div>`).join('');
}

// ----------------------------------------------------------------- results

function highlight(text, terms) {
  const ranges = [];
  for (const match of text.matchAll(TOKEN_PATTERN)) {
    ranges.push({ start: match.index, end: match.index + match[0].length, kind: 'token' });
  }
  const lower = text.toLowerCase();
  for (const term of terms) {
    const needle = term.toLowerCase();
    if (!needle) continue;
    for (let at = lower.indexOf(needle); at !== -1; at = lower.indexOf(needle, at + needle.length)) {
      ranges.push({ start: at, end: at + needle.length, kind: 'term' });
    }
  }
  ranges.sort((a, b) => a.start - b.start || b.end - a.end);
  let html = '';
  let cursor = 0;
  for (const range of ranges) {
    if (range.start < cursor) continue;
    html += escapeHtml(text.slice(cursor, range.start));
    const content = escapeHtml(text.slice(range.start, range.end));
    html += range.kind === 'token' ? `<span class="token">${content}</span>` : `<mark>${content}</mark>`;
    cursor = range.end;
  }
  return html + escapeHtml(text.slice(cursor));
}

function renderResults() {
  const result = state.result;
  if (!result) {
    $('#summary').innerHTML = '<p class="hint">Add evidence and run the analysis.</p>';
    $('#findings').innerHTML = '';
    $('#download-json').disabled = true;
    return;
  }
  const { report, texts, removed } = result;
  const chips = removed.length
    ? removed.map((item) => `<span class="chip">${item.count} ${escapeHtml(item.label)}${item.count === 1 ? '' : 's'} removed</span>`).join('')
    : `<span class="chip">${report.redacted ? 'Nothing needed redaction' : 'Redaction was off'}</span>`;
  $('#summary').innerHTML = `
    <strong>${report.findings.length} finding${report.findings.length === 1 ? '' : 's'}</strong>
    from ${report.sources.length} source${report.sources.length === 1 ? '' : 's'} · evidence redacted: ${report.redacted ? 'yes' : 'NO'}
    <div class="chips">${chips}</div>`;

  const rulesById = Object.fromEntries(state.rules.map((rule) => [rule.id, rule]));
  $('#findings').innerHTML = report.findings.length
    ? report.findings.map((finding) => {
      const rule = rulesById[finding.rule_id];
      const found = [...new Set(texts.flatMap((text) => matchedTerms(rule, text)))];
      return `<article class="finding ${escapeHtml(finding.severity)}">
        <h3><span class="badge ${escapeHtml(finding.severity)}">${escapeHtml(finding.severity)}</span>${escapeHtml(finding.title)}</h3>
        <div class="meta">Rule <code>${escapeHtml(finding.rule_id)}</code> · confidence ${escapeHtml(finding.confidence)} ·
          evidence: ${finding.evidence.map((source) => `<code>${escapeHtml(source)}</code>`).join(', ') || 'combined corpus'}</div>
        <div class="terms">${found.map((term) => `<mark>${escapeHtml(term)}</mark>`).join(' ')}</div>
        <ul>${finding.recommendations.map((item) => `<li>${escapeHtml(item)}</li>`).join('')}</ul>
      </article>`;
    }).join('')
    : `<p class="none-found">No deterministic rule matched. This is not proof that the environment is healthy; collect more evidence.</p>`;

  const allTerms = report.findings.flatMap((finding) => {
    const rule = rulesById[finding.rule_id];
    return [...rule.all, ...rule.any];
  });
  $('#evidence-view').innerHTML = report.sources.map((source, index) => `
    <div class="evidence-source"><h3>${escapeHtml(source)}</h3>
    <pre class="log" tabindex="0">${highlight(texts[index], allTerms)}</pre></div>`).join('');
  $('#download-json').disabled = false;
}

function runAnalysis() {
  if (!state.evidence.length) return;
  const redact = $('#redact').checked;
  const removed = new Map();
  if (redact) {
    for (const item of state.evidence) {
      for (const { label, count } of redactionSummary(item.text)) {
        removed.set(label, (removed.get(label) || 0) + count);
      }
    }
  }
  const { texts, report } = analyze(state.evidence, state.rules, { redact });
  state.result = { texts, report, removed: [...removed].map(([label, count]) => ({ label, count })) };
  renderResults();
}

// ------------------------------------------------------------------ events

function bind() {
  $('#incidents').addEventListener('click', (event) => {
    const button = event.target.closest('[data-incident]');
    if (!button) return;
    const incident = state.incidents.find((item) => item.id === button.dataset.incident);
    state.evidence = incident.files.map((file) => ({ source: file.source, text: file.text }));
    renderSources();
    runAnalysis();
  });
  $('#add-text').addEventListener('click', () => {
    const text = $('#evidence-text').value;
    if (!text.trim()) return;
    state.evidence.push({ source: uniqueSource($('#source-name').value), text });
    $('#evidence-text').value = '';
    renderSources();
  });
  $('#open-files').addEventListener('change', async (event) => {
    const skipped = [];
    for (const file of event.target.files) {
      if (file.size > MAX_FILE_BYTES) {
        skipped.push(file.name);
        continue;
      }
      state.evidence.push({ source: uniqueSource(file.name), text: await file.text() });
    }
    event.target.value = '';
    renderSources();
    if (skipped.length) {
      $('#sources').insertAdjacentHTML('beforeend',
        `<li class="warning">Skipped ${escapeHtml(skipped.join(', '))}: larger than 2 MB, the same limit as the CLI.</li>`);
    }
  });
  $('#sources').addEventListener('click', (event) => {
    const button = event.target.closest('[data-remove]');
    if (!button) return;
    state.evidence.splice(Number(button.dataset.remove), 1);
    renderSources();
  });
  $('#redact').addEventListener('change', (event) => {
    $('#redact-warning').hidden = event.target.checked;
    if (state.result) runAnalysis();
  });
  $('#analyze').addEventListener('click', runAnalysis);
  $('#download-json').addEventListener('click', () => {
    const blob = new Blob([`${JSON.stringify(state.result.report, null, 2)}\n`], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = Object.assign(document.createElement('a'), { href: url, download: 'report.json' });
    document.body.append(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  });
}

async function start() {
  const response = await fetch('./data/analyzer-data.json');
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  const data = await response.json();
  state.rules = validateRules(data.rules);
  state.incidents = data.incidents;
  bind();
  renderIncidents();
  renderRules();
  renderSources();
  renderResults();
}

start().catch((error) => {
  $('#summary').innerHTML = `<p class="warning">Could not load the rules: ${escapeHtml(error.message)}</p>`;
});
