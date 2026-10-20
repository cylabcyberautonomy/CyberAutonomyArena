/* Experiment Harness dashboard — client logic.
   Talks to the thin backend: /api/experiments, /api/usage, /api/schema,
   /api/environments, /api/submit, /experiment_file(s|_wait), and the manager
   proxies for priority/delete. All rendering happens here. */
'use strict';

const $  = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, c => (
  { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

let ATTACKER_SCHEMAS = {}, DEFENDER_SCHEMAS = {}, ENV_NICKNAMES = {};

const EXP_REFRESH_MS = 5000;
const USAGE_REFRESH_MS = 30000;
const MAX_EXP_NAME_LEN = 50;   // SSH ControlPath / AF_UNIX 108-byte limit (see ui_schema.py)

/* ── Tabs & theme ──────────────────────────────────────────────────────── */
$$('.tab').forEach(tab => tab.addEventListener('click', () => {
  $$('.tab').forEach(t => t.classList.remove('active'));
  $$('.panel').forEach(p => p.classList.remove('active'));
  tab.classList.add('active');
  $('#' + tab.dataset.panel).classList.add('active');
  if (tab.dataset.panel === 'panel-usage') refreshUsage();
}));

(function initTheme() {
  let saved = null;
  try { saved = localStorage.getItem('eh-theme'); } catch (_) {}
  if (saved) document.documentElement.setAttribute('data-theme', saved);
  $('#theme-toggle').addEventListener('click', () => {
    const cur = document.documentElement.getAttribute('data-theme') === 'light' ? 'dark' : 'light';
    document.documentElement.setAttribute('data-theme', cur);
    try { localStorage.setItem('eh-theme', cur); } catch (_) {}
  });
})();

/* ── Time formatting ───────────────────────────────────────────────────── */
function fmtTime(raw) {
  if (!raw) return '—';
  const d = new Date(raw);
  if (isNaN(d)) return '—';
  const now = new Date();
  const sameDay = d.toDateString() === now.toDateString();
  const opts = sameDay
    ? { hour: 'numeric', minute: '2-digit' }
    : { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' };
  return d.toLocaleString(undefined, opts);
}
function relAge(raw) {
  if (!raw) return '';
  const d = new Date(raw); if (isNaN(d)) return '';
  const s = Math.max(0, (Date.now() - d.getTime()) / 1000);
  if (s < 60) return Math.floor(s) + 's ago';
  if (s < 3600) return Math.floor(s / 60) + 'm ago';
  if (s < 86400) return Math.floor(s / 3600) + 'h ago';
  return Math.floor(s / 86400) + 'd ago';
}

/* ── Experiments ───────────────────────────────────────────────────────── */
const STATUS_ORDER = ['Queued', 'Deploying', 'Deployed', 'Configuring', 'Configured',
  'Running', 'Retrying', 'Finished', 'Error', 'TimedOut', 'Blocked'];
const ACTIVE_STATUSES = new Set(['Deploying', 'Deployed', 'Configuring', 'Configured', 'Running', 'Retrying']);
const FAILED_STATUSES = new Set(['Error', 'TimedOut', 'Blocked']);
const LIVE_STATUSES = new Set(['Queued', ...ACTIVE_STATUSES]);  // deletable / re-prioritisable

let allExperiments = [];
let statusFilter = null;
let textFilter = '';
let sortKey = 'created_at', sortAsc = false;

function attackerLabel(e) {
  const a = e.attacker || {};
  return a.strategy || a.type || e.attacker_plugin || '—';
}
function defenderLabel(e) {
  const d = e.defender;
  if (!d) return '(none)';
  return d.type || d.strategy || 'defender';
}
function envLabel(e) {
  const spec = e.environment_spec || (e.environment_config || {}).environment_spec || '';
  return spec.split('/').pop().replace(/\.json$/, '') || '—';
}

function phaseCell(e) {
  // env deploy → attacker → defender → teardown
  const failed = FAILED_STATUSES.has(e.status);
  const mk = (started, finished, label) => {
    let cls = 'skip';
    if (finished) cls = 'done';
    else if (started) cls = failed ? 'failed' : 'active';
    const state = finished ? 'done' : started ? (failed ? 'failed' : 'running') : 'pending';
    return `<span class="phase ${cls}" title="${label}: ${state}"></span>`;
  };
  return `<div class="phases">
    ${mk(e.environment_deploy_started_at, e.environment_deploy_finished_at, 'Env deploy')}
    ${mk(e.attacker_started_at, e.attacker_finished_at, 'Attacker')}
    ${mk(e.defender_started_at, e.defender_finished_at, 'Defender')}
    ${mk(e.teardown_started_at, e.teardown_finished_at, 'Teardown')}
  </div>`;
}

function badge(status) {
  const pulse = ACTIVE_STATUSES.has(status) ? ' pulse' : '';
  return `<span class="badge st-${esc(status)}${pulse}"><span class="bdot"></span>${esc(status)}</span>`;
}

function renderStats() {
  const counts = {};
  for (const e of allExperiments) counts[e.status] = (counts[e.status] || 0) + 1;
  const strip = $('#statstrip');
  const cards = [`<div class="stat stat-total ${statusFilter === null ? 'active' : ''}" data-st="">
      <div class="stat-n">${allExperiments.length}</div><div class="stat-l">Total</div></div>`];
  for (const st of STATUS_ORDER) {
    if (!counts[st]) continue;
    cards.push(`<div class="stat ${statusFilter === st ? 'active' : ''}" data-st="${st}"
        style="--sc: var(--st-${st === 'Deploying' || st === 'Deployed' ? 'deploy'
          : st === 'Configuring' || st === 'Configured' ? 'config'
          : st === 'Running' ? 'run' : st === 'Retrying' ? 'retry'
          : st === 'Error' ? 'error' : st === 'Finished' ? 'done'
          : st === 'TimedOut' ? 'timeout' : st === 'Blocked' ? 'blocked' : 'queued'}-fg)">
      <div class="stat-n">${counts[st]}</div><div class="stat-l">${st}</div></div>`);
  }
  strip.innerHTML = cards.join('');
  $$('.stat', strip).forEach(el => el.addEventListener('click', () => {
    const st = el.dataset.st || null;
    statusFilter = (statusFilter === st) ? null : st;
    renderStats(); renderRows();
  }));
}

function matchesFilter(e) {
  if (statusFilter && e.status !== statusFilter) return false;
  if (textFilter) {
    const hay = [e.experiment_name, envLabel(e), attackerLabel(e), defenderLabel(e), e.status]
      .join(' ').toLowerCase();
    if (!hay.includes(textFilter)) return false;
  }
  return true;
}

function sortExps(list) {
  const dir = sortAsc ? 1 : -1;
  return [...list].sort((a, b) => {
    let av = a[sortKey], bv = b[sortKey];
    if (sortKey.endsWith('_at')) { av = av ? Date.parse(av) : 0; bv = bv ? Date.parse(bv) : 0; }
    else { av = String(av ?? '').toLowerCase(); bv = String(bv ?? '').toLowerCase(); }
    return av < bv ? -dir : av > bv ? dir : 0;
  });
}

function renderRows() {
  const rows = sortExps(allExperiments.filter(matchesFilter));
  const tbody = $('#exp-rows');
  $('#exp-empty').hidden = rows.length > 0;
  tbody.innerHTML = rows.map(e => {
    const live = LIVE_STATUSES.has(e.status);
    const retry = e.retry_count ? `<span class="retry-badge" title="${e.retry_count} retries">↩${e.retry_count}</span>` : '';
    const prio = (e.priority !== undefined && e.priority !== 1000) ? `<span class="muted mono" title="priority"> ·p${e.priority}</span>` : '';
    const errRow = (FAILED_STATUSES.has(e.status) && e.error)
      ? `<tr class="err-row" data-name="${esc(e.experiment_name)}"><td colspan="9">
           <details class="err-details"><summary>${esc(e.status)} — error detail</summary>${esc(e.error)}</details></td></tr>`
      : '';
    return `<tr class="exp-row" data-name="${esc(e.experiment_name)}">
      <td><span class="exp-name">${esc(e.experiment_name)}</span>${retry}${prio}</td>
      <td>${badge(e.status)}</td>
      <td class="col-env">${esc(envLabel(e))}</td>
      <td class="col-atk cell-strong">${esc(attackerLabel(e))}</td>
      <td class="col-def">${esc(defenderLabel(e))}</td>
      <td class="col-phases">${phaseCell(e)}</td>
      <td class="col-time" title="${esc(e.created_at || '')}">${fmtTime(e.created_at)}</td>
      <td class="col-time" title="${esc(e.updated_at || '')}">${fmtTime(e.updated_at)}<br><span class="muted">${relAge(e.updated_at)}</span></td>
      <td class="col-actions">
        ${live ? `<button class="row-btn" data-act="prio" data-name="${esc(e.experiment_name)}" title="Set priority">prio</button>` : ''}
        ${live ? `<button class="row-btn danger" data-act="del" data-name="${esc(e.experiment_name)}" title="Cancel & remove">✕</button>` : ''}
      </td></tr>${errRow}`;
  }).join('');
  $('#exp-meta').textContent = `${rows.length}${rows.length !== allExperiments.length ? ' / ' + allExperiments.length : ''} shown`;
  // sort indicators
  $$('.exp-table th[data-sort]').forEach(th => {
    th.classList.toggle('sorted', th.dataset.sort === sortKey);
    th.classList.toggle('asc', th.dataset.sort === sortKey && sortAsc);
  });
}

async function refreshExperiments() {
  try {
    const r = await fetch('/api/experiments');
    const data = await r.json();
    allExperiments = data.experiments || [];
    setConn(true);
  } catch (_) {
    setConn(false);
    return;
  }
  renderStats();
  renderRows();
}

function setConn(ok) {
  const pill = $('#conn-pill');
  pill.className = 'pill ' + (ok ? 'pill-ok' : 'pill-bad');
  $('#conn-text').textContent = ok ? 'manager live' : 'manager unreachable';
}

/* row interactions (delegated; survive innerHTML swaps) */
$('#exp-rows').addEventListener('click', async (ev) => {
  const btn = ev.target.closest('[data-act]');
  if (btn) {
    ev.stopPropagation();
    const name = btn.dataset.name;
    if (btn.dataset.act === 'del') {
      if (!confirm(`Cancel and remove "${name}"?`)) return;
      const r = await fetch('/api/experiments/' + encodeURIComponent(name), { method: 'DELETE' });
      if (!r.ok) alert('Delete failed: ' + (await r.text()));
      refreshExperiments();
    } else if (btn.dataset.act === 'prio') {
      const v = prompt(`New priority for "${name}" (0–1000, higher = sooner):`, '1000');
      if (v === null) return;
      const n = parseInt(v, 10);
      if (isNaN(n)) { alert('Not a number'); return; }
      const r = await fetch('/api/experiments/' + encodeURIComponent(name) + '/priority',
        { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ priority: n }) });
      if (!r.ok) alert('Priority change failed: ' + (await r.text()));
      refreshExperiments();
    }
    return;
  }
  if (ev.target.closest('.err-details')) return;  // let the <details> toggle
  const row = ev.target.closest('.exp-row');
  if (row) openLogViewer(row.dataset.name);
});

$('#exp-filter').addEventListener('input', (e) => { textFilter = e.target.value.trim().toLowerCase(); renderRows(); });
$$('.exp-table th[data-sort]').forEach(th => th.addEventListener('click', () => {
  const k = th.dataset.sort;
  if (sortKey === k) sortAsc = !sortAsc; else { sortKey = k; sortAsc = false; }
  renderRows();
}));

/* ══════════════════════════════════════════════════════════════════════════
   FORM ENGINE — ported verbatim from the original dashboard so the schema
   contract (field types, show_when, cartesian_product, slug/label) is
   unchanged. Only the surrounding chrome is new.
   ══════════════════════════════════════════════════════════════════════════ */
function buildTypeDropdown(selectEl, schemas) {
  selectEl.innerHTML = '';
  for (const [configType, schema] of Object.entries(schemas)) {
    const opt = document.createElement('option');
    opt.value = configType;
    opt.textContent = schema.label || configType;
    selectEl.appendChild(opt);
  }
}

function renderFields(containerEl, schema) {
  containerEl.innerHTML = '';
  if (!schema) return;
  const row = document.createElement('div');
  row.className = 'form-row';
  row.style.alignItems = 'stretch';

  for (const field of schema.fields) {
    const grp = document.createElement('div');
    grp.className = 'form-group';
    grp.dataset.fieldKey = field.key;
    if (field.show_when) grp.dataset.showWhen = JSON.stringify(field.show_when);

    const lbl = document.createElement('label');
    lbl.textContent = field.label;
    grp.appendChild(lbl);

    if (field.field_type === 'text_with_suggestions') {
      const listId = `dl-${schema.config_type}-${field.key}`;
      const input = document.createElement('input');
      input.setAttribute('list', listId);
      input.value = field.default || '';
      input.placeholder = (field.suggestions || [])[0] || '';
      input.dataset.fieldKey = field.key;
      input.dataset.fieldType = field.field_type;
      const dl = document.createElement('datalist');
      dl.id = listId;
      for (const s of (field.suggestions || [])) {
        const opt = document.createElement('option'); opt.value = s; dl.appendChild(opt);
      }
      grp.appendChild(input); grp.appendChild(dl);

    } else if (field.field_type === 'flat_checkboxes') {
      const grid = document.createElement('div');
      grid.className = 'llm-check-grid';
      grid.dataset.fieldKey = field.key;
      grid.dataset.fieldType = field.field_type;
      for (const opt of (field.options || [])) {
        const safe = opt.replace(/[^a-z0-9]/gi, '-');
        const cbId = `cb-${schema.config_type}-${field.key}-${safe}`;
        const item = document.createElement('div');
        item.className = 'llm-item';
        item.innerHTML = `<input type="checkbox" class="llm-cb" id="${cbId}" value="${esc(opt)}">` +
                         `<label for="${cbId}">${esc(opt)}</label>`;
        grid.appendChild(item);
      }
      const controls = document.createElement('div');
      controls.className = 'llm-controls';
      controls.innerHTML = '<button type="button" class="llm-select-all">Select all</button> ' +
                           '<button type="button" class="llm-clear">Clear</button>';
      grid.appendChild(controls);
      grid.addEventListener('click', (event) => {
        if (event.target.classList.contains('llm-select-all')) grid.querySelectorAll('.llm-cb').forEach(cb => cb.checked = true);
        else if (event.target.classList.contains('llm-clear')) grid.querySelectorAll('.llm-cb').forEach(cb => cb.checked = false);
      });
      grp.appendChild(grid);

    } else if (field.field_type === 'grouped_checkboxes') {
      const grid = document.createElement('div');
      grid.className = 'llm-check-grid';
      grid.dataset.fieldKey = field.key;
      grid.dataset.fieldType = field.field_type;
      for (const [groupIndex, grpDef] of (field.groups || []).entries()) {
        const groupBlock = document.createElement('div');
        groupBlock.className = 'llm-group-block';
        groupBlock.dataset.groupIndex = String(groupIndex);
        const head = document.createElement('div');
        head.className = 'llm-group-head';
        const hdr = document.createElement('span');
        hdr.className = 'llm-group-label';
        hdr.textContent = grpDef.group_label;
        head.appendChild(hdr);
        const controls = document.createElement('div');
        controls.className = 'llm-group-controls';
        controls.innerHTML = '<button type="button" class="llm-select-all">Select all</button> ' +
                             '<button type="button" class="llm-clear">Clear</button>';
        head.appendChild(controls);
        groupBlock.appendChild(head);
        for (const opt of grpDef.options) {
          const safe = opt.replace(/[^a-z0-9]/gi, '-');
          const cbId = `cb-${schema.config_type}-${field.key}-${safe}`;
          const item = document.createElement('div');
          item.className = 'llm-item';
          item.innerHTML = `<input type="checkbox" class="llm-cb" id="${cbId}" value="${esc(opt)}">` +
                           `<label for="${cbId}">${esc(opt)}</label>`;
          groupBlock.appendChild(item);
        }
        grid.appendChild(groupBlock);
      }
      grid.addEventListener('click', (event) => {
        const btn = event.target.closest('.llm-select-all, .llm-clear');
        if (!btn) return;
        const groupBlock = btn.closest('.llm-group-block');
        if (!groupBlock) return;
        if (btn.classList.contains('llm-select-all')) groupBlock.querySelectorAll('.llm-cb').forEach(cb => cb.checked = true);
        else if (btn.classList.contains('llm-clear')) groupBlock.querySelectorAll('.llm-cb').forEach(cb => cb.checked = false);
      });
      grp.appendChild(grid);

    } else if (field.field_type === 'key_value_pairs') {
      const grid = document.createElement('div');
      grid.className = 'kv-pairs';
      grid.dataset.fieldKey = field.key;
      grid.dataset.fieldType = field.field_type;
      const header = document.createElement('div');
      header.className = 'kv-pairs-header';
      header.innerHTML = '<span>Key</span><span>Value</span><span></span>';
      grid.appendChild(header);
      const addRow = (keyValue = { key: '', value: '' }) => {
        const r = document.createElement('div');
        r.className = 'kv-pair-row';
        r.innerHTML =
          `<input type="text" class="kv-pair-key" placeholder="${esc(field.key_placeholder || 'name')}" value="${esc(keyValue.key || '')}">` +
          `<input type="text" class="kv-pair-value" placeholder="${esc(field.value_placeholder || 'value')}" value="${esc(keyValue.value || '')}">` +
          `<button type="button" class="kv-pair-remove">Remove</button>`;
        grid.appendChild(r);
      };
      for (const entry of (field.entries || [])) addRow(entry);
      if (!(field.entries || []).length) addRow();
      const controls = document.createElement('div');
      controls.className = 'kv-pairs-controls';
      controls.innerHTML = '<button type="button" class="kv-pair-add">+ Add row</button>';
      grid.appendChild(controls);
      grid.addEventListener('click', (event) => {
        if (event.target.classList.contains('kv-pair-add')) addRow();
        else if (event.target.classList.contains('kv-pair-remove')) {
          const r = event.target.closest('.kv-pair-row'); if (r) r.remove();
        }
      });
      grp.appendChild(grid);

    } else if (field.field_type === 'json') {
      const input = document.createElement('input');
      input.placeholder = field.placeholder || '{}';
      input.value = field.default || '';
      input.dataset.fieldKey = field.key;
      input.dataset.fieldType = field.field_type;
      grp.appendChild(input);
    }
    row.appendChild(grp);
  }
  containerEl.appendChild(row);

  if (!containerEl.dataset.showWhenBound) {
    containerEl.addEventListener('change', () => applyConditionalVisibility(containerEl));
    containerEl.addEventListener('click', () => applyConditionalVisibility(containerEl));
    containerEl.dataset.showWhenBound = '1';
  }
  applyConditionalVisibility(containerEl);
}

function currentFieldValues(containerEl) {
  const vals = {};
  containerEl.querySelectorAll('[data-field-type="flat_checkboxes"],[data-field-type="grouped_checkboxes"]').forEach(grid => {
    vals[grid.dataset.fieldKey] = [...grid.querySelectorAll('.llm-cb:checked')].map(cb => cb.value);
  });
  containerEl.querySelectorAll('input[data-field-key]').forEach(input => {
    vals[input.dataset.fieldKey] = [input.value.trim()];
  });
  return vals;
}

function applyConditionalVisibility(containerEl) {
  const vals = currentFieldValues(containerEl);
  containerEl.querySelectorAll('.form-group[data-show-when]').forEach(grp => {
    let cond;
    try { cond = JSON.parse(grp.dataset.showWhen); } catch (ex) { return; }
    let visible = true;
    for (const [ctrlKey, allowed] of Object.entries(cond)) {
      const cur = vals[ctrlKey] || [];
      if (!cur.some(v => allowed.includes(v))) { visible = false; break; }
    }
    grp.style.display = visible ? '' : 'none';
  });
}

function readFieldValues(containerEl) {
  const result = {};
  containerEl.querySelectorAll('input[data-field-key]').forEach(input => {
    if (input.closest('.form-group')?.style.display === 'none') return;
    result[input.dataset.fieldKey] = { type: input.dataset.fieldType, value: input.value.trim() };
  });
  containerEl.querySelectorAll('[data-field-type="flat_checkboxes"],[data-field-type="grouped_checkboxes"]').forEach(grid => {
    if (grid.closest('.form-group')?.style.display === 'none') return;
    result[grid.dataset.fieldKey] = { type: grid.dataset.fieldType, value: [...grid.querySelectorAll('.llm-cb:checked')].map(cb => cb.value) };
  });
  containerEl.querySelectorAll('[data-field-type="key_value_pairs"]').forEach(grid => {
    if (grid.closest('.form-group')?.style.display === 'none') return;
    result[grid.dataset.fieldKey] = {
      type: grid.dataset.fieldType,
      value: [...grid.querySelectorAll('.kv-pair-row')].map(r => ({
        key: r.querySelector('.kv-pair-key').value.trim(),
        value: r.querySelector('.kv-pair-value').value.trim(),
      })),
    };
  });
  return result;
}

function cartesianProduct(arrays) {
  return arrays.reduce((acc, arr) => acc.flatMap(combo => arr.map(v => [...combo, v])), [[]]);
}

function buildConfigs(configType, schema, fieldValues) {
  const present  = f => Object.prototype.hasOwnProperty.call(fieldValues, f.key);
  const cbKeys   = schema.fields.filter(f => present(f) && (f.field_type === 'flat_checkboxes' || f.field_type === 'grouped_checkboxes')).map(f => f.key);
  const textKeys = schema.fields.filter(f => present(f) && (f.field_type === 'text_with_suggestions' || f.field_type === 'json')).map(f => f.key);
  const kvKeys   = schema.fields.filter(f => present(f) && f.field_type === 'key_value_pairs').map(f => f.key);

  const fixedVals = {};
  for (const key of textKeys) {
    const raw = (fieldValues[key] || {}).value || '';
    const fieldDef = schema.fields.find(f => f.key === key);
    if (fieldDef && fieldDef.field_type === 'json') {
      if (raw) { try { fixedVals[key] = JSON.parse(raw); } catch (ex) { alert(`${fieldDef.label} JSON is invalid: ${ex.message}`); return null; } }
      else fixedVals[key] = {};
    } else {
      fixedVals[key] = raw || (fieldDef && fieldDef.default) || '';
    }
  }

  for (const key of kvKeys) {
    const rows = (fieldValues[key] || {}).value || [];
    const objectValue = {};
    for (const r of rows) {
      const entryKey = (r.key || '').trim(), entryValue = (r.value || '').trim();
      if (!entryKey && !entryValue) continue;
      const fieldDef = schema.fields.find(f => f.key === key);
      if (!entryKey || !entryValue) { alert(`Fill in both key and value for "${fieldDef ? fieldDef.label : key}".`); return null; }
      const parsed = Number(entryValue);
      if (!Number.isInteger(parsed)) { alert(`Value for "${entryKey}" in "${fieldDef ? fieldDef.label : key}" must be an integer.`); return null; }
      if (Object.prototype.hasOwnProperty.call(objectValue, entryKey)) { alert(`Duplicate key "${entryKey}" in "${fieldDef ? fieldDef.label : key}".`); return null; }
      objectValue[entryKey] = parsed;
    }
    if (!Object.keys(objectValue).length) { const fieldDef = schema.fields.find(f => f.key === key); alert(`Add at least one key/value pair for "${fieldDef ? fieldDef.label : key}".`); return null; }
    fixedVals[key] = objectValue;
  }

  if (schema.cartesian_product) {
    const arrays = [];
    for (const key of cbKeys) {
      const vals = (fieldValues[key] || {}).value || [];
      if (!vals.length) { const fieldDef = schema.fields.find(f => f.key === key); alert(`Select at least one option for "${fieldDef ? fieldDef.label : key}".`); return null; }
      arrays.push(vals.map(v => ({ key, v })));
    }
    return cartesianProduct(arrays).map(combo => {
      const cfg = { type: configType, ...fixedVals };
      for (const { key, v } of combo) cfg[key] = v;
      return cfg;
    });
  }
  if (cbKeys.length === 1) {
    const key = cbKeys[0];
    const vals = (fieldValues[key] || {}).value || [];
    if (!vals.length) { const fieldDef = schema.fields.find(f => f.key === key); alert(`Select at least one option for "${fieldDef ? fieldDef.label : key}".`); return null; }
    return vals.map(v => { const cfg = { type: configType, ...fixedVals }; cfg[key] = v; return cfg; });
  }
  const cfg = { type: configType, ...fixedVals };
  for (const key of cbKeys) cfg[key] = (fieldValues[key] || {}).value || [];
  return [cfg];
}

function configLabel(cfg, schema) {
  return schema.fields.map(f => {
    const v = cfg[f.key];
    if (v === undefined || v === null) return '';
    if (Array.isArray(v)) return v.join('+');
    if (typeof v === 'object') return JSON.stringify(v);
    return String(v);
  }).filter(Boolean).join(' / ');
}

function configSlug(cfg, schema) {
  const fieldByKey = {};
  for (const f of (schema ? schema.fields : [])) fieldByKey[f.key] = f;
  const parts = Object.entries(cfg).filter(([k]) => k !== 'type').map(([k, v]) => {
    const field = fieldByKey[k];
    const fieldType = field ? field.field_type : null;
    if (fieldType === 'text_with_suggestions' || fieldType === 'grouped_checkboxes' || fieldType === 'json') return null;
    if (fieldType === 'flat_checkboxes' && field.short_names && field.short_names[v]) return field.short_names[v];
    if (fieldType === 'key_value_pairs' && v && typeof v === 'object') {
      const shortKeys = field.key_short_names || {};
      return Object.entries(v).map(([ek, ev]) => (shortKeys[ek] || ek) + ev).join('');
    }
    return typeof v === 'string' ? v : JSON.stringify(v);
  }).filter(Boolean);
  const base = parts.length ? parts.join('_') : (schema ? schema.config_type : 'cfg');
  return base.toLowerCase().replace(/[^a-z0-9_]/g, '').slice(0, 24);
}

function formatSubmitError(data) {
  if (!data) return 'unknown error';
  const d = data.detail;
  if (typeof d === 'string') return d;
  if (Array.isArray(d)) return d.map(x => {
    const loc = Array.isArray(x.loc) ? x.loc.filter(p => p !== 'body').join('.') : '';
    return (loc ? loc + ': ' : '') + (x.msg || JSON.stringify(x));
  }).join('; ');
  if (d) return JSON.stringify(d);
  return JSON.stringify(data);
}

/* ── Attacker / defender / env lists ──────────────────────────────────── */
const attackerList = [], defenderList = [];
const selectedEnvs = new Map();   // spec -> label

function chipHTML(label, idx) {
  return `<div class="config-chip"><span class="config-chip-label" title="${esc(label)}">${esc(label)}</span>` +
         `<button type="button" class="config-chip-remove" data-idx="${idx}">✕</button></div>`;
}
function renderList(list, chipsEl, emptyEl, countEl) {
  chipsEl.innerHTML = list.map((it, i) => chipHTML(it.label, i)).join('');
  emptyEl.style.display = list.length ? 'none' : '';
  countEl.textContent = list.length;
  updateComboCount();
}
function renderAtk() { renderList(attackerList, $('#atk-chips'), $('#atk-chips-empty'), $('#atk-count')); }
function renderDef() { renderList(defenderList, $('#def-chips'), $('#def-chips-empty'), $('#def-count')); }

$('#atk-chips').addEventListener('click', e => { const b = e.target.closest('.config-chip-remove'); if (b) { attackerList.splice(+b.dataset.idx, 1); renderAtk(); } });
$('#def-chips').addEventListener('click', e => { const b = e.target.closest('.config-chip-remove'); if (b) { defenderList.splice(+b.dataset.idx, 1); renderDef(); } });

$('#atk-add-btn').addEventListener('click', () => {
  const type = $('#atk-type-select').value, schema = ATTACKER_SCHEMAS[type];
  if (!schema) return;
  const cfgs = buildConfigs(type, schema, readFieldValues($('#atk-fields-container')));
  if (!cfgs) return;
  cfgs.forEach(cfg => attackerList.push({ config: cfg, label: configLabel(cfg, schema), slug: configSlug(cfg, schema) }));
  renderAtk();
});
$('#def-add-btn').addEventListener('click', () => {
  const type = $('#def-type-select').value, schema = DEFENDER_SCHEMAS[type];
  if (!schema) return;
  const cfgs = buildConfigs(type, schema, readFieldValues($('#def-fields-container')));
  if (!cfgs) return;
  cfgs.forEach(cfg => defenderList.push({ config: cfg, label: configLabel(cfg, schema), slug: configSlug(cfg, schema) }));
  renderDef();
});
$('#def-add-none-btn').addEventListener('click', () => { defenderList.push({ config: null, label: '(no defender)', slug: 'nodef' }); renderDef(); });

/* ── Environments picker ──────────────────────────────────────────────── */
let ENV_GROUPS = {};
function renderEnvGrid() {
  const group = $('#env-group-select').value;
  const stems = ENV_GROUPS[group] || [];
  $('#env-grid').innerHTML = stems.map(stem => {
    const spec = group === 'misc' ? stem : `${group}/${stem}`;
    const id = 'env-' + spec.replace(/[^a-z0-9]/gi, '-');
    const checked = selectedEnvs.has(spec) ? 'checked' : '';
    return `<div class="env-item"><input type="checkbox" class="env-cb" id="${id}" value="${esc(spec)}" data-label="${esc(stem)}" ${checked}>` +
           `<label for="${id}">${esc(stem)}</label></div>`;
  }).join('');
}
function renderEnvChips() {
  const chips = [...selectedEnvs.entries()].map(([spec, label]) =>
    `<div class="env-chip"><span class="env-chip-label" title="${esc(spec)}">${esc(label)}</span>` +
    `<button type="button" class="env-chip-remove" data-spec="${esc(spec)}">✕</button></div>`).join('');
  $('#env-chips').innerHTML = chips;
  $('#env-chips-empty').style.display = selectedEnvs.size ? 'none' : '';
  $('#env-count').textContent = selectedEnvs.size;
  updateComboCount();
}
$('#env-group-select').addEventListener('change', renderEnvGrid);
$('#env-grid').addEventListener('change', e => {
  const cb = e.target.closest('.env-cb'); if (!cb) return;
  if (cb.checked) selectedEnvs.set(cb.value, cb.dataset.label); else selectedEnvs.delete(cb.value);
  renderEnvChips();
});
$('#env-chips').addEventListener('click', e => {
  const b = e.target.closest('.env-chip-remove'); if (!b) return;
  selectedEnvs.delete(b.dataset.spec); renderEnvChips(); renderEnvGrid();
});
$('#env-select-all').addEventListener('click', () => {
  const group = $('#env-group-select').value;
  (ENV_GROUPS[group] || []).forEach(stem => { const spec = group === 'misc' ? stem : `${group}/${stem}`; selectedEnvs.set(spec, stem); });
  renderEnvGrid(); renderEnvChips();
});
$('#env-clear').addEventListener('click', () => {
  const group = $('#env-group-select').value;
  (ENV_GROUPS[group] || []).forEach(stem => { const spec = group === 'misc' ? stem : `${group}/${stem}`; selectedEnvs.delete(spec); });
  renderEnvGrid(); renderEnvChips();
});

/* ── Batch submit ─────────────────────────────────────────────────────── */
function envStem(spec) { return ENV_NICKNAMES[spec] || spec.split('/').pop(); }
function repeats() { return Math.max(1, parseInt($('#repeats').value, 10) || 1); }

function updateComboCount() {
  const n = attackerList.length * defenderList.length * selectedEnvs.size * repeats();
  const el = $('#combo-count');
  el.textContent = `${n} experiment${n === 1 ? '' : 's'}`;
  el.style.color = n ? 'var(--accent)' : 'var(--text-faint)';
}
$('#repeats').addEventListener('input', updateComboCount);

$('#submit-form').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  if (!selectedEnvs.size) { alert('Select at least one environment.'); return; }
  if (!attackerList.length) { alert('Add at least one attacker config.'); return; }
  if (!defenderList.length) { alert('Add at least one defender config (or "No defender").'); return; }
  const prefix = $('#name-prefix').value.trim();
  if (/\s/.test(prefix)) { alert('Name prefix cannot contain spaces.'); return; }

  const specs = [...selectedEnvs.keys()];
  const reps = repeats();

  // Pre-flight: name-length guard.
  const tooLong = [];
  for (let i = 0; i < reps; i++) for (const atk of attackerList) for (const def of defenderList) for (const spec of specs) {
    const name = [prefix, atk.slug, def.slug, envStem(spec), i].filter(v => v !== '' && v !== null && v !== undefined).join('_');
    if (name.length > MAX_EXP_NAME_LEN) tooLong.push(name);
  }
  if (tooLong.length) {
    if (!confirm(`${tooLong.length} experiment name(s) exceed ${MAX_EXP_NAME_LEN} chars (e.g. "${tooLong[0]}", ${tooLong[0].length}). Long names can break SSH ControlPaths. Submit anyway?`)) return;
  }

  const box = $('#results-box');
  box.hidden = false; box.innerHTML = 'Submitting…';
  const lines = [];
  for (let i = 0; i < reps; i++) for (const atk of attackerList) for (const def of defenderList) for (const spec of specs) {
    const name = [prefix, atk.slug, def.slug, envStem(spec), i].filter(v => v !== '' && v !== null && v !== undefined).join('_');
    const payload = { experiment_name: name, environment: spec, attacker: atk.config, defender: def.config, trial: i };
    try {
      const r = await fetch('/api/submit', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
      const data = await r.json().catch(() => ({}));
      lines.push(r.ok
        ? `<div class="res-ok">✓ ${esc(name)} — ${esc(data.status || 'queued')}</div>`
        : `<div class="res-err">✗ ${esc(name)} — ${esc(formatSubmitError(data))}</div>`);
    } catch (e) {
      lines.push(`<div class="res-err">✗ ${esc(name)} — ${esc(e.message)}</div>`);
    }
    box.innerHTML = lines.join('');
    box.scrollTop = box.scrollHeight;
  }
  lines.push(`<div style="margin-top:8px;color:var(--text-dim)">Done — ${lines.length} submitted.</div>`);
  box.innerHTML = lines.join('');
  refreshExperiments();
});

/* ══════════════════════════════════════════════════════════════════════════
   LOG VIEWER
   ══════════════════════════════════════════════════════════════════════════ */
let logState = { name: null, path: null, size: null, mtime: null, abort: null };

function openLogViewer(name) {
  logState.name = name; logState.path = null;
  $('#log-exp-name').textContent = name;
  $('#log-content').textContent = '';
  $('#log-overlay').hidden = false;
  fetch('/experiment_files?name=' + encodeURIComponent(name))
    .then(r => r.json())
    .then(d => {
      const files = d.files || [];
      $('#log-file-list').innerHTML = files.length
        ? files.map(f => `<div class="log-file" data-path="${esc(f)}" title="${esc(f)}">${esc(f)}</div>`).join('')
        : '<div class="muted" style="padding:8px">No files.</div>';
    });
}
function closeLogViewer() {
  $('#log-overlay').hidden = true;
  stopLogWait();
  logState.name = logState.path = null;
}
function stopLogWait() { if (logState.abort) { logState.abort.abort(); logState.abort = null; } }

$('#log-file-list').addEventListener('click', e => {
  const f = e.target.closest('.log-file'); if (!f) return;
  $$('.log-file').forEach(el => el.classList.toggle('selected', el === f));
  loadLogFile(f.dataset.path);
});
$('#log-close').addEventListener('click', closeLogViewer);
$('#log-overlay').addEventListener('click', e => { if (e.target === $('#log-overlay')) closeLogViewer(); });
document.addEventListener('keydown', e => { if (e.key === 'Escape' && !$('#log-overlay').hidden) closeLogViewer(); });

function isAtBottom() { const el = $('#log-content'); return el.scrollHeight - el.scrollTop - el.clientHeight < 40; }

function loadLogFile(path) {
  stopLogWait();
  logState.path = path;
  fetch(`/experiment_file?name=${encodeURIComponent(logState.name)}&path=${encodeURIComponent(path)}`)
    .then(r => r.json())
    .then(d => {
      if (d.error) { $('#log-content').textContent = 'Error: ' + d.error; return; }
      $('#log-content').textContent = d.content || '';
      logState.size = d.size; logState.mtime = d.mtime;
      $('#log-content').scrollTop = $('#log-content').scrollHeight;
      if ($('#log-autorefresh').checked) pollLog(path);
    });
}
function pollLog(path) {
  if (!$('#log-autorefresh').checked || logState.path !== path) return;
  stopLogWait();
  const ac = new AbortController(); logState.abort = ac;
  const url = `/experiment_file_wait?name=${encodeURIComponent(logState.name)}&path=${encodeURIComponent(path)}` +
              `&since_size=${logState.size ?? ''}&since_mtime=${logState.mtime ?? ''}`;
  fetch(url, { signal: ac.signal })
    .then(r => r.json())
    .then(d => {
      if (logState.path !== path) return;
      if (d.changed && d.ok) {
        const stick = isAtBottom();
        $('#log-content').textContent = d.content || '';
        logState.size = d.size; logState.mtime = d.mtime;
        if (stick) $('#log-content').scrollTop = $('#log-content').scrollHeight;
      }
      pollLog(path);
    })
    .catch(err => { if (err.name !== 'AbortError') setTimeout(() => pollLog(path), 3000); });
}
$('#log-autorefresh').addEventListener('change', () => {
  if ($('#log-autorefresh').checked && logState.path) pollLog(logState.path); else stopLogWait();
});

/* ══════════════════════════════════════════════════════════════════════════
   API USAGE
   ══════════════════════════════════════════════════════════════════════════ */
const usd = (v) => (v === null || v === undefined || isNaN(v)) ? '—' : '$' + Number(v).toFixed(2);

function barHTML(spend, limit) {
  if (limit === null || limit === undefined || !(limit > 0)) return '<div class="usage-meta">No limit set</div>';
  const pct = Math.min(100, (spend / limit) * 100);
  const cls = pct >= 100 ? 'over' : pct > 90 ? 'warn' : '';
  return `<div class="usage-bar ${cls}"><span style="width:${pct.toFixed(1)}%"></span></div>` +
         `<div class="usage-meta">${usd(spend)} of ${usd(limit)} (${pct.toFixed(0)}%)</div>`;
}

function usageCard(title, sub, bodyHTML) {
  return `<div class="usage-card"><h3>${esc(title)}</h3><div class="usage-sub">${esc(sub)}</div>${bodyHTML}</div>`;
}

// Per-provider body renderers. Keyed by the generic provider type the backend
// reports for each configured source; the card title comes from the source's
// own label (config.yaml), so no deployment-specific names live here.
const USAGE_RENDERERS = {
  openrouter: (d) => d.error
    ? `<div class="usage-err">${esc(d.error)}</div>`
    : `<div class="usage-figure">${usd(d.usage)}<span class="unit"> used</span></div>` + barHTML(d.usage, d.limit),
  litellm: (d) => d.error
    ? `<div class="usage-err">${esc(d.error)}</div>`
    : `<div class="usage-figure">${usd(d.spend)}<span class="unit"> spent</span></div>` + barHTML(d.spend, d.max_budget),
  anthropic: (d) => {
    if (d.error && !d.key) return `<div class="usage-err">${esc(d.error)}</div>`;
    const local = d.local || {};
    const liveTag = d.live ? '<span class="tag-ok">● live</span>' : '<span class="tag-bad">● not accepted</span>';
    let body = '';
    if (d.local) {
      body += `<div class="usage-figure">${usd(local.cost)}<span class="unit"> est.</span></div>`;
      body += `<div class="usage-meta">reconstructed from defender token_usage.json — tracks the bill, isn't the bill</div>`;
    }
    body += `<div class="usage-kv"><span class="k">key</span><span class="v">${esc(d.key || '—')} ${liveTag}</span></div>`;
    if (d.local) body += `<div class="usage-kv"><span class="k">calls</span><span class="v">${local.calls ?? 0}${local.unpriced ? ` (${local.unpriced} unpriced)` : ''}</span></div>`;
    if ((local.models || []).length) body += `<div class="usage-kv"><span class="k">models</span><span class="v">${esc((local.models || []).join(', '))}</span></div>`;
    if (d.org && d.org.cost !== null && d.org.cost !== undefined) body += `<div class="usage-kv"><span class="k">org MTD (admin)</span><span class="v">${usd(d.org.cost)}</span></div>`;
    if (d.budget) body += barHTML((local.cost) || 0, d.budget);
    if (d.error) body += `<div class="usage-err">${esc(d.error)}</div>`;
    return body;
  },
};
const USAGE_SUBLABEL = { openrouter: 'per-key credit', litellm: 'key spend', anthropic: 'direct route' };

function renderUsage(u) {
  const sources = (u && u.sources) || [];
  if (!sources.length) {
    $('#usage-root').innerHTML = '<div class="empty-state">No <code class="mono">usage_sources</code> configured in config.yaml.</div>';
    return;
  }
  $('#usage-root').innerHTML = sources.map(s => {
    const render = USAGE_RENDERERS[s.provider];
    const sub = USAGE_SUBLABEL[s.provider] || s.provider || '';
    const body = render ? render(s.data || {}) : `<div class="usage-err">${esc((s.data || {}).error || 'unknown provider')}</div>`;
    return usageCard(s.label || s.provider || 'Provider', sub, body);
  }).join('');
}

let usageTimer = null;
async function refreshUsage() {
  try {
    const r = await fetch('/api/usage');
    renderUsage(await r.json());
  } catch (_) {
    $('#usage-root').innerHTML = '<div class="usage-err">Usage unavailable.</div>';
  }
}

/* ══════════════════════════════════════════════════════════════════════════
   BOOT
   ══════════════════════════════════════════════════════════════════════════ */
async function boot() {
  // schemas + env groups (once)
  try {
    const s = await (await fetch('/api/schema')).json();
    ATTACKER_SCHEMAS = s.attacker || {};
    DEFENDER_SCHEMAS = s.defender || {};
    ENV_NICKNAMES = s.env_nicknames || {};
  } catch (_) {}

  buildTypeDropdown($('#atk-type-select'), ATTACKER_SCHEMAS);
  buildTypeDropdown($('#def-type-select'), DEFENDER_SCHEMAS);
  if ($('#atk-type-select').value) renderFields($('#atk-fields-container'), ATTACKER_SCHEMAS[$('#atk-type-select').value]);
  if ($('#def-type-select').value) renderFields($('#def-fields-container'), DEFENDER_SCHEMAS[$('#def-type-select').value]);
  $('#atk-type-select').addEventListener('change', e => renderFields($('#atk-fields-container'), ATTACKER_SCHEMAS[e.target.value]));
  $('#def-type-select').addEventListener('change', e => renderFields($('#def-fields-container'), DEFENDER_SCHEMAS[e.target.value]));

  try {
    ENV_GROUPS = await (await fetch('/api/environments')).json();
  } catch (_) { ENV_GROUPS = {}; }
  const groups = Object.keys(ENV_GROUPS);
  $('#env-group-select').innerHTML = groups.map(g => `<option value="${esc(g)}">${esc(g)} (${ENV_GROUPS[g].length})</option>`).join('');
  renderEnvGrid();

  renderAtk(); renderDef(); renderEnvChips();

  await refreshExperiments();
  setInterval(refreshExperiments, EXP_REFRESH_MS);

  refreshUsage();
  usageTimer = setInterval(() => { if ($('#panel-usage').classList.contains('active')) refreshUsage(); }, USAGE_REFRESH_MS);
}
boot();
