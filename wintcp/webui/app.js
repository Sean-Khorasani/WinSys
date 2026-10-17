'use strict';

(() => {
  const token = document.querySelector('meta[name="wintcp-api-token"]')?.content || '';
  const $ = (id) => document.getElementById(id);
  const state = { templates: [], config: { version: 2, theme: 'system', refreshSeconds: 5, desktopNotifications: false, rules: [], scripts: [], presets: [], bookmarks: [], view: { protocol: 'all', state: 'all', groupByProcess: false, frozen: false, columns: ['process', 'pid', 'proto', 'local', 'remote', 'state', 'traffic'] } }, snapshot: null, liveSnapshot: null, selectedRows: new Set(), currentDetailRow: null, alerts: [], previous: new Map(), rowHistory: new Map(), rowFlash: new Map(), rowHistorySeeded: false, keyboardRow: '', eventSource: null, samples: [], seenPeers: new Set(), seenListeners: new Set(), initialized: false, timer: 0, filterTimer: 0, busy: false, sortKey: 'process', sortDescending: false, notificationTimes: [], suppressedNotificationCount: 0, currentScriptId: '', currentTemplateId: '', scriptRun: { running: false, variables: Object.create(null), steps: [], output: '' } };
  const defaultBytes = 10000000000;
  let saveTimer = 0;

  function esc(value) { return String(value ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])); }
  function timeText(value) { try { return new Date(value).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }); } catch { return String(value || ''); } }
  function shortBytes(value) { const n = Number(value); if (!Number.isFinite(n)) return '—'; if (n < 1024) return `${n} B`; const u = ['KiB', 'MiB', 'GiB', 'TiB']; let x = n, i = -1; do { x /= 1024; i++; } while (x >= 1024 && i < u.length - 1); return `${x.toFixed(x >= 10 ? 0 : 1)} ${u[i]}`; }
  function counterBigInt(row, key) {
    const exact = row[`${key}Exact`];
    if (typeof exact === 'string' && /^\d+$/.test(exact)) { try { return BigInt(exact); } catch { return null; } }
    const value = row[key];
    return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 ? BigInt(value) : null;
  }
  function shortBigBytes(value) {
    const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB'];
    let unit = 0, divisor = 1n;
    while (value / (divisor * 1024n) >= 1n && unit < units.length - 1) { divisor *= 1024n; unit++; }
    if (unit === 0) return `${value.toString()} B`;
    const whole = value / divisor;
    const decimal = ((value % divisor) * 10n) / divisor;
    return `${whole.toString()}.${decimal.toString()} ${units[unit]}`;
  }
  function connectionRows() {
    const snapshot = state.snapshot;
    if (!snapshot) return [];
    const filter = ($('connection-search').value || '').toLowerCase().trim();
    const view = state.config.view || {};
    const protocol = $('protocol-filter').value || view.protocol || 'all';
    const connectionState = $('state-filter').value || view.state || 'all';
    const nativeFiltered = Array.isArray(snapshot.filteredConnections) && snapshot.appliedFilter === (view.search || '');
    const sourceRows = nativeFiltered ? snapshot.filteredConnections : (snapshot.connections || []);
    const rows = sourceRows.filter(row => {
      const protocolText = String(row.proto || '').toLowerCase();
      if (protocol !== 'all' && !protocolText.startsWith(protocol)) return false;
      if (connectionState !== 'all' && String(row.state || '').toUpperCase() !== connectionState) return false;
      return nativeFiltered || `${row.process || ''} ${row.pid || ''} ${row.proto || ''} ${row.local || ''} ${row.lport || ''} ${row.remote || ''} ${row.rport || ''} ${row.state || ''}`.toLowerCase().includes(filter);
    });
    const collator = new Intl.Collator(undefined, { numeric: true, sensitivity: 'base' });
    const valueFor = row => {
      switch (state.sortKey) {
        case 'pid': return Number(row.pid);
        case 'proto': return String(row.proto || '');
        case 'local': return `${row.local || ''}:${row.lport || ''}`;
        case 'remote': return `${row.remote || ''}:${row.rport || ''}`;
        case 'state': return String(row.state || '');
        case 'rx': return counterBigInt(row, 'socketRxBytes');
        case 'tx': return counterBigInt(row, 'socketTxBytes');
        default: return String(row.process || '');
      }
    };
    return rows.map((row, index) => ({ row, index, value: valueFor(row) })).sort((a, b) => {
      const av = a.value, bv = b.value;
      const aMissing = av == null || (typeof av === 'number' && !Number.isFinite(av));
      const bMissing = bv == null || (typeof bv === 'number' && !Number.isFinite(bv));
      let order = 0;
      if (aMissing !== bMissing) return aMissing ? 1 : -1;
      if (aMissing) order = 0;
      else if (typeof av === 'bigint' && typeof bv === 'bigint') order = av < bv ? -1 : av > bv ? 1 : 0;
      else if (typeof av === 'number' && typeof bv === 'number') order = av - bv;
      else order = collator.compare(String(av), String(bv));
      return order === 0 ? a.index - b.index : order * (state.sortDescending ? -1 : 1);
    }).map(item => item.row);
  }
  function csvCell(value) {
    let text = String(value ?? '');
    if (/^[\t\r\n]/.test(text) || /^[\u0000-\u0020]*[=+\-@]/.test(text)) text = `'${text}`;
    return `"${text.replace(/"/g, '""')}"`;
  }
  function tsvCell(value) {
    let text = String(value ?? '');
    if (/^[\t\r\n]/.test(text) || /^[\u0000-\u0020]*[=+\-@]/.test(text)) text = `'${text}`;
    return text.replace(/[\t\r\n]+/g, ' ');
  }
  function exportableRows() {
    const visible = connectionRows();
    const selected = visible.filter(row => state.selectedRows.has(rowKey(row)));
    return { rows: selected.length ? selected : visible, selected: selected.length > 0 };
  }
  function exportConnections() {
    if (!state.snapshot) { toast('No snapshot to export', 'Refresh the connection snapshot first.', true); return; }
    const { rows: exportRows, selected } = exportableRows();
    const headers = ['Snapshot generated at (UTC)', 'Process', 'PID', 'Protocol', 'Local address', 'Local port', 'Remote address', 'Remote port', 'State', 'Received bytes', 'Sent bytes', 'RTT ms'];
    const generatedAt = state.snapshot.generatedAt || '';
    const values = exportRows.map(row => [generatedAt, row.process, row.pid, row.proto, row.local, row.lport, row.remote, row.rport, row.state, counterBigInt(row, 'socketRxBytes')?.toString() ?? '', counterBigInt(row, 'socketTxBytes')?.toString() ?? '', row.rttMs]);
    const format = $('export-format').value || 'csv';
    let content, type;
    if (format === 'json') {
      content = JSON.stringify(exportRows.map(row => ({ snapshotGeneratedAtUtc: generatedAt, process: row.process ?? null, pid: row.pid ?? null, protocol: row.proto ?? null, localAddress: row.local ?? null, localPort: row.lport ?? null, remoteAddress: row.remote ?? null, remotePort: row.rport ?? null, state: row.state ?? null, receivedBytesExact: counterBigInt(row, 'socketRxBytes')?.toString() ?? null, sentBytesExact: counterBigInt(row, 'socketTxBytes')?.toString() ?? null, rttMs: row.rttMs ?? null })), null, 2) + '\n';
      type = 'application/json;charset=utf-8';
    } else {
      const delimiter = format === 'tsv' ? '\t' : ',';
      const cell = format === 'tsv' ? tsvCell : csvCell;
      content = [headers, ...values].map(row => row.map(cell).join(delimiter)).join('\r\n') + '\r\n';
      if (format === 'csv') content = `\ufeff${content}`;
      type = format === 'tsv' ? 'text/tab-separated-values;charset=utf-8' : 'text/csv;charset=utf-8';
    }
    const blob = new Blob([content], { type });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `wintcp-connections-${new Date().toISOString().replace(/[:.]/g, '-')}.${format}`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    toast(`${format.toUpperCase()} export ready`, `${exportRows.length.toLocaleString()} ${selected ? 'selected' : 'filtered'} snapshot rows exported with exact counters where available.`);
  }
  async function copyConnections() {
    const { rows, selected } = exportableRows();
    if (!rows.length) { toast('No rows to copy', 'Adjust the current filter or refresh the snapshot.', true); return; }
    const headers = ['Process', 'PID', 'Protocol', 'Local address', 'Local port', 'Remote address', 'Remote port', 'State', 'Received bytes', 'Sent bytes'];
    const values = rows.map(row => [row.process, row.pid, row.proto, row.local, row.lport, row.remote, row.rport, row.state, counterBigInt(row, 'socketRxBytes')?.toString() ?? '', counterBigInt(row, 'socketTxBytes')?.toString() ?? '']);
    try { await navigator.clipboard.writeText([headers, ...values].map(row => row.map(tsvCell).join('\t')).join('\r\n')); toast('Rows copied', `${rows.length.toLocaleString()} ${selected ? 'selected' : 'filtered'} rows copied as tab-separated text.`); }
    catch { toast('Clipboard unavailable', 'Select rows and use the browser copy command, or export the current view as a file.', true); }
  }
  function toast(title, detail, warn = false) { const node = document.createElement('div'); node.className = 'toast'; node.innerHTML = `<strong>${esc(title)}</strong><p>${esc(detail)}</p>`; if (warn) node.style.borderColor = 'rgba(243,184,95,.45)'; $('toast-region').append(node); setTimeout(() => node.remove(), 6500); }
  function queueConfigSave(eventName = 'configuration-saved', delay = 900) { if (saveTimer) clearTimeout(saveTimer); saveTimer = setTimeout(() => { saveTimer = 0; saveConfig(eventName).catch(() => {}); }, delay); }

  async function api(path, options = {}) {
    const headers = new Headers(options.headers || {});
    if (options.method && options.method !== 'GET') headers.set('X-WinTCP-Token', token);
    const response = await fetch(path, { cache: 'no-store', credentials: 'same-origin', ...options, headers });
    const text = await response.text();
    let value;
    try { value = text ? JSON.parse(text) : {}; } catch { throw new Error(`Invalid response from ${path}`); }
    if (!response.ok) throw new Error(value.error || value.message || `Request failed (${response.status})`);
    return value;
  }

  let confirmResolver = null;
  let confirmPreviousFocus = null;
  function setupConfirmDialog() {
    const dialog = $('confirm-dialog');
    if (!dialog) return;
    dialog.addEventListener('close', () => {
      if (confirmResolver) { confirmResolver(dialog.returnValue === 'confirm'); confirmResolver = null; }
      if (confirmPreviousFocus && typeof confirmPreviousFocus.focus === 'function') confirmPreviousFocus.focus();
      confirmPreviousFocus = null;
    });
  }
  function confirmAction(message, options = {}) {
    const dialog = $('confirm-dialog');
    const title = options.title || 'Confirm action';
    const confirmLabel = options.confirmLabel || 'Confirm';
    const cancelLabel = options.cancelLabel || 'Cancel';
    if (!dialog || typeof dialog.showModal !== 'function') return Promise.resolve(window.confirm(message));
    confirmPreviousFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    $('confirm-dialog-title').textContent = title;
    $('confirm-dialog-message').textContent = message;
    $('confirm-ok').textContent = confirmLabel;
    $('confirm-cancel').textContent = cancelLabel;
    dialog.returnValue = 'cancel';
    dialog.showModal();
    return new Promise(resolve => { confirmResolver = resolve; });
  }

  function setServerStatus(mode, text) {
    const pill = $('server-status');
    const className = `status-pill ${mode}`;
    if (pill.className !== className || pill.textContent.trim() !== text) { pill.className = className; pill.innerHTML = `<i aria-hidden="true"></i> ${esc(text)}`; }
    document.querySelector('.snapshot-label .pulse')?.classList.toggle('pulse-stale', mode !== 'status-online');
    $('footer-health').textContent = mode === 'status-online' ? 'Loopback service connected' : text;
  }

  function switchView(name) {
    document.querySelectorAll('.view').forEach(v => v.classList.toggle('is-visible', v.id === `view-${name}`));
    document.querySelectorAll('.nav-item').forEach(b => { const active = b.dataset.view === name; b.classList.toggle('is-active', active); if (active) b.setAttribute('aria-current', 'page'); else b.removeAttribute('aria-current'); });
    if (name === 'settings') loadAudit();
  }
  // Sections inside the Automations page, tabs instead of one long scrolling
  // stack (templates, rules, events, workbench and console all at once was the
  // "messy page"). Uses the HTML hidden attribute so it works regardless of
  // each block's own display kind (grid lists, panels, etc.).
  function switchAutomationTab(name) {
    document.querySelectorAll('[data-autopane]').forEach(pane => { pane.hidden = pane.getAttribute('data-autopane') !== name; });
    document.querySelectorAll('[data-autotab]').forEach(btn => { const active = btn.getAttribute('data-autotab') === name; btn.classList.toggle('is-active', active); btn.setAttribute('aria-selected', active ? 'true' : 'false'); });
  }
  // Opening a template or saved script should land the operator in the editor,
  // not leave them on whichever tab happened to be showing.
  function revealScriptEditor() { switchAutomationTab('scripts'); }
  function canBlockRow(row) {
    return !!row && !row.removed && String(row.proto || '').toLowerCase().startsWith('tcp') && String(row.state || '').toUpperCase() === 'ESTABLISHED' && !!row.remote && /^\d{1,5}$/.test(String(row.rport)) && Number(row.rport) > 0 && Number(row.rport) <= 65535;
  }

  function isWildcardBindAddress(address) {
    let host = String(address || '').trim().toLowerCase();
    if (host.startsWith('[') && host.endsWith(']')) host = host.slice(1, -1);
    const zone = host.indexOf('%');
    if (zone >= 0) host = host.slice(0, zone);
    return host === '0.0.0.0' || host === '::' || host === '*';
  }

  function renderConnections() {
    const snapshot = state.snapshot;
    if (!snapshot) return;
    const rows = snapshot.connections || [];
    const visible = connectionRows();
    // ---- live diff (TCPView-style) ----
    // The server sends only `removed` (one-cycle ghosts); "new" and "changed"
    // are derived here by diffing this snapshot's live rows against the last
    // one. A flash lasts a few seconds and is not persisted, so a reload starts
    // calm; the first render only seeds the baseline.
    const diffNow = Date.now();
    const liveRows = rows.filter(r => !r.removed);
    const liveKeys = new Set(liveRows.map(rowKey));
    let newCount = 0, changedCount = 0, closedCount = 0;
    if (state.rowHistorySeeded) {
      for (const row of liveRows) {
        const key = rowKey(row);
        const prev = state.rowHistory.get(key);
        const cur = String(row.state || '');
        if (prev === undefined) { state.rowFlash.set(key, { kind: 'new', until: diffNow + 4000 }); ++newCount; }
        else if (prev !== cur) { state.rowFlash.set(key, { kind: 'changed', until: diffNow + 4000 }); ++changedCount; }
      }
      for (const key of state.rowHistory.keys()) if (!liveKeys.has(key)) ++closedCount;
    }
    state.rowHistory.clear();
    for (const row of liveRows) state.rowHistory.set(rowKey(row), String(row.state || ''));
    state.rowHistorySeeded = true;
    for (const [key, v] of state.rowFlash) if (v.until < diffNow) state.rowFlash.delete(key);
    const activityText = [newCount ? `+${newCount} new` : '', changedCount ? `${changedCount} changed` : '', closedCount ? `-${closedCount} closed` : ''].filter(Boolean).join(' · ');
    const view = state.config.view || {};
    const columns = Array.isArray(view.columns) ? view.columns : ['process', 'pid', 'proto', 'local', 'remote', 'state', 'traffic'];
    const table = $('connection-table');
    table.className = `connection-table ${['process', 'pid', 'proto', 'local', 'remote', 'state', 'traffic'].filter(column => !columns.includes(column)).map(column => `column-hidden-${column}`).join(' ')}`;
    const columnCount = columns.length + 2;
    $('metric-connections').textContent = rows.filter(r => !r.removed).length.toLocaleString();
    $('metric-established').textContent = rows.filter(r => !r.removed && String(r.state || '').toUpperCase() === 'ESTABLISHED').length.toLocaleString();
    $('metric-processes').textContent = new Set(rows.filter(r => !r.removed).map(r => r.pid).filter(Boolean)).size.toLocaleString();
    const traffic = snapshot.traffic || {};
    const coverage = traffic.tcpRows === 0 ? 'N/A' : `${Math.round((traffic.socketRows / traffic.tcpRows) * 100)}%`;
    $('metric-coverage').textContent = coverage;
    $('coverage-detail').textContent = `${traffic.socketRows || 0} of ${traffic.tcpRows || 0} TCP rows have socket counters`;
    $('last-updated').textContent = `${view.frozen ? 'Frozen · ' : ''}Updated ${timeText(snapshot.generatedAt)}${activityText ? ` · ${activityText}` : ''}`;
    $('connection-count-label').textContent = `${visible.length.toLocaleString()} of ${rows.length.toLocaleString()} rows`;
    $('traffic-source-label').textContent = `Sampler ${traffic.sampler ? 'available' : 'unavailable'} · ${traffic.timeouts || 0} timeouts · ${traffic.unreadable || 0} unreadable`;
    $('connection-sort').value = state.sortKey;
    $('protocol-filter').value = view.protocol || 'all';
    $('state-filter').value = view.state || 'all';
    $('group-by-process').checked = view.groupByProcess === true;
    $('freeze-view').checked = view.frozen === true;
    $('sort-direction').textContent = state.sortDescending ? 'Descending' : 'Ascending';
    $('sort-direction').setAttribute('aria-label', `Sort ${state.sortDescending ? 'descending' : 'ascending'}`);
    const body = $('connection-rows');
    const displayed = visible.slice(0, 250);
    const selectedVisible = visible.filter(row => state.selectedRows.has(rowKey(row)));
    $('selection-label').textContent = `${selectedVisible.length} selected${state.selectedRows.size > selectedVisible.length ? ` · ${state.selectedRows.size - selectedVisible.length} hidden by filters` : ''}`;
    $('select-visible-rows').disabled = !displayed.length;
    $('clear-row-selection').disabled = state.selectedRows.size === 0;
    $('bookmark-selected-rows').disabled = selectedVisible.length === 0;
    $('copy-connections').disabled = visible.length === 0;
    $('export-connections').disabled = !state.snapshot || visible.length === 0;
    $('export-connections').textContent = selectedVisible.length ? 'Export selected' : 'Export view';
    if (!visible.length) { body.innerHTML = `<tr><td colspan="${columnCount}" class="empty-state">${rows.length ? 'No rows match this filter.' : 'No connections in the current snapshot.'}</td></tr>`; return; }
    const renderRow = row => {
      const stateName = String(row.state || '—');
      const stateClass = stateName.toUpperCase() === 'LISTENING' ? 'state-listen' : stateName.toUpperCase() === 'ESTABLISHED' ? 'state-established' : '';
      const trafficText = row.traffic || (row.socketCountersAvailable ? `${shortBytes(row.socketRxBytes)} / ${shortBytes(row.socketTxBytes)}` : '—');
      const key = rowKey(row);
      const canBlock = canBlockRow(row);
      const flash = state.rowFlash.get(key);
      const diffClass = flash && flash.until > diffNow ? ` row-${flash.kind}` : '';
      return `<tr data-row-key="${esc(key)}" class="${row.removed ? 'removed-row' : ''}${diffClass}"><td data-column="select"><input type="checkbox" data-select-row="${esc(key)}" aria-label="Select ${esc(row.process || 'process')} PID ${esc(row.pid || 'unknown')}" ${state.selectedRows.has(key) ? 'checked' : ''}></td><td data-column="process" class="process-name">${esc(row.process || '—')}</td><td data-column="pid" class="muted-cell">${esc(row.pid || '—')}</td><td data-column="proto">${esc(row.proto || '—')}</td><td data-column="local">${esc(row.local || '—')}:${esc(row.lport || '—')}</td><td data-column="remote">${esc(row.remote || '—')}:${esc(row.rport || '—')}</td><td data-column="state"><span class="state-chip ${stateClass}">${esc(stateName)}</span></td><td data-column="traffic">${esc(trafficText)}</td><td data-column="action"><div class="row-actions"><button class="button button-small" data-detail-row="${esc(key)}" type="button">Details</button><button class="button button-danger button-small" data-block-row="" data-address="${esc(row.remote || '')}" data-port="${esc(row.rport || '')}" type="button" ${canBlock ? '' : 'disabled'}>Block</button></div></td></tr>`;
    };
    if (view.groupByProcess) {
      const groups = new Map();
      for (const row of displayed) { const name = String(row.process || 'Unknown process'); if (!groups.has(name)) groups.set(name, []); groups.get(name).push(row); }
      body.innerHTML = [...groups.entries()].map(([name, group]) => `<tr class="process-group-row"><th colspan="${columnCount}" scope="rowgroup">${esc(name)} <span>${group.length} connection${group.length === 1 ? '' : 's'}</span></th></tr>${group.map(renderRow).join('')}`).join('');
    } else body.innerHTML = displayed.map(renderRow).join('');
    document.querySelectorAll('[data-select-row]').forEach(input => input.addEventListener('change', () => {
      if (input.checked) state.selectedRows.add(input.dataset.selectRow); else state.selectedRows.delete(input.dataset.selectRow);
      renderConnections();
    }));
    document.querySelectorAll('[data-block-row]').forEach(button => button.addEventListener('click', () => previewAndBlock(button.dataset.address, Number(button.dataset.port))));
    document.querySelectorAll('[data-detail-row]').forEach(button => button.addEventListener('click', () => showConnectionDetails(button.dataset.detailRow)));
  }

  function readViewControls() {
    return {
      protocol: $('protocol-filter').value || 'all', state: $('state-filter').value || 'all',
      search: $('connection-search').value || '', sortKey: $('connection-sort').value || 'process',
      sortDescending: state.sortDescending, groupByProcess: $('group-by-process').checked,
      frozen: $('freeze-view').checked, columns: state.config.view.columns || []
    };
  }
  function applyViewControls(view) {
    const next = view || {};
    state.config.view = { ...state.config.view, ...next };
    $('protocol-filter').value = state.config.view.protocol || 'all';
    $('state-filter').value = state.config.view.state || 'all';
    $('connection-search').value = state.config.view.search || '';
    $('connection-sort').value = state.config.view.sortKey || 'process';
    $('group-by-process').checked = state.config.view.groupByProcess === true;
    $('freeze-view').checked = state.config.view.frozen === true;
    for (const column of ['process', 'pid', 'proto', 'local', 'remote', 'state', 'traffic']) $(`column-${column}`).checked = (state.config.view.columns || []).includes(column);
    state.sortKey = state.config.view.sortKey || 'process';
    state.sortDescending = state.config.view.sortDescending === true;
    if (!state.config.view.frozen && state.liveSnapshot) state.snapshot = state.liveSnapshot;
    renderConnections();
  }
  function renderViewPresets() {
    const select = $('view-preset');
    if (!select) return;
    const selected = select.value;
    select.innerHTML = '<option value="">Select a saved view</option>' + state.config.presets.map(preset => `<option value="${esc(preset.id)}">${esc(preset.name)}</option>`).join('');
    if (state.config.presets.some(preset => preset.id === selected)) select.value = selected;
    $('load-view-preset').disabled = !select.value;
    $('delete-view-preset').disabled = !select.value;
  }
  function applyTheme() {
    const mode = ['system', 'dark', 'light'].includes(state.config.theme) ? state.config.theme : 'system';
    const prefersLight = window.matchMedia('(prefers-color-scheme: light)').matches;
    const light = mode === 'light' || (mode === 'system' && prefersLight);
    document.body.classList.toggle('light-mode', light);
    const select = $('theme-mode');
    if (select) select.value = mode;
  }
  async function setThemeMode(mode) {
    state.config.theme = ['system', 'dark', 'light'].includes(mode) ? mode : 'system';
    applyTheme();
    await saveConfig('theme-updated');
    toast('Theme updated', `Color theme set to ${state.config.theme}.`);
  }

  async function saveViewPreset() {
    const name = $('view-preset-name').value.trim();
    if (!name || name.length > 60) { toast('View name required', 'Enter a name up to 60 characters.', true); return; }
    let preset = state.config.presets.find(item => item.name.toLowerCase() === name.toLowerCase());
    if (preset && !(await confirmAction(`Replace the saved view "${preset.name}"?`, { title: 'Replace saved view', confirmLabel: 'Replace' }))) return;
    if (!preset && state.config.presets.length >= 20) { toast('Preset limit reached', 'Remove an unused view before saving another.', true); return; }
    if (preset) preset.view = readViewControls();
    else { preset = { id: crypto.randomUUID(), name, view: readViewControls() }; state.config.presets.push(preset); }
    renderViewPresets();
    $('view-preset').value = preset.id;
    renderViewPresets();
    if (await saveConfig('view-preset-saved')) toast('View saved', `${preset.name} now restores your connection filters, sort, grouping, and freeze preference.`);
  }
  async function loadViewPreset() {
    const preset = state.config.presets.find(item => item.id === $('view-preset').value);
    if (!preset) return;
    applyViewControls(preset.view);
    if (await saveConfig('view-preset-loaded')) toast('View loaded', `Restored ${preset.name}.`);
  }
  async function deleteViewPreset() {
    const preset = state.config.presets.find(item => item.id === $('view-preset').value);
    if (!preset || !(await confirmAction(`Delete the saved view "${preset.name}"?`, { title: 'Delete saved view', confirmLabel: 'Delete', danger: true }))) return;
    state.config.presets = state.config.presets.filter(item => item.id !== preset.id);
    $('view-preset-name').value = ''; renderViewPresets();
    await saveConfig('view-preset-removed');
  }
  function renderBookmarks() {
    $('bookmark-count').innerHTML = `<strong>${state.config.bookmarks.length}</strong> saved`;
    $('bookmark-list').innerHTML = state.config.bookmarks.map(bookmark => `<article class="bookmark-row"><div class="bookmark-copy"><strong>${esc(bookmark.process || 'Unknown process')} <span>PID ${esc(bookmark.pid || '?')}</span></strong><div>${esc(bookmark.proto || '')} · ${esc(bookmark.local || '?')}:${esc(bookmark.lport || '?')} → ${esc(bookmark.remote || '?')}:${esc(bookmark.rport || '?')} · ${esc(bookmark.state || 'Unknown')}</div><p>${esc(bookmark.note || 'No investigation note. Add a note to preserve context for later review.')}</p><small>Saved ${esc(timeText(bookmark.addedAt))}</small></div><div class="bookmark-actions"><button class="button button-small" data-edit-bookmark="${esc(bookmark.id)}" type="button">Edit note</button><button class="button button-small button-quiet" data-remove-bookmark="${esc(bookmark.id)}" type="button">Remove</button></div></article>`).join('') || '<div class="empty-state">Select one or more visible connections and bookmark them to begin an investigation.</div>';
    document.querySelectorAll('[data-edit-bookmark]').forEach(button => button.addEventListener('click', () => editBookmarkNote(button.dataset.editBookmark)));
    document.querySelectorAll('[data-remove-bookmark]').forEach(button => button.addEventListener('click', () => removeBookmark(button.dataset.removeBookmark)));
  }
  async function bookmarkSelectedRows() {
    const rows = connectionRows().filter(row => state.selectedRows.has(rowKey(row)));
    if (!rows.length) { toast('Select connections first', 'Choose visible rows before bookmarking them.', true); return; }
    const existing = new Set(state.config.bookmarks.map(item => item.rowKey));
    const candidates = rows.filter(row => !existing.has(rowKey(row)));
    if (!candidates.length) { toast('Already bookmarked', 'Every selected connection is already in Bookmarks & notes.'); return; }
    if (state.config.bookmarks.length + candidates.length > 100) { toast('Bookmark limit reached', 'Remove older bookmarks before saving more; the local limit is 100.', true); return; }
    for (const row of candidates) state.config.bookmarks.push({ id: crypto.randomUUID(), rowKey: rowKey(row), process: String(row.process || ''), pid: String(row.pid || ''), proto: String(row.proto || ''), local: String(row.local || ''), lport: String(row.lport || ''), remote: String(row.remote || ''), rport: String(row.rport || ''), state: String(row.state || ''), note: '', addedAt: new Date().toISOString() });
    renderBookmarks();
    if (await saveConfig('connection-bookmarked')) toast('Connections bookmarked', `${candidates.length} selected connection${candidates.length === 1 ? '' : 's'} saved with editable local notes.`);
  }
  async function editBookmarkNote(id) {
    const bookmark = state.config.bookmarks.find(item => item.id === id);
    if (!bookmark) return;
    const note = window.prompt('Investigation note (up to 500 characters):', bookmark.note);
    if (note === null) return;
    bookmark.note = String(note).slice(0, 500);
    renderBookmarks(); await saveConfig('bookmark-note-updated');
  }
  async function removeBookmark(id) {
    const bookmark = state.config.bookmarks.find(item => item.id === id);
    if (!bookmark || !(await confirmAction(`Remove the bookmark for ${bookmark.process || 'this process'} PID ${bookmark.pid || '?'}?`, { title: 'Remove bookmark', confirmLabel: 'Remove', danger: true }))) return;
    state.config.bookmarks = state.config.bookmarks.filter(item => item.id !== id);
    renderBookmarks(); await saveConfig('bookmark-removed');
  }

  function renderTemplates() {
    const query = ($('template-search').value || '').toLowerCase().trim();
    const items = state.templates.filter(t => `${t.id} ${t.category} ${t.title} ${t.summary} ${t.script || ''}`.toLowerCase().includes(query));
    $('template-list').innerHTML = items.map(t => `<article class="template-card">
      <div class="template-card-head"><div><span class="template-id">${esc(t.id)} · ${esc(t.category)}</span><h3>${esc(t.title)}</h3></div><span class="${t.ready ? 'ready-badge' : 'planned-badge'}">${t.ready ? 'MONITOR READY' : 'PREPARED'}</span></div>
      <p>${esc(t.summary)}</p><div class="template-meta"><span>${esc(t.data)}</span><span>${esc(t.risk)}</span></div>
      <div class="template-actions"><small>${esc(t.response)}</small><div class="template-action-buttons"><button class="button button-small button-quiet" data-template-script="${esc(t.id)}" type="button">Open script</button><button class="button button-small ${t.ready ? '' : 'button-quiet'}" data-add-template="${esc(t.id)}" type="button" ${t.ready ? '' : 'disabled'}>${t.ready ? 'Add monitor' : 'No monitor evaluator'}</button></div></div>
    </article>`).join('') || '<div class="empty-state">No matching templates.</div>';
    document.querySelectorAll('[data-add-template]').forEach(button => button.addEventListener('click', () => addRule(button.dataset.addTemplate)));
    document.querySelectorAll('[data-template-script]').forEach(button => button.addEventListener('click', () => openTemplateScript(button.dataset.templateScript)));
    renderScriptLibrary();
  }

  function setScriptSource(template, editable) {
    const badge = $('script-source-badge');
    const capability = $('script-capability');
    if (!template) {
      badge.className = 'planned-badge';
      badge.textContent = editable ? 'Custom local CLI script' : 'No script selected';
      capability.textContent = 'Scripts invoke only the sibling wintcp.exe. Monitor readiness is separate; saving or running a script never creates a monitor.';
      return;
    }
    badge.className = 'ready-badge';
    badge.textContent = editable ? `${template.id} · editable CLI copy` : `${template.id} · built-in CLI script`;
    // Be explicit about what this playbook actually does: the title's threshold
    // (e.g. "10 GB in a rolling hour") is the MONITOR's rule, not the script.
    // The script is a read-only inspector of current state - running it will
    // never see "10 GB exceeded", because it holds no window and no threshold.
    // Enforcement happens only through "Add monitor" and only while this page
    // is open (no background instance, by design).
    let note;
    if (template.runtime === 'remote-byte-window') {
      const gb = (Number(template.defaultThreshold) || 0) / 1000000000;
      const winSec = Math.max(60, Number(template.windowSeconds) || 3600);
      const win = winSec % 3600 === 0 ? `${winSec / 3600}-hour` : `${Math.round((winSec / 3600) * 10) / 10}-hour`;
      note = `${template.category} playbook. The ${gb} GB / ${win} budget described by the title is enforced by the MONITOR (use "Add monitor"), which accumulates samples over the window and fires only while this page is open. The script below is a read-only inspector - it lists current per-peer totals and does NOT compute or enforce the ${gb} GB threshold.`;
    } else {
      note = `${template.category} playbook. If it has "Add monitor" available, its threshold is enforced by that rule while this page is open; the script below is a read-only CLI inspector of current state.`;
    }
    capability.textContent = note;
  }
  const starterScript = '# WinTCP Script v1\n# One local CLI call, followed by an exit-code branch.\nlet snapshot = list --format json --filter "state:estab" --limit 25\nif snapshot.exitCode == 0\n  print "Snapshot captured. Inspect ${snapshot.stdout} in Variables or use it in later commands."\nelse\n  print "CLI exit ${snapshot.exitCode}: ${snapshot.stderr}"\nend\n';
  function openNewScript() {
    state.currentScriptId = '';
    state.currentTemplateId = 'CUSTOM';
    $('script-name').value = 'New local script';
    $('automation-content').value = starterScript;
    setScriptSource(null, true);
    $('script-validation').className = 'script-validation';
    $('script-validation').textContent = 'Unsaved script. Validate it, then save to My scripts or run it locally.';
    $('script-remove').disabled = true;
    revealScriptEditor();
    $('script-workbench-title').scrollIntoView?.({ behavior: 'smooth', block: 'start' });
    toast('New script draft', 'A one-command starter is loaded. Validate, then Save script or Run it.');
  }
  function openTemplateScript(id, makeCopy = false) {
    const template = state.templates.find(item => item.id === id);
    if (!template || typeof template.script !== 'string') return;
    state.currentScriptId = '';
    state.currentTemplateId = template.id;
    $('script-name').value = makeCopy ? `${template.title} (copy)` : template.title;
    $('automation-content').value = template.script;
    setScriptSource(template, makeCopy);
    $('script-validation').className = 'script-validation';
    $('script-validation').textContent = makeCopy ? 'Editable copy not saved yet. Edit the source, validate it, then save to My scripts.' : 'Built-in source is read-only in My scripts; edit it here and Save script to create a managed copy.';
    $('script-remove').disabled = true;
    revealScriptEditor();
    $('script-workbench-title').scrollIntoView?.({ behavior: 'smooth', block: 'start' });
  }
  function openSavedScript(id) {
    const script = state.config.scripts.find(item => item.id === id);
    if (!script) return;
    const template = state.templates.find(item => item.id === script.templateId) || null;
    state.currentScriptId = script.id;
    state.currentTemplateId = template ? template.id : 'CUSTOM';
    $('script-name').value = script.name;
    $('automation-content').value = script.content;
    setScriptSource(template, true);
    $('script-validation').className = 'script-validation';
    $('script-validation').textContent = `Saved locally · updated ${timeText(script.updatedAt)}. Validate, edit, run, or save changes.`;
    $('script-remove').disabled = false;
    revealScriptEditor();
  }
  function renderScriptLibrary() {
    if (!$('my-script-list') || !$('script-template-list')) return;
    const query = ($('script-library-search').value || '').toLowerCase().trim();
    const scripts = state.config.scripts.filter(item => `${item.name} ${item.templateId} ${item.content}`.toLowerCase().includes(query));
    $('script-library-count').textContent = String(state.config.scripts.length);
    $('my-script-list').innerHTML = scripts.map(item => {
      const label = item.templateId === 'CUSTOM' ? 'Custom CLI script' : `${esc(item.templateId)} CLI script`;
      return `<button class="script-list-item" data-open-script="${esc(item.id)}" type="button"><span><strong>${esc(item.name)}</strong><small>${label} · local source</small></span><span aria-hidden="true">›</span></button>`;
    }).join('') || '<div class="empty-state">No saved scripts yet. Open one of the 40 templates or create a custom script.</div>';
    const templates = state.templates.filter(t => `${t.id} ${t.category} ${t.title} ${t.data} ${t.script || ''}`.toLowerCase().includes(query));
    $('script-template-list').innerHTML = templates.map(template => `<button class="script-list-item" data-open-template="${esc(template.id)}" type="button"><span><strong>${esc(template.id)} · ${esc(template.title)}</strong><small>${esc(template.category)} · local CLI playbook</small></span><span aria-hidden="true">›</span></button>`).join('') || '<div class="empty-state">No matching templates.</div>';
    document.querySelectorAll('[data-open-script]').forEach(button => button.addEventListener('click', () => openSavedScript(button.dataset.openScript)));
    document.querySelectorAll('[data-open-template]').forEach(button => button.addEventListener('click', () => openTemplateScript(button.dataset.openTemplate)));
  }

  function renderRules() {
    const list = $('rule-list');
    $('rule-count').textContent = String(state.config.rules.length);
    if (!state.config.rules.length) { list.innerHTML = '<div class="empty-state">No rules added yet. Choose a ready template to begin.</div>'; return; }
    list.innerHTML = state.config.rules.map(rule => {
      const template = state.templates.find(t => t.id === rule.templateId);
      if (!template) return '';
      const threshold = Number(rule.threshold ?? template.defaultThreshold ?? 10);
      const thresholdText = template.runtime === 'remote-byte-window' ? `<label>GB <input type="number" min="0.1" max="1024" step="0.1" value="${(threshold / 1000000000).toFixed(1)}" data-threshold="${esc(rule.id)}"></label>` : `<label>Limit <input type="number" min="1" max="100000" step="1" value="${esc(threshold)}" data-threshold="${esc(rule.id)}"></label>`;
      const canBlock = template.runtime === 'remote-byte-window';
      return `<article class="rule-card"><div class="rule-card-head"><div><span class="template-id">${esc(template.id)} · ${esc(template.category)}</span><h3>${esc(rule.name || template.title)}</h3></div><button class="button button-small button-quiet" data-remove-rule="${esc(rule.id)}" type="button">Remove</button></div>
        <div class="rule-controls"><label class="toggle"><input type="checkbox" data-enabled="${esc(rule.id)}" ${rule.enabled ? 'checked' : ''}> Monitor</label>${thresholdText}${canBlock ? `<label>Response <select data-action="${esc(rule.id)}"><option value="notify" ${rule.action === 'block' ? '' : 'selected'}>Notify only</option><option value="block" ${rule.action === 'block' ? 'selected' : ''}>Offer confirmed block</option></select></label>` : ''}</div>
        <div class="rule-status ${rule.enabled ? 'active' : ''}">${rule.enabled ? (template.runtime === 'remote-byte-window' ? 'Evaluating only with complete per-socket coverage.' : 'Monitor active while this page is open.') : 'Disabled. Enable to start monitoring.'}</div></article>`;
    }).join('');
    document.querySelectorAll('[data-enabled]').forEach(el => el.addEventListener('change', () => updateRule(el.dataset.enabled, { enabled: el.checked })));
    document.querySelectorAll('[data-action]').forEach(el => el.addEventListener('change', () => updateRule(el.dataset.action, { action: el.value })));
    document.querySelectorAll('[data-threshold]').forEach(el => el.addEventListener('change', () => {
      const template = state.templates.find(t => t.id === state.config.rules.find(r => r.id === el.dataset.threshold)?.templateId);
      const n = Number(el.value);
      const max = template?.runtime === 'remote-byte-window' ? 1024 : 100000;
      if (!Number.isFinite(n) || n <= 0 || n > max) { toast('Invalid threshold', `Use a value greater than 0 and no more than ${max}${template?.runtime === 'remote-byte-window' ? ' GB' : ''}.`, true); renderRules(); return; }
      updateRule(el.dataset.threshold, { threshold: template?.runtime === 'remote-byte-window' ? Math.round(n * 1000000000) : n });
    }));
    document.querySelectorAll('[data-remove-rule]').forEach(el => el.addEventListener('click', () => removeRule(el.dataset.removeRule)));
  }

  function scriptTokens(text) {
    const tokens = [];
    let token = '', quote = '', started = false;
    for (let i = 0; i < text.length; i++) {
      const c = text[i];
      if (quote && c === '\\' && i + 1 < text.length) {
        const next = text[i + 1];
        if (next === quote || next === '\\') { token += next; i++; }
        else token += c;
        started = true;
      } else if (quote) {
        if (c === quote) quote = '';
        else token += c;
        started = true;
      } else if (c === '"' || c === "'") {
        quote = c; started = true;
      } else if (/\s/.test(c)) {
        if (started) { tokens.push(token); token = ''; started = false; }
      } else { token += c; started = true; }
    }
    if (quote) throw new Error('Unclosed quoted argument.');
    if (started) tokens.push(token);
    return tokens;
  }
  function scriptLineWithoutComment(line) {
    let quote = '', escaped = false;
    for (let i = 0; i < line.length; i++) {
      const c = line[i];
      if (escaped) { escaped = false; continue; }
      if (quote && c === '\\') { escaped = true; continue; }
      if (quote) { if (c === quote) quote = ''; continue; }
      if (c === '"' || c === "'") { quote = c; continue; }
      if (c === '#') return line.slice(0, i);
    }
    return line;
  }
  function scriptCommand(commandText, line) {
    const words = scriptTokens(commandText);
    if (words[0]?.toLowerCase() === 'wintcp.exe' || words[0]?.toLowerCase() === 'wintcp') words.shift();
    if (!words.length || !/^[A-Za-z][A-Za-z0-9-]*$/.test(words[0])) throw new Error(`Line ${line}: expected a WinTCP CLI verb and arguments.`);
    const command = { type: 'command', verb: words[0].toLowerCase(), args: words.slice(1), line, source: commandText.trim() };
    if (isSensitiveCli([command.verb, ...command.args]) && command.args.some(arg => /\$\{/.test(arg)))
      throw new Error(`Line ${line}: sensitive command arguments cannot use variable substitution; write the reviewed target literally.`);
    return command;
  }
  function isSensitiveCli(argv) {
    const verb = String(argv[0] || '').toLowerCase();
    const args = argv.slice(1).map(value => String(value).toLowerCase());
    const dryRun = args.includes('--dry-run');
    if (!dryRun && ['kill', 'close', 'block', 'unblock', 'capture'].includes(verb)) return true;
    if (args.some(value => ['--yes', '-y', '--force'].includes(value))) return true;
    if (verb === 'export' || args.includes('--out')) return true;
    if (['bookmark', 'preset'].includes(verb) && ['add', 'remove', 'delete', 'note', 'colour', 'save', 'import'].includes(args[0])) return true;
    if (verb === 'alert' && args.some(value => ['--enable', '--disable', '--on-listener', '--off-listener', '--on-connection', '--off-connection', '--on-rst', '--off-rst', '--on-closed', '--off-closed', '--rule-on-new', '--rule-off-new', '--rule-on-close', '--rule-off-close', '--rule-on-threshold', '--bps-warn', '--bps-critical', '--connections', '--rule-name', '--rule-address', '--rule-process'].includes(value))) return true;
    return false;
  }
  function parseScriptCondition(text, line) {
    let match = /^if\s+([A-Za-z_][A-Za-z0-9_]*)\.exitCode\s*(==|!=|>=|<=|>|<)\s*(\d+)$/i.exec(text);
    if (match) return { variable: match[1], property: 'exitCode', operator: match[2], value: Number(match[3]) };
    match = /^if\s+([A-Za-z_][A-Za-z0-9_]*)\.(stdout|stderr)\s+contains\s+("(?:\\.|[^"\\])*")$/i.exec(text);
    if (match) {
      let value;
      try { value = JSON.parse(match[3]); } catch { throw new Error(`Line ${line}: the contains value must be a valid double-quoted string.`); }
      return { variable: match[1], property: match[2].toLowerCase(), operator: 'contains', value };
    }
    throw new Error(`Line ${line}: use if name.exitCode == 0 (or another numeric comparison), or if name.stdout contains "text".`);
  }
  function parseScript(text) {
    if (typeof text !== 'string' || new TextEncoder().encode(text).length > 8192) throw new Error('Script source must be no more than 8 KiB of UTF-8.');
    const lines = text.split(/\r?\n/);
    if (lines.length > 200) throw new Error('Scripts are limited to 200 lines.');
    const program = [], stack = [];
    let current = program, statements = 0, commands = 0;
    for (let index = 0; index < lines.length; index++) {
      const lineNumber = index + 1;
      const source = scriptLineWithoutComment(lines[index]).trim();
      if (!source) continue;
      if (/^else$/i.test(source)) {
        const frame = stack[stack.length - 1];
        if (!frame || frame.node.otherwise) throw new Error(`Line ${lineNumber}: else must appear once inside an if block.`);
        frame.node.otherwise = [];
        current = frame.node.otherwise;
        continue;
      }
      if (/^end$/i.test(source)) {
        const frame = stack.pop();
        if (!frame) throw new Error(`Line ${lineNumber}: end has no matching if.`);
        current = frame.parent;
        continue;
      }
      if (/^if\b/i.test(source)) {
        if (stack.length >= 8) throw new Error(`Line ${lineNumber}: if nesting is limited to 8 levels.`);
        const node = { type: 'if', condition: parseScriptCondition(source, lineNumber), then: [], otherwise: null, line: lineNumber };
        current.push(node); stack.push({ node, parent: current }); current = node.then; statements++;
      } else {
        let node = null;
        let match = /^let\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)$/i.exec(source);
        if (match) {
          node = scriptCommand(match[2], lineNumber);
          node.assign = match[1];
        } else if ((match = /^run\s+(.+)$/i.exec(source))) {
          node = scriptCommand(match[1], lineNumber);
          node.assign = 'last';
        } else if ((match = /^set\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)$/i.exec(source))) {
          let value = match[2].trim();
          if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
            const pieces = scriptTokens(value);
            if (pieces.length !== 1) throw new Error(`Line ${lineNumber}: set accepts one quoted string or plain text.`);
            value = pieces[0];
          }
          node = { type: 'set', name: match[1], value, line: lineNumber };
        } else if ((match = /^print\s+(.+)$/i.exec(source))) {
          let value = match[1].trim();
          if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
            const pieces = scriptTokens(value);
            if (pieces.length !== 1) throw new Error(`Line ${lineNumber}: print accepts one quoted string or plain text.`);
            value = pieces[0];
          }
          node = { type: 'print', value, line: lineNumber };
        } else {
          throw new Error(`Line ${lineNumber}: unknown statement. Use let, run, set, print, if, else, or end.`);
        }
        current.push(node); statements++;
        if (node.type === 'command') commands++;
      }
      if (statements > 100) throw new Error('Scripts are limited to 100 statements.');
    }
    if (stack.length) throw new Error(`Line ${stack[stack.length - 1].node.line}: if block is missing end.`);
    if (!statements) throw new Error('Add at least one command, assignment, print, or if statement.');
    return { program, statements, commands };
  }
  function validateCurrentScript(showToast = false) {
    try {
      const parsed = parseScript($('automation-content').value);
      $('script-validation').textContent = `Valid · ${parsed.commands} local CLI call(s), ${parsed.statements} statement(s). No shell or JavaScript is evaluated.`;
      $('script-validation').className = 'script-validation is-valid';
      if (showToast) toast('Script is valid', `${parsed.commands} local CLI command(s) are ready to run or save.`);
      return parsed;
    } catch (error) {
      $('script-validation').textContent = error.message;
      $('script-validation').className = 'script-validation is-invalid';
      if (showToast) toast('Script validation failed', error.message, true);
      return null;
    }
  }
  function scriptCommandNodes(nodes, result = []) {
    for (const node of nodes) {
      if (node.type === 'command') result.push(node);
      else if (node.type === 'if') { scriptCommandNodes(node.then, result); if (node.otherwise) scriptCommandNodes(node.otherwise, result); }
    }
    return result;
  }
  function displayCliArg(value) { return /^[A-Za-z0-9_./:\\-]+$/.test(value) ? value : JSON.stringify(value); }
  function scriptCommandDisplay(node) { return `wintcp.exe ${[node.verb, ...node.args].map(displayCliArg).join(' ')}`; }
  function renderScriptRun() {
    const run = state.scriptRun;
    $('script-run-status').textContent = run.status || (run.running ? 'Running' : 'Not run');
    $('script-run-status').className = `catalog-badge ${run.running ? 'script-status-running' : run.failed ? 'script-status-failed' : run.steps.length ? 'script-status-done' : ''}`;
    $('script-step-list').innerHTML = run.steps.length ? run.steps.map(step => `<li class="script-step script-step-${esc(step.kind)}"><span class="script-step-line">${step.line ? `L${step.line}` : 'RUN'}</span><span class="script-step-copy"><strong>${esc(step.title)}</strong><small>${esc(step.detail || '')}</small></span></li>`).join('') : '<li class="empty-state">Run a script to see its steps.</li>';
    const variables = Object.entries(run.variables);
    $('script-variable-list').innerHTML = variables.length ? variables.map(([name, value]) => {
      const detail = value && typeof value === 'object' ? `exit ${value.exitCode ?? '?'} · ${value.durationMs ?? 0} ms` : 'string';
      const preview = value && typeof value === 'object' ? `${value.stdout || ''}${value.stderr ? `\n[stderr] ${value.stderr}` : ''}`.slice(0, 1200) : String(value);
      return `<article class="script-variable"><div><strong>${esc(name)}</strong><small>${esc(detail)}</small></div><pre>${esc(preview || '(empty)')}</pre></article>`;
    }).join('') : '<div class="empty-state">Variables appear as steps assign them.</div>';
    $('script-output').textContent = run.output || 'No command output yet.';
    $('script-run').disabled = run.running;
  }
  function addScriptStep(step) {
    state.scriptRun.steps.push(step);
    state.scriptRun.steps = state.scriptRun.steps.slice(-100);
    renderScriptRun();
  }
  function addScriptOutput(text) {
    const next = state.scriptRun.output + text;
    state.scriptRun.output = next.length > 256000 ? `${next.slice(0, 256000)}\n[Combined output truncated at 256 KiB.]` : next;
    $('script-output').textContent = state.scriptRun.output;
  }
  function clearScriptResults() {
    if (state.scriptRun.running) return;
    state.scriptRun = { running: false, variables: Object.create(null), steps: [], output: '', status: 'Not run', failed: false };
    renderScriptRun();
  }
  // --- run history, persistence and refresh survival ----------------------
  // A run used to live only in client memory, so a reload (or an accidental F5)
  // wiped the status and captured output and the console read "Not run". The
  // outcome is now recorded into the persisted config (round-tripped by the
  // server), and restored on load, so a refresh shows what last ran, when, and
  // how it ended - and the Recent runs list keeps the last 25 outcomes.
  function scriptRunExit(steps) {
    let exit = null;
    for (const step of steps) {
      if (step.kind !== 'command') continue;
      const match = /exit (\d+)/.exec(step.detail || '');
      if (match) exit = Number(match[1]);
      else if (/timed out/.test(step.detail || '')) exit = null;
    }
    return exit;
  }
  function recordScriptRun() {
    const run = state.scriptRun;
    const name = ($('script-name').value || '').trim() || (state.currentTemplateId && state.currentTemplateId !== 'CUSTOM' ? `${state.currentTemplateId} playbook` : 'Untitled script');
    const exit = scriptRunExit(run.steps);
    const summary = {
      ts: new Date().toISOString(),
      name,
      templateId: state.currentTemplateId || 'CUSTOM',
      ok: !run.failed,
      status: run.status || (run.failed ? 'Stopped · error' : 'Completed'),
      exit,
      steps: run.steps.length,
    };
    state.config.scriptRuns = [summary, ...(Array.isArray(state.config.scriptRuns) ? state.config.scriptRuns : [])].slice(0, 25);
    state.config.lastScriptRun = { ...summary, output: (run.output || '').slice(0, 6000) };
    renderScriptHistory();
    saveConfig('script-run-recorded');
  }
  function renderScriptHistory() {
    const box = $('script-run-history');
    if (!box) return;
    const runs = Array.isArray(state.config.scriptRuns) ? state.config.scriptRuns : [];
    if (!runs.length) { box.innerHTML = '<div class="empty-state">No runs yet. Run a script and its outcome is recorded here, and survives a refresh.</div>'; return; }
    box.innerHTML = runs.map(run => {
      const when = run.ts ? timeText(run.ts) : '';
      const exit = run.exit === null || run.exit === undefined ? '—' : String(run.exit);
      const cls = run.ok ? 'is-ok' : 'is-bad';
      const steps = run.steps === 1 ? '1 step' : `${run.steps} steps`;
      return `<article class="script-run-item ${cls}"><span class="script-run-dot" aria-hidden="true"></span><div class="script-run-copy"><strong>${esc(run.name)}</strong><small>${esc(run.status || (run.ok ? 'Completed' : 'Stopped'))} · exit ${esc(exit)} · ${steps} · ${esc(when)}</small></div><small class="script-run-template">${esc(run.templateId || 'CUSTOM')}</small></article>`;
    }).join('');
  }
  function restoreLastScriptRun() {
    const last = state.config.lastScriptRun;
    if (!last) return;
    const status = last.status || (last.ok ? 'Completed' : 'Stopped · error');
    state.scriptRun = { running: false, variables: Object.create(null), steps: [], output: last.output || '', status, failed: !last.ok };
    const pill = $('script-run-status');
    if (pill) { pill.textContent = `${last.name} — ${status}`; pill.className = `catalog-badge ${last.ok ? 'script-status-done' : 'script-status-failed'}`; }
    const output = $('script-output');
    if (output) output.textContent = last.output || 'No command output yet.';
    const trace = $('script-step-list');
    if (trace) trace.innerHTML = `<li class="empty-state">Restored after reload — ${esc(last.name)} ${esc(String(last.exit === null || last.exit === undefined ? '' : `exit ${last.exit}`)).trim()} · ${last.steps === 1 ? '1 step' : `${last.steps} steps`}. Start a new run to record a fresh trace.</li>`;
  }
  function interpolateScript(text, variables) {
    return String(text).replace(/\$\{([A-Za-z_][A-Za-z0-9_]*)(?:\.(exitCode|stdout|stderr|durationMs))?\}/g, (_match, name, property) => {
      if (!Object.prototype.hasOwnProperty.call(variables, name)) throw new Error(`Variable '${name}' has not been assigned.`);
      const value = variables[name];
      if (!property) return value && typeof value === 'object' ? JSON.stringify(value) : String(value);
      if (!value || typeof value !== 'object' || !(property in value)) throw new Error(`Variable '${name}' has no '${property}' value.`);
      return String(value[property] ?? '');
    });
  }
  function evaluateScriptCondition(condition, variables) {
    if (!Object.prototype.hasOwnProperty.call(variables, condition.variable)) throw new Error(`Variable '${condition.variable}' has not been assigned.`);
    const value = variables[condition.variable]?.[condition.property];
    if (value == null) throw new Error(`Variable '${condition.variable}' has no '${condition.property}' value.`);
    if (condition.operator === 'contains') return String(value).includes(condition.value);
    const left = Number(value), right = Number(condition.value);
    if (!Number.isFinite(left)) throw new Error(`Variable '${condition.variable}.${condition.property}' is not numeric.`);
    return ({ '==': left === right, '!=': left !== right, '>': left > right, '<': left < right, '>=': left >= right, '<=': left <= right })[condition.operator];
  }
  function cliForm(verb, args, extra = {}) {
    const body = new URLSearchParams();
    body.set('verb', verb); body.set('argc', String(args.length));
    args.forEach((value, index) => body.set(`arg${index}`, value));
    for (const [key, value] of Object.entries(extra)) body.set(key, value);
    return body.toString();
  }
  async function runCliCommand(verb, args) {
    const sensitive = isSensitiveCli([verb, ...args]);
    let nonce = '';
    if (sensitive) {
      const permit = await api('/api/cli/authorize', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: cliForm(verb, args, { confirmed: '1' }) });
      nonce = permit.nonce;
    }
    const result = await api('/api/cli/run', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: cliForm(verb, args, nonce ? { nonce } : {}) });
    return result;
  }
  async function executeScriptNodes(nodes, variables, run) {
    for (const node of nodes) {
      if (++run.stepsExecuted > 100) throw new Error('Execution stopped at the 100-step limit.');
      if (node.type === 'if') {
        const passed = evaluateScriptCondition(node.condition, variables);
        addScriptStep({ kind: 'branch', line: node.line, title: `if ${node.condition.variable}.${node.condition.property} ${node.condition.operator} ${JSON.stringify(node.condition.value)}`, detail: passed ? 'condition true' : 'condition false' });
        await executeScriptNodes(passed ? node.then : (node.otherwise || []), variables, run);
      } else if (node.type === 'set') {
        variables[node.name] = interpolateScript(node.value, variables);
        addScriptStep({ kind: 'set', line: node.line, title: `set ${node.name}`, detail: 'string assigned' });
      } else if (node.type === 'print') {
        const text = interpolateScript(node.value, variables);
        addScriptStep({ kind: 'print', line: node.line, title: 'print', detail: text.slice(0, 220) });
        addScriptOutput(`${text}\n`);
      } else if (node.type === 'command') {
        const args = node.args.map(value => interpolateScript(value, variables));
        addScriptStep({ kind: 'command', line: node.line, title: scriptCommandDisplay({ verb: node.verb, args }), detail: 'running sibling wintcp.exe' });
        const result = await runCliCommand(node.verb, args);
        variables[node.assign || 'last'] = result;
        const outcome = result.timedOut ? 'timed out' : `exit ${result.exitCode}`;
        const last = state.scriptRun.steps[state.scriptRun.steps.length - 1];
        if (last) last.detail = `${outcome} · ${result.durationMs} ms`;
        const outputBlock = [`$ ${scriptCommandDisplay({ verb: node.verb, args })}`, `exit ${result.exitCode} · ${result.durationMs} ms`, result.stdout ? `stdout:\n${result.stdout}` : '', result.stderr ? `stderr:\n${result.stderr}` : '', result.truncated ? '[captured output truncated]' : ''].filter(Boolean).join('\n');
        addScriptOutput(`${outputBlock}\n\n`);
        renderScriptRun();
      }
      renderScriptRun();
    }
  }
  async function runCurrentScript() {
    if (state.scriptRun.running) return;
    const parsed = validateCurrentScript(false);
    if (!parsed) return;
    const sensitive = scriptCommandNodes(parsed.program).filter(node => isSensitiveCli([node.verb, ...node.args]));
    if (sensitive.length) {
      const exact = sensitive.map(node => `  ${scriptCommandDisplay(node)}`).join('\n');
      if (!(await confirmAction(`This script includes local commands that can change firewall, process, capture, bookmark, preset, or alert state, or write output files. Review the exact command(s):\n\n${exact}\n\nContinue? Each action receives a separate one-use permit.`, { title: 'Confirm sensitive script', confirmLabel: 'Run script', danger: true }))) {
        $('script-run-status').textContent = 'Cancelled before execution';
        return;
      }
    }
    state.scriptRun = { running: true, variables: Object.create(null), steps: [], output: '', status: 'Running', failed: false };
    renderScriptRun();
    try {
      await executeScriptNodes(parsed.program, state.scriptRun.variables, { stepsExecuted: 0 });
      state.scriptRun.status = 'Completed';
      state.scriptRun.failed = false;
      addScriptStep({ kind: 'done', line: 0, title: 'Script completed', detail: `${state.scriptRun.steps.length} trace entries` });
    } catch (error) {
      state.scriptRun.status = 'Stopped · error';
      state.scriptRun.failed = true;
      addScriptStep({ kind: 'error', line: 0, title: 'Script stopped', detail: error.message });
      addScriptOutput(`[script error] ${error.message}\n`);
      toast('Script stopped', error.message, true);
    } finally {
      state.scriptRun.running = false;
      renderScriptRun();
      recordScriptRun();
    }
  }
  async function saveManagedScript() {
    if (!validateCurrentScript(false)) return null;
    const name = $('script-name').value.trim();
    if (!name || name.length > 120) { toast('Invalid script name', 'Enter a name with 1 to 120 characters.', true); return null; }
    const content = $('automation-content').value;
    const templateId = state.currentTemplateId || 'CUSTOM';
    let record = state.config.scripts.find(item => item.id === state.currentScriptId);
    if (!record && state.config.scripts.length >= 40) { toast('Script library is full', 'Remove a saved script before adding another; the built-in 40 templates remain available.', true); return null; }
    if (record) Object.assign(record, { templateId, name, content, updatedAt: new Date().toISOString() });
    else {
      record = { id: crypto.randomUUID(), templateId, name, content, ruleId: '', createdAt: new Date().toISOString(), updatedAt: new Date().toISOString() };
      state.config.scripts.push(record);
    }
    state.currentScriptId = record.id;
    state.currentTemplateId = templateId;
    $('script-remove').disabled = false;
    setScriptSource(state.templates.find(item => item.id === templateId) || null, true);
    $('script-validation').textContent = `Saved locally · ${templateId} · ${timeText(record.updatedAt)}.`;
    $('script-validation').className = 'script-validation is-valid';
    renderScriptLibrary();
    if (!await saveConfig('automation-script-saved')) return null;
    toast('Script saved', `${name} is stored in the local WinTCP configuration.`);
    return record;
  }
  async function removeManagedScript() {
    const record = state.config.scripts.find(item => item.id === state.currentScriptId);
    if (!record) return;
    if (!(await confirmAction('Remove this saved script from My scripts? Built-in templates and monitor rules are not affected.', { title: 'Remove script', confirmLabel: 'Remove', danger: true }))) return;
    state.config.scripts = state.config.scripts.filter(item => item.id !== record.id);
    state.currentScriptId = ''; state.currentTemplateId = '';
    $('script-name').value = ''; $('automation-content').value = '';
    $('script-remove').disabled = true;
    setScriptSource(null, false);
    $('script-validation').textContent = 'Script removed from the local library.';
    renderScriptLibrary(); await saveConfig('automation-script-removed');
  }
  async function copyCurrentScript() {
    const text = $('automation-content').value;
    if (!text.trim()) { toast('No script content', 'Choose a template or paste WinTCP Script source first.', true); return; }
    try {
      await navigator.clipboard.writeText(text);
      toast('Source copied', 'Paste the local WinTCP Script source into another script or editor.');
    } catch {
      $('automation-content').focus(); $('automation-content').select();
      toast('Clipboard unavailable', 'The script source is selected; press Ctrl+C to copy it.', true);
    }
  }
  async function importScriptFile(file) {
    if (!file) return;
    if (file.size > 8192) { toast('Import too large', 'WinTCP Script files are limited to 8 KiB.', true); return; }
    try {
      const text = await file.text();
      $('automation-content').value = text;
      state.currentScriptId = '';
      state.currentTemplateId = 'CUSTOM';
      $('script-name').value = (file.name || 'Imported script').replace(/\.(wtscript|txt)$/i, '').slice(0, 120);
      $('script-remove').disabled = true;
      setScriptSource(null, true);
      const validation = validateCurrentScript(false);
      if (validation) toast('Script imported', 'Validate, edit if needed, then save it to My scripts.');
    } catch (error) { toast('Could not read script file', error.message, true); }
  }
  function exportCurrentScript() {
    if (!validateCurrentScript(false)) return;
    const source = $('automation-content').value;
    const blob = new Blob([source.endsWith('\n') ? source : `${source}\n`], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a'); link.href = url;
    const safeName = $('script-name').value.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || 'automation';
    link.download = `wintcp-${safeName}.wtscript`;
    document.body.appendChild(link); link.click(); link.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000);
    toast('Script exported', 'A validated WinTCP Script source file was downloaded.');
  }
  async function saveConfig(eventName = 'configuration-saved') {
    try {
      const body = JSON.stringify(state.config);
      if (new TextEncoder().encode(body).length > 60000) { toast('Configuration is too large', 'The local configuration limit is 60 KiB. Export scripts and remove unused copies before saving.', true); return false; }
      await api('/api/config', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body });
      await writeAudit({ type: eventName, rules: state.config.rules.length, scripts: state.config.scripts.length });
      return true;
    } catch (error) { toast('Could not save configuration', error.message, true); return false; }
  }
  function addRule(id) {
    const template = state.templates.find(t => t.id === id);
    if (!template?.ready) return;
    if (state.config.rules.some(r => r.templateId === id)) { toast('Monitor already added', template.title); return; }
    state.config.rules.push({ id: crypto.randomUUID(), templateId: id, name: template.title, enabled: false, action: 'notify', threshold: template.defaultThreshold ?? (template.runtime === 'remote-byte-window' ? defaultBytes : 10), windowSeconds: template.windowSeconds || 3600 });
    if (state.snapshot && (template.runtime === 'new-peer' || template.runtime === 'new-listener')) {
      for (const row of state.snapshot.connections || []) {
        if (row.removed) continue;
        if (template.runtime === 'new-peer' && String(row.state || '').toUpperCase() === 'ESTABLISHED' && row.remote) state.seenPeers.add(row.remote);
        if (template.runtime === 'new-listener' && String(row.state || '').toUpperCase() === 'LISTENING') state.seenListeners.add(`${row.pid}|${row.local}|${row.lport}`);
      }
    }
    renderRules(); saveConfig('monitor-added'); toast('Monitor added', 'Review its threshold, then enable it when ready.');
  }
  function updateRule(id, patch) { const rule = state.config.rules.find(r => r.id === id); if (!rule) return; Object.assign(rule, patch); renderRules(); saveConfig('monitor-updated'); }
  function removeRule(id) { state.config.rules = state.config.rules.filter(r => r.id !== id); renderRules(); saveConfig('monitor-removed'); }

  async function writeAudit(event) {
    try { await api('/api/audit', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(event) }); }
    catch (error) { console.warn('WinTCP audit write failed:', error.message); }
  }
  async function loadAudit() {
    try {
      const q = $('audit-search').value.trim();
      const events = await api('/api/audit' + (q ? '?q=' + encodeURIComponent(q) : ''));
      $('audit-list').innerHTML = events.length ? events.slice().reverse().map(item => `<div class="audit-row"><span>${esc(item.event?.type || 'event')}${item.event?.address ? ` · ${esc(item.event.address)}${item.event.port === 0 ? ' · all TCP ports' : item.event.port ? `:${esc(item.event.port)}` : ''}` : ''}</span><time>${esc(timeText(item.time))}</time></div>`).join('') : '<div class="empty-state">No audit events yet.</div>';
    } catch (error) { $('audit-list').innerHTML = `<div class="empty-state">Audit unavailable: ${esc(error.message)}</div>`; }
  }

  function exportAudit() {
    fetch('/api/audit?format=ndjson').then(async resp => {
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const blob = new Blob([await resp.text()], { type: 'application/x-ndjson' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'audit.ndjson';
      a.click();
      URL.revokeObjectURL(url);
    }).catch(err => toast('Export failed', err.message, true));
  }

  function addAlert(title, detail, remote = '', port = '', blockEligible = false) {
    const alert = { id: crypto.randomUUID(), title, detail, remote, port, blockEligible, time: new Date().toISOString() };
    state.alerts.unshift(alert); state.alerts = state.alerts.slice(0, 30);
    renderAlerts(); toast(title, detail, true); notifyDesktop(alert); writeAudit({ type: 'monitor-alert', title, detail, remote, port });
  }
  function updateNotificationUi() {
    const supported = window.isSecureContext !== false && 'Notification' in window;
    const permission = supported ? window.Notification.permission : 'unsupported';
    const checkbox = $('desktop-notifications');
    const button = $('enable-notifications');
    checkbox.disabled = !supported || permission !== 'granted';
    checkbox.checked = permission === 'granted' && state.config.desktopNotifications === true;
    button.disabled = !supported || permission === 'granted';
    if (!window.isSecureContext) $('notification-status').textContent = 'Browser notifications require a secure context; this page is not one.';
    else if (!('Notification' in window)) $('notification-status').textContent = 'This browser does not support desktop notifications.';
    else if (permission === 'denied') $('notification-status').textContent = 'Notifications are blocked in browser settings. Change that permission there to enable them.';
    else if (permission === 'default') $('notification-status').textContent = 'Off. Use Enable browser notifications to ask for permission; no prompt appears automatically.';
    else $('notification-status').textContent = checkbox.checked ? 'Desktop alerts are on for this browser.' : 'Permission is granted, but desktop alerts are off.';
    button.textContent = permission === 'granted' ? 'Browser permission granted' : permission === 'denied' ? 'Notifications blocked' : 'Enable browser notifications';
  }
  function notifyDesktop(alert) {
    if (!state.config.desktopNotifications || !('Notification' in window) || window.Notification.permission !== 'granted') return;
    const now = Date.now();
    state.notificationTimes = state.notificationTimes.filter(at => now - at < 60000);
    if (state.notificationTimes.length >= 3) { state.suppressedNotificationCount++; return; }
    const summary = state.suppressedNotificationCount > 0
      ? `${state.suppressedNotificationCount} additional monitor event(s) were grouped. Open WinTCP to review details.`
      : 'A network monitor reported an event. Open WinTCP to review details.';
    state.suppressedNotificationCount = 0;
    state.notificationTimes.push(now);
    try {
      const notification = new window.Notification('WinTCP monitor alert', { body: summary, tag: `wintcp-${alert.id}` });
      notification.onclick = () => { window.focus(); notification.close(); };
    } catch { /* Browser or OS notification delivery is best-effort. */ }
  }
  async function enableDesktopNotifications() {
    if (!window.isSecureContext || !('Notification' in window)) { updateNotificationUi(); return; }
    try {
      const permission = await window.Notification.requestPermission();
      state.config.desktopNotifications = permission === 'granted';
      updateNotificationUi();
      await saveConfig('desktop-notifications-updated');
      toast(permission === 'granted' ? 'Desktop alerts enabled' : 'Desktop alerts not enabled', permission === 'granted' ? 'Monitor alerts may now use generic browser notifications while this page is open.' : 'You can review notification permission in browser settings.', permission !== 'granted');
    } catch (error) { $('notification-status').textContent = `Could not request browser permission: ${error.message}`; }
  }
  function renderAlerts() {
    const box = $('alert-list');
    if (!state.alerts.length) { box.innerHTML = '<div class="empty-state">No events yet.</div>'; return; }
    box.innerHTML = state.alerts.map(alert => {
      const canOfferBlock = alert.blockEligible && alert.remote && state.config.rules.some(r => r.enabled && r.action === 'block' && state.templates.find(t => t.id === r.templateId)?.runtime === 'remote-byte-window');
      return `<div class="event-row"><span class="event-dot warn"></span><div class="event-copy"><strong>${esc(alert.title)}</strong><p>${esc(alert.detail)}</p><time>${esc(timeText(alert.time))}</time></div>${canOfferBlock ? `<div class="event-actions"><button class="button button-small button-danger" data-block="${esc(alert.id)}" type="button">Preview block</button></div>` : ''}</div>`;
    }).join('');
    document.querySelectorAll('[data-block]').forEach(button => button.addEventListener('click', () => {
      const alert = state.alerts.find(a => a.id === button.dataset.block);
      if (alert) previewAndBlock(alert.remote, Number(alert.port));
    }));
  }

  function rowKey(row) { return String(row.id ?? `${row.pid}|${row.proto}|${row.local}|${row.lport}|${row.remote}|${row.rport}`); }
  function evaluate(snapshot) {
    const rows = snapshot.connections || [];
    const traffic = snapshot.traffic || {};
    const complete = Boolean(traffic.sampler) && Number(traffic.tcpRows) === Number(traffic.socketRows) && !traffic.timeouts && !traffic.unreadable && !traffic.scanFailures;
    const now = Date.now();
    const deltas = new Map();
    const tcp = rows.filter(row => String(row.proto || '').startsWith('TCP') && !row.removed);
    if (!complete) { state.samples = []; state.previous.clear(); }
    for (const row of tcp) {
      if (!complete) continue;
      const key = rowKey(row);
      const rx = counterBigInt(row, 'socketRxBytes');
      const tx = counterBigInt(row, 'socketTxBytes');
      if (!row.socketCountersAvailable || rx === null || tx === null) { state.previous.delete(key); continue; }
      const current = rx + tx;
      const previous = state.previous.get(key);
      if (previous !== undefined && current >= previous.bytes) {
        const delta = current - previous.bytes;
        const remote = String(row.remote || '');
        deltas.set(remote, (deltas.get(remote) || 0n) + delta);
      }
      state.previous.set(key, { bytes: current, remote: String(row.remote || '') });
    }
    if (complete) {
      for (const [remote, bytes] of deltas) if (remote && bytes > 0n) state.samples.push({ at: now, remote, bytes });
    }
    const liveIds = new Set(rows.map(rowKey));
    for (const key of state.previous.keys()) if (!liveIds.has(key)) state.previous.delete(key);
    state.samples = state.samples.filter(sample => sample.at > now - 3600 * 1000);

    for (const rule of state.config.rules.filter(r => r.enabled)) {
      const template = state.templates.find(t => t.id === rule.templateId);
      if (!template) continue;
      if (template.runtime === 'remote-byte-window') {
        if (!complete) continue;
        const windowMs = Math.max(60, Number(rule.windowSeconds) || 3600) * 1000;
        const totals = new Map();
        for (const sample of state.samples) if (sample.at > now - windowMs) totals.set(sample.remote, (totals.get(sample.remote) || 0n) + sample.bytes);
        const threshold = BigInt(Math.max(1, Math.trunc(Number(rule.threshold) || defaultBytes)));
        for (const [remote, bytes] of totals) {
          const fireKey = `${rule.id}|${remote}`;
          const last = Number(sessionStorage.getItem(`fired:${fireKey}`) || 0);
          if (bytes >= threshold && now - last > 15 * 60 * 1000) {
            sessionStorage.setItem(`fired:${fireKey}`, String(now));
            addAlert('Remote peer exceeded traffic budget', `${remote} transferred ${shortBigBytes(bytes)} in the monitored window. Coverage was complete for this evaluation.`, remote, '', true);
          }
        }
      } else if (template.runtime === 'new-peer' || template.runtime === 'new-listener') {
        const matching = template.runtime === 'new-peer'
          ? rows.filter(row => !row.removed && String(row.state || '').toUpperCase() === 'ESTABLISHED' && row.remote && !['0.0.0.0', '::', '*'].includes(row.remote))
          : rows.filter(row => !row.removed && String(row.state || '').toUpperCase() === 'LISTENING');
        const seen = template.runtime === 'new-peer' ? state.seenPeers : state.seenListeners;
        for (const row of matching) {
          const key = template.runtime === 'new-peer' ? row.remote : `${row.pid}|${row.local}|${row.lport}`;
          if (!state.initialized) { seen.add(key); continue; }
          if (!seen.has(key)) { seen.add(key); addAlert(template.title, `${row.process || 'Process'} (PID ${row.pid || '?'}) · ${row.local || ''}:${row.lport || ''} → ${row.remote || ''}:${row.rport || ''}`, row.remote || '', row.rport || ''); }
        }
      } else if (template.runtime === 'wildcard-listener') {
        const listeners = rows.filter(row => !row.removed && String(row.proto || '').toUpperCase().startsWith('TCP') && String(row.state || '').toUpperCase() === 'LISTENING' && isWildcardBindAddress(row.local));
        const threshold = Math.max(1, Math.trunc(Number(rule.threshold) || 1));
        const fireKey = `fired:wildcard-listener:${rule.id}`;
        if (listeners.length < threshold) {
          sessionStorage.removeItem(fireKey);
          continue;
        }
        if (sessionStorage.getItem(fireKey)) continue;
        sessionStorage.setItem(fireKey, String(now));
        const examples = listeners.slice(0, 5).map(row => `${row.process || 'Process'} (PID ${row.pid || '?'}) · ${row.local}:${row.lport || '?'}`).join('; ');
        const remainder = listeners.length > 5 ? `; and ${listeners.length - 5} more` : '';
        addAlert(template.title, `${listeners.length} wildcard-bound TCP listener(s) detected (limit ${threshold}). ${examples}${remainder}`);
      } else if (template.runtime === 'listener-count' || template.runtime === 'process-fanout') {
        const groups = new Map();
        const relevant = template.runtime === 'listener-count'
          ? rows.filter(row => !row.removed && String(row.state || '').toUpperCase() === 'LISTENING')
          : rows.filter(row => !row.removed && String(row.state || '').toUpperCase() === 'ESTABLISHED' && row.remote);
        for (const row of relevant) {
          const pid = String(row.pid || '?');
          if (!groups.has(pid)) groups.set(pid, { count: new Set(), process: row.process || 'Process', remote: row.remote || '' });
          groups.get(pid).count.add(template.runtime === 'listener-count' ? `${row.local}|${row.lport}` : row.remote);
        }
        const limit = Number(rule.threshold) || Number(template.defaultThreshold) || 10;
        for (const [pid, info] of groups) {
          const key = `${rule.id}|${pid}`;
          if (info.count.size > limit && !sessionStorage.getItem(`fired:${key}`)) {
            sessionStorage.setItem(`fired:${key}`, String(now));
            addAlert(template.title, `${info.process} (PID ${pid}) has ${info.count.size} distinct ${template.runtime === 'listener-count' ? 'listeners' : 'remote peers'}; limit ${limit}.`, info.remote);
          }
        }
      } else if (template.runtime === 'rtt-threshold') {
        const limit = Number(rule.threshold) || Number(template.defaultThreshold) || 250;
        for (const row of rows) {
          if (row.removed || row.rttMs == null || Number(row.rttMs) <= limit) continue;
          const key = `${rule.id}|${rowKey(row)}`;
          if (!sessionStorage.getItem(`fired:${key}`)) {
            sessionStorage.setItem(`fired:${key}`, String(now));
            addAlert(template.title, `${row.process || 'Process'} (PID ${row.pid || '?'}) · ${row.remote || ''} · ${Number(row.rttMs).toFixed(1)} ms (limit ${limit} ms).`, row.remote || '', row.rport || '');
          }
        }
      }
    }
    state.initialized = true;
  }

  async function previewAndBlock(address, port) {
    if (!address) { toast('No block target', 'This event does not include a remote IP address.', true); return; }
    try {
      const scope = port ? `TCP port ${port}` : 'all remote TCP ports';
      const body = new URLSearchParams({ address, port: String(port || 0) });
      const preview = await api('/api/block/preview', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body });
      if (!(await confirmAction(`Review this dry-run plan before applying the firewall change:\n\n${preview.plan}\n\nContinue and block ${address} on ${scope}? This may interrupt network access.`, { title: 'Confirm firewall block', confirmLabel: 'Apply block', danger: true }))) return;
      const result = await api('/api/block/commit', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ nonce: preview.nonce }) });
      toast(result.ok ? 'Firewall rule applied' : 'Firewall action refused', `${result.message || 'See audit trail.'}${result.auditRecorded === false ? ' Warning: the outcome could not be appended to the audit log.' : ''}`, !result.ok || result.auditRecorded === false);
      await loadAudit();
    } catch (error) { toast('Firewall action failed', error.message, true); }
  }

  function showConnectionDetails(key) {
    const row = (state.snapshot?.connections || []).find(item => rowKey(item) === key);
    if (!row) { toast('Connection no longer available', 'Refresh the snapshot before opening this row.', true); return; }
    state.currentDetailRow = row;
    $('connection-detail-title').textContent = `${row.process || 'Connection'} · PID ${row.pid || '?'}`;
    $('connection-detail-summary').textContent = `${row.proto || 'Unknown protocol'} ${row.local || '?'}:${row.lport || '?'} → ${row.remote || '?'}:${row.rport || '?'} · ${row.state || 'Unknown state'}`;
    $('connection-detail-json').textContent = JSON.stringify(row, null, 2);
    $('block-connection-detail').disabled = !canBlockRow(row);
    const dialog = $('connection-detail-dialog');
    if (typeof dialog.showModal === 'function') dialog.showModal(); else dialog.setAttribute('open', '');
  }
  async function copyConnectionDetails() {
    if (!state.currentDetailRow) return;
    const content = JSON.stringify(state.currentDetailRow, null, 2);
    try { await navigator.clipboard.writeText(content); toast('Details copied', 'The current snapshot row JSON is on the clipboard.'); }
    catch { $('connection-detail-json').focus(); toast('Clipboard unavailable', 'Focus the JSON details and use the browser copy command.', true); }
  }
  async function blockDetailedConnection() {
    const row = state.currentDetailRow;
    if (!canBlockRow(row)) return;
    await previewAndBlock(row.remote, Number(row.rport));
  }

  async function refreshSnapshot() {
    if (state.busy) return;
    state.busy = true;
    try {
      const filter = (state.config.view?.search || '').trim();
      const snapshot = await api(filter ? `/api/connections?filter=${encodeURIComponent(filter)}` : '/api/connections');
      snapshot.appliedFilter = filter;
      state.liveSnapshot = snapshot;
      if (!state.config.view?.frozen || !state.snapshot) state.snapshot = snapshot;
      setServerStatus('status-online', 'Live · loopback');
      if (!state.config.view?.frozen) renderConnections();
      const status = $('snapshot-status');
      if (status) status.textContent = `Snapshot updated at ${timeText(snapshot.generatedAt)}. ${((snapshot.connections || []).length).toLocaleString()} connections.`;
      evaluate(snapshot);
    } catch (error) {
      setServerStatus('status-error', state.snapshot ? 'Stale snapshot' : 'Snapshot unavailable');
      $('last-updated').textContent = state.snapshot ? `Refresh failed; last good snapshot ${timeText(state.snapshot.generatedAt)} · ${error.message}` : error.message;
    } finally { state.busy = false; }
  }

  function migrateLegacyAutomationJson(content) {
    if (typeof content !== 'string' || !content.trimStart().startsWith('{')) return null;
    let legacy;
    try { legacy = JSON.parse(content); } catch { return null; }
    if (!legacy || legacy.format !== 'wintcp-automation') return null;
    const header = '# Migrated WinTCP declarative monitor draft.\n# Its old fields were metadata, not executable commands.\n# Original JSON is preserved below as comments.\n';
    const trailer = '\n# End of preserved legacy JSON.\nprint "This migrated draft was not executable. Replace or extend these comments with local WinTCP CLI commands before use."\n';
    let preserved = '';
    for (const line of content.split(/\r?\n/)) {
      const next = `${preserved}# ${line}\n`;
      if (new TextEncoder().encode(header + next + trailer).length > 7600) break;
      preserved = next;
    }
    if (preserved.length < content.length) preserved += '# Original JSON was truncated to stay within the local script-size limit.\n';
    return header + preserved + trailer;
  }
  function normalizeConfig(raw) {
    let changed = !raw || typeof raw !== 'object' || Array.isArray(raw) || raw.version !== 2;
    const source = raw && typeof raw === 'object' && !Array.isArray(raw) ? raw : {};
    const theme = source.theme === 'dark' || source.theme === 'light' || source.theme === 'system' ? source.theme : 'system';
    if (theme !== source.theme) changed = true;
    const refreshValue = Number(source.refreshSeconds);
    const refreshSeconds = Number.isFinite(refreshValue) ? Math.max(2, Math.min(30, Math.round(refreshValue))) : 5;
    if (refreshSeconds !== source.refreshSeconds) changed = true;
    const desktopNotifications = source.desktopNotifications === true;
    if (desktopNotifications !== source.desktopNotifications) changed = true;
    const cleanView = value => {
      const input = value && typeof value === 'object' && !Array.isArray(value) ? value : {};
      const protocols = ['all', 'tcp', 'udp'];
      const states = ['all', 'LISTENING', 'ESTABLISHED', 'CLOSE_WAIT', 'TIME_WAIT'];
      const sortKeys = ['process', 'pid', 'proto', 'local', 'remote', 'state', 'rx', 'tx'];
      const columnKeys = ['process', 'pid', 'proto', 'local', 'remote', 'state', 'traffic'];
      const protocol = protocols.includes(input.protocol) ? input.protocol : 'all';
      const connectionState = states.includes(input.state) ? input.state : 'all';
      const sortKey = sortKeys.includes(input.sortKey) ? input.sortKey : 'process';
      const search = typeof input.search === 'string' ? input.search.slice(0, 256) : '';
      const columns = Array.isArray(input.columns) ? [...new Set(input.columns.filter(column => columnKeys.includes(column)))] : columnKeys;
      if (protocol !== input.protocol || connectionState !== input.state || sortKey !== input.sortKey || search !== input.search || columns.length !== (Array.isArray(input.columns) ? input.columns.length : columnKeys.length) || (input.groupByProcess === true) !== input.groupByProcess || (input.frozen === true) !== input.frozen || (input.sortDescending === true) !== input.sortDescending) changed = true;
      return { protocol, state: connectionState, search, sortKey, sortDescending: input.sortDescending === true, groupByProcess: input.groupByProcess === true, frozen: input.frozen === true, columns };
    };
    const view = cleanView(source.view);
    if (!source.view || typeof source.view !== 'object' || Array.isArray(source.view)) changed = true;
    const sourceRules = Array.isArray(source.rules) ? source.rules : [];
    if (!Array.isArray(source.rules) || sourceRules.length > 40) changed = true;
    const rules = [], seenRuleIds = new Set();
    for (const candidate of sourceRules.slice(0, 40)) {
      if (!candidate || typeof candidate !== 'object' || Array.isArray(candidate)) { changed = true; continue; }
      const template = state.templates.find(item => item.id === candidate.templateId && item.ready);
      if (!template) { changed = true; continue; }
      const defaultThreshold = Number(template.defaultThreshold ?? (template.runtime === 'remote-byte-window' ? defaultBytes : 10));
      const minimum = template.runtime === 'remote-byte-window' ? 100000000 : 1;
      const maximum = template.runtime === 'remote-byte-window' ? 1024000000000 : 100000;
      const requestedThreshold = Number(candidate.threshold);
      const threshold = Math.max(minimum, Math.min(maximum, Math.round(Number.isFinite(requestedThreshold) ? requestedThreshold : defaultThreshold)));
      const requestedWindow = Number(candidate.windowSeconds);
      const windowSeconds = Math.max(60, Math.min(86400, Math.round(Number.isFinite(requestedWindow) ? requestedWindow : 3600)));
      let requestedId = typeof candidate.id === 'string' && /^[A-Za-z0-9-]{1,80}$/.test(candidate.id) ? candidate.id : crypto.randomUUID();
      if (seenRuleIds.has(requestedId)) { requestedId = crypto.randomUUID(); changed = true; }
      seenRuleIds.add(requestedId);
      const name = typeof candidate.name === 'string' ? candidate.name.slice(0, 120) : template.title;
      const enabled = candidate.enabled === true;
      const action = template.runtime === 'remote-byte-window' && candidate.action === 'block' ? 'block' : 'notify';
      if (requestedId !== candidate.id || name !== candidate.name || enabled !== candidate.enabled || action !== candidate.action || threshold !== candidate.threshold || windowSeconds !== candidate.windowSeconds) changed = true;
      rules.push({ id: requestedId, templateId: template.id, name, enabled, action, threshold, windowSeconds });
    }
    const sourceScripts = Array.isArray(source.scripts) ? source.scripts : [];
    if (!Array.isArray(source.scripts) || sourceScripts.length > 40) changed = true;
    const scripts = [];
    let scriptBytes = 0;
    for (const candidate of sourceScripts.slice(0, 40)) {
      if (!candidate || typeof candidate !== 'object' || Array.isArray(candidate) || typeof candidate.content !== 'string') { changed = true; continue; }
      const migratedContent = migrateLegacyAutomationJson(candidate.content);
      const content = migratedContent || candidate.content;
      const bytes = new TextEncoder().encode(content).length;
      if (bytes > 8192 || scriptBytes + bytes > 46000) { changed = true; continue; }
      const template = state.templates.find(item => item.id === candidate.templateId);
      const templateId = template ? template.id : 'CUSTOM';
      const id = typeof candidate.id === 'string' && /^[A-Za-z0-9-]{1,80}$/.test(candidate.id) && !scripts.some(item => item.id === candidate.id) ? candidate.id : crypto.randomUUID();
      const name = typeof candidate.name === 'string' && candidate.name.trim() ? candidate.name.trim().slice(0, 120) : (template?.title || 'Imported script');
      const ruleId = typeof candidate.ruleId === 'string' && rules.some(rule => rule.id === candidate.ruleId) && rules.find(rule => rule.id === candidate.ruleId).templateId === templateId ? candidate.ruleId : '';
      const createdAt = typeof candidate.createdAt === 'string' && candidate.createdAt.length <= 40 ? candidate.createdAt : new Date().toISOString();
      const updatedAt = typeof candidate.updatedAt === 'string' && candidate.updatedAt.length <= 40 ? candidate.updatedAt : createdAt;
      if (migratedContent || id !== candidate.id || templateId !== candidate.templateId || name !== candidate.name || ruleId !== candidate.ruleId || createdAt !== candidate.createdAt || updatedAt !== candidate.updatedAt) changed = true;
      scripts.push({ id, templateId, name, content, ruleId, createdAt, updatedAt });
      scriptBytes += bytes;
    }
    const sourcePresets = Array.isArray(source.presets) ? source.presets : [];
    if (!Array.isArray(source.presets) || sourcePresets.length > 20) changed = true;
    const presets = [];
    for (const candidate of sourcePresets.slice(0, 20)) {
      if (!candidate || typeof candidate !== 'object' || Array.isArray(candidate) || typeof candidate.name !== 'string' || !candidate.name.trim()) { changed = true; continue; }
      const id = typeof candidate.id === 'string' && /^[A-Za-z0-9-]{1,80}$/.test(candidate.id) && !presets.some(item => item.id === candidate.id) ? candidate.id : crypto.randomUUID();
      const name = candidate.name.trim().slice(0, 60);
      const presetView = cleanView(candidate.view);
      if (id !== candidate.id || name !== candidate.name) changed = true;
      presets.push({ id, name, view: presetView });
    }
    const sourceBookmarks = Array.isArray(source.bookmarks) ? source.bookmarks : [];
    if (!Array.isArray(source.bookmarks) || sourceBookmarks.length > 100) changed = true;
    const bookmarks = [];
    for (const candidate of sourceBookmarks.slice(0, 100)) {
      if (!candidate || typeof candidate !== 'object' || Array.isArray(candidate)) { changed = true; continue; }
      const id = typeof candidate.id === 'string' && /^[A-Za-z0-9-]{1,80}$/.test(candidate.id) && !bookmarks.some(item => item.id === candidate.id) ? candidate.id : crypto.randomUUID();
      const bounded = (key, limit) => typeof candidate[key] === 'string' ? candidate[key].slice(0, limit) : '';
      const bookmark = { id, rowKey: bounded('rowKey', 512), process: bounded('process', 260), pid: bounded('pid', 32), proto: bounded('proto', 16), local: bounded('local', 128), lport: bounded('lport', 16), remote: bounded('remote', 128), rport: bounded('rport', 16), state: bounded('state', 32), note: bounded('note', 500), addedAt: typeof candidate.addedAt === 'string' && candidate.addedAt.length <= 40 ? candidate.addedAt : new Date().toISOString() };
      if (!bookmark.rowKey) { changed = true; continue; }
      if (id !== candidate.id || Object.keys(bookmark).some(key => key !== 'id' && bookmark[key] !== candidate[key])) changed = true;
      bookmarks.push(bookmark);
    }
    // Run history + the last finished run. Kept in the SAME config the server
    // stores verbatim (WebUi.cpp WriteFileAtomic copies the posted body), so
    // threading them through here is what makes a run survive a page refresh -
    // previously every result and status lived only in client memory and a
    // reload showed "Not run". Cheap summaries (no captured output) keep the
    // config bounded; the last run keeps a bounded output tail for restore.
    const sourceRuns = Array.isArray(source.scriptRuns) ? source.scriptRuns : [];
    const scriptRuns = [];
    let runCount = 0;
    for (const candidate of sourceRuns.slice(0, 30)) {
      if (runCount >= 25) break;
      if (!candidate || typeof candidate !== 'object' || Array.isArray(candidate)) { changed = true; continue; }
      const exit = Number(candidate.exit);
      const steps = Number(candidate.steps);
      scriptRuns.push({
        ts: typeof candidate.ts === 'string' && candidate.ts.length <= 40 ? candidate.ts : new Date().toISOString(),
        name: typeof candidate.name === 'string' ? candidate.name.slice(0, 120) : 'Unnamed script',
        templateId: typeof candidate.templateId === 'string' && candidate.templateId.length <= 40 ? candidate.templateId : 'CUSTOM',
        ok: candidate.ok === true,
        status: typeof candidate.status === 'string' ? candidate.status.slice(0, 60) : '',
        exit: Number.isFinite(exit) ? exit : null,
        steps: Number.isFinite(steps) ? Math.max(0, Math.round(steps)) : 0,
      });
      ++runCount;
    }
    const lastRaw = source.lastScriptRun && typeof source.lastScriptRun === 'object' && !Array.isArray(source.lastScriptRun) ? source.lastScriptRun : null;
    const lastScriptRun = lastRaw ? (() => {
      const exit = Number(lastRaw.exit);
      const steps = Number(lastRaw.steps);
      return {
        ts: typeof lastRaw.ts === 'string' && lastRaw.ts.length <= 40 ? lastRaw.ts : new Date().toISOString(),
        name: typeof lastRaw.name === 'string' ? lastRaw.name.slice(0, 120) : 'Unnamed script',
        templateId: typeof lastRaw.templateId === 'string' && lastRaw.templateId.length <= 40 ? lastRaw.templateId : 'CUSTOM',
        ok: lastRaw.ok === true,
        status: typeof lastRaw.status === 'string' ? lastRaw.status.slice(0, 60) : '',
        exit: Number.isFinite(exit) ? exit : null,
        steps: Number.isFinite(steps) ? Math.max(0, Math.round(steps)) : 0,
        output: typeof lastRaw.output === 'string' ? lastRaw.output.slice(0, 6000) : '',
      };
    })() : null;
    return { changed, config: { version: 2, theme, refreshSeconds, desktopNotifications, rules, scripts, presets, bookmarks, view, scriptRuns, lastScriptRun } };
  }

  function scheduleRefresh() {
    if (state.timer) clearInterval(state.timer);
    const seconds = Math.max(2, Math.min(30, Number(state.config.refreshSeconds) || 5));
    state.timer = setInterval(refreshSnapshot, seconds * 1000);
  }

  function stopPolling() {
    if (state.timer) { clearInterval(state.timer); state.timer = 0; }
  }

  // Prefer a server-pushed SSE stream over timed polling: the server emits a
  // `tick` every second and we re-fetch, so the UI reflects a change about a
  // second after it happens instead of up to refreshSeconds later. Falls back to
  // scheduleRefresh() when EventSource is unavailable or the stream is rejected.
  function startLiveUpdates() {
    stopPolling();
    if (state.eventSource) { state.eventSource.close(); state.eventSource = null; }
    if (!('EventSource' in window)) { scheduleRefresh(); return; }
    let es;
    let fallenBack = false;
    const fallback = () => {
      if (fallenBack) return;
      fallenBack = true;
      if (es) { es.close(); es = null; state.eventSource = null; }
      scheduleRefresh();
    };
    try {
      es = new EventSource('/api/events');
    } catch { scheduleRefresh(); return; }
    state.eventSource = es;
    es.addEventListener('tick', () => { if (!state.busy) refreshSnapshot(); });
    // EventSource auto-reconnects on a transient drop (readyState CONNECTING). A
    // non-SSE response (403/404) is terminal - readyState CLOSED - so stop
    // retrying and poll instead, keeping the UI live either way.
    es.onerror = () => { if (es.readyState === EventSource.CLOSED) fallback(); };
  }
  async function loadConfig() {
    try {
      const config = await api('/api/config');
      const normalized = normalizeConfig(config);
      state.config = normalized.config;
      updateNotificationUi();
      if (normalized.changed) toast('Saved configuration normalized', 'Settings were clamped or migrated. Existing scripts were preserved; legacy declarative JSON was converted to inert comments. Review the library and save to persist this version.', true);
      $('refresh-seconds').value = String(state.config.refreshSeconds || 5);
      applyViewControls(state.config.view);
      renderViewPresets();
      renderRules(); renderScriptLibrary(); renderBookmarks(); applyTheme(); startLiveUpdates();
      renderScriptHistory(); restoreLastScriptRun();
    } catch (error) { toast('Configuration unavailable', error.message, true); }
  }
  async function initialize() {
    setupConfirmDialog();
    try {
      const health = await api('/api/health');
      if (!health.ok) throw new Error('Health check failed');
      state.templates = await api('/api/templates');
      renderTemplates();
      await loadConfig();
      applyTheme();
      await loadAudit();
      await refreshSnapshot();
      startLiveUpdates();
      window.matchMedia('(prefers-color-scheme: light)').addEventListener('change', () => { if (state.config.theme === 'system') applyTheme(); });
    } catch (error) { setServerStatus('status-error', 'Unable to connect'); toast('WinTCP service error', error.message, true); }
  }

  document.querySelectorAll('.nav-item').forEach(button => button.addEventListener('click', () => switchView(button.dataset.view)));
  document.querySelectorAll('[data-autotab]').forEach(button => button.addEventListener('click', () => switchAutomationTab(button.dataset.autotab)));
  // A run is a series of awaited CLI calls; a reload mid-run cancels them. The
  // browser's own "leave site?" prompt is the honest guard - show it rather
  // than silently throwing the run away.
  window.addEventListener('beforeunload', (event) => { if (state.scriptRun.running) { event.preventDefault(); event.returnValue = ''; return ''; } });
  $('refresh-button').addEventListener('click', refreshSnapshot);
  $('connection-search').addEventListener('input', () => {
    state.config.view.search = $('connection-search').value.slice(0, 256);
    renderConnections();
    if (state.filterTimer) clearTimeout(state.filterTimer);
    state.filterTimer = setTimeout(() => { state.filterTimer = 0; queueConfigSave('connection-search-updated', 1000); refreshSnapshot(); }, 300);
  });
  $('connection-search').addEventListener('change', async () => {
    if (state.filterTimer) clearTimeout(state.filterTimer);
    state.filterTimer = 0;
    await saveConfig('connection-search-updated'); await refreshSnapshot();
  });
  $('connection-sort').addEventListener('change', () => { state.sortKey = $('connection-sort').value; state.config.view.sortKey = state.sortKey; renderConnections(); saveConfig('connection-sort-updated'); });
  $('sort-direction').addEventListener('click', () => { state.sortDescending = !state.sortDescending; state.config.view.sortDescending = state.sortDescending; renderConnections(); saveConfig('connection-sort-updated'); });
  $('protocol-filter').addEventListener('change', () => { state.config.view.protocol = $('protocol-filter').value; renderConnections(); queueConfigSave('connection-filter-updated'); });
  $('state-filter').addEventListener('change', () => { state.config.view.state = $('state-filter').value; renderConnections(); queueConfigSave('connection-filter-updated'); });
  for (const column of ['process', 'pid', 'proto', 'local', 'remote', 'state', 'traffic']) $(`column-${column}`).addEventListener('change', () => {
    const columns = new Set(state.config.view.columns || []);
    if ($(`column-${column}`).checked) columns.add(column); else columns.delete(column);
    state.config.view.columns = [...columns];
    renderConnections(); queueConfigSave('connection-columns-updated');
  });
  $('group-by-process').addEventListener('change', () => { state.config.view.groupByProcess = $('group-by-process').checked; renderConnections(); queueConfigSave('connection-grouping-updated'); });
  $('freeze-view').addEventListener('change', () => { state.config.view.frozen = $('freeze-view').checked; if (!state.config.view.frozen && state.liveSnapshot) state.snapshot = state.liveSnapshot; renderConnections(); queueConfigSave('connection-freeze-updated'); });
  $('select-visible-rows').addEventListener('click', () => { connectionRows().slice(0, 250).forEach(row => state.selectedRows.add(rowKey(row))); renderConnections(); });
  $('clear-row-selection').addEventListener('click', () => { state.selectedRows.clear(); renderConnections(); });
  $('bookmark-selected-rows').addEventListener('click', bookmarkSelectedRows);
  $('copy-connections').addEventListener('click', copyConnections);
  $('export-connections').addEventListener('click', exportConnections);
  $('copy-connection-detail').addEventListener('click', copyConnectionDetails);
  $('block-connection-detail').addEventListener('click', blockDetailedConnection);
  $('connection-detail-dialog').addEventListener('close', () => { state.currentDetailRow = null; });
  $('view-preset').addEventListener('change', () => { $('load-view-preset').disabled = !$('view-preset').value; $('delete-view-preset').disabled = !$('view-preset').value; });
  $('save-view-preset').addEventListener('click', saveViewPreset);
  $('load-view-preset').addEventListener('click', loadViewPreset);
  $('delete-view-preset').addEventListener('click', deleteViewPreset);
  $('template-search').addEventListener('input', renderTemplates);
  $('script-library-search').addEventListener('input', renderScriptLibrary);
  $('script-new').addEventListener('click', openNewScript);
  $('script-validate').addEventListener('click', () => validateCurrentScript(true));
  $('script-run').addEventListener('click', runCurrentScript);
  $('script-clear-output').addEventListener('click', clearScriptResults);
  $('automation-content').addEventListener('input', () => { $('script-validation').className = 'script-validation'; $('script-validation').textContent = 'Source changed. Validate before saving or running it.'; });
  $('script-name').addEventListener('input', () => { $('script-validation').className = 'script-validation'; });
  $('script-copy').addEventListener('click', copyCurrentScript);
  $('script-import-file').addEventListener('click', () => $('script-file').click());
  $('script-file').addEventListener('change', () => importScriptFile($('script-file').files?.[0]));
  $('script-export').addEventListener('click', exportCurrentScript);
  $('script-save').addEventListener('click', saveManagedScript);
  $('script-remove').addEventListener('click', removeManagedScript);
  $('enable-notifications').addEventListener('click', enableDesktopNotifications);
  $('theme-mode').addEventListener('change', () => setThemeMode($('theme-mode').value));
  $('desktop-notifications').addEventListener('change', () => { state.config.desktopNotifications = $('desktop-notifications').checked; updateNotificationUi(); saveConfig('desktop-notifications-updated'); });
  $('save-settings').addEventListener('click', async () => {
    state.config.refreshSeconds = Number($('refresh-seconds').value) || 5;
    await saveConfig('configuration-saved'); startLiveUpdates(); toast('Settings saved', `Refreshing every ${state.config.refreshSeconds} seconds.`);
  });
  $('reload-audit').addEventListener('click', loadAudit);
  let auditSearchTimer = 0;
  $('audit-search').addEventListener('input', () => { clearTimeout(auditSearchTimer); auditSearchTimer = setTimeout(loadAudit, 300); });
  $('export-audit').addEventListener('click', exportAudit);
  $('clear-alerts').addEventListener('click', () => { state.alerts = []; renderAlerts(); });
  // ---- keyboard controls ----
  // A keyboard-first operator should not have to reach for the mouse:
  //   j / ArrowDown  next row      k / ArrowUp  previous row
  //   Enter          open Details  Esc          clear selection
  //   /              focus filter  r            refresh now
  document.addEventListener('keydown', event => {
    const el = event.target;
    const tag = ((el && el.tagName) || '').toLowerCase();
    if (tag === 'input' || tag === 'textarea' || tag === 'select' || (el && el.isContentEditable)) {
      if (event.key === 'Escape') el.blur();
      return;
    }
    if (event.ctrlKey || event.metaKey || event.altKey) return;
    const trs = [...document.querySelectorAll('#connection-rows tr[data-row-key]')];
    const index = trs.findIndex(tr => tr.dataset.rowKey === state.keyboardRow);
    const select = i => {
      const tr = trs[i];
      if (!tr) return;
      state.keyboardRow = tr.dataset.rowKey;
      state.selectedRows.clear();
      state.selectedRows.add(tr.dataset.rowKey);
      renderConnections();
      tr.scrollIntoView({ block: 'nearest' });
    };
    switch (event.key) {
      case 'j': case 'ArrowDown': event.preventDefault(); select(index < 0 ? 0 : Math.min(index + 1, trs.length - 1)); break;
      case 'k': case 'ArrowUp': event.preventDefault(); select(index < 0 ? trs.length - 1 : Math.max(index - 1, 0)); break;
      case 'Enter': { const tr = trs[index]; if (tr) { event.preventDefault(); showConnectionDetails(tr.dataset.rowKey); } break; }
      case 'Escape': state.selectedRows.clear(); state.keyboardRow = ''; renderConnections(); break;
      case '/': event.preventDefault(); $('connection-search').focus(); break;
      case 'r': event.preventDefault(); refreshSnapshot(); break;
      default: break;
    }
  });

  initialize();
})();
