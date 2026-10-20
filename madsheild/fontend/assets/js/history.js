/* Scan history page: list, verdict stats, pagination, report modal. */
(function () {
  'use strict';

  const PAGE_SIZE = 10;
  let offset = 0;
  let listRequest = 0;

  const $ = (id) => document.getElementById(id);

  function setText(id, value) {
    const el = $(id);
    if (el) el.textContent = value;
  }

  function setVisible(id, visible) {
    const el = $(id);
    if (el) el.hidden = !visible;
  }

  const ui = {
    loading: 'historyLoading',
    empty: 'historyEmpty',
    error: 'historyError',
    table: 'historyTableWrap',
    pagination: 'historyPagination',
    rows: 'historyRows',
  };

  function showState(state) {
    setVisible(ui.loading, state === 'loading');
    setVisible(ui.empty, state === 'empty');
    setVisible(ui.error, state === 'error');
    setVisible(ui.table, state === 'table');
    setVisible(ui.pagination, state === 'table');
  }

  /* ---------- formatting helpers ---------- */
  const VERDICT_LABELS = {
    no_indicators_found: 'No indicators found',
    suspicious: 'Suspicious',
    review_required: 'Review required',
  };

  function verdictLabel(verdict) {
    return VERDICT_LABELS[verdict] || String(verdict || 'Unknown').replaceAll('_', ' ');
  }

  function formatBytes(bytes) {
    const value = Number(bytes);
    if (!Number.isFinite(value)) return '—';
    if (value < 1024) return `${value} B`;
    const units = ['KB', 'MB', 'GB'];
    let size = value / 1024;
    let unit = 0;
    while (size >= 1024 && unit < units.length - 1) { size /= 1024; unit += 1; }
    return `${size >= 10 ? size.toFixed(0) : size.toFixed(1)} ${units[unit]}`;
  }

  function formatDate(iso) {
    const date = new Date(iso);
    return Number.isNaN(date.getTime()) ? String(iso || '—') : date.toLocaleString();
  }

  function riskClass(score) {
    const value = Number(score) || 0;
    if (value >= 60) return 'high';
    if (value >= 25) return 'mid';
    return '';
  }

  /* ---------- stats chips (counts over all reports) ---------- */
  async function refreshStats() {
    const counts = { total: 0, clean: 0, suspicious: 0, review: 0 };
    let pageOffset = 0;
    // Walk pages of 100 (the API maximum) until everything is counted.
    for (;;) {
      const page = await readApiResponse(await fetch(`/api/v1/reports?offset=${pageOffset}&limit=100`));
      counts.total += page.items.length;
      for (const item of page.items) {
        if (item.verdict === 'suspicious') counts.suspicious += 1;
        else if (item.verdict === 'review_required') counts.review += 1;
        else counts.clean += 1;
      }
      pageOffset += page.items.length;
      if (pageOffset >= page.total || page.items.length === 0) break;
    }
    setText('chipTotal', String(counts.total));
    setText('chipClean', String(counts.clean));
    setText('chipSuspicious', String(counts.suspicious));
    setText('chipReview', String(counts.review));
  }

  /* ---------- table rows ---------- */
  function buildRow(report) {
    const row = document.createElement('tr');

    // File cell
    const fileCell = document.createElement('td');
    fileCell.dataset.label = 'File';
    const fileWrap = document.createElement('div');
    fileWrap.className = 'file-cell';
    const ico = document.createElement('span');
    ico.className = 'file-ico';
    ico.innerHTML = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z"></path><polyline points="14 2 14 8 20 8"></polyline></svg>';
    const name = document.createElement('span');
    name.className = 'file-name';
    name.textContent = report.filename;
    fileWrap.append(ico, name);
    fileCell.append(fileWrap);
    row.append(fileCell);

    // Scanned
    const dateCell = document.createElement('td');
    dateCell.dataset.label = 'Scanned';
    dateCell.textContent = formatDate(report.created_at);
    row.append(dateCell);

    // Verdict
    const verdictCell = document.createElement('td');
    verdictCell.dataset.label = 'Verdict';
    const badge = document.createElement('span');
    badge.className = `verdict verdict-${report.verdict}`;
    badge.textContent = verdictLabel(report.verdict);
    verdictCell.append(badge);
    row.append(verdictCell);

    // Risk meter
    const risk = Number(report.risk_score) || 0;
    const riskCell = document.createElement('td');
    riskCell.dataset.label = 'Risk';
    const riskWrap = document.createElement('div');
    riskWrap.className = 'risk-cell';
    const bar = document.createElement('span');
    bar.className = 'risk-bar';
    const fill = document.createElement('span');
    fill.className = `risk-fill ${riskClass(risk)}`.trim();
    fill.style.width = `${Math.min(100, Math.max(0, risk))}%`;
    bar.append(fill);
    const riskValue = document.createElement('span');
    riskValue.className = 'risk-value';
    riskValue.textContent = `${risk}`;
    riskWrap.append(bar, riskValue);
    riskCell.append(riskWrap);
    row.append(riskCell);

    // Size
    const sizeCell = document.createElement('td');
    sizeCell.dataset.label = 'Size';
    sizeCell.textContent = formatBytes(report.size_bytes);
    row.append(sizeCell);

    // Action — opens the full report page (no popup/modal).
    const actionCell = document.createElement('td');
    actionCell.dataset.label = 'Report';
    const viewLink = document.createElement('a');
    viewLink.className = 'btn btn-text view-btn';
    viewLink.textContent = 'View report';
    viewLink.href = `/report.html?scan_id=${encodeURIComponent(report.scan_id)}`;
    viewLink.setAttribute('aria-label', `View report for ${report.filename}`);
    actionCell.append(viewLink);
    row.append(actionCell);

    return row;
  }

  /* ---------- list loading ---------- */
  async function loadHistory() {
    const request = ++listRequest;
    showState('loading');
    setText('historyStatus', 'Loading…');
    try {
      const page = await readApiResponse(await fetch(`/api/v1/reports?offset=${offset}&limit=${PAGE_SIZE}`));
      if (request !== listRequest) return;

      if (!page.items.length && offset > 0) {
        // Page emptied out (e.g. after refresh) — fall back to the first page.
        offset = 0;
        return loadHistory();
      }

      const rows = $(ui.rows);
      rows.replaceChildren();
      for (const report of page.items) {
        rows.append(buildRow(report));
      }

      if (page.total === 0) {
        showState('empty');
        setText('historyStatus', 'No scans yet.');
      } else {
        showState('table');
        const from = offset + 1;
        const to = offset + page.items.length;
        setText('historyStatus', `${page.total} total`);
        setText('historyPageInfo', `${from}–${to} of ${page.total}`);
        $('historyPrevious').disabled = offset === 0;
        $('historyNext').disabled = to >= page.total;
      }
      refreshStats().catch(() => { /* chips are non-critical */ });
    } catch (error) {
      if (request !== listRequest) return;
      showState('error');
      setText('historyErrorMessage', `Unable to load history: ${error.message}`);
      setText('historyStatus', '');
    }
  }


  /* ---------- wiring ---------- */
  $('refreshHistory').addEventListener('click', () => { offset = 0; loadHistory(); });
  $('historyRetry').addEventListener('click', loadHistory);
  $('historyPrevious').addEventListener('click', () => { offset = Math.max(0, offset - PAGE_SIZE); loadHistory(); });
  $('historyNext').addEventListener('click', () => { offset += PAGE_SIZE; loadHistory(); });

  loadHistory();
})();

