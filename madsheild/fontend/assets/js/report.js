/* Standalone scan-report page: loads one report by scan_id and renders it full-page. */
(function () {
  'use strict';

  const $ = (id) => document.getElementById(id);

  function setText(id, value) {
    const el = $(id);
    if (el) el.textContent = value;
  }

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  /* ---------- formatting helpers (mirrors history.js) ---------- */
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

  function metaItem(label, value) {
    const item = el('div', 'meta-item');
    item.append(el('span', 'mk', label), el('span', 'mv', value));
    return item;
  }

  const SCAN_ID_PATTERN = /^[a-f0-9]{32}$/;

  function scanIdFromUrl() {
    return new URLSearchParams(window.location.search).get('scan_id') || '';
  }

  function showError(message) {
    $('reportPageBody').hidden = true;
    $('reportPageError').hidden = false;
    setText('reportPageErrorMessage', message);
    setText('reportPageTitle', 'Report unavailable');
    setText('reportPageSummary', 'This report could not be loaded.');
  }

  /* ---------- rendering ---------- */
  function renderVerdict(report) {
    const verdictClass = report.verdict === 'no_indicators_found' ? 'ok' : report.verdict;
    const banner = el('div', `report-verdict ${verdictClass}`);
    banner.append(el('span', 'rv-label', 'Verdict'));
    banner.append(el('span', 'rv-value', verdictLabel(report.verdict)));
    banner.append(el('span', 'rv-score', `Rule risk score ${report.risk_score} / 100 · ${report.risk_score_type === 'heuristic_rule_score' ? 'heuristic' : report.risk_score_type || 'n/a'}`));
    return banner;
  }

  function renderMeta(report) {
    const meta = el('div', 'report-meta');
    meta.append(metaItem('File name', report.filename || '—'));
    meta.append(metaItem('Size', formatBytes(report.size_bytes)));
    meta.append(metaItem('Scanned at', formatDate(report.created_at)));
    meta.append(metaItem('Type', report.content_type || '—'));
    meta.append(metaItem('SHA-256', report.sha256 || '—'));
    meta.append(metaItem('Model probability', report.malware_probability === null || report.malware_probability === undefined
      ? 'Not configured' : String(report.malware_probability)));
    return meta;
  }

  function renderThreats(report) {
    const fragment = document.createDocumentFragment();
    fragment.append(el('h3', 'report-section-title', `Threat indicators (${(report.threats || []).length})`));
    const threats = report.threats || [];
    if (!threats.length) {
      fragment.append(el('div', 'no-threats', 'No indicators found by the implemented checks — this does not certify the file as safe.'));
      return fragment;
    }
    for (const threat of threats) {
      const item = el('div', `threat-item sev-${threat.severity || 'medium'}`);
      const top = el('div', 'th-top');
      top.append(el('span', 'th-title', threat.title || threat.rule_id || 'Indicator'));
      if (threat.severity) top.append(el('span', 'sev-tag', threat.severity));
      item.append(top);
      if (threat.reason) item.append(el('p', 'th-reason', threat.reason));
      if (threat.excerpt) item.append(el('pre', 'th-excerpt', threat.excerpt));
      const loc = threat.location || {};
      const locText = [loc.line_number !== undefined ? `line ${loc.line_number}` : null,
        loc.page !== undefined ? `page ${loc.page}` : null,
        loc.member ? `member ${loc.member}` : null].filter(Boolean).join(' · ');
      if (locText) item.append(el('span', 'th-loc', locText));
      fragment.append(item);
    }
    return fragment;
  }

  function renderLimitations(report) {
    const fragment = document.createDocumentFragment();
    if (Array.isArray(report.limitations) && report.limitations.length) {
      fragment.append(el('h3', 'report-section-title', 'Analysis coverage and limitations'));
      const list = el('ul', 'report-limits');
      for (const limitation of report.limitations) list.append(el('li', '', String(limitation)));
      fragment.append(list);
    }
    return fragment;
  }

  function renderReport(report) {
    document.title = `${report.filename || 'Scan report'} — MadSheild`;
    setText('reportPageTitle', report.filename || 'Scan report');
    setText('reportPageSummary', report.summary || 'Full analysis details for this scan.');

    const jsonLink = $('reportJsonLink');
    if (SCAN_ID_PATTERN.test(report.scan_id)) {
      jsonLink.href = `/api/v1/reports/${encodeURIComponent(report.scan_id)}`;
      jsonLink.hidden = false;
    } else {
      jsonLink.hidden = true;
    }

    const body = $('reportPageContent');
    body.replaceChildren();
    body.append(renderVerdict(report));
    body.append(renderMeta(report));
    body.append(renderThreats(report));
    body.append(renderLimitations(report));

    $('reportPageError').hidden = true;
    $('reportPageBody').hidden = false;
  }

  /* ---------- boot ---------- */
  async function load() {
    const scanId = scanIdFromUrl();
    if (!SCAN_ID_PATTERN.test(scanId)) {
      showError('No valid scan reference was provided in the URL.');
      return;
    }
    try {
      const report = await readApiResponse(await fetch(`/api/v1/reports/${encodeURIComponent(scanId)}`));
      renderReport(report);
    } catch (error) {
      showError(`Unable to load report: ${error.message}`);
    }
  }

  load();
})();
