(() => {
  'use strict';
  const element = (id) => document.getElementById(id);
  const modal = element('uploadModal');
  const fileInput = element('fileInput');
  const continueBtn = element('continueBtn');
  let selectedFile = null;
  let activeRequest = null;
  let previousFocus = null;
  let maxFileSize = 10 * 1024 * 1024;
  let allowedExtensions = ['.txt', '.docx'];

  function setText(id, text) { element(id).textContent = text; }
  function formatSize(bytes) {
    return bytes >= 1024 * 1024
      ? `${(bytes / (1024 * 1024)).toFixed(2)} MB`
      : `${(bytes / 1024).toFixed(2)} KB`;
  }
  function showSelection(state, message = '', filename = '') {
    element('defaultContent').hidden = state !== 'default';
    element('successContent').hidden = state !== 'success';
    element('errorContent').hidden = state !== 'error';
    element('dropZone').classList.toggle('success', state === 'success');
    element('dropZone').classList.toggle('error', state === 'error');
    setText('successFileName', filename);
    setText('errorFileName', filename);
    setText('errorMessage', message);
    continueBtn.disabled = state !== 'success';
    continueBtn.classList.toggle('btn-active', state === 'success');
  }
  function selectFile(file) {
    selectedFile = null;
    const extension = `.${file.name.split('.').pop().toLowerCase()}`;
    if (!allowedExtensions.includes(extension)) {
      showSelection('error', `Supported files: ${allowedExtensions.join(', ')}.`, file.name);
    } else if (!file.size) {
      showSelection('error', 'The file is empty.', file.name);
    } else if (file.size > maxFileSize) {
      showSelection('error', `The file exceeds the ${formatSize(maxFileSize)} limit.`, file.name);
    } else {
      selectedFile = file;
      showSelection('success', '', file.name);
    }
  }
  function openModal() {
    previousFocus = document.activeElement;
    selectedFile = null;
    fileInput.value = '';
    element('uploadStepView').hidden = false;
    element('analyzingStepView').hidden = true;
    showSelection('default');
    modal.classList.add('active');
    modal.setAttribute('aria-hidden', 'false');
    element('closeModalBtn').focus();
  }
  function closeModal() {
    if (activeRequest) activeRequest.abort();
    activeRequest = null;
    modal.classList.remove('active');
    modal.setAttribute('aria-hidden', 'true');
    if (previousFocus) previousFocus.focus();
  }
  function describeLocation(location = {}) {
    if (location.scope === 'document_archive') return 'DOCX archive';
    if (location.scope === 'whole_document') return 'Whole document';
    const parts = [];
    if (location.line_number) parts.push(`Line ${location.line_number}`);
    if (location.paragraph_number) parts.push(`Paragraph ${location.paragraph_number}`);
    for (const table of location.table_location || []) {
      parts.push(`Table ${table.table_number}, row ${table.row_number}, cell ${table.cell_number}`);
    }
    if (location.character_offset) parts.push(`Character offset ${location.character_offset}`);
    return parts.join(' · ') || 'Document';
  }
  function renderReport(report) {
    const titles = {
      suspicious: 'Suspicious content found',
      review_required: 'Review recommended',
      no_indicators_found: 'No indicators found',
    };
    setText('resultVerdict', titles[report.verdict] || 'Analysis completed');
    setText('resultSummary', report.summary);
    element('resultBanner').className = `result-banner ${report.verdict}`;
    setText('resFileName', report.filename);
    setText('resFileSize', formatSize(report.size_bytes));
    setText('resFileType', report.filename.split('.').pop().toUpperCase());
    setText('resStatus', report.status);
    setText('resDuration', `${report.analysis.timings_ms.total.toFixed(2)} ms`);
    setText('resScanTime', new Date(report.created_at).toLocaleString());
    setText('resCache', report.analysis.cache_hit ? 'Yes' : 'No');
    setText('resRisk', `${report.risk_score} / 100 (rules)`);
    setText('resProbability', report.malware_probability === null
      ? 'Not available' : `${(report.malware_probability * 100).toFixed(1)}%`);
    const modelStatuses = {
      not_configured: 'Not configured', completed: 'Completed', failed: 'Unavailable', skipped: 'Skipped',
    };
    setText('resModelStatus', modelStatuses[report.model.status] || report.model.status);
    let modelMessage = report.model.message || `Model: ${report.model.model_name || report.model.mode}.`;
    if (Number.isFinite(report.model.coverage?.analyzed_characters) && Number.isFinite(report.model.coverage?.total_characters)) {
      modelMessage += ` Model coverage: ${report.model.coverage.analyzed_characters} of ${report.model.coverage.total_characters} text characters.`;
    }
    setText('modelMessage', modelMessage);
    const findings = element('findingsList');
    findings.replaceChildren();
    for (const finding of report.threats) {
      const article = document.createElement('article');
      article.className = 'finding';
      const title = document.createElement('h4');
      title.textContent = finding.title || 'Model finding';
      const location = document.createElement('p');
      location.className = 'finding-location';
      location.textContent = `${finding.filename} · ${describeLocation(finding.location)} · ${finding.source}`;
      const reason = document.createElement('p');
      reason.textContent = finding.reason;
      article.append(title, location, reason);
      if (finding.excerpt) {
        const excerpt = document.createElement('pre');
        excerpt.textContent = finding.excerpt;
        article.append(excerpt);
      }
      findings.append(article);
    }
    if (!report.threats.length) findings.textContent = 'No suspicious indicators were found in the analyzed content.';
    const limitations = element('limitationsList');
    limitations.replaceChildren();
    for (const text of report.limitations) {
      const item = document.createElement('li');
      item.textContent = text;
      limitations.append(item);
    }
    const validId = /^[a-f0-9]{32}$/.test(report.scan_id);
    element('reportLink').hidden = !validId;
    if (validId) element('reportLink').href = `/api/v1/reports/${report.scan_id}`;
    element('heroSection').hidden = true;
    element('dashboardSection').hidden = false;
    closeModal();
    element('dashboardSection').scrollIntoView({ block: 'start' });
  }

  element('openModalBtn').addEventListener('click', openModal);
  element('scanAgainBtn').addEventListener('click', openModal);
  element('closeModalBtn').addEventListener('click', closeModal);
  modal.addEventListener('click', (event) => { if (event.target === modal) closeModal(); });
  document.addEventListener('keydown', (event) => {
    if (!modal.classList.contains('active')) return;
    if (event.key === 'Escape') {
      event.preventDefault();
      closeModal();
      return;
    }
    if (event.key !== 'Tab') return;
    const focusable = [...modal.querySelectorAll('button, a[href], input')]
      .filter((item) => !item.disabled && item.getClientRects().length);
    const first = focusable[0];
    const last = focusable[focusable.length - 1];
    if (!first) return;
    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault(); last.focus();
    } else if (!event.shiftKey && (document.activeElement === last || !modal.contains(document.activeElement))) {
      event.preventDefault(); first.focus();
    }
  });
  for (const id of ['browseLink', 'changeFileLink', 'retryLink']) {
    element(id).addEventListener('click', (event) => {
      event.preventDefault(); fileInput.value = ''; fileInput.click();
    });
  }
  fileInput.addEventListener('change', () => { if (fileInput.files.length) selectFile(fileInput.files[0]); });
  const dropZone = element('dropZone');
  dropZone.addEventListener('dragover', (event) => {
    event.preventDefault(); dropZone.classList.add('drag-over');
  });
  dropZone.addEventListener('dragleave', () => dropZone.classList.remove('drag-over'));
  dropZone.addEventListener('drop', (event) => {
    event.preventDefault(); dropZone.classList.remove('drag-over');
    if (event.dataTransfer.files.length === 1) selectFile(event.dataTransfer.files[0]);
    else { selectedFile = null; showSelection('error', 'Please upload one file at a time.'); }
  });
  continueBtn.addEventListener('click', async () => {
    if (!selectedFile || activeRequest) return;
    const file = selectedFile;
    const request = new AbortController();
    activeRequest = request;
    element('uploadStepView').hidden = true;
    element('analyzingStepView').hidden = false;
    setText('analyzingFileName', file.name);
    element('closeModalBtn').focus();
    try {
      const report = await scanFile(file, request.signal);
      if (activeRequest !== request) return;
      activeRequest = null;
      renderReport(report);
    } catch (error) {
      if (activeRequest !== request) return;
      activeRequest = null;
      if (error.name === 'AbortError') return;
      element('uploadStepView').hidden = false;
      element('analyzingStepView').hidden = true;
      const message = error instanceof TypeError
        ? 'Unable to reach the server. Check that the application is running and try again.'
        : error.message;
      showSelection('error', message, file.name);
      element('retryLink').focus();
    }
  });
  getCapabilities().then((capabilities) => {
    maxFileSize = capabilities.max_file_size_bytes;
    allowedExtensions = capabilities.supported_extensions;
    fileInput.accept = allowedExtensions.join(',');
    setText('supportedFilesText', `Supported files: ${allowedExtensions.join(' and ')} (maximum ${formatSize(maxFileSize)} per file)`);
    if (selectedFile && !activeRequest) selectFile(selectedFile);
  }).catch(() => { /* The server also validates each upload. */ });
})();
