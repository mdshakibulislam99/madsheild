(() => {
  'use strict';
  const element = (id) => document.getElementById(id);
  const modal = element('uploadModal');
  const fileInput = element('fileInput');
  const folderInput = element('folderInput');
  const continueBtn = element('continueBtn');
  let selectedFiles = [];
  let activeRequest = null;
  let previousFocus = null;
  let historyOffset = 0;
  let historyRequest = 0;
  let maxFileSize = 10 * 1024 * 1024;
  let maxBatchFiles = 100;
  let maxBatchSize = 100 * 1024 * 1024;
  let allowedExtensions = ['.txt', '.log', '.csv', '.json', '.md', '.doc', '.docx', '.pdf', '.zip', '.exe', '.dll'];

  function setText(id, text) { element(id).textContent = text; }
  function formatSize(bytes) {
    return bytes >= 1024 * 1024
      ? `${(bytes / (1024 * 1024)).toFixed(2)} MB`
      : `${(bytes / 1024).toFixed(2)} KB`;
  }
  function formatExtensions(extensions) {
    return new Intl.ListFormat('en', { style: 'long', type: 'conjunction' }).format(extensions);
  }
  function isIgnoredSystemFile(relativePath) {
    const parts = relativePath.split('/');
    const filename = parts.at(-1).toLowerCase();
    return filename === '.ds_store' || filename === 'thumbs.db' || parts.includes('__MACOSX');
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
  function selectFiles(items) {
    selectedFiles = [];
    const unique = new Map();
    for (const item of items) {
      const file = item.file || item;
      const relativePath = (item.relativePath || file.webkitRelativePath || file.name).replaceAll('\\', '/');
      unique.set(`${relativePath}:${file.size}:${file.lastModified}`, { file, relativePath });
    }
    const files = [...unique.values()].filter((item) => !isIgnoredSystemFile(item.relativePath));
    if (!files.length) return showSelection('error', 'No files were selected.');
    if (files.length > maxBatchFiles) {
      return showSelection('error', `Select no more than ${maxBatchFiles} files.`);
    }
    let totalSize = 0;
    for (const item of files) {
      const extension = `.${item.file.name.split('.').pop().toLowerCase()}`;
      if (!allowedExtensions.includes(extension)) {
        return showSelection('error', `Unsupported file: ${item.relativePath}. Supported files: ${formatExtensions(allowedExtensions)}.`);
      }
      if (!item.file.size) return showSelection('error', `Empty file: ${item.relativePath}.`);
      if (item.file.size > maxFileSize) {
        return showSelection('error', `${item.relativePath} exceeds the ${formatSize(maxFileSize)} per-file limit.`);
      }
      totalSize += item.file.size;
    }
    if (totalSize > maxBatchSize) {
      return showSelection('error', `The selection exceeds the ${formatSize(maxBatchSize)} batch limit.`);
    }
    selectedFiles = files;
    const label = files.length === 1
      ? files[0].relativePath
      : `${files.length} files selected (${formatSize(totalSize)})`;
    showSelection('success', '', label);
  }
  function openModal() {
    previousFocus = document.activeElement;
    selectedFiles = [];
    fileInput.value = '';
    folderInput.value = '';
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
    if (location.scope === 'file_structure') return 'File structure';
    if (location.scope === 'legacy_doc_string') return 'Legacy DOC readable string';
    if (location.scope === 'pe_string') return 'PE readable string';
    if (location.scope === 'whole_document') return 'Whole document';
    const parts = [];
    if (location.archive_member) parts.push(`Archive member: ${location.archive_member}`);
    if (location.line_number) parts.push(`Line ${location.line_number}`);
    if (location.paragraph_number) parts.push(`Paragraph ${location.paragraph_number}`);
    if (location.page_number) parts.push(`Page ${location.page_number}`);
    for (const table of location.table_location || []) {
      parts.push(`Table ${table.table_number}, row ${table.row_number}, cell ${table.cell_number}`);
    }
    if (location.character_offset) parts.push(`Character offset ${location.character_offset}`);
    return parts.join(' · ') || 'Document';
  }
  function renderReport(report, preserveBatch = false) {
    element('historySection').hidden = true;
    if (!preserveBatch) element('batchSummary').hidden = true;
    document.querySelector('.details-grid').hidden = false;
    document.querySelector('.findings-section').hidden = false;
    document.querySelector('.limitations-section').hidden = false;
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

  function renderBatch(batch) {
    setText('batchCompleted', String(batch.completed_files));
    setText('batchSuspicious', String(batch.suspicious_files));
    setText('batchReview', String(batch.review_required_files));
    setText('batchFailed', String(batch.failed_files));
    const list = element('batchFileList');
    list.replaceChildren();
    for (const report of batch.reports) {
      const button = document.createElement('button');
      button.type = 'button';
      button.className = `batch-file ${report.verdict}`;
      button.textContent = report.relative_path || report.filename;
      button.addEventListener('click', () => renderReport(report, true));
      list.append(button);
    }
    for (const failure of batch.errors) {
      const item = document.createElement('span');
      item.className = 'batch-file failed';
      item.textContent = `${failure.relative_path}: ${failure.error}`;
      list.append(item);
    }
    element('batchSummary').hidden = false;
    if (batch.reports.length) {
      renderReport(batch.reports[0], true);
      return;
    }
    setText('resultVerdict', 'No files could be analyzed');
    setText('resultSummary', 'Review the file errors below and try again with valid documents.');
    element('resultBanner').className = 'result-banner suspicious';
    document.querySelector('.details-grid').hidden = true;
    document.querySelector('.findings-section').hidden = true;
    document.querySelector('.limitations-section').hidden = true;
    element('reportLink').hidden = true;
    element('heroSection').hidden = true;
    element('dashboardSection').hidden = false;
    closeModal();
    element('dashboardSection').scrollIntoView({ block: 'start' });
  }

  async function readEntry(entry, prefix = '') {
    if (entry.isFile) {
      const file = await new Promise((resolve, reject) => entry.file(resolve, reject));
      return [{ file, relativePath: `${prefix}${file.name}` }];
    }
    if (!entry.isDirectory) return [];
    const reader = entry.createReader();
    const entries = [];
    while (true) {
      const page = await new Promise((resolve, reject) => reader.readEntries(resolve, reject));
      if (!page.length) break;
      entries.push(...page);
    }
    const nested = await Promise.all(entries.map((child) => readEntry(child, `${prefix}${entry.name}/`)));
    return nested.flat();
  }

  async function droppedItems(dataTransfer) {
    const entries = [...dataTransfer.items]
      .map((item) => item.webkitGetAsEntry?.())
      .filter(Boolean);
    if (!entries.length) return [...dataTransfer.files].map((file) => ({ file, relativePath: file.name }));
    return (await Promise.all(entries.map((entry) => readEntry(entry)))).flat();
  }

  async function showHistory() {
    const request = ++historyRequest;
    element('heroSection').hidden = true;
    element('dashboardSection').hidden = true;
    element('historySection').hidden = false;
    element('historyRows').replaceChildren();
    setText('historyStatus', 'Loading...');
    element('historyPrevious').disabled = true;
    element('historyNext').disabled = true;
    try {
      const page = await readApiResponse(await fetch(`/api/v1/reports?offset=${historyOffset}&limit=20`));
      if (request !== historyRequest) return;
      for (const report of page.items) {
        const row = document.createElement('tr');
        for (const value of [report.filename, new Date(report.created_at).toLocaleString(), report.verdict.replaceAll('_', ' '), `${report.risk_score} / 100`]) {
          const cell = document.createElement('td');
          cell.textContent = value;
          cell.style.padding = '12px 8px';
          cell.style.overflowWrap = 'anywhere';
          row.append(cell);
        }
        const cell = document.createElement('td');
        const button = document.createElement('button');
        button.className = 'btn btn-text';
        button.textContent = 'View';
        button.addEventListener('click', async () => {
          button.disabled = true;
          try {
            const result = await readApiResponse(await fetch(`/api/v1/reports/${encodeURIComponent(report.scan_id)}`));
            if (request === historyRequest && !element('historySection').hidden) renderReport(result);
          } catch (error) { setText('historyStatus', error.message); }
          finally { button.disabled = false; }
        });
        cell.append(button); row.append(cell); element('historyRows').append(row);
      }
      setText('historyStatus', page.total ? `${historyOffset + 1}-${historyOffset + page.items.length} of ${page.total} scans` : 'No scans yet.');
      element('historyPrevious').disabled = historyOffset === 0;
      element('historyNext').disabled = historyOffset + page.items.length >= page.total;
    } catch (error) {
      if (request === historyRequest) setText('historyStatus', `Unable to load history: ${error.message}`);
    }
  }
  element('historyNav').addEventListener('click', (event) => { event.preventDefault(); historyOffset = 0; showHistory(); });
  element('scanNav').addEventListener('click', (event) => {
    event.preventDefault(); ++historyRequest;
    element('historySection').hidden = true;
    element('dashboardSection').hidden = true;
    element('heroSection').hidden = false;
  });
  element('refreshHistory').addEventListener('click', () => { historyOffset = 0; showHistory(); });
  element('historyPrevious').addEventListener('click', () => { historyOffset = Math.max(0, historyOffset - 20); showHistory(); });
  element('historyNext').addEventListener('click', () => { historyOffset += 20; showHistory(); });
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
  element('browseFolderLink').addEventListener('click', (event) => {
    event.preventDefault(); folderInput.value = ''; folderInput.click();
  });
  fileInput.addEventListener('change', () => { if (fileInput.files.length) selectFiles(fileInput.files); });
  folderInput.addEventListener('change', () => { if (folderInput.files.length) selectFiles(folderInput.files); });
  const dropZone = element('dropZone');
  dropZone.addEventListener('dragover', (event) => {
    event.preventDefault(); dropZone.classList.add('drag-over');
  });
  dropZone.addEventListener('dragleave', () => dropZone.classList.remove('drag-over'));
  dropZone.addEventListener('drop', async (event) => {
    event.preventDefault(); dropZone.classList.remove('drag-over');
    try {
      selectFiles(await droppedItems(event.dataTransfer));
    } catch (error) {
      selectedFiles = [];
      showSelection('error', 'The dropped folder could not be read.');
    }
  });
  continueBtn.addEventListener('click', async () => {
    if (!selectedFiles.length || activeRequest) return;
    const files = [...selectedFiles];
    const request = new AbortController();
    activeRequest = request;
    element('uploadStepView').hidden = true;
    element('analyzingStepView').hidden = false;
    setText('analyzingFileName', files.length === 1 ? files[0].relativePath : `${files.length} files`);
    element('closeModalBtn').focus();
    try {
      const batch = await scanFiles(files, request.signal);
      if (activeRequest !== request) return;
      activeRequest = null;
      renderBatch(batch);
    } catch (error) {
      if (activeRequest !== request) return;
      activeRequest = null;
      if (error.name === 'AbortError') return;
      element('uploadStepView').hidden = false;
      element('analyzingStepView').hidden = true;
      const message = error instanceof TypeError
        ? 'Unable to reach the server. Check that the application is running and try again.'
        : error.message;
      showSelection('error', message, files.length === 1 ? files[0].relativePath : `${files.length} files`);
      element('retryLink').focus();
    }
  });
  getCapabilities().then((capabilities) => {
    maxFileSize = capabilities.max_file_size_bytes;
    maxBatchFiles = capabilities.max_batch_files;
    maxBatchSize = capabilities.max_batch_size_bytes;
    allowedExtensions = capabilities.supported_extensions;
    fileInput.accept = allowedExtensions.join(',');
    folderInput.accept = allowedExtensions.join(',');
    setText('supportedFilesText', `Supported files: ${formatExtensions(allowedExtensions)} · up to ${maxBatchFiles} files · ${formatSize(maxFileSize)} per file`);
    if (selectedFiles.length && !activeRequest) selectFiles(selectedFiles);
  }).catch(() => { /* The server also validates each upload. */ });
})();
