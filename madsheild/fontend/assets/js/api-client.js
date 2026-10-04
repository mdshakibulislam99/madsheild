(() => {
  const configuredBaseUrl = window.MADSHEILD_API_BASE_URL;
  const apiBaseUrl = (configuredBaseUrl || 'http://127.0.0.1:8000').replace(/\/$/, '');

  async function uploadScan(file) {
    const formData = new FormData();
    formData.append('files', file, file.name);

    const response = await fetch(`${apiBaseUrl}/api/v1/scans`, {
      method: 'POST',
      body: formData,
    });

    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(payload.detail || 'The backend could not upload this file.');
    }

    return payload;
  }

  window.MadSheildApi = { uploadScan };
})();
