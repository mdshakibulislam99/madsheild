const API_BASE_URL = '';

async function scanFile(file) {
  const formData = new FormData();
  formData.append('file', file);

  const response = await fetch(`${API_BASE_URL}/api/v1/scans`, {
    method: 'POST',
    body: formData,
  });

  if (!response.ok) {
    let detail = `Scan failed with status ${response.status}.`;
    try {
      const error = await response.json();
      if (error.detail) detail = error.detail;
    } catch (error) {
      console.warn('The scan error response was not valid JSON.', error);
    }
    throw new Error(detail);
  }

  return response.json();
}