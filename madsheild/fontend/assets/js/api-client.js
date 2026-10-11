async function readApiResponse(response) {
  let body;
  try {
    body = await response.json();
  } catch (error) {
    throw new Error(`The server returned an unreadable response (status ${response.status}).`);
  }
  if (!response.ok) {
    const message = typeof body.detail === 'string'
      ? body.detail : `Request failed with status ${response.status}.`;
    throw new Error(message);
  }
  return body;
}

async function getCapabilities() {
  return readApiResponse(await fetch('/api/v1/capabilities'));
}

async function scanFile(file, signal) {
  const formData = new FormData();
  formData.append('file', file);
  return readApiResponse(await fetch('/api/v1/scans', {
    method: 'POST', body: formData, signal,
  }));
}
