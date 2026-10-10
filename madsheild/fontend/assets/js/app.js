// Grab elements from your upload card HTML
const fileInput = document.getElementById('fileInput');
const browseLink = document.getElementById('browseLink');
const continueBtn = document.getElementById('continueBtn');

let selectedFile = null;

// 1. Click "browse" to open file picker
browseLink.addEventListener('click', (e) => {
  e.preventDefault();
  fileInput.click();
});

// 2. Handle file selection via dialog
fileInput.addEventListener('change', (e) => {
  if (e.target.files.length > 0) {
    setFile(e.target.files[0]);
  }
});

// Helper to store file and enable continue button
function setFile(file) {
  selectedFile = file;
  continueBtn.removeAttribute('disabled');
  browseLink.textContent = file.name; // Show selected filename
}

// 3. When user clicks "Continue", call your backend via scanFile()
continueBtn.addEventListener('click', async () => {
  if (!selectedFile) return;

  try {
    continueBtn.textContent = 'Scanning...';
    continueBtn.disabled = true;

    // This calls the scanFile function from api-client.js!
    const result = await scanFile(selectedFile);

    console.log('Scan successful:', result);
    alert(`File uploaded & scanned successfully!\nSHA256: ${result.sha256}`);

    continueBtn.textContent = 'Continue';
    continueBtn.disabled = false;
  } catch (error) {
    console.error('Scan failed:', error);
    alert('Error: ' + error.message);
    continueBtn.textContent = 'Continue';
    continueBtn.disabled = false;
  }
});