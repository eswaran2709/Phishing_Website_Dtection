# PhishGuard AI Browser Extension

This browser extension integrates with the PhishGuard AI phishing detection system.

## Setup Instructions

1. **Start the API Server**:
   ```bash
   cd /path/to/phishing_website_detection
   source venv/bin/activate
   uvicorn api:app --interface wsgi --host 0.0.0.0 --port 5001
   ```
   The API should be running on http://localhost:5001

2. **Configure VirusTotal (Optional but Recommended)**:
   - Get a free API key from [VirusTotal](https://www.virustotal.com/)
   - Set environment variable: `export VIRUSTOTAL_API_KEY=your_key_here`
   - Or create a `.env` file with: `VIRUSTOTAL_API_KEY=your_key_here`

3. **Load the Extension**:
   - **Firefox**: Go to `about:debugging`, click "This Firefox", "Load Temporary Add-on", select `manifest.json`.
   - **Chrome**: Go to `chrome://extensions/`, enable "Developer mode", click "Load unpacked", select the `browser_extension/` folder.
   - **Edge**: Similar to Chrome.

4. **Icons**: ✅ Already created (icon16.png, icon48.png, icon128.png)

## Features

- Automatically analyzes the current tab's URL
- Displays AI-powered phishing verdict
- Shows detailed metrics (RF, LSTM, YARA, VirusTotal)
- **Enhanced VirusTotal Display**: 
  - Prominent status indicator (MALICIOUS/CLEAN)
  - Detailed scan statistics with color-coded icons
  - URL and IP analysis breakdown
  - Visual status badges
  - **Legend**: 🔴 Malicious | 🟡 Suspicious | 🟢 Clean | ⚪ Unknown (number of antivirus engines)

- **Connection Error**: Make sure the API server is running on localhost:5001
- **Icons Missing**: Icons are already created in the folder
- **VirusTotal Not Working**: Ensure VIRUSTOTAL_API_KEY is set in the .env file

## Deployment

For production use, deploy the Flask API to a cloud service and update the fetch URL in `popup.js`.