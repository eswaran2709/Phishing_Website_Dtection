// Cross-browser compatibility for WebExtensions API
if (typeof browser === "undefined") {
  var browser = chrome;
}

document.addEventListener('DOMContentLoaded', function() {
  browser.tabs.query({active: true, currentWindow: true}, function(tabs) {
    const url = tabs[0].url;
    analyzeUrl(url);
  });
});

async function analyzeUrl(url) {
  const statusEl = document.getElementById('status');
  const resultEl = document.getElementById('result');

  try {
    const response = await fetch('http://localhost:5001/analyze', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ url: url })
    });

    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }

    const result = await response.json();
    displayResult(result);
  } catch (error) {
    statusEl.textContent = '❌ Connection Error';
    statusEl.className = 'phishing';
    resultEl.innerHTML = `
      <p>Could not connect to PhishGuard detector.</p>
      <p>Make sure the API server is running on localhost:5001</p>
      <p>Error: ${error.message}</p>
    `;
    console.error('Error:', error);
  }
}

function displayResult(result) {
  const statusEl = document.getElementById('status');
  const resultEl = document.getElementById('result');

  // Set verdict and color
    statusEl.textContent = result.verdict;
  if (result.verdict.includes('PHISHING')) {
    statusEl.className = 'phishing';
  } else if (result.verdict.includes('SUSPICIOUS')) {
    statusEl.className = 'suspicious';
  } else {
    statusEl.className = 'safe';
  }

  // Display detailed results
  const details = result.details;
  resultEl.innerHTML = `
    <div class="metric"><span>URL:</span> <span>${result.url}</span></div>
    <div class="metric"><span>Risk Score:</span> <span>${result.risk_score}/100</span></div>
    <div class="metric"><span>RF Probability:</span> <span>${(details.rf_probability * 100).toFixed(1)}%</span></div>
    <div class="metric"><span>LSTM Probability:</span> <span>${(details.lstm_probability * 100).toFixed(1)}%</span></div>
    <div class="metric"><span>Hybrid Probability:</span> <span>${(details.hybrid_probability * 100).toFixed(1)}%</span></div>
    <div class="metric"><span>YARA Matches:</span> <span>${details.yara_matches}</span></div>
    <div class="metric"><span>Typosquat Check:</span> <span>${details.typosquat}</span></div>

    ${details.virustotal ? `
      <div class="vt-section">
        <div class="vt-header">
          <span class="vt-label">VirusTotal Analysis</span>
          <span class="vt-status ${details.virustotal.malicious ? 'vt-malicious' : 'vt-clean'}">
            ${details.virustotal.malicious ? 'MALICIOUS' : 'CLEAN'}
          </span>
        </div>
        <div class="vt-details">
          ${details.virustotal.url_stats ? `
            <div class="vt-metric">
              <span class="vt-metric-label">URL Scan:</span>
              <span class="vt-metric-value">
                Malicious: ${details.virustotal.url_stats.malicious}, Suspicious: ${details.virustotal.url_stats.suspicious}, Clean: ${details.virustotal.url_stats.harmless}, Unknown: ${details.virustotal.url_stats.undetected}
              </span>
            </div>
          ` : ''}
          ${details.virustotal.ip_stats ? `
            <div class="vt-metric">
              <span class="vt-metric-label">IP Analysis:</span>
              <span class="vt-metric-value">
                Malicious: ${details.virustotal.ip_stats.malicious}, Suspicious: ${details.virustotal.ip_stats.suspicious}, Clean: ${details.virustotal.ip_stats.harmless}, Unknown: ${details.virustotal.ip_stats.undetected}
              </span>
            </div>
          ` : ''}
          ${!details.virustotal.url_stats && !details.virustotal.ip_stats ? `
            <div class="vt-metric">
              <span class="vt-metric-label">Status:</span>
              <span class="vt-metric-value">${details.virustotal.url_detail} | ${details.virustotal.ip_detail}</span>
            </div>
          ` : ''}
        </div>
      </div>
    ` : '<div class="vt-section"><div class="vt-header"><span class="vt-label">VirusTotal</span><span class="vt-status vt-disabled">Not Configured</span></div></div>'}
  `;
}