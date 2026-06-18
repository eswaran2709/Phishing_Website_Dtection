// Content script - runs on web pages
// Optional: Add visual indicators or warnings

// Cross-browser compatibility for WebExtensions API
if (typeof browser === "undefined") {
  var browser = chrome;
}

// Example: Inject a warning banner for suspicious sites
function injectWarning(message, type = 'warning') {
  const banner = document.createElement('div');
  banner.style.cssText = `
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    background: ${type === 'danger' ? '#dc3545' : '#ffc107'};
    color: ${type === 'danger' ? 'white' : 'black'};
    text-align: center;
    padding: 10px;
    z-index: 10000;
    font-family: Arial, sans-serif;
    font-weight: bold;
  `;
  banner.textContent = `⚠️ PhishGuard: ${message}`;
  document.body.insertBefore(banner, document.body.firstChild);
}

// Listen for messages from popup (if needed)
// browser.runtime.onMessage.addListener(function(request, sender, sendResponse) {
//   if (request.action === 'showWarning') {
//     injectWarning(request.message, request.type);
//   }
// });