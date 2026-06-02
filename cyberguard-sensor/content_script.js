// --- CyberGuard Content Script (The Sensor) ---

const scannedUrls = new Set();
let mutationTimeout = null;

/**
 * Strips query parameters and hashes to prevent leaking PII or session tokens to the SOC.
 */
function sanitizeUrl(rawUrl) {
    try {
        const urlObj = new URL(rawUrl);
        return `${urlObj.protocol}//${urlObj.hostname}${urlObj.pathname}`;
    } catch (e) {
        return null;
    }
}

/**
 * Extracts links and actionable targets from the DOM safely.
 */
function extractLinks() {
    // Scans anchors, iframes, forms, and external script elements
    const elements = document.querySelectorAll('a[href], iframe[src], form[action], script[src]');
    const newUrls = [];

    elements.forEach(el => {
        const link = el.href || el.src || el.action;
        if (!link || link.startsWith('javascript:') || link.startsWith('data:')) return;
        
        const safeUrl = sanitizeUrl(link);
        if (safeUrl && !scannedUrls.has(safeUrl)) {
            scannedUrls.add(safeUrl);
            newUrls.push(safeUrl);
        }
    });

    if (newUrls.length > 0) {
        // Offload processing and API ingestion to the background service worker
        chrome.runtime.sendMessage({ 
            type: "SCAN_URLS", 
            urls: newUrls, 
            source: sanitizeUrl(window.location.href) 
        });
    }
}

/**
 * Monitors dynamic changes in the DOM with a debounce mechanism to preserve CPU performance.
 */
function observeDynamicContent() {
    const observer = new MutationObserver(() => {
        clearTimeout(mutationTimeout);
        mutationTimeout = setTimeout(() => {
            extractLinks();
        }, 1500); // 1.5 second buffer to throttle execution on heavy SPA environments
    });
    
    if (document.body) {
        observer.observe(document.body, { childList: true, subtree: true });
    }
}

/**
 * Listens for block verdicts originating from the SOC background threat verification system.
 */
chrome.runtime.onMessage.addListener((message) => {
    if (message.type === "THREAT_DETECTED") {
        highlightAndBlockLink(message.url);
    }
});

/**
 * Visually isolates and neutralizes malicious elements on the page.
 */
function highlightAndBlockLink(url) {
    const badElements = document.querySelectorAll(`[href^="${url}"], [src^="${url}"], [action^="${url}"]`);
    badElements.forEach(el => {
        el.style.border = "3px dashed #ff0000";
        el.style.backgroundColor = "rgba(255, 0, 0, 0.15)";
        el.style.color = "#ff0000";
        el.title = "CyberGuard SOC: This link has been neutralized for security policy compliance.";
        
        // Neutralize navigation attempts completely
        el.addEventListener('click', (e) => {
            e.preventDefault();
            e.stopPropagation();
            alert("CyberGuard Warning: Access to this indicator has been restricted by your enterprise SOC.");
        }, true);
    });
}

// Initialize Sensor
extractLinks();
observeDynamicContent();