// --- CyberGuard Client-Side Scanner ---
const THREAT_PATTERNS = [
    { category: "IP-Based Domains", regex: /^https?:\/\/(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?:\:[0-9]{1,5})?(?:\/|$)/, severity: "High" },
    { category: "Punycode/Homograph Attacks", regex: /^https?:\/\/(?:www\.)?xn--[a-zA-Z0-9-]+/, severity: "Critical" },
    { category: "Highly Abused / Free Dynamic TLDs", regex: /^https?:\/\/[a-zA-Z0-9.-]+\.(tk|ml|ga|cf|gq|duckdns\.org|freeddns\.org|bounceme\.net)(?:\/|$)/i, severity: "Medium" },
    { category: "Suspicious Embedded Payloads (XSS/SQLi)", regex: /(?:javascript:|%3Cscript%3E|<script>|UNION(\+|%20)SELECT|base64_decode)/i, severity: "Critical" },
    { category: "Excessive Subdomains (Fast-Flux)", regex: /^https?:\/\/(?:[a-zA-Z0-9-]+\.){4,}[a-zA-Z]{2,}/, severity: "Low" }
];

const scannedUrls = new Set();

function analyzeUrl(url) {
    if (!url || scannedUrls.has(url)) return;
    scannedUrls.add(url);

    for (const pattern of THREAT_PATTERNS) {
        if (pattern.regex.test(url)) {
            console.warn(`[CyberGuard] Threat Detected! [${pattern.category}]: ${url}`);
            reportToRepository(url, pattern.category, pattern.severity);
            highlightVulnerableLink(url);
            break;
        }
    }
}

function scanDOM() {
    const links = document.querySelectorAll('a[href]');
    links.forEach(link => analyzeUrl(link.href));
}

function observeDynamicContent() {
    const observer = new MutationObserver((mutations) => {
        mutations.forEach((mutation) => {
            mutation.addedNodes.forEach((node) => {
                if (node.tagName === 'A' && node.href) analyzeUrl(node.href);
                else if (node.querySelectorAll) {
                    const childLinks = node.querySelectorAll('a[href]');
                    childLinks.forEach(link => analyzeUrl(link.href));
                }
            });
        });
    });
    observer.observe(document.body, { childList: true, subtree: true });
}

async function reportToRepository(vulnerableUrl, category, severity) {
    // UPDATE THIS URL to point to your actual backend API endpoint
    const repositoryEndpoint = "http://localhost:3000/api/v1/threats";
    
    const threatData = {
        detectedUrl: vulnerableUrl, 
        category: category, 
        severity: severity,
        sourcePage: window.location.href, 
        timestamp: new Date().toISOString()
    };
    
    try {
        console.log("[CyberGuard] Sending to backend:", threatData);
        // Uncomment the lines below once your backend API is ready to receive data
        /*
        const response = await fetch(repositoryEndpoint, { 
            method: "POST", 
            headers: { "Content-Type": "application/json" }, 
            body: JSON.stringify(threatData) 
        });
        */
    } catch (error) {
        console.error("[CyberGuard] Failed to reach repository:", error);
    }
}

function highlightVulnerableLink(url) {
    const badLinks = document.querySelectorAll(`a[href="${url}"]`);
    badLinks.forEach(el => {
        el.style.border = "2px solid red";
        el.style.backgroundColor = "#ffcccc";
        el.title = "CyberGuard Warning: Potentially unsafe link!";
    });
}

// Initialize the scanner
scanDOM();
observeDynamicContent();