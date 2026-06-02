// utils/reportParser.js

const extractIocs = (text) => {
    const results = {
        ips: [],
        domains: [],
        hashes: []
    };

    if (!text) return results;

    // Regex Patterns
    const ipRegex = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g;
    
    // Defangs domains like example[.]com to example.com before evaluating
    const defangedText = text.replace(/\[\.\]/g, '.').replace(/\[\.\]/g, '.'); 
    
    // Matches standard domains
    const domainRegex = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]\b/gi;
    
    // Matches Hashes
    const sha256Regex = /\b[A-Fa-f0-9]{64}\b/g;
    const md5Regex = /\b[A-Fa-f0-9]{32}\b/g;
    const sha1Regex = /\b[A-Fa-f0-9]{40}\b/g;

    // Extract & Deduplicate
    results.ips = [...new Set(text.match(ipRegex) || [])];
    
    // Filter out domains that are actually IP addresses
    results.domains = [...new Set(defangedText.match(domainRegex) || [])]
        .filter(d => !d.match(ipRegex))
        .map(d => d.toLowerCase());
        
    results.hashes = [
        ...new Set(text.match(sha256Regex) || []),
        ...new Set(text.match(sha1Regex) || []),
        ...new Set(text.match(md5Regex) || [])
    ].map(h => h.toLowerCase());

    return results;
};

module.exports = extractIocs;