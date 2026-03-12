// ============================================
// RULE: Link Analysis
// ============================================
// This rule inspects every link in the email body to detect:
//   - Mismatched links (display text says one domain, actual URL goes elsewhere)
//   - Suspicious URL patterns (IP addresses, excessive subdomains)
//   - URL shorteners (hiding the real destination)
//   - Known phishing URL patterns

// URL shortener domains — these hide where a link actually goes
const URL_SHORTENERS = [
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly',
  'is.gd', 'buff.ly', 'rebrand.ly', 'bl.ink', 'short.io',
  'tiny.cc', 'lnkd.in', 'surl.li', 'cutt.ly', 'rb.gy',
];

// Suspicious keywords commonly found in phishing URLs
const SUSPICIOUS_URL_KEYWORDS = [
  'login', 'signin', 'sign-in', 'verify', 'verification',
  'secure', 'security', 'account', 'update', 'confirm',
  'authenticate', 'wallet', 'banking', 'password', 'credential',
  'suspend', 'restore', 'unlock', 'reactivate',
];

// Trusted domains — links pointing to these are generally safe
const TRUSTED_LINK_DOMAINS = [
  'google.com', 'gmail.com', 'youtube.com',
  'microsoft.com', 'outlook.com', 'live.com', 'office.com',
  'apple.com', 'icloud.com',
  'amazon.com', 'amazon.co.uk',
  'paypal.com', 'paypal.co.uk',
  'facebook.com', 'instagram.com', 'meta.com',
  'twitter.com', 'x.com',
  'linkedin.com',
  'github.com',
  'dropbox.com',
  'netflix.com', 'spotify.com',
  'bbc.co.uk', 'bbc.com',
  'gov.uk',
];

/**
 * Extract the domain from a URL
 * "https://www.paypal-secure.xyz/login?id=123" → "paypal-secure.xyz"
 */
function extractDomainFromURL(url) {
  try {
    // Handle URLs that might not have a protocol
    let fullUrl = url;
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
      fullUrl = 'https://' + url;
    }
    const urlObj = new URL(fullUrl);
    // Remove "www." prefix for cleaner comparison
    return urlObj.hostname.replace(/^www\./, '').toLowerCase();
  } catch {
    return null;
  }
}

/**
 * Extract the path from a URL
 * "https://example.com/login/verify" → "/login/verify"
 */
function extractPath(url) {
  try {
    let fullUrl = url;
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
      fullUrl = 'https://' + url;
    }
    return new URL(fullUrl).pathname.toLowerCase();
  } catch {
    return '';
  }
}

/**
 * Check if a URL contains an IP address instead of a domain name
 * Legitimate companies never use IP addresses in their email links
 * "http://192.168.1.1/login" → true
 */
function isIPAddress(url) {
  const domain = extractDomainFromURL(url);
  if (!domain) return false;
  // Match IPv4 pattern
  const ipv4Pattern = /^(\d{1,3}\.){3}\d{1,3}$/;
  return ipv4Pattern.test(domain);
}

/**
 * Count subdomain levels
 * "login.secure.paypal.com" has 2 extra subdomains (login, secure)
 * Phishers often use excessive subdomains to hide the real domain
 */
function countSubdomains(url) {
  const domain = extractDomainFromURL(url);
  if (!domain) return 0;
  
  // Split by dots and account for TLDs like .co.uk
  const parts = domain.split('.');
  const multiPartTLDs = ['.co.uk', '.com.au', '.co.nz', '.org.uk', '.gov.uk'];
  
  const hasMultiPartTLD = multiPartTLDs.some(tld => domain.endsWith(tld));
  const baseParts = hasMultiPartTLD ? 3 : 2; // e.g., "example.co.uk" = 3 parts
  
  return Math.max(0, parts.length - baseParts);
}

/**
 * Check if a link's display text shows a different domain than the actual URL
 * This is one of the most dangerous phishing tricks:
 * Display text: "Click here to visit paypal.com"
 * Actual URL: "http://evil-site.xyz/steal-credentials"
 */
function checkMismatch(displayText, actualUrl) {
  if (!displayText || !actualUrl) return null;
  
  // Only check if the display text looks like a URL or contains a domain
  const displayLower = displayText.toLowerCase().trim();
  
  // Check if display text contains a domain-like pattern
  const domainPattern = /[a-z0-9][-a-z0-9]*\.[a-z]{2,}/i;
  const displayDomainMatch = displayLower.match(domainPattern);
  
  if (!displayDomainMatch) return null; // Display text doesn't look like a URL
  
  const displayDomain = displayDomainMatch[0].replace(/^www\./, '');
  const actualDomain = extractDomainFromURL(actualUrl);
  
  if (!actualDomain) return null;
  
  // Compare the domains — if they're different, this is a mismatch
  if (displayDomain !== actualDomain && !actualDomain.endsWith('.' + displayDomain)) {
    return {
      displayDomain,
      actualDomain,
    };
  }
  
  return null;
}

/**
 * Main rule function — analyses all links in the email
 * Returns an array of indicators found
 */
function checkLinks(emailData) {
  const indicators = [];
  const { links } = emailData;
  
  // links is an array of objects: [{ text: "Click here", url: "http://..." }, ...]
  // OR just an array of URL strings: ["http://...", ...]
  if (!links || links.length === 0) return indicators;
  
  let hasShortener = false;
  let hasIPAddress = false;
  let hasMismatch = false;
  let hasExcessiveSubdomains = false;
  let hasSuspiciousKeywords = false;
  let suspiciousLinkCount = 0;
  
  for (const link of links) {
    // Handle both formats: string or object with text/url
    const url = typeof link === 'string' ? link : link.url;
    const displayText = typeof link === 'string' ? null : link.text;
    
    if (!url) continue;
    
    const domain = extractDomainFromURL(url);
    if (!domain) continue;
    
    const path = extractPath(url);
    const isTrusted = TRUSTED_LINK_DOMAINS.some(d => domain === d || domain.endsWith('.' + d));
    
    // CHECK 1: URL Shortener
    if (!hasShortener && URL_SHORTENERS.some(s => domain === s || domain.endsWith('.' + s))) {
      hasShortener = true;
      indicators.push({
        type: 'link_analysis',
        severity: 'medium',
        result: 'warning',
        label: 'URL Shortener Detected',
        explanation: `This email contains a shortened link using "${domain}". URL shorteners hide the real destination of a link. Legitimate companies rarely use URL shorteners in official emails because they want you to see and trust their real domain. Before clicking, consider: would this company normally send you a shortened link?`
      });
    }
    
    // CHECK 2: IP Address in URL
    if (!hasIPAddress && isIPAddress(url)) {
      hasIPAddress = true;
      indicators.push({
        type: 'link_analysis',
        severity: 'high',
        result: 'fail',
        label: 'IP Address Link Detected',
        explanation: `This email contains a link that goes to a raw IP address (${domain}) instead of a named website. No legitimate company sends emails with links to IP addresses — they always use their domain name (like amazon.co.uk or paypal.com). This is a strong indicator of phishing.`
      });
    }
    
    // CHECK 3: Mismatched display text vs actual URL
    if (!hasMismatch && displayText) {
      const mismatch = checkMismatch(displayText, url);
      if (mismatch) {
        hasMismatch = true;
        indicators.push({
          type: 'link_analysis',
          severity: 'high',
          result: 'fail',
          label: 'Mismatched Link URL',
          explanation: `A link in this email displays "${mismatch.displayDomain}" but actually points to "${mismatch.actualDomain}". This is a classic phishing trick — the visible text makes you think you're going to a trusted site, but the real destination is completely different. Always hover over links to check where they really go before clicking.`
        });
      }
    }
    
    // CHECK 4: Excessive subdomains
    if (!hasExcessiveSubdomains) {
      const subdomainCount = countSubdomains(url);
      if (subdomainCount >= 3) {
        hasExcessiveSubdomains = true;
        indicators.push({
          type: 'link_analysis',
          severity: 'medium',
          result: 'warning',
          label: 'Suspicious Link Structure',
          explanation: `A link in this email has an unusually complex structure with ${subdomainCount} subdomains (${domain}). Phishers often use long, complex URLs with many subdomains to make the real domain harder to spot. The actual domain is always the last part before the extension — everything before it could be designed to mislead you.`
        });
      }
    }
    
    // CHECK 5: Suspicious keywords in URL path
    if (!hasSuspiciousKeywords && !isTrusted) {
      const urlString = (url + path).toLowerCase();
      const foundKeywords = SUSPICIOUS_URL_KEYWORDS.filter(kw => urlString.includes(kw));
      
      if (foundKeywords.length >= 2) {
        hasSuspiciousKeywords = true;
        indicators.push({
          type: 'link_analysis',
          severity: 'medium',
          result: 'warning',
          label: 'Suspicious Link Keywords',
          explanation: `A link in this email contains multiple security-related words ("${foundKeywords.slice(0, 3).join('", "')}") in its URL. While individual words like "login" are normal, phishing links often stack multiple urgent or security-related terms to appear legitimate. Compare this URL to the company's official website address.`
        });
      }
    }
    
    // Track how many links are suspicious overall
    if (!isTrusted) {
      suspiciousLinkCount++;
    }
  }
  
  // CHECK 6: If ALL links in the email go to untrusted domains
  if (links.length > 0 && suspiciousLinkCount === links.length && indicators.length === 0) {
    // Only add this if no other link indicators were found
    // This is a softer warning — not every unknown domain is dangerous
    indicators.push({
      type: 'link_analysis',
      severity: 'low',
      result: 'info',
      label: 'Unrecognised Link Destinations',
      explanation: `The links in this email point to domains that aren't in our trusted list. This doesn't necessarily mean the email is dangerous, but it's worth double-checking the sender and the context before clicking any links.`
    });
  }
  
  // If all links checked out fine
  if (indicators.length === 0 && links.length > 0) {
    indicators.push({
      type: 'link_analysis',
      severity: 'none',
      result: 'pass',
      label: 'Links Verified',
      explanation: 'All links in this email point to recognised, trusted domains and show no signs of manipulation.'
    });
  }
  
  return indicators;
}

module.exports = { checkLinks };