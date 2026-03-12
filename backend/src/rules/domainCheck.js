// ============================================
// RULE: Domain Verification Check
// ============================================
// This rule catches one of the most common phishing tricks:
// spoofing the sender's email domain to look like a trusted company.
//
// Examples it catches:
//   security@paypa1.com       (number "1" instead of letter "l")
//   support@arnazon.com       (rn looks like m)
//   alerts@microsoft-support.xyz  (real brand + suspicious domain)

// Known legitimate domains for commonly spoofed brands
// In a production app, this would be a much larger database
const TRUSTED_DOMAINS = {
  'paypal': ['paypal.com', 'paypal.co.uk'],
  'amazon': ['amazon.com', 'amazon.co.uk', 'amazon.de', 'amazon.fr'],
  'microsoft': ['microsoft.com', 'outlook.com', 'hotmail.com', 'live.com'],
  'apple': ['apple.com', 'icloud.com'],
  'google': ['google.com', 'gmail.com', 'youtube.com'],
  'netflix': ['netflix.com'],
  'facebook': ['facebook.com', 'meta.com', 'instagram.com'],
  'linkedin': ['linkedin.com'],
  'dropbox': ['dropbox.com'],
  'barclays': ['barclays.co.uk', 'barclays.com'],
  'hsbc': ['hsbc.co.uk', 'hsbc.com'],
  'lloyds': ['lloydsbank.co.uk', 'lloydsbank.com'],
  'natwest': ['natwest.com'],
  'halifax': ['halifax.co.uk'],
  'revolut': ['revolut.com'],
  'monzo': ['monzo.com'],
  'wise': ['wise.com'],
  'stripe': ['stripe.com'],
  'dhl': ['dhl.com', 'dhl.co.uk'],
  'royalmail': ['royalmail.com'],
  'hmrc': ['hmrc.gov.uk'],
};

// Characters that attackers commonly swap to create lookalike domains
// For example: paypa1.com (1 instead of l), arnazon.com (rn instead of m)
const LOOKALIKE_MAP = {
  '0': ['o'],
  '1': ['l', 'i'],
  '3': ['e'],
  '5': ['s'],
  '8': ['b'],
  'o': ['0'],
  'l': ['1', 'i'],
  'i': ['1', 'l'],
  'e': ['3'],
  's': ['5'],
  'b': ['8'],
  'rn': ['m'],
  'vv': ['w'],
  'cl': ['d'],
  'nn': ['m'],
};

// Suspicious top-level domains commonly used in phishing
const SUSPICIOUS_TLDS = [
  '.xyz', '.top', '.club', '.online', '.site', '.icu',
  '.buzz', '.tk', '.ml', '.ga', '.cf', '.gq',
  '.work', '.click', '.link', '.info', '.win', '.bid',
];

/**
 * Extract the domain from an email address
 * "security@paypa1-verify.com" → "paypa1-verify.com"
 */
function extractDomain(email) {
  if (!email || !email.includes('@')) return null;
  return email.split('@')[1].toLowerCase().trim();
}

/**
 * Extract the display name brand from an email
 * "PayPal Security <security@paypa1.com>" → checks if "paypal" appears
 */
function extractBrandFromDisplayName(displayName) {
  if (!displayName) return null;
  const name = displayName.toLowerCase();
  
  for (const brand of Object.keys(TRUSTED_DOMAINS)) {
    if (name.includes(brand)) {
      return brand;
    }
  }
  return null;
}

/**
 * Check if a domain is a lookalike of a trusted domain
 * "paypa1.com" → matches "paypal.com" (1 swapped for l)
 */
function findLookalikeBrand(domain) {
  // Remove TLD for comparison — "paypa1-verify.com" → "paypa1-verify"
  const domainBase = domain.split('.')[0].replace(/-/g, '');
  
  for (const [brand, trustedDomains] of Object.entries(TRUSTED_DOMAINS)) {
    for (const trusted of trustedDomains) {
      const trustedBase = trusted.split('.')[0].replace(/-/g, '');
      
      // Direct match — domain IS the trusted domain
      if (domain === trusted) {
        return { match: true, brand, isTrusted: true };
      }
      
      // Check if domain base is similar but not identical to trusted base
      if (domainBase !== trustedBase && isSimilar(domainBase, trustedBase)) {
        return { match: true, brand, isTrusted: false, lookalike: trusted };
      }
    }
  }
  
  return { match: false };
}

/**
 * Check if two strings are suspiciously similar using lookalike characters
 * "paypa1" vs "paypal" → true (1 and l are lookalikes)
 */
function isSimilar(suspicious, legitimate) {
  // Length check — lookalike domains are usually very close in length
  if (Math.abs(suspicious.length - legitimate.length) > 2) return false;
  
  // Check character-by-character similarity
  let differences = 0;
  const maxLen = Math.max(suspicious.length, legitimate.length);
  
  for (let i = 0; i < maxLen; i++) {
    const suspChar = suspicious[i] || '';
    const legitChar = legitimate[i] || '';
    
    if (suspChar !== legitChar) {
      // Check if this is a known lookalike substitution
      const isLookalike = LOOKALIKE_MAP[suspChar]?.includes(legitChar) ||
                          LOOKALIKE_MAP[legitChar]?.includes(suspChar);
      
      if (isLookalike) {
        differences += 0.5; // Lookalike swaps count as half a difference
      } else {
        differences += 1;
      }
    }
  }
  
  // If very few differences and at least one is a lookalike swap, it's suspicious
  return differences > 0 && differences <= 2;
}

/**
 * Main rule function — analyses the sender domain
 * Returns an array of indicators found
 */
function checkDomain(emailData) {
  const indicators = [];
  const { sender, senderDisplayName } = emailData;
  
  if (!sender) return indicators;
  
  const domain = extractDomain(sender);
  if (!domain) return indicators;
  
  // CHECK 1: Is the display name claiming to be a brand that doesn't match the domain?
  const claimedBrand = extractBrandFromDisplayName(senderDisplayName || sender);
  
  if (claimedBrand) {
    const trustedDomains = TRUSTED_DOMAINS[claimedBrand];
    const isDomainTrusted = trustedDomains.some(d => domain === d || domain.endsWith('.' + d));
    
    if (!isDomainTrusted) {
      indicators.push({
        type: 'domain_check',
        severity: 'high',
        result: 'fail',
        label: 'Spoofed Sender Address',
        explanation: `The display name suggests this email is from ${claimedBrand.charAt(0).toUpperCase() + claimedBrand.slice(1)}, but the actual email address uses "${domain}" — which is not an official ${claimedBrand.charAt(0).toUpperCase() + claimedBrand.slice(1)} domain. Real emails from this company would come from ${trustedDomains.map(d => '@' + d).join(' or ')}.`
      });
    }
  }
  
  // CHECK 2: Is this a lookalike domain?
  const lookalike = findLookalikeBrand(domain);
  
  if (lookalike.match && !lookalike.isTrusted) {
    indicators.push({
      type: 'domain_check',
      severity: 'high',
      result: 'fail',
      label: 'Lookalike Domain Detected',
      explanation: `The domain "${domain}" looks very similar to the legitimate domain "${lookalike.lookalike}" but it's not the same. Attackers often swap similar-looking characters (like the number "1" for the letter "l", or "rn" for "m") to trick you into thinking the email is from a trusted source.`
    });
  }
  
  // CHECK 3: Does the domain use a suspicious TLD?
  const hasSuspiciousTLD = SUSPICIOUS_TLDS.some(tld => domain.endsWith(tld));
  
  if (hasSuspiciousTLD) {
    indicators.push({
      type: 'domain_check',
      severity: 'medium',
      result: 'warning',
      label: 'Unusual Domain Extension',
      explanation: `This email comes from a "${domain.substring(domain.lastIndexOf('.'))}" domain. While not always malicious, this type of domain extension is frequently used in phishing because they are cheap to register and rarely used by established companies. Most legitimate businesses use .com, .co.uk, .org, or their country-specific domain.`
    });
  }
  
  // CHECK 4: Does the domain contain suspicious patterns?
  // e.g., "paypal-security-verify.com" — real brands don't use hyphens like this
  const suspiciousPatterns = [
    { pattern: /secure|security|verify|account|login|update|alert|confirm/i, label: 'Security-themed Domain' },
    { pattern: /-{2,}/, label: 'Multiple Hyphens' },
  ];
  
  for (const { pattern, label } of suspiciousPatterns) {
    const domainBase = domain.split('.')[0];
    if (pattern.test(domainBase) && !lookalike.isTrusted) {
      indicators.push({
        type: 'domain_check',
        severity: 'medium',
        result: 'warning',
        label: 'Suspicious Domain Name',
        explanation: `The domain "${domain}" contains words like "secure", "verify", or "account" in its name. Legitimate companies use their actual brand name as their domain — they don't need to add words like these. Phishers often include these words to create a false sense of legitimacy.`
      });
      break; // Only flag once for suspicious patterns
    }
  }
  
  // If all checks passed and we recognise the brand, mark as verified
  if (claimedBrand && indicators.length === 0) {
    indicators.push({
      type: 'domain_check',
      severity: 'none',
      result: 'pass',
      label: 'Verified Sender Domain',
      explanation: `This email comes from "${domain}", which is a verified domain for ${claimedBrand.charAt(0).toUpperCase() + claimedBrand.slice(1)}. The sender address matches the expected domain for this company.`
    });
  }
  
  return indicators;
}

// Export the function so other files can use it
module.exports = { checkDomain };