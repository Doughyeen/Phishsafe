// ============================================
// PRE-WRITTEN EDUCATION CONTENT
// ============================================
// Each rule has matching education tips that teach users
// what to look for. These are displayed in the "Learn" section
// of the PhishSafe banner.

const EDUCATION_TIPS = {
  domain_check: [
    {
      title: 'How to Check a Sender Address',
      content: 'Always look at the actual email address, not just the display name. A display name can say anything — "PayPal Security", "Your Bank", "Apple Support" — but the email address after the @ symbol tells the truth. If it doesn\'t match the company\'s real domain, it\'s likely phishing.'
    },
    {
      title: 'Spot the Difference: Lookalike Domains',
      content: 'Attackers register domains that look almost identical to real ones by swapping similar characters. Watch for: "1" instead of "l", "0" instead of "o", "rn" instead of "m". For example, "paypa1.com" and "paypal.com" look nearly identical at a glance. Always read domain names carefully, character by character.'
    },
    {
      title: 'Domain Extensions Matter',
      content: 'Legitimate companies almost always use well-known domain extensions like .com, .co.uk, or .org. If you receive an email from a .xyz, .top, .club, or other unusual extension claiming to be from a major company, treat it with extreme caution.'
    }
  ],
  
  link_analysis: [
    {
      title: 'Hover Before You Click',
      content: 'Before clicking any link in an email, hover your mouse over it (don\'t click!). Your browser will show the actual URL at the bottom of the screen. If the link text says "paypal.com" but the real URL points somewhere else, it\'s a phishing link.'
    },
    {
      title: 'URL Shorteners Hide Danger',
      content: 'Links using services like bit.ly, tinyurl.com, or t.co hide the real destination. Legitimate companies rarely use URL shorteners in official emails — they want you to see their real domain for trust. If an "official" email uses shortened links, be suspicious.'
    }
  ],
  
  language_check: [
    {
      title: 'The Urgency Trick',
      content: 'Phishing emails almost always try to create panic: "Your account will be closed!", "Unauthorised access detected!", "Act within 24 hours!". This urgency is designed to make you act before you think. Real companies give you reasonable timeframes and never threaten immediate account closure by email.'
    },
    {
      title: 'Generic Greetings Are a Red Flag',
      content: 'If a company you have an account with emails you as "Dear Customer" or "Dear User" instead of your actual name, that\'s a warning sign. Companies you do business with know your name and use it. Phishers send the same email to thousands of people, so they use generic greetings.'
    }
  ],

  credential_request: [
    {
      title: 'No Legitimate Company Asks for Passwords by Email',
      content: 'No bank, tech company, or service provider will ever ask you to send your password, PIN, or full card number via email. If an email asks for these, it is phishing — no exceptions. If you\'re worried about your account, go directly to the company\'s website by typing the address yourself.'
    }
  ]
};

/**
 * Get a random education tip for a given rule type
 */
function getEducationTip(ruleType) {
  const tips = EDUCATION_TIPS[ruleType];
  if (!tips || tips.length === 0) return null;
  
  // Pick a random tip from the available ones for this rule type
  const randomIndex = Math.floor(Math.random() * tips.length);
  return tips[randomIndex];
}

/**
 * Get the most relevant education tip based on indicators found
 */
function getRelevantTip(indicators) {
  // Find the highest severity indicator and return a tip for that type
  const severityOrder = { high: 3, medium: 2, low: 1, none: 0 };
  
  const sorted = [...indicators].sort((a, b) => {
    return (severityOrder[b.severity] || 0) - (severityOrder[a.severity] || 0);
  });
  
  if (sorted.length > 0) {
    return getEducationTip(sorted[0].type);
  }
  
  // Default tip if no indicators found
  return {
    title: 'Stay Vigilant',
    content: 'Even safe-looking emails deserve a quick check. Get in the habit of glancing at the sender address and hovering over links before clicking. These two simple habits will protect you from most phishing attempts.'
  };
}

module.exports = { getEducationTip, getRelevantTip, EDUCATION_TIPS };