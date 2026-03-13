// ============================================
// RULE: Language & Pattern Analysis
// ============================================
// This rule detects social engineering tactics in the email body:
//   - Urgency and pressure language ("act now!", "within 24 hours")
//   - Threat language ("suspended", "closed", "terminated")
//   - Generic greetings ("Dear Customer" instead of your name)
//   - Credential/sensitive info requests ("enter your password")
//   - Too-good-to-be-true offers ("you've won!", "free gift")
//
// Social engineering works by manipulating emotions — fear, urgency,
// greed, curiosity — to make people act before they think.
// This rule catches those manipulation patterns.

// Urgency phrases — designed to make you panic and act fast
const URGENCY_PHRASES = [
  'act now', 'act immediately', 'immediate action',
  'within 24 hours', 'within 48 hours', 'within 12 hours',
  'expires today', 'expires soon', 'expiring',
  'urgent', 'urgently', 'time sensitive', 'time-sensitive',
  'as soon as possible', 'right away', 'without delay',
  'don\'t delay', 'do not delay', 'limited time',
  'last chance', 'final warning', 'final notice',
  'respond immediately', 'action required', 'immediate response',
  'must be completed', 'failure to respond',
];

// Threat phrases — designed to scare you into complying
const THREAT_PHRASES = [
  'account will be suspended', 'account will be closed',
  'account will be terminated', 'account will be locked',
  'account has been suspended', 'account has been compromised',
  'account has been locked', 'account has been limited',
  'permanently closed', 'permanently deleted',
  'permanently suspended', 'permanently locked',
  'loss of access', 'lose access', 'lose your account',
  'unauthorised access', 'unauthorized access',
  'unusual activity', 'suspicious activity',
  'security breach', 'security alert', 'security warning',
  'will be forfeited', 'legal action', 'law enforcement',
];

// Credential request phrases — no legitimate company asks for these by email
const CREDENTIAL_PHRASES = [
  'enter your password', 'confirm your password',
  'verify your password', 'update your password',
  'enter your pin', 'confirm your pin',
  'provide your card number', 'enter your card number',
  'credit card details', 'debit card details',
  'bank account number', 'sort code',
  'social security', 'national insurance number',
  'date of birth', 'mother\'s maiden name',
  'security question', 'security answer',
  'login credentials', 'sign-in details',
  'confirm your identity by providing',
  'verify your identity by entering',
];

// Generic greetings — companies you have accounts with know your name
const GENERIC_GREETINGS = [
  'dear customer', 'dear user', 'dear valued customer',
  'dear valued member', 'dear account holder',
  'dear sir', 'dear madam', 'dear sir/madam',
  'dear sir or madam', 'dear member',
  'dear client', 'dear subscriber',
  'dear email user', 'dear valued user',
  'dear beneficiary', 'dear winner',
  'dear taxpayer', 'dear cardholder',
];

// Too-good-to-be-true phrases — bait to get you to click
const BAIT_PHRASES = [
  'you have won', 'you\'ve won', 'you are a winner',
  'congratulations!', 'you have been selected',
  'you\'ve been selected', 'exclusively selected',
  'claim your prize', 'claim your reward',
  'free gift', 'free money', 'free iphone',
  'lottery winner', 'inheritance fund',
  'million pounds', 'million dollars',
  'risk free', 'risk-free', 'no cost',
  'double your money', 'guaranteed income',
  'work from home', 'make money fast',
];

/**
 * Count how many phrases from a list appear in the text
 * Returns the matched phrases for educational feedback
 */
function findMatchingPhrases(text, phraseList) {
  const lowerText = text.toLowerCase();
  const matches = [];
  
  for (const phrase of phraseList) {
    if (lowerText.includes(phrase.toLowerCase())) {
      matches.push(phrase);
    }
  }
  
  return matches;
}

/**
 * Check if the email uses a generic greeting
 */
function checkGreeting(body, subject) {
  const fullText = ((subject || '') + ' ' + (body || '')).toLowerCase();
  
  for (const greeting of GENERIC_GREETINGS) {
    if (fullText.includes(greeting)) {
      return greeting;
    }
  }
  
  return null;
}

/**
 * Analyse the overall emotional manipulation score
 * Phishing emails typically combine multiple tactics
 */
function calculateManipulationScore(urgencyCount, threatCount, credentialCount, baitCount, hasGenericGreeting) {
  let score = 0;
  
  score += Math.min(urgencyCount * 2, 6);    // Max 6 points from urgency
  score += Math.min(threatCount * 3, 9);      // Max 9 points from threats (weighted higher)
  score += Math.min(credentialCount * 4, 8);  // Max 8 points from credential requests
  score += Math.min(baitCount * 2, 6);        // Max 6 points from bait
  score += hasGenericGreeting ? 2 : 0;        // 2 points for generic greeting
  
  return score;
}

/**
 * Main rule function — analyses email language patterns
 * Returns an array of indicators found
 */
function checkLanguage(emailData) {
  const indicators = [];
  const { subject, body } = emailData;
  
  if (!body && !subject) return indicators;
  
  // Combine subject and body for analysis
  const fullText = ((subject || '') + ' ' + (body || ''));
  
  // CHECK 1: Urgency language
  const urgencyMatches = findMatchingPhrases(fullText, URGENCY_PHRASES);
  
  if (urgencyMatches.length >= 2) {
    indicators.push({
      type: 'language_check',
      severity: 'high',
      result: 'fail',
      label: 'Urgency & Pressure Language',
      explanation: `This email uses ${urgencyMatches.length} urgency phrases including "${urgencyMatches.slice(0, 3).join('", "')}". Phishing emails create a false sense of urgency to pressure you into acting before you think. Legitimate companies give you reasonable timeframes and don't threaten immediate consequences by email.`
    });
  } else if (urgencyMatches.length === 1) {
    indicators.push({
      type: 'language_check',
      severity: 'low',
      result: 'info',
      label: 'Urgency Language Noted',
      explanation: `This email contains the phrase "${urgencyMatches[0]}". A single urgency phrase isn't necessarily a red flag on its own — many legitimate emails mention deadlines. But combined with other suspicious elements, it could indicate phishing.`
    });
  }
  
  // CHECK 2: Threat language
  const threatMatches = findMatchingPhrases(fullText, THREAT_PHRASES);
  
  if (threatMatches.length >= 1) {
    const severity = threatMatches.length >= 2 ? 'high' : 'medium';
    indicators.push({
      type: 'language_check',
      severity: severity,
      result: threatMatches.length >= 2 ? 'fail' : 'warning',
      label: 'Threat Language Detected',
      explanation: `This email contains threatening language: "${threatMatches.slice(0, 3).join('", "')}". Phishing emails often threaten account suspension, closure, or legal action to create fear. If you're genuinely concerned about your account, go directly to the company's website by typing the address yourself — never through a link in the email.`
    });
  }
  
  // CHECK 3: Credential requests
  const credentialMatches = findMatchingPhrases(fullText, CREDENTIAL_PHRASES);
  
  if (credentialMatches.length >= 1) {
    indicators.push({
      type: 'credential_request',
      severity: 'high',
      result: 'fail',
      label: 'Sensitive Information Request',
      explanation: `This email asks you to provide sensitive information: "${credentialMatches.slice(0, 2).join('", "')}". No legitimate company will ever ask for your password, PIN, or full card details by email. This is one of the strongest indicators of a phishing attempt. If any email asks for this information, do not respond — contact the company directly through their official website or phone number.`
    });
  }
  
  // CHECK 4: Generic greeting
  const genericGreeting = checkGreeting(body, subject);
  
  if (genericGreeting) {
    indicators.push({
      type: 'language_check',
      severity: 'medium',
      result: 'warning',
      label: 'Generic Greeting',
      explanation: `This email uses "${genericGreeting}" instead of your actual name. Companies you have accounts with typically address you by name because they have your details on file. Phishers send the same email to thousands of people, so they use generic greetings. While some legitimate marketing emails do use generic greetings, it's worth noting when combined with other suspicious signs.`
    });
  }
  
  // CHECK 5: Too-good-to-be-true bait
  const baitMatches = findMatchingPhrases(fullText, BAIT_PHRASES);
  
  if (baitMatches.length >= 1) {
    const severity = baitMatches.length >= 2 ? 'high' : 'medium';
    indicators.push({
      type: 'language_check',
      severity: severity,
      result: baitMatches.length >= 2 ? 'fail' : 'warning',
      label: 'Too Good to Be True',
      explanation: `This email contains phrases like "${baitMatches.slice(0, 2).join('", "')}". If something sounds too good to be true, it almost certainly is. Legitimate prizes, inheritances, and rewards don't arrive via unsolicited email. These phrases are designed to trigger excitement that overrides your caution.`
    });
  }
  
  // CHECK 6: Overall manipulation assessment
  const manipulationScore = calculateManipulationScore(
    urgencyMatches.length,
    threatMatches.length,
    credentialMatches.length,
    baitMatches.length,
    !!genericGreeting
  );
  
  // If high manipulation score but we haven't flagged as high severity yet
  if (manipulationScore >= 10) {
    const hasHighSeverity = indicators.some(i => i.severity === 'high');
    if (!hasHighSeverity) {
      indicators.push({
        type: 'language_check',
        severity: 'high',
        result: 'fail',
        label: 'Multiple Manipulation Tactics',
        explanation: `This email combines several social engineering tactics — a mix of urgency, threats, and suspicious requests. While each element alone might be innocent, the combination is a classic phishing pattern. Legitimate communications don't need to pressure, scare, and entice you all at once.`
      });
    }
  }
  
  return indicators;
}

module.exports = { checkLanguage };