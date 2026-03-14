// ============================================
// SCORING SYSTEM
// ============================================
// Takes all indicators from every rule and calculates:
//   - An overall threat level (safe / suspicious / dangerous)
//   - A confidence percentage
//   - A numeric score for internal use
//
// Scoring logic:
//   Each indicator has a severity (high, medium, low, none)
//   We assign points based on severity and total them up.
//   The total determines the threat level.

const SEVERITY_POINTS = {
  high: 10,
  medium: 5,
  low: 2,
  none: 0,
};

// Thresholds for threat levels
const THRESHOLDS = {
  dangerous: 15,   // 15+ points = dangerous
  suspicious: 5,   // 5-14 points = suspicious
  safe: 0,         // 0-4 points = safe
};

/**
 * Calculate the threat score from a list of indicators
 */
function calculateThreatScore(indicators) {
  // Filter out "pass" results — those are positive signals, not threats
  const threatIndicators = indicators.filter(i => i.result !== 'pass');
  const passIndicators = indicators.filter(i => i.result === 'pass');

  // Calculate raw score
  let rawScore = 0;
  for (const indicator of threatIndicators) {
    rawScore += SEVERITY_POINTS[indicator.severity] || 0;
  }

  // Determine threat level
  let threatLevel;
  if (rawScore >= THRESHOLDS.dangerous) {
    threatLevel = 'dangerous';
  } else if (rawScore >= THRESHOLDS.suspicious) {
    threatLevel = 'suspicious';
  } else {
    threatLevel = 'safe';
  }

  // Calculate confidence — higher when we have more data points
  const totalChecks = indicators.length;
  let confidence;

  if (totalChecks === 0) {
    confidence = 0.3; // Low confidence if no rules matched at all
  } else if (threatLevel === 'dangerous' && threatIndicators.length >= 3) {
    confidence = 0.95; // Very confident when multiple high-severity indicators
  } else if (threatLevel === 'dangerous') {
    confidence = 0.85;
  } else if (threatLevel === 'suspicious') {
    confidence = 0.7;
  } else if (passIndicators.length >= 2) {
    confidence = 0.9; // Confident it's safe when multiple checks passed
  } else {
    confidence = 0.6;
  }

  // Build the summary — a one-line human-readable description
  const summary = buildSummary(threatLevel, threatIndicators, passIndicators);

  return {
    threatLevel,
    score: rawScore,
    confidence: Math.round(confidence * 100) / 100,
    summary,
    totalIndicators: threatIndicators.length,
    totalPassed: passIndicators.length,
  };
}

/**
 * Build a human-readable summary of the analysis
 */
function buildSummary(threatLevel, threatIndicators, passIndicators) {
  if (threatLevel === 'dangerous') {
    const count = threatIndicators.length;
    const highCount = threatIndicators.filter(i => i.severity === 'high').length;
    return `${count} phishing indicator${count > 1 ? 's' : ''} detected, including ${highCount} high-risk signal${highCount > 1 ? 's' : ''}. This email is very likely a phishing attempt.`;
  }

  if (threatLevel === 'suspicious') {
    const count = threatIndicators.length;
    return `${count} suspicious indicator${count > 1 ? 's' : ''} found. This email may not be dangerous, but proceed with caution.`;
  }

  if (passIndicators.length > 0) {
    return `No phishing indicators detected. ${passIndicators.length} security check${passIndicators.length > 1 ? 's' : ''} passed.`;
  }

  return 'No phishing indicators detected in this email.';
}

module.exports = { calculateThreatScore };