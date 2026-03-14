// ============================================
// RULE ENGINE — Orchestrates All Rules
// ============================================
// This file imports all individual rules, runs them against
// an email, and returns the combined results.
// Think of it as the manager that coordinates the team.

const { checkDomain } = require('./domainCheck');
const { checkLinks } = require('./linkAnalysis');
const { checkLanguage } = require('./languageCheck');

/**
 * Run all rules against an email and return combined indicators
 */
function runAllRules(emailData) {
  const allIndicators = [];

  // Run each rule and collect indicators
  const domainResults = checkDomain(emailData);
  const linkResults = checkLinks(emailData);
  const languageResults = checkLanguage(emailData);

  allIndicators.push(...domainResults);
  allIndicators.push(...linkResults);
  allIndicators.push(...languageResults);

  return allIndicators;
}

module.exports = { runAllRules };