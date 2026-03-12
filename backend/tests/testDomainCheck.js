// Simple test script to see the domain check rule in action
const { checkDomain } = require('../src/rules/domainCheck');
const sampleEmails = require('./sampleEmails.json');

console.log('=== PhishSafe Domain Check Rule Test ===\n');

for (const email of sampleEmails) {
  console.log(`Test: ${email.description}`);
  console.log(`Sender: ${email.senderDisplayName} <${email.sender}>`);
  
  const indicators = checkDomain(email);
  
  if (indicators.length === 0) {
    console.log('Result: No indicators found');
  } else {
    for (const indicator of indicators) {
      console.log(`Result: [${indicator.severity.toUpperCase()}] ${indicator.label}`);
      console.log(`Education: ${indicator.explanation}`);
    }
  }
  
  console.log('---\n');
}