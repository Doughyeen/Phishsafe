// Test script for the language analysis rule
const { checkLanguage } = require('../src/rules/languageCheck');

console.log('=== PhishSafe Language Analysis Rule Test ===\n');

const testCases = [
  {
    description: 'Classic phishing — urgency + threats + credential request + generic greeting',
    subject: 'Urgent: Your account has been suspended',
    body: 'Dear Customer, We detected unusual activity on your account. Your account has been suspended. To avoid permanent loss of access, confirm your password and enter your card number within 24 hours. Failure to respond will result in your account being permanently closed.'
  },
  {
    description: 'Legitimate email — no manipulation tactics',
    subject: 'Your order has shipped',
    body: 'Hi Adedoyin, Great news! Your order #4821-9937 has shipped and is on its way. Estimated delivery is Friday 28 February. Track your package using the link below.'
  },
  {
    description: 'Prize scam — too good to be true',
    subject: 'Congratulations! You have won',
    body: 'Dear Winner, You have been selected as the winner of our annual lottery. You have won a prize of one million pounds. To claim your reward, please provide your bank account number and sort code. This is a limited time offer.'
  },
  {
    description: 'Subtle phishing — mild urgency only',
    subject: 'Action required on your account',
    body: 'Hello, We need you to update your payment method as soon as possible to continue using our services. Please log in to your account to make the necessary changes.'
  },
  {
    description: 'Government impersonation — HMRC scam',
    subject: 'Tax Refund Notification',
    body: 'Dear Taxpayer, You are eligible for a tax refund of 438.20 GBP. To claim your refund, you must act immediately. Please confirm your identity by providing your national insurance number and bank account details. Failure to respond within 48 hours will result in forfeiture of your refund.'
  },
  {
    description: 'Corporate email — normal business urgency',
    subject: 'Q4 Report Due Friday',
    body: 'Hi team, Just a reminder that the Q4 financial report is due by end of day Friday. Please submit your sections to the shared drive. Let me know if you need any extensions. Thanks, Sarah.'
  }
];

for (const test of testCases) {
  console.log(`Test: ${test.description}`);
  console.log(`Subject: ${test.subject}`);
  
  const indicators = checkLanguage(test);
  
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