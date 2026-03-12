// Test script for the link analysis rule
const { checkLinks } = require('../src/rules/linkAnalysis');

console.log('=== PhishSafe Link Analysis Rule Test ===\n');

const testCases = [
  {
    description: 'Mismatched link — display says PayPal, URL goes elsewhere',
    links: [
      { text: 'Click here to verify at paypal.com', url: 'http://paypal-secure.evil-site.xyz/login' }
    ]
  },
  {
    description: 'IP address link — no legitimate company does this',
    links: ['http://192.168.45.12/account/verify']
  },
  {
    description: 'URL shortener hiding the destination',
    links: ['https://bit.ly/3xK9mN2']
  },
  {
    description: 'Excessive subdomains — hiding the real domain',
    links: ['https://secure.login.account.verify.paypal.evil-site.com/auth']
  },
  {
    description: 'Suspicious keywords stacked in URL',
    links: ['https://some-random-site.com/secure/login/verify-account/password-reset']
  },
  {
    description: 'Legitimate Amazon link — should pass',
    links: ['https://www.amazon.co.uk/gp/your-account/order-history']
  },
  {
    description: 'Mix of safe and suspicious links',
    links: [
      'https://google.com/search',
      'http://free-prize-winner.xyz/claim-now',
      { text: 'Visit google.com', url: 'http://not-google.xyz/phish' }
    ]
  }
];

for (const test of testCases) {
  console.log(`Test: ${test.description}`);
  
  const indicators = checkLinks({ links: test.links });
  
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