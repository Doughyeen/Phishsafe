const http = require('http');

function sendTest(description, emailData) {
  const data = JSON.stringify(emailData);

  const options = {
    hostname: 'localhost',
    port: 3000,
    path: '/api/analyse',
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(data),
    },
  };

  const req = http.request(options, (res) => {
    let body = '';
    res.on('data', (chunk) => body += chunk);
    res.on('end', () => {
      try {
        const result = JSON.parse(body);
        console.log('\n=== ' + description + ' ===');
        console.log('Threat Level: ' + result.threatScore.toUpperCase());
        console.log('Confidence: ' + result.confidence);
        console.log('Summary: ' + result.summary);
        for (const ind of result.indicators) {
          console.log('  [' + ind.severity.toUpperCase() + '] ' + ind.label);
        }
        if (result.educationTip) {
          console.log('Tip: ' + result.educationTip.title);
        }
        console.log('---');
      } catch (e) {
        console.log('Raw response: ' + body);
      }
    });
  });

  req.write(data);
  req.end();
}

console.log('=== PhishSafe Full API Test ===');

sendTest('PHISHING: PayPal Spoofed Email', {
  sender: 'security@paypa1-verify.com',
  senderDisplayName: 'PayPal Security',
  subject: 'Urgent: Your account has been suspended',
  body: 'Dear Customer, We detected unusual activity on your account. Your account has been suspended. To avoid permanent loss of access, verify your identity within 24 hours.',
  links: [{ text: 'Click here to verify at paypal.com', url: 'http://paypal-secure.evil-site.xyz/login/verify-account' }]
});

sendTest('SAFE: Amazon Shipping Email', {
  sender: 'shipping@amazon.co.uk',
  senderDisplayName: 'Amazon Shipping',
  subject: 'Your order has shipped',
  body: 'Hi Adedoyin, Great news! Your order 4821-9937 has shipped. Estimated delivery Friday 28 February.',
  links: ['https://amazon.co.uk/track/4821-9937']
});

sendTest('PHISHING: HMRC Tax Scam', {
  sender: 'refund@hmrc-tax-refund.xyz',
  senderDisplayName: 'HMRC Tax Refund',
  subject: 'You are eligible for a tax refund',
  body: 'Dear Taxpayer, Act immediately. Confirm your identity by providing your national insurance number and bank account details. Failure to respond within 48 hours will result in forfeiture.',
  links: ['http://hmrc-refund-claim.xyz/apply']
});