// Load environment variables from .env file
const dotenv = require('dotenv');
dotenv.config();

// Import dependencies
const express = require('express');
const cors = require('cors');

// Create the Express application
const app = express();

// Middleware
// cors() allows the Chrome extension to communicate with this server
app.use(cors());
// express.json() tells Express to understand JSON data sent in requests
app.use(express.json());

// Set the port — use the one from .env, or default to 3000
const PORT = process.env.PORT || 3000;

// ============================================
// ROUTES
// ============================================

// Health check — a simple endpoint to verify the server is running
// When you visit http://localhost:3000/ in your browser, you'll see this response
app.get('/', (req, res) => {
  res.json({
    status: 'running',
    name: 'PhishSafe API',
    version: '1.0.0'
  });
});

// The main analysis endpoint — this is where the Chrome extension will send emails
// For now it's a skeleton that returns a dummy response
// We'll build the real analysis logic on Days 4-7
app.post('/api/analyse', (req, res) => {
  // req.body contains the email data sent by the extension
  const { sender, subject, body, links } = req.body;

  // Check that we actually received email data
  if (!sender && !subject && !body) {
    return res.status(400).json({
      error: 'No email data provided. Send sender, subject, body, and links.'
    });
  }

  // Dummy response for now — this is the structure the extension will expect
  res.json({
    threatScore: 'safe',
    confidence: 0.95,
    indicators: [
      {
        type: 'domain_check',
        result: 'pass',
        label: 'Verified Sender Domain',
        explanation: 'The sender domain matches the expected domain for this organisation.'
      }
    ],
    educationTip: {
      title: 'Did you know?',
      content: 'Legitimate companies almost always email you from their official domain (e.g. @amazon.co.uk, @paypal.com). Check the sender address carefully.'
    },
    metadata: {
      analysedAt: new Date().toISOString(),
      rulesChecked: 0,
      aiUsed: false
    }
  });
});

// ============================================
// START THE SERVER
// ============================================
app.listen(PORT, () => {
  console.log(`PhishSafe API is running on http://localhost:${PORT}`);
  console.log('Press Ctrl+C to stop the server');
});