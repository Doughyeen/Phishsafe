// Load environment variables from .env file
const dotenv = require('dotenv');
dotenv.config();

// Import dependencies
const express = require('express');
const cors = require('cors');

// Import our analysis modules
const { runAllRules } = require('./rules/index');
const { calculateThreatScore } = require('./utils/scorer');
const { getRelevantTip } = require('./education/explanations');

// Create the Express application
const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// Set the port
const PORT = process.env.PORT || 3000;

// ============================================
// ROUTES
// ============================================

// Health check
app.get('/', (req, res) => {
  res.json({
    status: 'running',
    name: 'PhishSafe API',
    version: '1.0.0',
    rulesActive: 3,
  });
});

// Main analysis endpoint — NOW WITH REAL DETECTION
app.post('/api/analyse', (req, res) => {
  const { sender, senderDisplayName, subject, body, links } = req.body;

  // Check that we received some email data
  if (!sender && !subject && !body) {
    return res.status(400).json({
      error: 'No email data provided. Send sender, subject, body, and links.'
    });
  }

  // Package the email data
  const emailData = {
    sender: sender || '',
    senderDisplayName: senderDisplayName || sender || '',
    subject: subject || '',
    body: body || '',
    links: links || [],
  };

  // Run all rules
  const indicators = runAllRules(emailData);

  // Calculate the threat score
  const scoring = calculateThreatScore(indicators);

  // Get a relevant education tip
  const educationTip = getRelevantTip(indicators);

  // Send the response
  res.json({
    threatScore: scoring.threatLevel,
    confidence: scoring.confidence,
    summary: scoring.summary,
    score: scoring.score,
    indicators: indicators,
    educationTip: educationTip,
    metadata: {
      analysedAt: new Date().toISOString(),
      rulesChecked: 3,
      totalIndicators: scoring.totalIndicators,
      totalPassed: scoring.totalPassed,
      aiUsed: false,
    }
  });
});

// ============================================
// START THE SERVER
// ============================================
app.listen(PORT, () => {
  console.log(`PhishSafe API is running on http://localhost:${PORT}`);
  console.log('Rules active: Domain Check, Link Analysis, Language Analysis');
  console.log('Press Ctrl+C to stop the server');
});