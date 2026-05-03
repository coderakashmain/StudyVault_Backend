const express = require('express');
const router = express.Router();

const { verifyAuth } = require('../middleware/authHandler');
const {
  verifyTurnstile,
  connectUsData,
  submitFeedback,
  shortenUrl
} = require('../controllers/misc.controller');

router.post('/verify-turnstile', verifyTurnstile);
router.get('/connectusdata', connectUsData);
router.post('/feedback', verifyAuth, submitFeedback);
router.get('/shorten', shortenUrl);

module.exports = router;
