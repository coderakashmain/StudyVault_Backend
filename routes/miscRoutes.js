const express = require('express');
const router = express.Router();

const { verifyAuth } = require('../middleware/authHandler');
const {
  verifyTurnstile,
  connectUsData,
  submitFeedback,
  shortenUrl,
  getAppVersion
} = require('../controllers/misc.controller');
const { downloadLatestApk } = require('../controllers/admin.controller');

router.post('/verify-turnstile', verifyTurnstile);
router.get('/connectusdata', connectUsData);
router.post('/feedback', verifyAuth, submitFeedback);
router.get('/shorten', shortenUrl);
router.get('/app-version', getAppVersion);
router.get('/download-apk', downloadLatestApk);

module.exports = router;
