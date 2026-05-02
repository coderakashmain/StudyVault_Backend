const express = require('express');
const router = express.Router();

const {
  verifyTurnstile,
  connectUsData,
  shortenUrl
} = require('../controllers/misc.controller');

router.post('/verify-turnstile', verifyTurnstile);
router.get('/connectusdata', connectUsData);
router.get('/shorten', shortenUrl);

module.exports = router;
