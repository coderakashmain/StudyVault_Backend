const express = require('express');
const router = express.Router();
const aiController = require('../controllers/aiController');
const { verifyAuth } = require('../middleware/authHandler');

// All AI routes require authentication
router.use(verifyAuth);

// Credits
router.get('/credits', aiController.getCredits);
router.post('/credits/use', aiController.useCredit);
router.post('/credits/topup', aiController.topupCredits);

// Chat History
router.get('/history', aiController.getChatHistory);
router.post('/history', aiController.saveChatSession);

module.exports = router;
