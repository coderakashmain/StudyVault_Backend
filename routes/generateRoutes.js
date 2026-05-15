const express = require('express');
const router = express.Router();
const multer = require('multer');
const generateController = require('../controllers/generateController');
const { verifyAuth } = require('../middleware/authHandler');

// Use memory storage for multer so we can directly pass the buffer to Gemini
const storage = multer.memoryStorage();
const upload = multer({ 
  storage,
  limits: { fileSize: 10 * 1024 * 1024 } // 10MB limit
});

// All generate routes require authentication
router.use(verifyAuth);

router.post('/notes', upload.single('file'), generateController.generateNotes);
router.get('/history', generateController.getNotesHistory);

module.exports = router;
