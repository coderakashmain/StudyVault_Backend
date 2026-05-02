const express = require('express');
const router = express.Router();
const { verifyAuth } = require('../middleware/authHandler');
const upload = require('../utils/multer');

const {
  uploadProfileFile,
  uploadNonUser,
  fetchPdf,
  getProfile,
  feedbackCheck,
  feedbackSubmission
} = require('../controllers/profile.controller');

// Profile logic
router.get('/Profile', verifyAuth, getProfile);
router.post('/Profile/upload', upload.single("file"), uploadProfileFile);
router.post('/Profile/upload/non-user', upload.array("files", 10), uploadNonUser);
router.get('/Profile/fetchpdf', fetchPdf);

// Feedback logic
router.get('/feedback-check', verifyAuth, feedbackCheck);
router.post('/feedback-submission', feedbackSubmission);

module.exports = router;
