const express = require('express');
const router = express.Router();
const { verifyAuth } = require('../middleware/authHandler');

const {
  filterPapers,
  getSyllabus,
  getNotes,
  noteClickCount,
  noteDownloadCount
} = require('../controllers/content.controller');

router.get('/Filter', filterPapers);
router.get('/syllabus', getSyllabus);
router.get('/notefetch', getNotes);
router.post('/noteClickCount', noteClickCount);
router.post('/notedonwloadcount', verifyAuth, noteDownloadCount);

module.exports = router;
