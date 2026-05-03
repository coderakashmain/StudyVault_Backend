const express = require('express');
const router = express.Router();
const { verifyAuth } = require('../middleware/authHandler');

const {
  filterPapers,
  getSyllabus,
  getNotes,
  getHomeData,
  noteClickCount,
  noteDownloadCount
} = require('../controllers/content.controller');

router.get('/Filter', filterPapers);
router.get('/syllabus', getSyllabus);
router.get('/notefetch', getNotes);
router.get('/home-data', getHomeData);
router.post('/noteClickCount', noteClickCount);
router.post('/notedonwloadcount', verifyAuth, noteDownloadCount);

module.exports = router;
