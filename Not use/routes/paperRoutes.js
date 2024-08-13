const express = require('express');
const { filterPapers, uploadPaper, getPapers } = require('../controllers/paperController');
const multer = require('multer');
const path = require('path');

const router = express.Router();

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = path.join(__dirname, '../uploads');
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    cb(null, `${Date.now()}-${file.originalname}`);
  },
});

const upload = multer({ storage });

router.get('/Filter', filterPapers);
router.post('/Upload', upload.single('file'), uploadPaper);
router.get('/', getPapers);

module.exports = router;