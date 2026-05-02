const express = require('express');
const router = express.Router();

const {
  fetchComments,
  addComment,
  replyToComment
} = require('../controllers/comment.controller');

router.get('/fetch', fetchComments);
router.post('/', addComment);
router.post('/:id/replies', replyToComment);

module.exports = router;
