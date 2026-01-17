const express = require("express");
const router = express.Router();

const upload = require("../utils/multer");
const verifyAuth = require("../middleware/verifyAuth");
const verifyAdmin = require("../middleware/verifyAdmin");

const {
  getPendingUploads,
  approvePaper,
  rejectPaper,
  updateRemark,
} = require("../controllers/paperSubmission.controller");

//  student


//  admin
router.get("/admin/pending", verifyAuth, verifyAdmin, getPendingUploads);
router.post("/admin/approve/:submissionId", verifyAuth, verifyAdmin, approvePaper);
router.post("/admin/reject/:submissionId", verifyAuth, verifyAdmin, rejectPaper);
router.put("/admin/remark/:submissionId", verifyAuth, verifyAdmin, updateRemark);

module.exports = router;
