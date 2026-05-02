const express = require('express');
const router = express.Router();
const upload = require("../utils/multer");

const {
  uploadPaper, uploadSyllabus, uploadNote, fetchData, deletePdf,
  requestDelete, verifyDeleteOtp, adminPage, adminLogout
} = require("../controllers/adminData.controller");

router.post("/Admin/upload", upload.single("file"), uploadPaper);
router.post("/Admin/syllabusUpload", upload.single("file"), uploadSyllabus);
router.post("/Admin/noteUpload", upload.single("file"), uploadNote);
router.get("/admin/fetchData", fetchData);
router.post("/admin/deletepdf", deletePdf);
router.post("/admin/request-delete", requestDelete);
router.post("/admin/delete/verify-otp", verifyDeleteOtp);
router.get("/adminPage", adminPage);
router.post("/Admin/logout", adminLogout);

module.exports = router;
