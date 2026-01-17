const router = require("express").Router();
const { adminLogin } = require("../controllers/adminauth.controller");
const validate = require("../middleware/validate");
const { adminLoginSchemas } = require("../schemas/AdminScemas");
const { adminLoginCheck ,verifyAdminAuth} = require("../middleware/adminauthHandler");
const {getPendingUploads,approvePaper,rejectPaper,updateRemark} = require("../controllers/paperSubmission.controller");

router.get("/pending-uploads", verifyAdminAuth, getPendingUploads);
router.post("/submissions/:id/approve", verifyAdminAuth, approvePaper);
router.post("/submissions/:id/reject", verifyAdminAuth, rejectPaper);
router.post("/submissions/:id/update-remark", verifyAdminAuth, updateRemark); 


router.post("/AdminLogIn", validate(adminLoginSchemas), adminLogin);
router.get("/admin-login-check", adminLoginCheck);

module.exports = router;