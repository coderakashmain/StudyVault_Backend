const router = require("express").Router();
// const { getUserProfile, updateUserProfile } = require("../controllers/userController");
const {verifyAuth ,loginCheck} = require("../middleware/authHandler");
const {questionUpload,avatarUpdate,getTopContributors, getUserSubmissions, updateProfile, requestDeletion} = require("../controllers/userController")
const validate = require("../middleware/validate");
const { uploadSchemas } = require("../schemas/userSchemas");
const upload = require("../utils/multer");

router.get("/login-check-context", loginCheck);
router.post('/avatar',verifyAuth,avatarUpdate)
router.get('/contributer-list',getTopContributors)
router.post("/upload",verifyAuth, upload.single("pdf"),validate(uploadSchemas), questionUpload);
router.get("/submissions", verifyAuth, getUserSubmissions);
router.put("/update-profile", verifyAuth, updateProfile);
router.post("/request-deletion", verifyAuth, requestDeletion);


module.exports = router;