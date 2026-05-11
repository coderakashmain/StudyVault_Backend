const express = require("express");
const router = express.Router();
const {
  getColleges,
  createCollege,
  updateCollege,
  deleteCollege,
  setUserCollege,
} = require("../controllers/college.controller");
const { verifyAuth } = require("../middleware/authHandler");

// ─── Public ───────────────────────────────────────────────────────────────────
router.get("/", getColleges);

// ─── Authenticated user — set own college ────────────────────────────────────
router.put("/user/college", verifyAuth, setUserCollege);

// ─── Admin only ───────────────────────────────────────────────────────────────
router.post("/admin/colleges", createCollege);
router.put("/admin/colleges/:id", updateCollege);
router.delete("/admin/colleges/:id", deleteCollege);

module.exports = router;
