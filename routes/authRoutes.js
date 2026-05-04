const express = require('express');
const router = express.Router();
const { verifyAuth } = require('../middleware/authHandler');

const {
  otpVerify,
  otpVerifyConfirm,
  signup,
  login,
  logout,
  forgotPassword,
  verifyForgotOtp,
  resetPassword,
  googleAuth
} = require('../controllers/auth.controller');

router.post('/login/signup/otp-verify', otpVerify);
router.post('/login/signup/otp-verify/confirm', otpVerifyConfirm);
router.post('/login/signup', signup);
router.post('/login', login);
router.post('/logout', logout);
router.post('/login/forgot-password', forgotPassword);
router.post('/login/verify-otp', verifyForgotOtp);
router.post('/login/reset-password', resetPassword);
router.post('/auth/google', googleAuth);

// Authenticated routes removed as they were redundant

module.exports = router;
