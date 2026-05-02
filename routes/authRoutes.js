const express = require('express');
const router = express.Router();
const { verifyAuth } = require('../middleware/authHandler');

const {
  otpVerify,
  otpVerifyConfirm,
  signup,
  login,
  logout,
  signupCheck,
  userCheck,
  loginCheckFilter,
  loginCheckContext,
  forgotPassword,
  verifyForgotOtp,
  resetPassword,
  googleAuth
} = require('../controllers/auth.controller');

router.post('/LogIn/Signup/otpVarify', otpVerify);
router.post('/LogIn/Signup/otpVarify/confirm', otpVerifyConfirm);
router.post('/LogIn/Signup', signup);
router.post('/LogIn', login);
router.post('/logOut', logout);
router.post('/LogIn/ForgatePw', forgotPassword);
router.post('/LogIn/verifyOtp', verifyForgotOtp);
router.post('/LogIn/ForgatePw/ResetPassword', resetPassword);
router.post('/auth/google', googleAuth);

// Authenticated routes
router.get('/signup-check', verifyAuth, signupCheck);
router.get('/usercheck', verifyAuth, userCheck);
router.get('/login-check-filter', verifyAuth, loginCheckFilter);
router.get('/login-check-context', verifyAuth, loginCheckContext);

module.exports = router;
