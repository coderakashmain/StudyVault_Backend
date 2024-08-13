const express = require('express');
const { signup, login, requestPasswordReset, resetPassword } = require('../controllers/authController');
const { otpVerification, otpConfirmation } = require('../controllers/otpController');


const router = express.Router();

// User Authentication
router.post('/Signup', signup);
router.post('/', login);

// OTP Verification
router.post('/Signup/otpVarify', otpVerification);
router.post('/Signup/otpVerify/confirm', otpConfirmation);

// Password Reset
router.post('/ForgatePw', requestPasswordReset);
router.post('/ForgatePw/ResetPassword', resetPassword);

module.exports = router;