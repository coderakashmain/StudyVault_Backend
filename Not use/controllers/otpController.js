const { connectionUserdb } = require('../../db');
const { generateOtp, verifyOtp } = require('../../services/otpService');
const { sendOtpEmail } = require('../../services/emailService');

const otpVerification = async (req, res) => {
  try {
    const { email } = req.body;
    const otp = generateOtp();
    const otpExpires = new Date(Date.now() + 10 * 60000);

    const query = 'UPDATE useremailverification SET otp = ?, expireotp = ? WHERE gmail = ?';
    connectionUserdb.query(query, [otp, otpExpires, email], (err, results) => {
      if (err) {
        console.error('Error updating database', err);
        return res.status(500).json({ error: 'Database error' });
      }
      sendOtpEmail(email, otp);
      res.status(200).json({ message: 'OTP sent' });
    });
  } catch (error) {
    console.error('Error in OTP verification:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
};

const otpConfirmation = async (req, res) => {
  try {
    const { email, otp } = req.body;
    const isValidOtp = await verifyOtp(email, otp);
    
    if (!isValidOtp) {
      return res.status(400).json({ error: 'Invalid or expired OTP' });
    }
    
    const query = 'UPDATE useremailverification SET otp = NULL, expireotp = NULL WHERE gmail = ?';
    connectionUserdb.query(query, [email], (err, results) => {
      if (err) {
        console.error('Error updating database', err);
        return res.status(500).json({ error: 'Database error' });
      }
      res.status(200).json({ message: 'OTP verified successfully' });
    });
  } catch (error) {
    console.error('Error in OTP confirmation:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
};
    module.exports = {
        otpVerification,
        otpConfirmation,
      }