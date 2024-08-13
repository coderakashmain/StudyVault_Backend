const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

const sendOtpEmail = (email, otp) => {
  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: email,
    subject: 'Your OTP Code',
    text: `Your OTP code is ${otp}. It will expire in 10 minutes.`,
  };

  transporter.sendMail(mailOptions, (err, info) => {
    if (err) {
      console.error('Error sending OTP email:', err);
    } else {
      console.log('OTP email sent:', info.response);
    }
  });
};

const sendPasswordResetEmail = (email, resetToken) => {
  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: email,
    subject: 'Password Reset Request',
    text: `Please use the following link to reset your password: ${process.env.CLIENT_URL}/reset-password?token=${resetToken}`,
  };

  transporter.sendMail(mailOptions, (err, info) => {
    if (err) {
      console.error('Error sending password reset email:', err);
    } else {
      console.log('Password reset email sent:', info.response);
    }
  });
};

module.exports = {
  sendOtpEmail,
  sendPasswordResetEmail,
};
