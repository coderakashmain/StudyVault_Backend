const crypto = require('crypto');
const { connectionUserdb } = require('../../db');

const generateOtp = () => {
  return crypto.randomInt(100000, 999999).toString();
};

const verifyOtp = (email, otp) => {
  return new Promise((resolve, reject) => {
    const query = 'SELECT * FROM useremailverification WHERE gmail = ? AND otp = ? AND expireotp > NOW()';
    connectionUserdb.query(query, [email, otp], (err, results) => {
      if (err) reject(err);
      resolve(results.length > 0);
    });
  });
};

module.exports = {
  generateOtp,
  verifyOtp,
};
