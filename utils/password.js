const bcrypt = require("bcrypt");

const SALT_ROUNDS = 10;

// Hash password
exports.hashPassword = async (password) => {
  return await bcrypt.hash(password, SALT_ROUNDS);
};

// Compare password
exports.comparePassword = async (password, hashedPassword) => {
  return await bcrypt.compare(password, hashedPassword);
};
