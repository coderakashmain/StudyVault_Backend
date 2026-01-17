const asyncHandler = require("../middleware/asyncHandler");
const connectionUserdb = require("../config/db");
const jwt = require("jsonwebtoken");
const { JWT_SECRET } = process.env;
const { comparePassword,hashPassword } = require("../utils/password");


exports.adminRegister = asyncHandler(async (req, res) => {
  const { userid, password } = req.body;


  if (!userid || !password) {
    return res.status(400).json({ error: "Userid and password required" });
  }

  // Check if user already exists
  const [existingUser] = await connectionUserdb.query(
    "SELECT id FROM admin_login WHERE userid = ?",
    [userid]
  );

  if (existingUser.length > 0) {
    return res.status(409).json({ error: "User already exists" });
  }

  // Hash password
  const hashedPassword = await hashPassword(password);

  // Insert user
  await connectionUserdb.query(
    "INSERT INTO admin_login (userid, password) VALUES (?, ?)",
    [userid, hashedPassword]
  );

  res.status(201).json({ message: "Admin registered successfully" });
});

exports.adminLogin = asyncHandler(async (req, res) => {
  const { userid, password } = req.body;

  if (!userid || !password) {
    return res.status(400).json({ error: "Userid and password required" });
  }

  const query = "SELECT * FROM admin_login WHERE userid = ?";

  const [results] = await connectionUserdb.query(query, [userid]);

  if (results.length === 0) {
    return res.status(400).json({ error: "Invalid Credentials" });
  }

  const admin = results[0];

  // Compare password
  const isMatch = await comparePassword(password, admin.password);

  if (!isMatch) {
    return res.status(400).json({ error: "Invalid Credentials" });
  }

  const accestoken = jwt.sign(
    {id : admin.id, userId: admin.userid },
    JWT_SECRET,
    { expiresIn: "7d" }
  );

  res.cookie("accestoken", accestoken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    maxAge: 1000 * 60 * 60 * 24 * 7, // 7 days
  });

  res.status(200).json({ admintoken : accestoken, message: "Successfully logged in" });
});
