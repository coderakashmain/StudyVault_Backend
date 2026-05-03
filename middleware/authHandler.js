const jwt = require("jsonwebtoken");
const asyncHandler = require("./asyncHandler");
const { success, failure } = require("../utils/response"); 
const connectionUserdb = require("../config/db");

const verifyAuth = asyncHandler(async (req, res, next) => {
  let token = null;

  // 1️ Authorization header (Bearer token)
  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith("Bearer ")
  ) {
    token = req.headers.authorization.split(" ")[1];
  }

  // 2 Cookie fallback
  if (!token && req.cookies?.token) {
    token = req.cookies.token;
  }

  //  No token
  if (!token) {
    return failure(res, "Unauthorized: Token missing", 401);
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // Attach decoded payload to request
    req.user = decoded;

    next();
  } catch (err) {
    return failure(res, "Unauthorized: Invalid or expired token", 401);
  }
});

const loginCheck = asyncHandler(async (req, res, next) => {
  let token = null;

  // Check Authorization header first (mobile apps send Bearer token)
  if (req.headers.authorization && req.headers.authorization.startsWith("Bearer ")) {
    token = req.headers.authorization.split(" ")[1];
  }

  // Fallback to cookie (web browsers)
  if (!token) {
    token = req.cookies?.token;
  }

  if (!token) {
    return failure(res, "Unauthorized: Token missing", 401);
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const query = "SELECT id, firstname, lastname, gmail, rollno, avatar_url FROM users WHERE id = $1";
    const [user] = await connectionUserdb.query(query, [decoded.id]);
    const userData = user[0];
    if (!userData) return failure(res, "Unauthorized: User not found", 401);

    return success(res, "User is logged in", {
      token,
      id: decoded.id,
      avatar_url: userData.avatar_url,
      firstname: userData.firstname,
      lastname: userData.lastname,
      gmail: userData.gmail,
      rollno: userData.rollno,
    });
  } catch (err) {
    return failure(res, `Unauthorized: ${err.message}`, 401);
  }
});

module.exports = {  verifyAuth, loginCheck };
