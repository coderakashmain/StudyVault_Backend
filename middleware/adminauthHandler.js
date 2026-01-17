const jwt = require("jsonwebtoken");
const asyncHandler = require("./asyncHandler");
const { success, failure } = require("../utils/response");

const verifyAdminAuth = asyncHandler(async (req, res, next) => {
  let token = null;

  // 1️ Authorization header (Bearer token)
  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith("Bearer ")
  ) {
    token = req.headers.authorization.split(" ")[1];
  }

  // 2️ Cookie fallback (admin token)
  if (!token && req.cookies?.accestoken) {
    token = req.cookies.accestoken;
  }

  //  No token
  if (!token) {
    return failure(res, "Unauthorized: Admin token missing", 401);
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // Optional safety check
    if (!decoded.userId) {
      return failure(res, "Unauthorized: Invalid admin token", 401);
    }

    // Attach admin info
    req.admin = decoded;

    next();
  } catch (err) {
    return failure(res, "Unauthorized: Invalid or expired admin token", 401);
  }
});

const adminLoginCheck = asyncHandler(async (req, res) => {
  const token = req.cookies?.accestoken;

  if (!token) {
    return failure(res, "Admin not logged in", 401);
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    return success(res, "Admin is logged in", {
      adminId: decoded.userId,
     admintoken :   token,
    });
  } catch (err) {
    return failure(res, "Unauthorized: Invalid or expired admin token", 401);
  }
});

module.exports = {
  verifyAdminAuth,
  adminLoginCheck,
};
