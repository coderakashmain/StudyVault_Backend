const jwt = require("jsonwebtoken");
const asyncHandler = require("./asyncHandler");
const { success, failure } = require("../utils/response"); 

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
  token = req.cookies?.token;
  if(!token){
    return failure(res, "Unauthorized: Token missing", 401);
  }
  try{
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
 
    return success(res, "User is logged in",{token,avatar_url : decoded.avatar_url,id:decoded.id});
  }catch(err){
    return failure(res, "Unauthorized: Invalid or expired token", 401);
  }
});

module.exports = {  verifyAuth, loginCheck };
