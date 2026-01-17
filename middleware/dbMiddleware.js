const db = require('../config/db');

const dbMiddleware = (req, res, next) => {
  if (!db) {
    return res.status(500).json({
      status: false,
      message: "Database connection not available "
    });
  }
  req.db = db; 
  next();
};

module.exports = dbMiddleware;
