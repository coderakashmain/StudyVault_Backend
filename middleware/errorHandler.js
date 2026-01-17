const errorHandler = (err, req, res, next) => {
  console.error(`[Error] ${err.message}`);

  res.status(err.statusCode || 500).json({
    status: false,
    message: err.message || "Internal Server Error ",
  });
};

module.exports = errorHandler;
