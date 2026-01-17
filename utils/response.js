const success = (res, message, data = {},extra = {}) => {
  return res.json({
    status: true,
    message,
    data,
    ...extra
  });
};

const failure = (res, message, statusCode = 400) => {
  return res.status(statusCode).json({
    status: false,
    message,
  });
};

module.exports = { success, failure };
