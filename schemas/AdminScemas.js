const Joi = require('joi');
const adminLoginSchemas = Joi.object({
  userid: Joi.string()
    .min(2)
    .max(100)
    .required(),
    password: Joi.string()
    .min(5)
    .max(100)
    .required(),
});

exports = module.exports = {
    adminLoginSchemas,
};