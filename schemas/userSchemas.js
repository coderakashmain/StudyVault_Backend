const Joi = require('joi');



const uploadSchemas = Joi.object({
  departmentName: Joi.string()
    .min(2)
    .max(100)
    .required(),

  educationLevel: Joi.string()
    .valid("ug", "pg")
    .required(),

  years: Joi.number()
    .integer()
    .min(2000)
    .max(new Date().getFullYear())
    .required(),

  departmentYear: Joi.string()
    .max(10)
    .optional()
    .allow(null, ""),

  sem: Joi.number()
    .integer()
    .valid(0, 1)
    .optional(),

  midSem: Joi.number()
    .integer()
    .valid(0, 1)
    .optional(),

  title: Joi.string()
    .min(2)
    .max(255)
    .required(),

  renamedFile: Joi.string()
    .max(255)
    .optional()
    .allow(null, ""),

  semester: Joi.string()
    .max(50)
    .optional()
    .allow(null, ""),
})
.required();


module.exports = {    uploadSchemas,
};
