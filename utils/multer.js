const multer = require("multer");
const path = require("path");
const fs = require("fs");

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = path.join(__dirname, "uploads");
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir); // Create uploads directory if it doesn't exist
    }
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const {
      departmentName = "General",
      years = "unknown",
      semester = "unknown",
      title = "paper",
      sem,
      midSem,
      educationLevel = "ug",
      departmentYear = "na",
    } = req.body;

    const examType = sem === "1" ? "sem" : "midsem";

    const safeName =
      `${departmentName} ${departmentYear}_${semester}_${title}_${examType}_${educationLevel}_${years}`.replace(/[^a-zA-Z0-9-_. ]/g, "_");;
    cb(null, `${safeName}.pdf`);
  },
});

const upload = multer({ storage });

module.exports = upload;
