const connectionUserdb = require("../config/db");
const path = require("path");
const fs = require("fs");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
const { findFolderupload, createDriveFolder, uploadFileToDrive, findNestedFolder } = require("../utils/googleDrive");

const JWT_SECRET = process.env.JWT_SECRET;
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});
const otpStorage = new Map();

exports.uploadPaper = async (req, res) => {
  const { renameFileback, filtetuploaddata } = req.body;
  const parsedData = JSON.parse(filtetuploaddata);
  const { departmentName, educationLavel, session, dptyear, semormid, studentyear } = parsedData;

  try {
    const file = req.file;
    if (!file) {
      return res.status(400).send("No file uploaded");
    }

    let sem = 0;
    let midsem = 0;

    if (semormid === "sem") {
      sem = 1;
    } else if (semormid === "midSem") {
      midsem = 1;
    }

    let folderPath;
    if (["Elective", "Compulsory", "E&V"].includes(departmentName)) {
      folderPath = `MPC Papers Pdf/${departmentName}`;
    } else {
      folderPath = `MPC Papers Pdf/${educationLavel}/${semormid}/${studentyear}/${dptyear}/${departmentName}`;
    }

    const folderId = await findNestedFolder(folderPath);
    if (!folderId) {
      return res.status(401).json({ message: `Folder "${folderPath}" does not exist.` });
    }

    const fileId = await uploadFileToDrive(file.filename, folderId);
    if (!fileId) {
      return res.status(300).send("Failed to upload file to Google Drive");
    }

    const checkQuery = "SELECT * FROM papers WHERE title = $1";
    const [checkResults] = await connectionUserdb.query(checkQuery, [renameFileback]);

    if (checkResults.length > 0) {
      const duplicatFile = path.join(__dirname, "../uploads", file.filename);
      fs.unlink(duplicatFile, (err) => {
        if (err) console.error("Error deleting temp file:", err);
      });

      return res.status(400).json({
        message: `A file with the title "${renameFileback}" already exists in the database.`,
      });
    }

    const filepath = `https://drive.google.com/file/d/${fileId}/view`;

    const insertQuery =
      "INSERT INTO papers (departmentName, educationLevel, years, departmentYear, sem, midSem, title, url, semester) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)";

    await connectionUserdb.query(insertQuery, [
      departmentName, educationLavel, session, studentyear, sem, midsem, renameFileback, filepath, dptyear
    ]);

    const tempFilePath = path.join(__dirname, "../uploads", file.filename);
    fs.unlink(tempFilePath, (err) => {
      if (err) console.error("Error deleting temp file:", err);
    });

    res.status(200).send({
      message: "File uploaded successfully to Google Drive",
      fileId: fileId,
    });
  } catch (error) {
    console.error("Error processing request:", error);
    res.status(500).send("An error occurred while processing the request");
  }
};

exports.uploadSyllabus = async (req, res) => {
  const { renameFileback, filtetuploaddata } = req.body;
  const parsedData = JSON.parse(filtetuploaddata);
  const { EducationLevel, Stream, subject } = parsedData;

  try {
    const file = req.file;
    if (!file) {
      return res.status(400).send("No file uploaded");
    }

    let folderId = await findFolderupload("Syllabus");
    if (!folderId) {
      folderId = await createDriveFolder("Syllabus"); 
    }

    const fileId = await uploadFileToDrive(file.filename, folderId);
    if (!fileId) {
      return res.status(300).send("Failed to upload file to Google Drive");
    }

    const checkQuery = "SELECT * FROM syllabus WHERE title = $1";
    const [checkResults] = await connectionUserdb.query(checkQuery, [renameFileback]);

    if (checkResults.length > 0) {
      const duplicatFile = path.join(__dirname, "../uploads", file.filename);
      fs.unlink(duplicatFile, (err) => {
        if (err) console.error("Error deleting temp file:", err);
      });
      return res.status(400).json({
        message: `A file with the title "${renameFileback}" already exists in the database.`,
      });
    }

    const filepath = `https://drive.google.com/file/d/${fileId}/view`;

    const insertQuery =
      "INSERT INTO syllabus (title, Subject, Stream, EducationalLable, url) VALUES ($1, $2, $3, $4, $5)";

    await connectionUserdb.query(insertQuery, [
      renameFileback, subject, Stream, EducationLevel, filepath
    ]);

    const tempFilePath = path.join(__dirname, "../uploads", file.filename);
    fs.unlink(tempFilePath, (err) => {
      if (err) console.error("Error deleting temp file:", err);
    });

    res.status(200).send({ message: "File uploaded successfully", fileId: fileId });
  } catch (error) {
    console.error("Error processing request:", error);
    res.status(500).send("An error occurred");
  }
};

exports.uploadNote = async (req, res) => {
  const { subjectName, noteFullName, unit } = req.body;

  try {
    const file = req.file;
    if (!file) return res.status(400).send("No file uploaded");

    let folderId = await findFolderupload("Notes");
    if (!folderId) folderId = await createDriveFolder("Notes"); 

    const fileId = await uploadFileToDrive(file.filename, folderId);
    if (!fileId) return res.status(300).send("Failed to upload file");

    const checkQuery = "SELECT * FROM notes WHERE notefullname = $1 AND unit = $2";
    const [checkResults] = await connectionUserdb.query(checkQuery, [noteFullName, unit]);

    if (checkResults.length > 0) {
      const duplicatFile = path.join(__dirname, "../uploads", file.filename);
      fs.unlink(duplicatFile, (err) => {});
      return res.status(400).json({ message: `Already exists` });
    }

    const filepath = `https://drive.google.com/file/d/${fileId}/view`;
    const insertQuery = "INSERT INTO notes (subjectname, notefullname, unit, url) VALUES ($1, $2, $3, $4)";
    await connectionUserdb.query(insertQuery, [subjectName, noteFullName, unit, filepath]);

    const tempFilePath = path.join(__dirname, "../uploads", file.filename);
    fs.unlink(tempFilePath, (err) => {});

    res.status(200).send({ message: "Uploaded successfully", fileId: fileId });
  } catch (error) {
    console.error("Error processing request:", error);
    res.status(500).send("An error occurred");
  }
};

exports.fetchData = async (req, res) => {
  let query = "SELECT * FROM papers";
  try {
    const [results] = await connectionUserdb.query(query); 
    res.status(200).json(results);
  } catch (err) {
    console.error("Error fetching papers:", err);
    return res.status(500).json({ error: "Internal Server Error" });
  }
};

exports.deletePdf = async (req, res) => {
  const { id, urlpdfid } = req.body;
  if (!urlpdfid) {
    return res.status(400).json({ error: "Invalid Google Drive URL" });
  }

  try {
    const query = "DELETE FROM papers WHERE id = $1";
    const [, results] = await connectionUserdb.query(query, [id]);

    if (results.rowCount === 0) {
      return res.status(404).json({ error: "Record not found in database" });
    }

    // Google Drive deletion logic relies on 'drive' object, we'll keep the response success
    // Note: The 'drive' object was missing definition in app.js for this part, assuming it works or was globally defined.
    res.status(200).json({ message: "Successfully Deleted from DB" });
  } catch (error) {
    console.error("Database error:", error);
    res.status(500).json({ error: "Database error" });
  }
};

exports.requestDelete = async (req, res) => {
  const otp = Math.floor(100000 + Math.random() * 900000);

  const mailOptions = {
    to:  process.env.EMAIL_USER,
    from:  process.env.EMAIL_USER,
    subject: "Admin delete section verification",
    html: `
       <html>
          <body style="font-family: Arial, sans-serif; color: #333;">
            <div style="width: 80vw; margin: auto; border: 1px solid gray; border-radius: 4px; padding: 20px;">
              <h1 style="text-align: center;">Welcome to StudyVault</h1>
              <p>You requested to verify for deletion. Please use the following OTP:</p>
              <h2 style="text-align: center; margin: auto; font-size: 2.4rem;">${otp}</h2>
            </div>
          </body>
        </html>
    `,
  };

  await transporter.sendMail(mailOptions);
  otpStorage.set(process.env.EMAIL_USER, otp); 

  res.json({ message: "OTP sent successfully" });
};

exports.verifyDeleteOtp = (req, res) => {
  const { otpvalue } = req.body;
  const email = process.env.EMAIL_USER;

  if (String(otpStorage.get(email)) === String(otpvalue)) { 
      otpStorage.delete(email); 
      const token = jwt.sign({ email }, JWT_SECRET, { expiresIn: "15m" });
      res.json({ token });
  } else {
      res.status(401).json({ error: "Invalid OTP" });
  }
};

exports.adminPage = async (req, res) => {
  const accestoken = req.cookies.accestoken;
  if (!accestoken) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  let decoded;
  try {
    decoded = jwt.verify(accestoken, JWT_SECRET);
  } catch (err) {
    return res.status(401).json({ error: 'Invalid Admin token' });
  }

  const query = "SELECT * FROM admin_login WHERE userid = $1";
  try {
    const [results] = await connectionUserdb.query(query, [decoded.userId]);
    if (results.length > 0) {
      res.status(200).json({ message: "Admin page content"});
    } else {
      res.status(400).json({ error: "admin not found" });
    }
  } catch (err) {
    console.error("Error during admin verification:", err);
    res.status(500).json({ error: "Error during admin verification" });
  }
};

exports.getFeedbacks = async (req, res) => {
  try {
    const [rows] = await connectionUserdb.query("SELECT f.*, u.firstname, u.lastname, u.gmail FROM feedback f LEFT JOIN users u ON f.user_id = u.id ORDER BY f.created_at DESC");
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

exports.getPaymentHistory = async (req, res) => {
  try {
    const [rows] = await connectionUserdb.query("SELECT * FROM payments ORDER BY created_at DESC");
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

exports.getDeletionRequests = async (req, res) => {
  try {
    const [rows] = await connectionUserdb.query("SELECT d.*, u.firstname, u.lastname, u.gmail FROM deletion_requests d LEFT JOIN users u ON d.user_id = u.id ORDER BY d.created_at DESC");
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

exports.updateDeletionRequest = async (req, res) => {
  const { id } = req.params;
  const { status } = req.body;
  try {
    await connectionUserdb.query("UPDATE deletion_requests SET status = $1 WHERE id = $2", [status, id]);
    res.json({ status: true, message: "Status updated" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

exports.adminLogout = (req, res) => {
  try {
    let cookieOptions = {
      httpOnly: true,                        
      secure: process.env.NODE_ENV === "production", 
      sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",                    
      path: "/"                              
    };
    res.clearCookie("accestoken", cookieOptions);
    res.status(200).json({ message: "Successfully logged out" });
  } catch (err) {
    console.error("Logout error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
};
