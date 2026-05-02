const connectionUserdb = require("../config/db");
const path = require("path");
const fs = require("fs");
const { findFolderupload, createDriveFolder, uploadFileToDrive, uploadFileToDrivett } = require("../utils/googleDrive");

exports.uploadProfileFile = async (req, res) => {
  const { renameFileback, userid } = req.body;
  try {
    const file = req.file;
    if (!file) {
      return res.status(400).json({ error: "No file uploaded" });
    }
    
    let folderId = await findFolderupload("User Uploads Files");
    if (!folderId) {
      folderId = await createDriveFolder("User Uploads Files"); 
    }
    
    const fileId = await uploadFileToDrive(file.filename, folderId);
    const filepath = `https://drive.google.com/file/d/${fileId}/view`;
    
    if (fileId) {
      const query = "INSERT INTO user_uploads (user_id, papername, paperlink) VALUES ($1, $2, $3)";
      await connectionUserdb.query(query, [userid, renameFileback, filepath]);
    }

    const tempFilePath = path.join(__dirname, "../uploads", file.filename);
    try {
      await fs.promises.unlink(tempFilePath);
    } catch (err) {
      console.error("Error unlinking temp file", err);
    }

    return res.status(200).json({
      message: "File uploaded successfully to Google Drive",
      fileId: fileId, 
    });
  } catch (error) {
    console.error("Error uploading file:", error);
    return res.status(500).json({ error: "Failed to upload file" });
  }
};

exports.uploadNonUser = async (req, res) => {
  try {
    const files = req.files;
    if (!files || files.length === 0) {
      return res.status(400).json({ error: "No files uploaded" });
    }

    let folderId = await findFolderupload("User Uploads Files");
    if (!folderId) {
      folderId = await createDriveFolder("User Uploads Files");
    }

    const uploadedFileIds = [];
    for (const file of files) {
      const fileId = await uploadFileToDrivett(file.filename, folderId);
      uploadedFileIds.push({ filename: file.originalname, fileId });

      const tempFilePath = path.join(__dirname, "../uploads", file.filename);
      try {
        await fs.promises.unlink(tempFilePath);
      } catch (err) {
        console.error("Error unlinking file", err);
      }
    }

    return res.status(200).json({
      message: "Files uploaded successfully to Google Drive",
      uploadedFiles: uploadedFileIds,
    });
  } catch (error) {
    console.error("Error uploading files:", error);
    return res.status(500).json({ error: "Failed to upload files" });
  }
};

exports.fetchPdf = async (req, res) => {
  try {
    const { userid } = req.query;
    
    const query = "SELECT * FROM user_uploads WHERE user_id = $1";
    const [results] = await connectionUserdb.query(query, [userid]);

    if(results.length > 0) {
      res.status(200).json(results);
    } else {
      res.status(400).json({error : 'User not found'})
    }
  } catch (error) {
    console.error("Error fetching data:", error);
    res.status(500).json({ error: "Internal server error" });
  }
};

exports.getProfile = async (req, res) => {
  if (!req.user || !req.user.id) {
    return res.status(400).json({ error: "Invalid user information in token" });
  }

  const query = "SELECT * FROM users WHERE id = $1";
  try {
    const [results] = await connectionUserdb.query(query, [req.user.id]);

    if (results.length > 0) {
      const user = results[0];
      res.status(200).json({ user });
    } else {
      res.status(404).json({ error: "User not found" });
    }
  } catch(err) {
    console.error("Error retrieving user data", err);
    return res.status(500).json({ error: "Internal Server Error" });
  }
};

exports.feedbackCheck = async (req, res) => {
  const query = "SELECT * FROM users WHERE id = $1";
  try {
    const [results] = await connectionUserdb.query(query, [req.user.id]);
    if (results.length > 0) {
      const user = results[0];
      return res.status(200).json(user);
    }
    return res.status(404).json({ error: "User not found" });
  } catch(err) {
    console.error("Error retrieving user data", err);
    return res.status(500).json({ error: "Internal Server Error" });
  }
};

exports.feedbackSubmission = async (req, res) => {
  const { star, feedbackmessage, gmail } = req.body;

  try {
    const [user] = await connectionUserdb.query("SELECT * FROM users WHERE gmail = $1", [gmail]);

    if (user.length === 0) {
      return res.status(404).json({ err: "User not logged in" });
    }

    const [, result] = await connectionUserdb.query(
      "UPDATE users SET ratestar = $1, feedbackmessage = $2 WHERE gmail = $3",
      [star, feedbackmessage, gmail]
    );

    if (result.rowCount === 0) {
      return res.status(500).json({ err: "Database error while updating feedback" });
    }

    res.status(200).json({ message: "Feedback submitted successfully", result: result.rowCount });
  } catch (error) {
    console.error("Internal error", error);
    res.status(500).json({ err: "Internal error" });
  }
};
