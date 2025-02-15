require('dotenv').config();
const express = require("express");
const cors = require("cors");
const multer = require("multer");
const path = require("path");
const { connectionUserdb, connectionPaperdb } = require("./db");
const jwt = require("jsonwebtoken");
// const { error } = require('console');
const crypto = require("crypto");
const nodemailer = require("nodemailer");
const bodyParser = require("body-parser");
const { error } = require("console");
const cookieParser = require("cookie-parser");
const fs = require("fs");
const { google } = require("googleapis");
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const mime = require('mime');
const axios = require('axios');
const rateLimit = require('express-rate-limit');
const { OAuth2Client } = require('google-auth-library');
const session = require("express-session");
const otpStorage = new Map();



const app = express();
const JWT_SECRET = process.env.JWT_SECRET;
const JWT_REFRESH_SECRET=process.env.JWT_REFRESH_SECRET;
const RECAPTCHA_SECRET_KEY = process.env.RECAPTCHA_SECRET_KEY
const APP_ID_CASHFREE = process.env.APP_ID_CASHFREE;
const  SECRET_KEY_CASHFREE = process.env.SECRET_KEY_CASHFREE;
const  CASHFREE_URL = process.env.CASHFREE_URL;
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;


app.use(cors());
app.use(bodyParser.json());
app.use(cookieParser());
app.use(express.urlencoded({ extended: true }));
app.use(express.json());


const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

const oauth2Client = new google.auth.OAuth2(
  process.env.CLIENT_ID,
  process.env.CLIENT_SECRET,
  process.env.REDIRECT_URI
);

oauth2Client.setCredentials({ refresh_token: process.env.REFRESH_TOKEN });

const drive = google.drive({
  version: "v3",
  auth: oauth2Client,
});


connectionUserdb.getConnection()
    .catch(error => {
        console.error('Database connection lost:', error);
        process.exit(1); // Let PM2 restart the backend
    });

 if (!JWT_SECRET) {
      console.error('JWT_SECRET is not defined in the environment variables!');
      process.exit(1); // Stop the server if critical variables are missing
    }


// // Example function to query user data
async function getUserData() {
    try {
       console.log("Userdb Database is connected");
    } catch (err) {
        console.error('Error fetching user data:', err);
    }
}

// 
async function getPapersData() {
    try {
      console.log("Papersdb Database is connected");
    } catch (err) {
        console.error('Error fetching papers data:', err);
    }
}

getUserData();
getPapersData();



app.set('trust proxy', 1); 

const limiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 500, // limit each IP to 100 requests per minute
  handler: (req, res) => {
    console.log(`Rate limit exceeded for IP: ${req.ip}`);
    res.status(429).send("Too many requests, please try again later.");
  },
});

app.use('/api/', limiter);

app.use('/api/Admin/noteUpload', (req, res, next) => {
  next(); 
});




app.use(session({
  secret: process.env.SESSION_SECRET,   // Change this to a secure key
  resave: false,
  saveUninitialized: true,
  cookie: { secure: true }    // Set to `true` if using HTTPS
}));



app.post("/api/verify-turnstile", async (req, res) => {
  const { token } = req.body;

  if (!token) return res.status(400).json({ success: false, error: "No token provided" });

  try {
    const response = await axios.post(
      "https://challenges.cloudflare.com/turnstile/v0/siteverify",
      new URLSearchParams({
        secret: process.env.CLOUDFLARE_SECRET_KEY,
        response: token,
      })
    );
 

    if (response.data.success) {
      req.session.isVerified = true; 
       
      return res.json({ success: true });
    } else {
      console.error('Invalid captha');
      return res.status(400).json({ success: false, error: "Invalid captcha" });
    }
  } catch (error) {
    console.error("something error",error)
    return res.status(500).json({ success: false, error: "Server error" });
  }
});



async function findFolderupload(folderName) {
  try {
    const response = await drive.files.list({
      q: `mimeType='application/vnd.google-apps.folder' and name='${folderName}' and trashed=false`,
      fields: "files(id, name)",
      spaces: "drive",
    });

    const folders = response.data.files;
    if (folders.length > 0) {
      // Folder exists, return its ID
      return folders[0].id;
    } else {
      // Folder doesn't exist, return null
      return null;
    }
  } catch (error) {
    console.error("Error finding folder on Google Drive:", error);
    throw error;
  }
}

async function createDriveFolder(folderName) {
  try {
    const fileMetadata = {
      name: folderName,
      mimeType: "application/vnd.google-apps.folder",
    };

    const response = await drive.files.create({
      resource: fileMetadata,
      fields: "id",
    });

    // console.log('Folder created on Google Drive with ID:', response.data.id);
    return response.data.id; // Return the folder ID
  } catch (error) {
    console.error("Error creating folder on Google Drive:", error);
    throw error;
  }
}

// Function to Upload File to Google Drive
async function uploadFileToDrive(filename, folderId) {
  try {
    const filePath = path.join(__dirname, "uploads", filename); // File saved temporarily in uploads folder
    const fileMetadata = {
      name: filename, // Use the uploaded file's name
      parents: [folderId],
    };

    const media = {
      mimeType: "application/pdf", // Assuming the file is a PDF, adjust if needed
      body: fs.createReadStream(filePath),
    };

    const response = await drive.files.create({
      resource: fileMetadata,
      media: media,
      fields: "id",
    });

    const fileId = response.data.id;

   await drive.permissions.create({
      fileId: fileId,
      resource: {
        role: "reader",
        type: "anyone",
      },
    });

    // console.log('File uploaded successfully to Google Drive. File ID:', fileId);

    return response.data.id; // Return Google Drive file ID
  } catch (error) {
    console.error("Error uploading file to Google Drive:", error);
    throw error;
  }
}

// Multer Setup to Store Files Temporarily
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = path.join(__dirname, "uploads");
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir); // Create uploads directory if it doesn't exist
    }
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    cb(null, `${Date.now()}-${file.originalname}`); // Append timestamp to avoid overwriting
  },
});

const upload = multer({ storage });

// POST Route to Handle File Upload and Google Drive Integration
app.post("/api/Profile/upload", upload.single("file"), async (req, res) => {
  const { renameFileback, userid } = req.body;
  try {
    const file = req.file; // Get file info from multer
    if (!file) {
      return res.status(400).json({ error: "No file uploaded" });
    }
    
    // Ensure folder exists or create it
    let folderId = await findFolderupload("User Uploads Files");
    if (!folderId) {
      folderId = await createDriveFolder("User Uploads Files"); // Create folder if it doesn't exist
    }
    
    // Upload the file to Google Drive
    const fileId = await uploadFileToDrive(file.filename, folderId);
    const filepath = `https://drive.google.com/file/d/${fileId}/view`;
    
    // Insert file details into database
    if (fileId) {
      const query = "INSERT INTO user_uploads (user_id, papername, paperlink) VALUES (?, ?, ?)";
      await new Promise((resolve, reject) => {
    
        connectionUserdb.query(query, [userid, renameFileback, filepath], (err) => {
          if (err) {
            console.error("Error inserting in database:", err);
            return reject("Error inserting data into database");
          }
        });
        resolve();
      });
    }

    // Delete the file from the local uploads directory after upload
    const tempFilePath = path.join(__dirname, "uploads", file.filename);
    await fs.promises.unlink(tempFilePath);

    // Clean up temporary folders
    const tmpDir = path.join(__dirname, "uploads/.tmp.driveupload");
    if(tmpDir){

      await fs.promises.rm(tmpDir, { recursive: true, force: true });
    }

    // Send success response

    return res.status(200).json({
      message: "File uploaded successfully to Google Drive",
      fileId: fileId, // Returning Google Drive File ID
    });
  } catch (error) {
    console.error("Error uploading file:", error);
    return res.status(500).json({ error: "Failed to upload file" });
  }
});


async function uploadFileToDrivett(filename, folderId) {
  try {
    const filePath = path.join(__dirname, "uploads", filename);
    if (!fs.existsSync(filePath)) {
      throw new Error(`File not found: ${filePath}`);
    }
    
    const mimeType = mime.getType(filePath) || "application/octet-stream";
    const fileMetadata = {
      name: filename,
      parents: [folderId],
    };

    const media = {
      mimeType,
      body: fs.createReadStream(filePath),
    };

    const response = await drive.files.create({
      resource: fileMetadata,
      media: media,
      fields: "id",
    });

    const fileId = response.data.id;

    await drive.permissions.create({
      fileId,
      resource: {
        role: "reader",
        type: "anyone",
      },
    });

    return fileId;
  } catch (error) {
    console.error("Error uploading file to Google Drive:", error);
    throw error;
  }
}


app.post("/api/Profile/upload/non-user", upload.array("files", 10), async (req, res) => {
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

      const tempFilePath = path.join(__dirname, "uploads", file.filename);
      await fs.promises.unlink(tempFilePath);
    }

    return res.status(200).json({
      message: "Files uploaded successfully to Google Drive",
      uploadedFiles: uploadedFileIds,
    });
  } catch (error) {
    console.error("Error uploading files:", error);
    return res.status(500).json({ error: "Failed to upload files" });
  }
});







app.get("/api/Profile/fetchpdf", async (req, res) => {
  try {
    const { userid } = req.query;
    
  
    // Build the query dynamically
    const query = "SELECT * FROM user_uploads WHERE user_id = ?";
    


    // Execute the query
    const [results] = await connectionUserdb.query(query, [userid]);

    if(results.length > 0){
      
      res.status(200).json(results);
    }else{
      res.status(400).json({error : 'User not found'})
    }

    // Send the response
  } catch (error) {
    console.error("Error fetching data:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});


app.post("/api/LogIn/Signup/otpVarify", async (req, res) => {
  const { email } = req.body;

  try {
    // Check if the email already exists in the verification table
    const checkQuery = "SELECT * FROM useremailverification WHERE gmail = ?";
    const [results] = await connectionUserdb.query(checkQuery, [email]);

    if (results.length === 0) {
      // If the email does not exist, insert it into the database
      const insertQuery = "INSERT INTO useremailverification (gmail) VALUES (?)";
      await connectionUserdb.query(insertQuery, [email]);
    }

    // Generate OTP and its expiry time
    const otp = crypto.randomInt(100000, 999999).toString();
    const otpExpires = new Date(Date.now() + 10 * 60000); // OTP expires in 10 minutes

    // Update the OTP and expiry time in the database
    const updateQuery =
      "UPDATE useremailverification SET otp = ?, expireotp = ? WHERE gmail = ?";
    await connectionUserdb.query(updateQuery, [otp, otpExpires, email]);

    // Prepare and send OTP email
    const mailOptions = {
      to: email,
      from: process.env.EMAIL_USER,
      subject: "StudyVault OTP for verify Email",
      html: `
        <html>
          <body style="font-family: Arial, sans-serif; color: #333;">
            <div style="width: 80vw; margin: auto; border: 1px solid gray; border-radius: 4px; padding: 20px;">
              <h1 style="text-align: center;">Welcome to StudyVault</h1>
              <p style="text-align: center;font-size: 1.1rem">Hi...</p>
              <p>You requested to verify your email. Please use the following One-Time Password (OTP) to verify your email:</p>
              <h2 style="text-align: center; margin: auto; font-size: 2.4rem;">${otp}</h2>
              <p>The OTP is valid for the next 10 minutes. If you did not request to verify your email, please ignore this email.</p>
              <h4>Best regards,</h4>
              <h4>The StudyVault Team</h4>
            </div>
          </body>
        </html>
      `,
    };

    // Send OTP email
    await transporter.sendMail(mailOptions);

    // Send success response
    return res.status(200).json("OTP sent");
  } catch (error) {
    // Log the error and send a 500 response with error message
    console.error("Error:", error);
    return res.status(500).json({ error: "Internal Server Error" });
  }
});


app.post("/api/LogIn/Signup/otpVarify/confirm", async (req, res) => {
  const { email, otp } = req.body;

  try {
    // Query to check the OTP for the given email
    const checkQuery = "SELECT * FROM useremailverification WHERE gmail = ? AND otp = ?";
    const [results] = await connectionUserdb.query(checkQuery, [email, otp]);

    if (results.length === 0) {
      // If no matching results, return an error
      return res.status(405).json({ error: "Invalid OTP or Invalid Email id" });
    }

    const otpExpires = results[0].expireotp;

    // Check if OTP is expired
    if (new Date(otpExpires) < new Date()) {
      return res.status(410).json({ error: "OTP expired" });
    }

    // Query to update the OTP and expiration fields
    const updateQuery = "UPDATE useremailverification SET otp = NULL, expireotp = NULL, gmail = NULL WHERE gmail = ?";
    await connectionUserdb.query(updateQuery, [email]);

    // Return success response
    return res.status(200).json({ message: "OTP verified and reset successfully" });

  } catch (err) {
    // Handle any unexpected errors
    console.error("Internal Error:", err);
    return res.status(500).json({ error: "Internal Server Error" });
  }
});




app.post("/api/LogIn/Signup", async (req, res) => {
  const { firstname, lastname, gmail, rollno, password, passwordcheck } = req.body;

  // Input validation
  if (!firstname || !lastname || !gmail || !rollno || !password || !passwordcheck) {
    return res.status(400).json({ error: "All fields are required" });
  }

  if (password !== passwordcheck) {
    return res.status(400).json({ error: "Passwords do not match" });
  }

  try {
    // Check if email already exists
    const checkQuery = "SELECT * FROM users WHERE gmail = ?";
    const [emailResults] = await connectionUserdb.query(checkQuery, [gmail]);

    if (emailResults.length > 0) {
      return res.status(409).json({ error: "Email already exists" });
    }

    // Check if roll number already exists
    const checkQueryRoll = "SELECT * FROM users WHERE rollno = ?";
    const [rollnoResults] = await connectionUserdb.query(checkQueryRoll, [rollno]);

    if (rollnoResults.length > 0) {
      return res.status(408).json({ error: "Roll number already exists" });
    }

    // Hash the password before storing it
    const hashedPassword = await bcrypt.hash(password, 10);
    

    // Insert new user into the database
    const query = "INSERT INTO users (firstname, lastname, gmail, rollno, password, passwordcheck) VALUES(?,?,?,?,?,?)";
    await connectionUserdb.query(query, [firstname, lastname, gmail, rollno, hashedPassword, passwordcheck]);

    return res.status(201).json({ message: "User registered successfully" });

  } catch (err) {
    console.error("Error during signup:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});


app.post("/api/LogIn", async (req, res) => {
  const { gmail, password } = req.body;
  
  if (!req.session.isVerified && process.env.NODE_ENV === "production") {
    console.log('CAPTCHA verification required')
    return res.status(403).json({ success: false, message: "CAPTCHA verification required" });
  }
  
  const query = "SELECT * FROM users WHERE gmail = ?";
  
  try {
    // Use `await` with `connectionUserdb.query` as `createPool` supports promises
    const [results] = await connectionUserdb.query(query, [gmail]);
   

    
    if (results.length > 0) {
      const user = results[0];
      
      const originalpassword = user.password;
     

      const isPasswordMatch = await bcrypt.compare(password, originalpassword);
      if(isPasswordMatch){
        const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: "7d" });

        res.cookie("token", token, {
          httpOnly: true,
          secure: process.env.NODE_ENV === "production", // Set to true in production
          sameSite: process.env.NODE_ENV === "production" ? "None" : "Lax",
          domain: process.env.NODE_ENV === "production" ? ".studyvault.online" : undefined,
          maxAge: 1000*60*60*24, 
        });
        req.session.isVerified = false;
        res.status(200).json({ success: true, user });
      }
      else {
        res.status(300).json({ error: "Invalid password" });
      }

    
    } else {
      res.status(401).json({ error: "You are not resgistered" });
    }
  } catch (err) {
    console.error("Error retrieving data:", err);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// Middleware to authenticate the token
function authenticateToken(req, res, next) {
  const token = req.cookies.token;

  if (!token) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  jwt.verify(token,JWT_SECRET, (err, user) => {
    if (err) {
      if (err.name === 'TokenExpiredError') {
        console.error('User token expired');
        return res.status(401).send({ error: 'User token expired. Please login again.' });
    }
    return res.status(401).send('Invalid user token');
    }
    req.user = user;
    // console.log(req.user);
    next();
  });
}

app.get("/api/signup-check", authenticateToken,async (req, res) => {
  const query = "SELECT * FROM users WHERE id = ?";

  try {
    const [results] = await connectionUserdb.query(query, [req.user.id]);

    if (results.length > 0) {
      res.status(200).json({ message: "user is available" });
    } else {
      res.status(404).json({ error: "User not found" });
      return res.status({ error: "User not found" });
    }
}catch(err){
  console.error("Error retrieving user data", err);
  return res.status(500).json({ error: "Internal Server Error" });
}
  

});

app.get("/api/Profile", authenticateToken, async (req, res) => {
  const query = "SELECT * FROM users WHERE id = ?";
  if (!req.user || !req.user.id) {
    return res.status(400).json({ error: "Invalid user information in token" });
  }

  try {
    const [results] = await connectionUserdb.query(query, [req.user.id]);

    if (results.length > 0) {
      const user = results[0];
      res.status(200).json({ user });
    } else {
      res.status(404).json({ error: "User not found" });
    }
}catch(err){
  console.error("Error retrieving user data", err);
  return res.status(500).json({ error: "Internal Server Error" });
}
  

});

app.get("/api/Profile", authenticateToken, async (req, res) => {
  const query = "SELECT * FROM users WHERE id = ?";
  if (!req.user || !req.user.id) {
    return res.status(400).json({ error: "Invalid user information in token" });
  }


  try {
    const [results] = await connectionUserdb.query(query, [req.user.id]);

    if (results.length > 0) {
      const user = results[0];
      res.status(200).json({ user });
    }
    else {
      res.status(404).json({ error: "User not found" });
    }
}catch(err){
  console.error("Error retrieving user data", err);
  return res.status(500).json({ error: "Internal Server Error" });
}
});

app.get("/api/usercheck", authenticateToken,async (req, res) => {
  const query = "SELECT * FROM users WHERE id = ?";
  // console.log('dsfd');

  if (!req.user || !req.user.id) {
    return res.status(400).json({ error: "Invalid user information in token" });
  }
  // console.log("user id : " ,req.user);
  try{
    const [results] = await  connectionUserdb.query(query, [req.user.id]);

    if (results.length > 0) {
      const user = results[0];
      // console.log(user);
      return res.status(200).json({ success: true });
    } else {
      return res.status(404).json({ message: "User not found" });
    }
  }catch(err){
    console.error("Error retrieving user data", err);
      return res.status(500).json({ error: "Internal Server Error" });
  }

});

app.post("/api/logOut", (req, res) => {
  let cookieOptions = {
    httpOnly: true,                        
    secure: process.env.NODE_ENV === "production", 
    sameSite: "Strict",
    path: "/"                             
  };



  res.clearCookie("token", cookieOptions);

  res.status(200).json({ success: true });
});


// Paper PDF BACKEND

app.get("/api/login-check-filter", authenticateToken, async (req, res) => {

  if (!req.user || !req.user.id) {
    return res.status(400).json({ error: "Invalid user information in token" });
  }
// console.log('hle')
  const query = "SELECT * FROM users WHERE id = ?";

  try {
    // Execute query using async/await with promise-based API
    const [results] = await connectionUserdb.query(query, [req.user.id]);

    // Check if user exists and respond accordingly
    if (results.length > 0) {
      return res.status(200).json({ message: "Successful" });
    }

    // If no user is found, send a 404 response
    return res.status(404).json({ error: "User not found" });

  } catch (err) {
    console.error("Error retrieving user data:", err);
    return res.status(500).json({ error: "Internal Server Error" });
  }
});



app.get("/api/login-check-context", authenticateToken, async (req, res) => {
  const query = "SELECT * FROM users WHERE id = ?";

  try {
    const [results] = await connectionUserdb.query(query, [req.user.id]);

    if (results.length > 0) {
      return res.status(200).json({ message: "Successful" });
    } else {
      return res.status(404).json({ error: "User not found" });
    }
  } catch (err) {
    console.error("Error retrieving user data:", err);
    return res.status(500).json({ error: "Internal Server Error" });
  }
});


app.get("/api/Filter", async (req, res) => {
  let query = "SELECT * FROM papers WHERE 1=1";
  const params = [];

  try {
    // Add departmentName filter if provided
    if (req.query.departmentName) {
      query += " AND departmentName = ?";
      params.push(req.query.departmentName);
    }

    // Add educationLevel filter for UG and PG
    if (req.query.educationLevelug === "ug" || req.query.educationLevelpg === "pg") {
      let educationLevels = [];
      if (req.query.educationLevelug === "ug") {
        educationLevels.push("ug");
      }
      if (req.query.educationLevelpg === "pg") {
        educationLevels.push("pg");
      }

      if (educationLevels.length > 0) {
        query += " AND educationLevel IN (?)"; // Use ? to prevent SQL injection
        params.push(educationLevels);
      }
    }

    // Add fromDate filter if provided
    if (req.query.fromDate) {
      query += " AND years >= ?";
      params.push(req.query.fromDate);
    }

    // Add toDate filter if provided
    if (req.query.toDate) {
      query += " AND years < ?";
      params.push(req.query.toDate);
    }

    // Add departmentYear filter if provided
    if (req.query.departmentYear) {
      query += " AND departmentYear = ?";
      params.push(req.query.departmentYear);
    }

    // Add semester or midSem filter if provided
    if (req.query.sem === "true" || req.query.midSem === "true") {
      let conditions = [];
      if (req.query.sem === "true") {
        conditions.push("sem = true");
      }
      if (req.query.midSem === "true") {
        conditions.push("midSem = true");
      }

      if (conditions.length > 0) {
        query += " AND (" + conditions.join(" OR ") + ")";
      }
    }

    // If no valid filters are provided, return an error
    if (params.length === 0 && !req.query.sem && !req.query.midSem) {
      return res.status(400).json({ error: "No filter parameters provided" });
    }

    // Execute the query with parameters
    const [results] = await connectionPaperdb.query(query, params);

    // Return the filtered results
    res.status(200).json(results);
  } catch (err) {
    console.error("Error fetching papers:", err);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// syllabus 



app.get("/api/syllabus", async (req, res) => {
  let query = "SELECT * FROM  syllabus WHERE 1=1";
  const params = [];

  try {
    // Add departmentName filter if provided
    if (req.query.Educationlavel) {
      query += " AND EducationalLable = ?";
      params.push(req.query.Educationlavel);
    }
    
    // Add educationLevel filter for UG and PG
    if (req.query.Stream) {
      
      query += " AND Stream = ?";
      
      params.push(req.query.Stream);
  
    }

   


  if (!params) {
      return res.status(400).json({ error: "No filter parameters provided" });
    }


    

    // Execute the query with parameters
    const [results] = await connectionPaperdb.query(query, params);

    // Return the filtered results
    res.status(200).json(results);
  } catch (err) {
    console.error("Error fetching syllabus:", err);
    res.status(500).json({ error: "Internal Server Error" });
  }
});


// Forgate page

app.post("/api/LogIn/ForgatePw", async (req, res) => {
  const { email } = req.body;

  try {
    // Check if the email exists in the database
    const [results] = await connectionUserdb.query("SELECT * FROM users WHERE gmail = ?", [email]);
    if (results.length === 0) {
      return res.status(409).json({ error: "Email not found" });
    }

    const user = results[0];
    const now = new Date();
    const lastOtpTime = new Date(user.lastOtpTime);

    // Prevent sending OTP if the last OTP request was made within 30 seconds
    if (user.lastOtpTime && now - lastOtpTime < 30000) {
      return res.status(429).json({
        error: "OTP already sent. Please wait 30 seconds before requesting another OTP",
      });
    }

    // Generate OTP and expiration time
    const otp = crypto.randomInt(100000, 999999).toString();
    const otpExpires = new Date(Date.now() + 10 * 60000); // OTP valid for 10 minutes

    // Update OTP, expiration time, and last OTP sent time in the database
    await connectionUserdb.query(
      "UPDATE users SET otp = ?, otpExpires = ?, lastOtpTime = ? WHERE gmail = ?",
      [otp, otpExpires, now, email]
    );

    // Send OTP email
    const mailOptions = {
      to: email,
      from: process.env.EMAIL_USER,
      subject: "StudyVault Password Reset OTP",
      html: `
        <html>
          <body style="font-family: Arial, sans-serif; color: #333;">
            <div style="width: 80vw; margin: auto; border: 1px solid gray; border-radius: 4px; padding: 20px;">
              <h1 style="text-align: center;">Welcome to StudyVault</h1>
              <p style="text-align: center; font-size: 1.1rem">Hi, ${user.firstname} ${user.lastname}</p>
              <p>You requested to reset your password. Please use the following One-Time Password (OTP) to reset your password:</p>
              <h2 style="text-align: center; margin: auto; font-size: 2.4rem;">${otp}</h2>
              <p>The OTP is valid for the next 10 minutes. If you did not request a password reset, please ignore this email.</p>
              <h4>Best regards,</h4>
              <h4>The StudyVault Team</h4>
            </div>
          </body>
        </html>
      `,
    };

    // Send the email
    transporter.sendMail(mailOptions, (err, info) => {
      if (err) {
        console.error("Email sending error:", err);
        return res.status(500).json({ error: "Email sending error" });
      }
      // console.log("Email sent:", info.response);
      return res.status(200).json("OTP sent");
    });
  } catch (err) {
    console.error("Error handling request:", err);
    return res.status(500).json({ error: "Database or server error" });
  }
});


app.post("/api/LogIn/verifyOtp", async (req, res) => {
  const { otp, email } = req.body;

  try {
    // Check if the user exists and the OTP is correct
    const [results] = await connectionUserdb.query(
      "SELECT * FROM users WHERE gmail = ? AND otp = ?",
      [email, otp]
    );

    if (results.length === 0) {
      console.error("Incorrect OTP");
      return res.status(409).json({ error: "Incorrect OTP" });
    }

    const otpExpires = results[0].otpExpires;
    if (new Date(otpExpires) < new Date()) {
      return res.status(410).json({ error: "OTP expired" });
    }

    // Update the OTP and expiration time to null after verification
    const [updateResults] = await connectionUserdb.query(
      "UPDATE users SET otp = NULL, otpExpires = NULL, lastOtpTime = NULL WHERE gmail = ?",
      [email]
    );

    if (updateResults.affectedRows === 0) {
      console.error("Error updating OTP status in database");
      return res.status(500).json({ error: "Error updating database" });
    }

    // Respond with a success message
    return res.status(200).json({ message: "OTP verified and reset successfully" });
  } catch (err) {
    console.error("Error verifying OTP:", err);
    return res.status(500).json({ error: "Internal error" });
  }
});


app.post("/api/LogIn/ForgatePw/ResetPassword",async (req, res) => {
  const { email, resetPassword } = req.body;

  const hashedPassword = await bcrypt.hash(resetPassword, 10);
  const query =
    "UPDATE users SET password = ?, passwordcheck = ? WHERE gmail = ?";

    try{
      const [result] = await connectionUserdb.query(
        query,
        [hashedPassword, hashedPassword, email]);

        return res.status(200).json({ message: "Update password successfully" });

    }catch(err){
      console.error("Error inserting in database", err);
      return res.status(500).json({ error: "Error inserting in database" });
    }
});

app.get("/api/feedback-check", authenticateToken, async (req, res) => {
  const query = "SELECT * FROM users WHERE id = ?";


  try{
    const [results] = await connectionUserdb.query(query, [req.user.id]);
    if (results.length > 0) {
      const user = results[0];
      res.status(200).json(user);

    }
    return res.status(404).json({ error: "User not found" });

  }catch(err){
    console.error("Error retrieving user data", err);
    return res.status(500).json({ error: "Internal Server Error" });
  }
 
});

app.post("/api/feedback-submission", async (req, res) => {
  const { star, feedbackmessage, gmail } = req.body;

  try {
    // Check if the user exists in the database
    const [user] = await connectionUserdb.query("SELECT * FROM users WHERE gmail = ?", [gmail]);

    if (user.length === 0) {
      console.error("User not found");
      return res.status(404).json({ err: "User not logged in" });
    }

    // Update the user's rating and feedback
    const [result] = await connectionUserdb.query(
      "UPDATE users SET ratestar = ?, feedbackmessage = ? WHERE gmail = ?",
      [star, feedbackmessage, gmail]
    );

    if (result.affectedRows === 0) {
      console.error("Database error while updating feedback");
      return res.status(500).json({ err: "Database error while updating feedback" });
    }

    // Send success response
    res.status(200).json({ message: "Feedback submitted successfully", result });
  } catch (error) {
    console.error("Internal error", error);
    res.status(500).json({ err: "Internal error" });
  }
});


//Admin

//File Upload



async function findFolder(folderName, parentFolderId = "root") { 
  try {
    const response = await drive.files.list({
      q: `name = '${folderName}' and mimeType = 'application/vnd.google-apps.folder' and '${parentFolderId}' in parents`,
      fields: "files(id, name)",
    });

    const folder = response.data.files[0];
    if (!folder) {
      console.log(`Folder "${folderName}" not found in parent "${parentFolderId}".`);
      return null;
    }

    console.log(`Folder "${folderName}" found with ID: ${folder.id}`);
    return folder.id; // Return the folder ID
  } catch (error) {
    console.error("Error finding folder on Google Drive:", error);
    throw error;
  }
}

async function findNestedFolder(folderPath) {
  const folderNames = folderPath.split("/"); // Split the folder path into parts
  let currentParentId = "root"; // Start from the root directory

  for (const folderName of folderNames) {
    const folderId = await findFolder(folderName, currentParentId);
    if (!folderId) {
      console.log(`Folder "${folderName}" does not exist.`);

      // If folder doesn't exist, attempt to clean up the "uploads" folder
      await deleteTempFiles();
      return null; // Stop if any folder in the path is not found
    }
    currentParentId = folderId; // Move into the found folder
  }

  return currentParentId; // Return the ID of the final folder in the path
}

// Function to clean up the temporary files in the uploads directory
async function deleteTempFiles() {
  const uploadFolderPath = path.join(__dirname, "uploads");

  try {
    const files = await fs.promises.readdir(uploadFolderPath);

    for (const file of files) {
      const filePath = path.join(uploadFolderPath, file);
      await fs.promises.unlink(filePath); // Delete the file
      // console.log("Deleted file:", filePath);
    }
  } catch (error) {
    console.error("Error deleting files in uploads folder:", error);
  }
}



app.post("/api/Admin/upload", upload.single("file"), async (req, res) => {
  const { renameFileback, filtetuploaddata } = req.body;
  const parsedData = JSON.parse(filtetuploaddata);

  const {
    departmentName,
    educationLavel,
    session,
    dptyear,
    semormid,
    studentyear,
  } = parsedData;

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

    // Determine the folder path based on department and other attributes
    let folderPath;
    if (["Elective", "Compulsory", "E&V"].includes(departmentName)) {
      folderPath = `MPC Papers Pdf/${departmentName}`;
    } else {
      folderPath = `MPC Papers Pdf/${educationLavel}/${semormid}/${studentyear}/${dptyear}/${departmentName}`;
    }

    // Check if folder exists on Google Drive
    const folderId = await findNestedFolder(folderPath);

    if (!folderId) {
      return res.status(401).json({ message: `Folder "${folderPath}" does not exist.` });
    }

    // Upload the file to Google Drive
    const fileId = await uploadFileToDrive(file.filename, folderId);
    if (!fileId) {
      return res.status(300).send("Failed to upload file to Google Drive");
    }

    // Check if a file with the same title already exists in the database
    const checkQuery = "SELECT * FROM papers WHERE title = ?";
    const [checkResults] = await connectionPaperdb.query(checkQuery, [renameFileback]);

    if (checkResults.length > 0) {
     
      const duplicatFile = path.join(__dirname, "uploads", file.filename);
      fs.unlink(duplicatFile, (err) => {
        if (err) console.error("Error deleting temp file:", err);
      });

      return res.status(400).json({
        message: `A file with the title "${renameFileback}" already exists in the database.`,
      });
    }

    // Construct the file URL
    const filepath = `https://drive.google.com/file/d/${fileId}/view`;

    // Insert the file details into the database
    const insertQuery =
      "INSERT INTO papers (departmentName, educationLevel, years, departmentYear, sem, midSem, title, url, semester) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";

    await connectionPaperdb.query(insertQuery, [
      departmentName,
      educationLavel,
      session,
      studentyear,
      sem,
      midsem,
      renameFileback,
      filepath,
      dptyear,
    ]);

    // Clean up the temporary file
    const tempFilePath = path.join(__dirname, "uploads", file.filename);
    fs.unlink(tempFilePath, (err) => {
      if (err) console.error("Error deleting temp file:", err);
    });

    // const tmpDir = path.join(__dirname, "uploads/.tmp.driveupload");
    // fs.rm(tmpDir, { recursive: true, force: true }, (err) => {
    //   // if (err) console.error("Error deleting temp folder:", err);
    // });

    res.status(200).send({
      message: "File uploaded successfully to Google Drive",
      fileId: fileId,
    });
  } catch (error) {
    console.error("Error processing request:", error);
    res.status(500).send("An error occurred while processing the request");
  }
});

//syllabus upload
app.post("/api/Admin/syllabusUpload", upload.single("file"), async (req, res) => {
  const { renameFileback, filtetuploaddata } = req.body;
  const parsedData = JSON.parse(filtetuploaddata);

  const {
    EducationLevel,
   Stream,
   subject
  } = parsedData;

  try {
    const file = req.file;
    if (!file) {
      return res.status(400).send("No file uploaded");
    }

   
  

    let folderId = await findFolderupload("Syllabus");
    if (!folderId) {
      folderId = await createDriveFolder("Syllabus"); // Create folder if it doesn't exist
    }

    // if (!folderId) {
    //   return res.status(401).json({ message: `Folder "${folderPath}" does not exist.` });
    // }

    // Upload the file to Google Drive
    const fileId = await uploadFileToDrive(file.filename, folderId);
    if (!fileId) {
      return res.status(300).send("Failed to upload file to Google Drive");
    }

    // Check if a file with the same title already exists in the database
    const checkQuery = "SELECT * FROM syllabus WHERE title = ?";
    const [checkResults] = await connectionPaperdb.query(checkQuery, [renameFileback]);

    if (checkResults.length > 0) {
     
      const duplicatFile = path.join(__dirname, "uploads", file.filename);
      fs.unlink(duplicatFile, (err) => {
        if (err) console.error("Error deleting temp file:", err);
      });

      return res.status(400).json({
        message: `A file with the title "${renameFileback}" already exists in the database.`,
      });
    }

    // Construct the file URL
    const filepath = `https://drive.google.com/file/d/${fileId}/view`;

    // Insert the file details into the database
    const insertQuery =
      "INSERT INTO syllabus (title, Subject, Stream, EducationalLable, url) VALUES (?, ?, ?, ?, ?)";

    await connectionPaperdb.query(insertQuery, [
      renameFileback,
      subject,
      Stream,
      EducationLevel,
      filepath,
    ]);

    // Clean up the temporary file
    const tempFilePath = path.join(__dirname, "uploads", file.filename);
    fs.unlink(tempFilePath, (err) => {
      if (err) console.error("Error deleting temp file:", err);
    });

    // const tmpDir = path.join(__dirname, "uploads/.tmp.driveupload");
    // fs.rm(tmpDir, { recursive: true, force: true }, (err) => {
    //   // if (err) console.error("Error deleting temp folder:", err);
    // });

    res.status(200).send({
      message: "File uploaded successfully to Google Drive",
      fileId: fileId,
    });
  } catch (error) {
    console.error("Error processing request:", error);
    res.status(500).send("An error occurred while processing the request");
  }
});


app.post("/api/Admin/noteUpload", upload.single("file"), async (req, res) => {
  const { subjectName, noteFullName,unit } = req.body;
  
  

  

  try {
    const file = req.file;
    if (!file) {
      return res.status(400).send("No file uploaded");
    }


  

    let folderId = await findFolderupload("Notes");
    if (!folderId) {
      folderId = await createDriveFolder("Notes"); 
    }

   
    const fileId = await uploadFileToDrive(file.filename, folderId);
    if (!fileId) {
      return res.status(300).send("Failed to upload file to Google Drive");
    }

    
    const checkQuery = "SELECT * FROM notes WHERE notefullname = ?";
    const [checkResults] = await connectionPaperdb.query(checkQuery, [noteFullName]);

    if (checkResults.length > 0) {
     
      const duplicatFile = path.join(__dirname, "uploads", file.filename);
      fs.unlink(duplicatFile, (err) => {
        if (err) console.error("Error deleting temp file:", err);
      });

      return res.status(400).json({
        message: `A file with the title "${noteFullName}" already exists in the database.`,
      });
    }

  
    const filepath = `https://drive.google.com/file/d/${fileId}/view`;

 
    const insertQuery =
      "INSERT INTO notes (subjectname, notefullname, unit,url) VALUES (?, ?, ?, ?)";

    await connectionPaperdb.query(insertQuery, [
      subjectName,
      noteFullName,
      unit,
      filepath,
    ]);

    // Clean up the temporary file
    const tempFilePath = path.join(__dirname, "uploads", file.filename);
    fs.unlink(tempFilePath, (err) => {
      if (err) console.error("Error deleting temp file:", err);
    });

    // const tmpDir = path.join(__dirname, "uploads/.tmp.driveupload");
    // fs.rm(tmpDir, { recursive: true, force: true }, (err) => {
    //   // if (err) console.error("Error deleting temp folder:", err);
    // });

    res.status(200).send({
      message: "File uploaded successfully to Google Drive",
      fileId: fileId,
    });
  } catch (error) {
    console.error("Error processing request:", error);
    res.status(500).send("An error occurred while processing the request");
  }
});






app.get("/api/admin/fetchData", async (req, res) => {
  let query = "SELECT * FROM papers ";
  try{
    const [results] = await connectionPaperdb.query(query); 
    
    res.status(200).json(results);

  }catch(err){
    console.error("Error fetching papers:", err);
    return res.status(500).json({ error: "Internal Server Error" });
  }
});

app.get("/api/notefetch", async (req, res) => {
  let query = "SELECT * FROM notes ";
  try{
    const [results] = await connectionPaperdb.query(query); 
    
    res.status(200).json(results);

  }catch(err){
    console.error("Error fetching papers:", err);
    return res.status(500).json({ error: "Internal Server Error" });
  }
});
app.post("/api/noteClickCount", async (req, res) => {
  const {id} = req.body;
 
  try{
    await connectionPaperdb.query('UPDATE notes SET totalClicks = totalClicks + 1 WHERE id = ?', [id]);
    const [results] = await db.query('SELECT totalClicks FROM notes WHERE id = ?', [id]);
    
    res.json({ count: results[0].totalClicks });

  }catch(err){
    // console.error("Database error:", error);
    res.status(500).send("Error updating click count");
  }
});
app.post("/api/notedonwloadcount",authenticateToken, async (req, res) => {
  const {id,filename,unit,fileUrl} = req.body;

  const userid=req.user.id;
 
 
  try {

    await connectionPaperdb.query(
      'UPDATE notes SET totaldownload = totaldownload + 1 WHERE id = ?',
      [id]
    );


    await connectionUserdb.query(
      `
      INSERT INTO notedownloads (user_id, note_id, note_full_name, note_unit, download_url, downloaded_at)
      VALUES (?, ?, ?, ?, ?, NOW())
      `,
      [userid, id, filename, unit, fileUrl]
    );


    const [results] = await connectionPaperdb.query(
      'SELECT totaldownload FROM notes WHERE id = ?',
      [id]
    );


    res.status(200).json({
      message: 'Download recorded successfully',
      count: results[0]?.totaldownload || 0
    });

  } catch (error) {
    console.error("Database error:", error);
    res.status(500).json({
      message: 'Error updating download count or recording download'
    });
  }

});






app.post("/api/admin/deletepdf", async (req, res) => {
  const { id, urlpdfid } = req.body;

  if (!urlpdfid) {
    console.error("Invalid Google Drive URL");
    return res.status(400).json({ error: "Invalid Google Drive URL" });
  }

  try {
    const query = "DELETE FROM papers WHERE id = ?";
    const [results] = await connectionPaperdb.query(query, [id]);

    if (results.affectedRows === 0) {
      return res.status(404).json({ error: "Record not found in database" });
    }

    try {
      // Check if file exists before deleting
      await drive.files.get({ fileId: urlpdfid });
  
      // If file exists, delete it
      await drive.files.delete({ fileId: urlpdfid });
      
  } catch (error) {
      if (error.code === 404) {
          console.log(`File with ID ${urlpdfid} not found, skipping deletion.`);
      } else {
          console.error("Error deleting file:", error.message);
          return res.status(500).json({ error: "Failed to delete file from Google Drive" });
      }
  }
  res.status(200).json({ message: "Successfully Deleted" });


  } catch (error) {
    console.error("Database error:", error);
    res.status(500).json({ error: "Database error" });
  }
});

app.post("/api/admin/request-delete", async (req, res) => {
  
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
              <p style="text-align: center; font-size: 1.1rem">Hi</p>
              <p>You requested to for verify for deletation. Please use the following One-Time Password (OTP) to get verified </p>
              <h2 style="text-align: center; margin: auto; font-size: 2.4rem;">${otp}</h2>
           
              <h4>Best regards,</h4>
              <h4>The StudyVault Team</h4>
            </div>
          </body>
        </html>
    `,
  };

  // Send OTP email
  await transporter.sendMail(mailOptions);

  otpStorage.set(process.env.EMAIL_USER, otp); 

  


  res.json({ message: "OTP sent successfully" });
});


app.post("/api/admin/delete/verify-otp", (req, res) => {
  const { otpvalue } = req.body;
  const email = process.env.EMAIL_USER;

 
  if (String(otpStorage.get(email)) === String(otpvalue)) { // Ensure both are strings
      otpStorage.delete(email); // Remove OTP after verification

      // Generate JWT valid for 15 minutes
      const token = jwt.sign({ email }, JWT_SECRET, { expiresIn: "15m" });

      res.json({ token });
  } else {
      res.status(401).json({ error: "Invalid OTP" });
  }
});






//Admin LogIN

app.post("/api/Admin/AdminLogIn", async (req, res) => {
    const { userid, password } = req.body;
  
   
    const query = "SELECT * FROM admin_login WHERE userid = ? AND password = ? ";
  
    try{
      const [results] = await connectionPaperdb.query(query, [userid, password]);
  
      if (results.length === 0) {
        return res.status(400).json({ error: "Invalid Credentials" });
  
        
      }
      const accestoken = jwt.sign({ userId: results[0].userid },JWT_SECRET, {
        expiresIn: "7d", // Token expiration time
      });

      res.cookie("accestoken", accestoken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production", // Set to true in production
        maxAge: 1000*60*60*24, // 10 hour in milliseconds
      });
      return res.status(200).json({ message: "Seccessfully LogIn"});
  
    }catch(err){
      return res.status(500).json({ error: "Internal server error" });
    } 
  
    });


app.get("/api/adminPage", async (req, res) => {

  const accestoken = req.cookies.accestoken;
  
  if (!accestoken) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  // console.log( "accesstoken is : ",accestoken);
  jwt.verify(accestoken,JWT_SECRET, (err, user) => {
    if (err) {
      if (err.name === 'TokenExpiredError') {
        console.error('Admin token expired');
        return res.status(405).send({ error: 'Admin token expired. Please login again.' });
    }
    return res.status(401).send('Invalid Admin token');
    }
    req.userid = user;
  });

  // console.log( "admin id : ",req.userid);
  const query = "SELECT * FROM admin_login WHERE userid = ?";
  
  try {
    
  
    const [results] = await connectionPaperdb.query(query, [ req.userid.userId]);
    
    if (results.length > 0) {
      
    res.status(200).json({ message: "Admin page content"});
    } else {
      res.status(400).json({ error: "admin not found" });
      return res.status({ error: " admin found" });
    }

  
  } catch (err) {
    console.error("Error during admin  verification:", err);
    res.status(500).json({ error: "Error during admin  verification" });
  }
});


app.post("/api/Admin/logout", (req, res) => {
  try {
    let cookieOptions = {
      httpOnly: true,                        // Protects against XSS
      secure: process.env.NODE_ENV === "production", // Only send over HTTPS in production
      sameSite: "Strict",                    // Only sent in first-party contexts
      path: "/"                              // Applies to the entire site
    };
  
    
  
    res.clearCookie("accestoken", cookieOptions);

    res.status(200).json({ message: "Successfully logged out" });
  } catch (err) {
    console.error("Logout error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.get('/api/connectusdata', async (req,res)=>{
  // const {messageus} = req.query;
  const {firstName,lastName,gmail,message} = req.query;
  const mygmail = 'ab791235@gmail.com';


  try{
  const mailOptions = {
    to: mygmail,
    from: gmail,
    subject: "StudyVault Connect fo advertising, Client message",
    html: `
      <html>
        <body style="font-family: Arial, sans-serif; color: #333;">
          <div style="width: 80vw; margin: auto; border: 1px solid gray; border-radius: 4px; padding: 20px;">
            <h1 style="text-align: center;">Someone try to message you.</h1>
            <p style="text-align: center;font-size: 1.1rem">Check the details...</p>
            <p>Check the details here : </p>
            <h2 style=" margin: auto; font-size: 1.3rem;">Name - <span style=" margin: auto; font-size: 1.1rem; font-weight : 600;"> ${firstName} ${lastName} </span></h2>
            <h2 style=" margin: auto; font-size: 1.3rem;"> Gmail - <span style=" margin: auto; font-size: 1.1rem; font-weight : 600;"> ${gmail} </span></h2>
            <h2 style=" margin: auto; font-size: 1.3rem;"> Message -  ${message} </h2>
            <p>This message from advertising section.</p>
            <h4>Best regards,</h4>
            <h4>The StudyVault Team</h4>
          </div>
        </body>
      </html>
    `,
  };

  // Send OTP email
  await transporter.sendMail(mailOptions);

  // Send success response
  return res.status(200).json("Message successfully sent");
} catch (error) {
  // Log the error and send a 500 response with error message
  console.error("Error:", error);
  return res.status(500).json({ error: "Internal Server Error" });
}
  
});

//CASHFREEPAY






app.post('/api/create-payment-order', async (req, res) => {
  const { amount, customerEmail, customerPhone, redirect_url } = req.body;

  if (!amount || !customerEmail || !customerPhone) {
    return res.status(400).json({ error: 'Missing required fields' });
  }
  let customerId;

  try {
    
    const quary = "SELECT * FROM customers WHERE customer_phone = ?";

    const [results] = await connectionUserdb.query(quary, [customerPhone]);

    if (results.length > 0) {
       customerId = results[0].customer_id;
    } else{
      customerId = `cust_${Date.now()}`;

      try{
        const addquary = "INSERT INTO customers (customer_id, customer_phone) VALUES (?, ?)"


        const [results] = await connectionUserdb.query(addquary, [customerId,customerPhone]);
  
      }catch(err){
        console.error("update cutomer err",err);
      }

     

    }
  
   

   
  const orderId = `ORD_${Date.now()}_${Math.random().toString(36).substring(2, 15)}`;


  const data =  {
    order_amount: amount,
    order_currency: 'INR',
    customer_details: {
      customer_email: customerEmail,  // Corrected: moved inside customer_details
      customer_phone: customerPhone,  // Corrected: moved inside customer_details
      customer_id: customerId,        // Corrected: moved inside customer_details
    },
    order_meta: {
      notify_url: `${req.protocol}://${req.get('host')}/api/payment-donate-us/notifyurl`, 
      return_url: `${redirect_url}?order_id={order_id}&tx_status={txStatus}`,
      payment_methods: "upi,cc,dc,nb,app", // Payment methods
    },
    order_id: orderId,
  }
 

  try {
    const response = await axios.post(CASHFREE_URL,data,{
      headers: {
        "Content-Type": "application/json",
        "accept": "application/json",
        "x-client-id": APP_ID_CASHFREE,   
        "x-client-secret": SECRET_KEY_CASHFREE,
        'x-api-version': "2023-08-01",
      }
    });


    const paymentSessionId = response.data.payment_session_id;
    const orderid = response.data.order_id;
    res.json({ paymentSessionId ,orderid});
  } catch (error) {
    console.error('Error creating payment order:', error);

    // Log detailed error information
    if (error.response) {
      console.error('Error response:', error.response.data);
      console.error('Error status:', error.response.status);
    } else {
      console.error('Error message:', error.message);
    }

    res.status(500).send('Error creating payment order');
  }
}catch(err){
  console.error("Number findding error",err);
 }
});










app.post('/api/payment-donate-us/notifyurl',express.raw({ type: 'application/json' }), (req, res) => {
  
  const rawBody = req.body.toString('utf8');

  req.rawBody = rawBody; 
  
  console.log("Raw Body:", rawBody || "No raw body received"); 

  const signature = req.headers['x-webhook-signature'];  // Ensure correct header key

  if (!signature) {
    console.log("Signature not found in headers");
    return res.status(400).send('Signature missing');
  }

  // Convert buffer to string for verification
  if (!verifySignature(rawBody, signature)) {
    console.log("Invalid Signature");
    return res.status(400).send('Invalid Signature');
  }
  if (!rawBody) {
    console.error("Raw body is missing from the request.");
    return res.status(400).send('Invalid request, raw body missing');
  }

  console.log("Payment notification received:", JSON.parse(rawBody));

  res.status(200).send('Notification received successfully');
});

const verifySignature = (bodyString, receivedSignature) => {
  // const bodyString = JSON.stringify(body); 


  const hmac = crypto.createHmac('sha256',SECRET_KEY_CASHFREE);
  hmac.update(bodyString); 
  const calculatedSignature = hmac.digest('base64');
  console.log( "Recieved signature Is : ",receivedSignature);
  console.log( "calculatedSignature signature Is : ",calculatedSignature);
  return receivedSignature === calculatedSignature;
};



app.get('/api/payment-status/:orderId', async (req, res) => {
  const { orderId } = req.params;
 

  try {
    const response = await axios.get(`${CASHFREE_URL}/${orderId}`, {
      headers: {
        "Content-Type": "application/json",
        "accept": "application/json",
        "x-client-id": APP_ID_CASHFREE,   
        "x-client-secret": SECRET_KEY_CASHFREE,
        'x-api-version': "2023-08-01",
      }
    });




    if (response.data && response.data.order_status) {

     
      if(response.data.order_status === "PAID"){
        const usermail = response.data.customer_details.customer_email;
       

        const mailOptions = {
          to: usermail,
         
          from: process.env.EMAIL_USER,
          subject: "StudyVault Payment verificaiton Message .",
          html: `
           <html>
  <body style="font-family: Arial, sans-serif; background-color: #f9f9f9; color: #333; padding: 20px;">
    <div style="max-width: 600px; margin: auto; background: #fff; border: 1px solid #ddd; border-radius: 8px; padding: 20px; box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);">
      <h1 style="text-align: center; color: #4CAF50;">🎉 Payment Successful!</h1>

      <p style="text-align: center; font-size: 1.1rem; color: #555;">Thank you for your payment. Here are the details:</p>

      <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">

      <h2 style="font-size: 1.3rem;">Order Id  : <span style="font-size: 1.1rem; font-weight: 600; color: #333;">${orderId}</span></h2>
      <h2 style="font-size: 1.3rem;">Payment Status : <span style="font-size: 1.1rem; font-weight: 600; color: #333;">PAID</span></h2>
      <h2 style="font-size: 1.3rem;">Order amount : <span style="font-size: 1.1rem; font-weight: 500; color: #666;">${response.data.order_amount}</span></h2>

      <div style="background-color: #f1f1f1; padding: 15px; border-radius: 6px; margin: 20px 0;">
        <p style="font-size: 1rem; color: #444;">Your payment has been successfully processed. Thank you for supporting Us. If you have any questions, feel free to reach out to our support team.</p>
      </div>

      <p style="font-size: 0.9rem; color: #777;">This message is related to your payment through StudyVault.</p>

      <h4 style="margin-top: 30px; color: #333;">Best regards,</h4>
      <h4 style="color: #4CAF50;">The StudyVault Team</h4>
    </div>
  </body>
</html>
          `,
        };
      
        // Send OTP email
        await transporter.sendMail(mailOptions);
      }


      res.status(200).json({
        orderId: response.data.order_id,
        status: response.data.order_status,
      });
    } else {
      res.status(400).json({ error: 'Invalid response from Cashfree' });
    }
  } catch (error) {
    console.error('Error fetching payment status:', error);
    res.status(500).json({ error: 'Failed to fetch payment status' });
  }
});

//GOOGL AUTH LOGIN 



const client = new OAuth2Client(GOOGLE_CLIENT_ID);

app.post("/api/auth/google", async (req, res) => {
  const { token } = req.body;


  if (!token) {
    return res.status(400).json({ message: "No token provided" });
  }


  try {
    const ticket = await client.verifyIdToken({
      idToken: token,
      audience: GOOGLE_CLIENT_ID,
    });

    if (!ticket) {
      return res.status(401).json({ message: "Invalid Google token" });
    }

    const payload = ticket.getPayload();
    // console.log("User Info:", payload);
    const { name, email, picture, sub } = payload;

    const query = "SELECT * FROM users WHERE google_id = ? OR gmail = ?";
    try{
      const [results] = await connectionUserdb.query(query,[sub,email]);


      if (results.length > 0) {
        const user=results[0];
        const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: "7d" });

        res.cookie("token", token, {
          httpOnly: true,
          secure: process.env.NODE_ENV === "production", // Set to true in production
          sameSite: process.env.NODE_ENV === "production" ? "None" : "Lax",
           domain: process.env.NODE_ENV === "production" ? ".studyvault.online" : undefined,
          maxAge: 1000*60*60*24, 
        });


        res.json({ success: true, message: "Login successful", user: results[0] });
      }else{
        const loginquery = "INSERT INTO users (google_id, firstname, gmail, picture) VALUES (?, ?, ?, ?)";
        try{
          const [results] = await connectionUserdb.query(loginquery,[sub,name,email,picture]);
          const user=results[0];

          const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: "7d" });

        res.cookie("token", token, {
          httpOnly: true,
          secure: process.env.NODE_ENV === "production", // Set to true in production
          sameSite: process.env.NODE_ENV === "production" ? "None" : "Lax",
           domain: process.env.NODE_ENV === "production" ? ".studyvault.online" : undefined,
          maxAge: 1000*60*60*24, 
        });

          res.status(200).json({
            success: true,
            message: "Login successful",
            user: {
              name: payload.name,
              email: payload.email,
              picture: payload.picture,
            },
          });

        }catch(err){
          console.error("Insert error:", err);
          return res.status(500).json({ message: "Error saving user" });
        }
      }

    }catch(err){
      console.error("Token verification error:", err);
    res.status(401).json({ message: "Invalid token" });
    }

 
  } catch (error) {
    console.error("Error verifying token:", error);
    res.status(401).json({ message: "Invalid token" });
  }
});


/////Comment section 



app.get('/api/comments/fetch', async (req, res) => {
  const query = `
  SELECT c.id, c.name, c.gender, c.message, c.created_at, 
    COALESCE(
      JSON_ARRAYAGG(
        JSON_OBJECT(
          'id', r.id,
          'name', r.name,
          'gender', r.gender,
          'gmail', r.gmail,
          'message', r.message,
          'created_at', r.created_at
        )
      ), JSON_ARRAY()
    ) AS replies
  FROM comments c
  LEFT JOIN replies r ON c.id = r.comment_id
  GROUP BY c.id
`;


  try {
    const [results] = await connectionUserdb.query(query);
    // console.log('Comment fetch');

    res.json(results.map(comment => ({
      ...comment,
      replies: comment.replies || []  // No need for fallback as IFNULL handles it
    })));
  } catch (err) {
    console.error('Error fetching comments:', err);
    res.status(500).json({ error: 'Failed to fetch comments' });
  }
});

app.post('/api/comments', async (req, res) => {
  const { name, gmail, gender, message } = req.body;
  const query = 'INSERT INTO comments (name, gmail, gender, message) VALUES (?, ?, ?, ?)';

  try {
    await connectionUserdb.query(query, [name, gmail, gender, message]);
    const mailOptions = {
      to: process.env.MY_GMAIL,
      from: process.env.EMAIL_USER,
      subject: "Someone Comment on Studyvault",
      html: `
        <html>
          <body style="font-family: Arial, sans-serif; color: #333;">
            <div style="width: 80vw; margin: auto; border: 1px solid gray; border-radius: 4px; padding: 20px;">
              <h1 >Name is :${name} <br/> Gmail is : ${gmail} <br/>  Gender :${gender} </h1>
        
              <h2 style=" margin: auto; font-size: 1.5rem;">This is the messsage : ${message}</h2>

              
              <h4>The StudyVault Team</h4>
            </div>
          </body>
        </html>
      `,
    };

    // Send OTP email
    await transporter.sendMail(mailOptions);

    // console.log('Comment send');
    res.sendStatus(201);
  } catch (err) {
    console.error('Error posting comment:', err);
    res.status(500).json({ error: 'Failed to post comment' });
  }
});

app.post('/api/comments/:id/replies', async (req, res) => {
  const { id } = req.params;
  const { name, gmail, gender, message } = req.body;

 
  const query = `
    INSERT INTO replies (comment_id, name, gmail, gender, message)
    VALUES (?, ?, ?, ?, ?)
  `;

  try {
    await connectionUserdb.query(query, [id, name, gmail, gender, message]);

    const mailOptions = {
      to: process.env.MY_GMAIL,
      from: process.env.EMAIL_USER,
      subject: `Someone Replies on Studyvault of this id : ${id}`,
      html: `
        <html>
          <body style="font-family: Arial, sans-serif; color: #333;">
            <div style="width: 80vw; margin: auto; border: 1px solid gray; border-radius: 4px; padding: 20px;">
              <h1 >Name is :${name} <br/> Gmail is : ${gmail} <br/>  Gender :${gender} </h1>
        
              <h2 style=" margin: auto; font-size: 1.5rem;">This is the Reply messsage : ${message}</h2>

              
              <h4>The StudyVault Team</h4>
            </div>
          </body>
        </html>
      `,
    };

    // Send OTP email
    await transporter.sendMail(mailOptions);
    
    res.sendStatus(201);
  } catch (err) {
    console.error('Error posting reply:', err);
    res.status(500).json({ error: 'Failed to post reply' });
  }
});





/////////////

const port = process.env.PORT || 3000;
const ip = process.env.IP || "127.0.0.1";

app.listen(port, ip, () => {
  console.log(`The website is running on port ${port}`);
});
