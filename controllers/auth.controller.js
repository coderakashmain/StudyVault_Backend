const connectionUserdb = require("../config/db");
const bcrypt = require('bcryptjs');
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const nodemailer = require("nodemailer");
const { OAuth2Client } = require('google-auth-library');

const JWT_SECRET = process.env.JWT_SECRET;
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const client = new OAuth2Client(GOOGLE_CLIENT_ID);

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

exports.otpVerify = async (req, res) => {
  const { email } = req.body;

  try {
    const checkQuery = "SELECT * FROM useremailverification WHERE gmail = $1";
    const [results] = await connectionUserdb.query(checkQuery, [email]);

    if (results.length === 0) {
      const insertQuery = "INSERT INTO useremailverification (gmail) VALUES ($1)";
      await connectionUserdb.query(insertQuery, [email]);
    }

    const otp = crypto.randomInt(100000, 999999).toString();
    const otpExpires = new Date(Date.now() + 10 * 60000); 

    const updateQuery = "UPDATE useremailverification SET otp = $1, expireotp = $2 WHERE gmail = $3";
    await connectionUserdb.query(updateQuery, [otp, otpExpires, email]);

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

    await transporter.sendMail(mailOptions);
    return res.status(200).json("OTP sent");
  } catch (error) {
    console.error("Error:", error);
    return res.status(500).json({ error: "Internal Server Error" });
  }
};

exports.otpVerifyConfirm = async (req, res) => {
  const { email, otp } = req.body;

  try {
    const checkQuery = "SELECT * FROM useremailverification WHERE gmail = $1 AND otp = $2";
    const [results] = await connectionUserdb.query(checkQuery, [email, otp]);

    if (results.length === 0) {
      return res.status(405).json({ error: "Invalid OTP or Invalid Email id" });
    }

    const otpExpires = results[0].expireotp;
    if (new Date(otpExpires) < new Date()) {
      return res.status(410).json({ error: "OTP expired" });
    }

    const updateQuery = "UPDATE useremailverification SET otp = NULL, expireotp = NULL, gmail = NULL WHERE gmail = $1";
    await connectionUserdb.query(updateQuery, [email]);

    return res.status(200).json({ message: "OTP verified and reset successfully" });
  } catch (err) {
    console.error("Internal Error:", err);
    return res.status(500).json({ error: "Internal Server Error" });
  }
};

exports.signup = async (req, res) => {
  const { firstname, lastname, gmail, rollno, password, passwordcheck } = req.body;

  if (!firstname || !lastname || !gmail || !rollno || !password || !passwordcheck) {
    return res.status(400).json({ error: "All fields are required" });
  }

  if (password !== passwordcheck) {
    return res.status(400).json({ error: "Passwords do not match" });
  }

  try {
    const checkQuery = "SELECT * FROM users WHERE gmail = $1";
    const [emailResults] = await connectionUserdb.query(checkQuery, [gmail]);

    if (emailResults.length > 0) {
      return res.status(409).json({ error: "Email already exists" });
    }

    const checkQueryRoll = "SELECT * FROM users WHERE rollno = $1";
    const [rollnoResults] = await connectionUserdb.query(checkQueryRoll, [rollno]);

    if (rollnoResults.length > 0) {
      return res.status(408).json({ error: "Roll number already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const query = "INSERT INTO users (firstname, lastname, gmail, rollno, password, passwordcheck) VALUES($1, $2, $3, $4, $5, $6)";
    await connectionUserdb.query(query, [firstname, lastname, gmail, rollno, hashedPassword, passwordcheck]);

    return res.status(201).json({ message: "User registered successfully" });
  } catch (err) {
    console.error("Error during signup:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
};

exports.login = async (req, res) => {
  const { gmail, password } = req.body;
  
  if (!req.session.isVerified && process.env.NODE_ENV === "production") {
    return res.status(403).json({ success: false, message: "CAPTCHA verification required" });
  }
  
  try {
    const query = "SELECT * FROM users WHERE gmail = $1";
    const [results] = await connectionUserdb.query(query, [gmail]);
    
    if (results.length > 0) {
      const user = results[0];
      const isPasswordMatch = await bcrypt.compare(password, user.password);
      
      if(isPasswordMatch) {
        const token = jwt.sign({ id: user.id, avatar_url: user.avatar_url }, JWT_SECRET, { expiresIn: "7d" });

        res.cookie("token", token, {
          httpOnly: true,
          secure: process.env.NODE_ENV === "production", 
          sameSite: process.env.NODE_ENV === "production" ? "None" : "Lax",
          domain: process.env.NODE_ENV === "production" ? ".studyvault.space" : undefined,
          maxAge: 1000 * 60 * 60 * 24, 
        });
        req.session.isVerified = false;
        res.status(200).json({ success: true, token });
      } else {
        res.status(300).json({ error: "Invalid password" });
      }
    } else {
      res.status(401).json({ error: "You are not registered" });
    }
  } catch (err) {
    console.error("Error retrieving data:", err);
    res.status(500).json({ error: "Internal Server Error" });
  }
};

exports.logout = (req, res) => {
  let cookieOptions = {
    httpOnly: true,                        
    secure: process.env.NODE_ENV === "production", 
    sameSite: "Strict",
    path: "/"                             
  };
  res.clearCookie("token", cookieOptions);
  res.status(200).json({ success: true });
};

exports.signupCheck = async (req, res) => {
  try {
    const query = "SELECT * FROM users WHERE id = $1";
    const [results] = await connectionUserdb.query(query, [req.user.id]);

    if (results.length > 0) {
      res.status(200).json({ message: "user is available" });
    } else {
      res.status(404).json({ error: "User not found" });
    }
  } catch(err) {
    console.error("Error retrieving user data", err);
    return res.status(500).json({ error: "Internal Server Error" });
  }
};

exports.userCheck = async (req, res) => {
  if (!req.user || !req.user.id) {
    return res.status(400).json({ error: "Invalid user information in token" });
  }
  try {
    const query = "SELECT * FROM users WHERE id = $1";
    const [results] = await connectionUserdb.query(query, [req.user.id]);

    if (results.length > 0) {
      return res.status(200).json({ success: true });
    } else {
      return res.status(404).json({ message: "User not found" });
    }
  } catch(err) {
    console.error("Error retrieving user data", err);
    return res.status(500).json({ error: "Internal Server Error" });
  }
};

exports.loginCheckFilter = async (req, res) => {
  if (!req.user || !req.user.id) {
    return res.status(400).json({ error: "Invalid user information in token" });
  }
  try {
    const query = "SELECT * FROM users WHERE id = $1";
    const [results] = await connectionUserdb.query(query, [req.user.id]);

    if (results.length > 0) {
      return res.status(200).json({ message: "Successful" });
    }
    return res.status(404).json({ error: "User not found" });
  } catch (err) {
    console.error("Error retrieving user data:", err);
    return res.status(500).json({ error: "Internal Server Error" });
  }
};

exports.loginCheckContext = async (req, res) => {
  try {
    const query = "SELECT * FROM users WHERE id = $1";
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
};

exports.forgotPassword = async (req, res) => {
  const { email } = req.body;

  try {
    const [results] = await connectionUserdb.query("SELECT * FROM users WHERE gmail = $1", [email]);
    if (results.length === 0) {
      return res.status(409).json({ error: "Email not found" });
    }

    const user = results[0];
    const now = new Date();
    const lastOtpTime = new Date(user.lastOtpTime);

    if (user.lastOtpTime && now - lastOtpTime < 30000) {
      return res.status(429).json({
        error: "OTP already sent. Please wait 30 seconds before requesting another OTP",
      });
    }

    const otp = crypto.randomInt(100000, 999999).toString();
    const otpExpires = new Date(Date.now() + 10 * 60000); 

    await connectionUserdb.query(
      "UPDATE users SET otp = $1, otpExpires = $2, lastOtpTime = $3 WHERE gmail = $4",
      [otp, otpExpires, now, email]
    );

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

    transporter.sendMail(mailOptions, (err, info) => {
      if (err) {
        console.error("Email sending error:", err);
        return res.status(500).json({ error: "Email sending error" });
      }
      return res.status(200).json("OTP sent");
    });
  } catch (err) {
    console.error("Error handling request:", err);
    return res.status(500).json({ error: "Database or server error" });
  }
};

exports.verifyForgotOtp = async (req, res) => {
  const { otp, email } = req.body;

  try {
    const [results] = await connectionUserdb.query(
      "SELECT * FROM users WHERE gmail = $1 AND otp = $2",
      [email, otp]
    );

    if (results.length === 0) {
      return res.status(409).json({ error: "Incorrect OTP" });
    }

    const otpExpires = results[0].otpExpires;
    if (new Date(otpExpires) < new Date()) {
      return res.status(410).json({ error: "OTP expired" });
    }

    const [, updateResults] = await connectionUserdb.query(
      "UPDATE users SET otp = NULL, otpExpires = NULL, lastOtpTime = NULL WHERE gmail = $1",
      [email]
    );

    if (updateResults.rowCount === 0) {
      return res.status(500).json({ error: "Error updating database" });
    }

    return res.status(200).json({ message: "OTP verified and reset successfully" });
  } catch (err) {
    console.error("Error verifying OTP:", err);
    return res.status(500).json({ error: "Internal error" });
  }
};

exports.resetPassword = async (req, res) => {
  const { email, resetPassword } = req.body;

  try {
    const hashedPassword = await bcrypt.hash(resetPassword, 10);
    const query = "UPDATE users SET password = $1, passwordcheck = $2 WHERE gmail = $3";
    await connectionUserdb.query(query, [hashedPassword, hashedPassword, email]);

    return res.status(200).json({ message: "Update password successfully" });
  } catch (err) {
    console.error("Error inserting in database", err);
    return res.status(500).json({ error: "Error inserting in database" });
  }
};

exports.googleAuth = async (req, res) => {
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
    const { name, email, picture, sub } = payload;

    try {
      const query = "SELECT * FROM users WHERE google_id = $1 OR gmail = $2";
      const [results] = await connectionUserdb.query(query, [sub, email]);

      if (results.length > 0) {
        const user = results[0];
        const authToken = jwt.sign({ id: user.id, avatar_url: user.avatar_url }, JWT_SECRET, { expiresIn: "7d" });

        res.cookie("token", authToken, {
          httpOnly: true,
          secure: process.env.NODE_ENV === "production", 
          sameSite: process.env.NODE_ENV === "production" ? "None" : "Lax",
          domain: process.env.NODE_ENV === "production" ? ".studyvault.space" : undefined,
          maxAge: 1000 * 60 * 60 * 24, 
        });

        res.json({ success: true, message: "Login successful", user: results[0] });
      } else {
        const loginquery = "INSERT INTO users (google_id, firstname, gmail, picture) VALUES ($1, $2, $3, $4) RETURNING *";
        try {
          const [insertResults] = await connectionUserdb.query(loginquery, [sub, name, email, picture]);
          const user = insertResults[0];

          const authToken = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: "7d" });

          res.cookie("token", authToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production", 
            sameSite: process.env.NODE_ENV === "production" ? "None" : "Lax",
            domain: process.env.NODE_ENV === "production" ? ".studyvault.space" : undefined,
            maxAge: 1000 * 60 * 60 * 24, 
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
        } catch (err) {
          console.error("Insert error:", err);
          return res.status(500).json({ message: "Error saving user" });
        }
      }
    } catch (err) {
      console.error("Token verification error:", err);
      res.status(401).json({ message: "Invalid token" });
    }   
  } catch (error) {
    console.error("Error verifying token:", error);
    res.status(401).json({ message: "Invalid token" });
  }
};
