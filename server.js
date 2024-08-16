require('dotenv').config();
const express = require('express');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const {connectionUserdb,connectionPaperdb} = require('./db');
const jwt = require('jsonwebtoken');
// const { error } = require('console');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const bodyParser = require('body-parser');
const { error } = require('console');
const cookieParser = require('cookie-parser');


const app = express();
const SECRET_KEY = process.env.SECRET_KEYP;

app.use(cors());
app.use(express.json());
app.use(bodyParser.json());
app.use(cookieParser());



const transporter = nodemailer.createTransport({
  service : 'gmail',
  auth : {
    user : process.env.EMAIL_USER,
    pass : process.env.EMAIL_PASS
  }
});




app.post('/api/LogIn/Signup/otpVarify',(req,res)=>{

  const {email} = req.body;

  const query = 'INSERT INTO useremailverification (gmail) VALUES(?)';

  connectionUserdb.query(query,[email],(err,results)=>{

    if(err){
      console.error('Error in inserting',err);
      return res.status(420).json({ error: 'Internal server error' });
        }

     else{
          return res.status(201).json ({message : 'Insert to database'});
        }
  });

  
 
  

  const otp = crypto.randomInt(100000, 999999).toString();
  const otpExpires  = new Date(Date.now() + 10 * 60000);

  const verifyquery = 'UPDATE useremailverification SET otp = ?, expireotp = ? WHERE gmail = ?';

  connectionUserdb.query(verifyquery,[otp,otpExpires,email],(err,results)=>{
    if(err) {
      console.error('Error in Database', err);
      return res.status(410).json({error : 'Database error'});
    }
    const mailOptions = {
      to: email,
      from: process.env.EMAIL_USER,
      subject: "StudyVault OTP for verify Email",
      html: `
              <html>
      <body style="font-family: Arial, sans-serif; color: #333;">
        <div style="width: 80vw; margin: auto; border: 1px solid gray; border-radius: 4px; padding: 20px;">
          <h1 style="text-align: center;">Welcome to StudyVault</h1>
          <p style="text-align: center;font-size : 1.1rem"> Hi</p>
          <p>You requested to verify your email. Please use the following One-Time Password (OTP) to verify your email:</p>
          <h2 style="text-align: center; margin: auto ; font-size : 2.4rem;">${otp}</h2>
          <p>The OTP is valid for the next 10 minutes. If you did not request a verify you email, please ignore this email.</p>
          <h4>Best regards,</h4>
          <h4>The StudyVault Team</h4>
        </div>
      </body>
    </html>
`,
    };
    console.log(mailOptions);

    transporter.sendMail(mailOptions, (err, info) => {
      if (err) {
        console.error('Email sending error:', err);
        return res.status(500).json({ error: 'Email sending error' });
      }
      console.log('Email sent:', info.response);
      return res.status(200).json('OTP sent');
    });


  
  });
  
});


app.post('/api/LogIn/Signup/otpVarify/confirm',(req,res)=>{

  const {email,otp} = req.body;
  const checkquery = 'SELECT * FROM useremailverification WHERE gmail = ? AND otp = ?';

  connectionUserdb.query(checkquery,[email,otp],(err,results)=>{
      if(err){
        console.error('Internal Error',err);
        res.status(500).json({error : 'Inernal Error'});
      }


      if(results.length > 0){
        const otpExpires = results[0].expireotp;
        console.log(results.length);
        if(new Date(otpExpires) < new Date()){
          return res.status(410).json({error : 'OTP expired'});
        } 
        
        const upadateQuery = 'UPDATE useremailverification SET otp = NULL , expireotp = NULL,gmail = NULL WHERE gmail = ?';

        connectionUserdb.query(upadateQuery,[otp,otpExpires,email],(err,results)=>{
          if(err){
            console.error('Error updating database', err);
            return res.status(409).json({ error: 'Error updating database' });
          }
          return  res.status(200).json({message : 'OTP verified and reset successfully'});
        })
      }
      else{
          console.error('Invalid OTP',err);
          res.status(405).json({error : 'Invalid OTP or Invalid Email id'});
      }


  });
})


app.post('/api/LogIn/Signup', (req, res) => {
    const { firstname, lastname, gmail, rollno, password, passwordcheck } = req.body;

    const checkQuery = 'SELECT * FROM users WHERE gmail = ?';
    connectionUserdb.query(checkQuery, [gmail], (err, results) => {
        if (err) {
            console.error('Error checking email:', err);
            return res.status(500).json({ error: 'Internal server error' });
        }
        if (results.length > 0) {
            return res.status(409).json({ error: 'Email already exists' });
        }

      
        const checkqueryroll = 'SELECT * FROM users WHERE rollno = ?';
        connectionUserdb.query(checkqueryroll,[rollno],(err,results)=>{
          if(err){
            console.error('Error checking rollno:',err);
            return res.status(500).json({error : 'Intenal server error'});
          };
          if(results.length > 0){
            return res.status(408).json({ error: 'rollno already exists' });
          }
        

        const query = 'INSERT INTO users (firstname, lastname, gmail, rollno, password, passwordcheck) VALUES(?,?,?,?,?,?)';
        connectionUserdb.query(query, [firstname, lastname, gmail, rollno, password, passwordcheck], (err, results) => {
            if (err) {
                console.error('Error inserting data:', err);
                return res.status(500).json({ error: 'Internal server error' });
            }
            res.json({ message: 'User registered successfully' });
        });
      });
    });
});




app.post('/api/LogIn', (req,res)=>{
    const {gmail,password} = req.body;

    const query = 'SELECT * FROM users WHERE gmail = ? AND password =?';

    connectionUserdb.query(query,[gmail,password], (err,results)=>{
        if(err){
            console.log('Error retrieving data', err);
            return res.status(500).json({error :'Internal Server Error'})
        }
        if(results.length > 0){
            const user = results[0];
            const token = jwt.sign({ id: user.id }, SECRET_KEY, { expiresIn: '1h' });

            res.cookie('token', token, {
              httpOnly: true,
              secure: process.env.NODE_ENV === 'production', // Set to true in production
              maxAge: 3600000 // 1 hour in milliseconds
          });
            res.status(200).json({ success: true, user });
        }else{
            res.status(401).json ({error : 'Invalid credentials'});
        }
    });
});

function authenticateToken(req, res, next) {
  const token = req.cookies.token;

  if (!token) {
      return res.status(401).json({ error: 'Unauthorized' });
  }

  jwt.verify(token, SECRET_KEY, (err, user) => {
      if (err) {
          return res.status(403).json({ error: 'Forbidden' });
      }
      req.user = user;
      next();
  });
}

app.get('/api/profile',authenticateToken, (req, res) => {

  // const token = req.cookies.token;
  //   if (!token) {
  //       return res.status(401).json({ error: 'Unauthorized' });
  //   }
  // try {
    // const decoded = jwt.verify(token,SECRET_KEY);
    const query = 'SELECT * FROM users WHERE id = ?';

    connectionUserdb.query(query, [req.user.id], (err, results) => {
        if (err) {
            console.log('Error retrieving user data', err);
            return res.status(500).json({ error: 'Internal Server Error' });
        }

        if (results.length > 0) {
            const user = results[0];
            res.status(200).json({ user });
        } else {
            res.status(404).json({ error: 'User not found' });
        }
    })
//   }
//   catch (err) {
//     res.status(401).json({ error: 'Invalid token' });
// }
});

app.get('/api/profile',authenticateToken, (req, res) => {

  // const token = req.cookies.token;
  //   if (!token) {
  //       return res.status(401).json({ error: 'Unauthorized' });
  //   }
  // try {
    // const decoded = jwt.verify(token,SECRET_KEY);
    const query = 'SELECT * FROM users WHERE id = ?';

    connectionUserdb.query(query, [req.user.id], (err, results) => {
        if (err) {
            console.log('Error retrieving user data', err);
            return res.status(500).json({ error: 'Internal Server Error' });
        }

        if (results.length > 0) {
            const user = results[0];
            res.status(200).json({ user });
        } else {
            res.status(404).json({ error: 'User not found' });
        }
    })
//   }
//   catch (err) {
//     res.status(401).json({ error: 'Invalid token' });
// }
});





// app.get('/api/dptlist',authenticateToken, (req, res) => {
//       const query = 'SELECT * FROM users WHERE id = ?';

//       connectionUserdb.query(query, [req.user.id], (err, results) => {
//           if (err) {
//               console.log('Error retrieving user data', err);
//               return res.status(500).json({ error: 'Internal Server Error' });
//           }

//           if (results.length > 0) {
//               const user = results[0];
//               console.log(user);
//               return res.status(200).json({ success : true });
//           } else {
//               return res.status(404).json({ message: 'User not found' });
//           }
//       });
// });



app.get('/api/navbar',authenticateToken, (req, res) => {
  // const token = req.cookies.token;
  // console.log("Token received:", token);  // Debugging

  // if (!token) {
  //     return res.status(401).json({ isAuthenticated: false, message: 'Unauthorized' });
  // }
  
  // try {
  //     const decoded = jwt.verify(token, SECRET_KEY);
  //     console.log("Decoded token:", decoded);  // Debugging
      const query = 'SELECT * FROM users WHERE id = ?';

      connectionUserdb.query(query, [req.user.id], (err, results) => {
          if (err) {
              console.log('Error retrieving user data', err);
              return res.status(500).json({ error: 'Internal Server Error' });
          }

          if (results.length > 0) {
              const user = results[0];
              console.log(user);
              return res.status(200).json({ success : true });
          } else {
              return res.status(404).json({ message: 'User not found' });
          }
      });
  // } catch (err) {
  //     console.log('Invalid token:', err.message);  // Debugging
  //     return res.status(401).json({ isAuthenticated: false, message: 'Invalid token' });
  // }
});

app.post('/api/logOut', (req, res) => {
  res.clearCookie('token');
  res.status(200).json({ success: true });
});

// Paper PDF BACKEND   


app.get('/api/Filter', (req, res) => {
  
    let query = 'SELECT * FROM papers WHERE 1=1';
    const params = [];
  
    if (req.query.departmentName) {
        query += ' AND departmentName = ?';
        params.push(req.query.departmentName);
      }

      if (req.query.educationLevelug === 'ug' || req.query.educationLevelpg === 'pg') {
        let educationLevels = [];
        if (req.query.educationLevelug === 'ug') {
          educationLevels.push('ug');
        }
        if (req.query.educationLevelpg === 'pg') {
          educationLevels.push('pg');
        }
        if (educationLevels.length > 0) {
          query += ' AND educationLevel IN (?)';
          params.push(educationLevels);
        }
      }
     
      if (req.query.fromDate) {
        query += ' AND years >= ?';
        params.push(req.query.fromDate);
      }
    
      if (req.query.toDate) {
        query += ' AND years < ?';
        params.push(req.query.toDate);
      }  
    
      if (req.query.departmentYear) {
        query += ' AND departmentYear = ?';
        params.push(req.query.departmentYear);
      }
      
        if(req.query.sem === 'true' || req.query.midSem === 'true' ){

          
          let conditions = [];
          if (req.query.sem === 'true') {

            conditions.push('sem = true');
            
            // params.push(req.query.sem);
        }

        if (req.query.midSem === 'true') {
    
          conditions.push('midSem = true');

          // params.push(req.query.midSem);
        }

        if(conditions.length > 0){
          query += ' AND (' + conditions.join(' OR ') + ')';
          params.push(conditions);
        }
       }
    
       
        
        if (params.length === 0 && !req.query.sem && !req.query.midSem) {
            return res.status(400).json({ error: 'No filter parameters provided' });
        }
    console.log('Executing query:', query);
    console.log('With parameters:', params);
  
    connectionPaperdb.query(query, params, (err, results) => {
      if (err) {
        console.error('Error fetching papers:', err);
        return res.status(500).json({ error: 'Internal Server Error' });
      }
      res.json(results);
    });
});

//Upload pdf

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = path.join(__dirname, 'uploads');
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    cb(null, `${Date.now()}-${file.originalname}`);
  },
});

const upload = multer({ storage });

app.post('/api/Profile', upload.single('file'), (req, res) => {
    // if (!req.file) {
    //   return res.status(400).json({ error: 'No file uploaded or invalid file type' });
    // }
  
    // const { filename, path: filepath } = req.file;
  
   
    // const query = 'INSERT INTO papers (filename, filepath) VALUES (?, ?)';
    // connectionPaperdb.query(query, [filename, filepath], (err, results) => {
    //   if (err) {
    //     console.error('Error saving file info to database:', err);
    //     return res.status(500).json({ error: 'Internal Server Error' });
    //   }
    //   res.status(200).json({ message: 'File uploaded and saved successfully', filepath: filepath });
    // });
  });

  app.get('/api/Profile', (req, res) => {


    res.status(200).json(results);
    // const query = 'SELECT * FROM papers';
  
    // connectionPaperdb.query(query, (err, results) => {
    //   if (err) {
    //     console.error('Error fetching files from database:', err);
    //     return res.status(500).json({ error: 'Internal Server Error' });
    //   }
    //   res.status(200).json(results);
    // });
  });


  // Forgate page


  

  app.post('/api/LogIn/ForgatePw',(req,res)=>{
    
    const {email} = req.body;
   

      


    const checkquery = 'SELECT * FROM users WHERE gmail = ?';
    connectionUserdb.query(checkquery,[email],(err,results)=>{
      const param=[];
        if(err){
          console.error('Database error',err);
          return res.status(500).json({ error : 'Database error'})
        }
        if(results.length   === 0){
          return res.status(409).json({error : 'Email not found'});
        }

        const user = results[0];
        const now = new Date();
        const lastOtpTime = new Date(user.lastOtpTime);
        if(user.lastOtpTime && (now - lastOtpTime) < 30000){
          return res.status(429).json({error : 'OTP already sent. Please wait 30 seconds before requesting another OTP'});
        }
        const firstname = results[0].firstname;
        const lastname = results[0].lastname;

        param.push(email);
        console.log(param);
        const otp = crypto.randomInt(100000, 999999).toString();
        const otpExpires  = new Date(Date.now() + 10 * 60000);

        const query = 'UPDATE users SET otp = ?, otpExpires = ?, lastOtpTime = ? WHERE gmail = ?';

        connectionUserdb.query(query,[otp,otpExpires,now,email],(err,results)=>{
          if(err) {
            console.error('Error in Database', err);
            return res.status(410).json({error : 'Database error'});
          }


          const mailOptions = {
            to: email,
            from: process.env.EMAIL_USER,
            subject: "StudyVault Password Reset OTP",
            html: `
                    <html>
            <body style="font-family: Arial, sans-serif; color: #333;">
              <div style="width: 80vw; margin: auto; border: 1px solid gray; border-radius: 4px; padding: 20px;">
                <h1 style="text-align: center;">Welcome to StudyVault</h1>
                <p style="text-align: center;font-size : 1.1rem"> Hi, ${firstname} ${lastname}</p>
                <p>You requested to reset your password. Please use the following One-Time Password (OTP) to reset your password:</p>
                <h2 style="text-align: center; margin: auto ; font-size : 2.4rem;">${otp}</h2>
                <p>The OTP is valid for the next 10 minutes. If you did not request a password reset, please ignore this email.</p>
                <h4>Best regards,</h4>
                <h4>The StudyVault Team</h4>
              </div>
            </body>
          </html>
  `,
          };
          console.log(mailOptions);

          transporter.sendMail(mailOptions, (err, info) => {
            if (err) {
              console.error('Email sending error:', err);
              return res.status(500).json({ error: 'Email sending error' });
            }
            console.log('Email sent:', info.response);
            return res.status(200).json('OTP sent');
          });
        });

    });

  });

  app.post('/api/LogIn/verifyOtp',(req,res)=>{
    const {otp,email} = req.body;
    const checkquery = 'SELECT * FROM users WHERE gmail = ? AND otp = ?';
    connectionUserdb.query(checkquery,[email,otp],(err,results)=>{

      if(err){
        console.error('Database query error:',err);
        return res.status(500).json({error : 'Internal error '});
        
      }
      if(results.length > 0){
        const otpExpires = results[0].otpExpires;
        console.log(results.length);
        if(new Date(otpExpires) < new Date()){
          return res.status(410).json({error : 'OTP expired'});
        } 
        
        const upadateQuery = 'UPDATE users SET otp = NULL , otpExpires = NULL, lastOtpTime = NULL WHERE gmail = ?';

        connectionUserdb.query(upadateQuery,[email],(err,results)=>{
          if(err){
            console.error('Error updating database', err);
            return res.status(500).json({ error: 'Error updating database' });
          }
          
          return  res.status(200).json({message : 'OTP verified and reset successfully'});
        });
        
        

      }
      else{
        console.error('Incorrect OTP',err);
        return res.status(409).json({error : 'Incorrect OTP'});
      };
    });
    
  });

  app.post('/api/LogIn/ForgatePw/ResetPassword',(req,res)=>{
    const {email,resetPassword} = req.body;
    const query = 'UPDATE users SET password = ?, passwordcheck = ? WHERE gmail = ?';

    connectionUserdb.query(query,[resetPassword,resetPassword,email],(err,results)=>{
      if(err){
        console.error('Error inserting in database',err);
        return res.status(500).json({error : 'Error inserting in database'});
      }
      
      return res.status(200).json({message : 'Update password successfully'});

    })
  })

const port = process.env.PORT || 3001;


app.listen(port,()=>{
    console.log(`The website is running on port ${port}`);
  
});