const express = require('express');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const {connectionUserdb,connectionPaperdb} = require('./db');
const jwt = require('jsonwebtoken');
const { error } = require('console');


const app = express();
const SECRET_KEY = '6370';

app.use(cors());
app.use(express.json());

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

    const query = 'SELECT * FROM users WHERE gmail = ? AND PASSWORD =?';

    connectionUserdb.query(query,[gmail,password], (err,results)=>{
        if(err){
            console.log('Error retrieving data', err);
            return res.status(500).json({error :'Internal Server Error'})
        }
        if(results.length > 0){
            const user = results[0];
            const token = jwt.sign({ id: user.id }, SECRET_KEY, { expiresIn: '24h' });
            res.status(200).json({ success: true, token, user });
        }else{
            res.status(401).json ({error : 'Invalid credentials'});
        }
    });
});

// Paper PDF BACKEND   


app.get('/api/Filter', (req, res) => {
  
    let query = 'SELECT * FROM papers WHERE 1=1';
    const params = [];
  
    if (req.query.departmentName) {
        query += ' AND departmentName = ?';
        params.push(req.query.departmentName);
      }
      if (req.query.educationLevel) {
        query += ' AND educationLevel = ?';
        params.push(req.query.educationLevel);
      }
      if (req.query.fromDate) {
        query += ' AND year >= ?';
        params.push(req.query.fromDate);
      }
    
      if (req.query.toDate) {
        query += ' AND year < ?';
        params.push(req.query.toDate);
      }  
    
      if (req.query.departmentYear) {
        query += ' AND departmentYear = ?';
        params.push(req.query.departmentYear);
      }
    
    
        if (req.query.sem === 'true') {
            query += ' AND sem = true';
            params.push(req.query.sem);
        }
        if (req.query.midSem === 'true') {
            query += ' AND midSem = true';
            params.push(req.query.midSem);
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

app.post('/api/Profile', upload.single('file'), (req, res) => {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded or invalid file type' });
    }
  
    const { filename, path: filepath } = req.file;
  
   
    const query = 'INSERT INTO papers (filename, filepath) VALUES (?, ?)';
    connectionPaperdb.query(query, [filename, filepath], (err, results) => {
      if (err) {
        console.error('Error saving file info to database:', err);
        return res.status(500).json({ error: 'Internal Server Error' });
      }
      res.status(200).json({ message: 'File uploaded and saved successfully', filePath: filepath });
    });
  });

  app.get('/api/Profile', (req, res) => {
    const query = 'SELECT * FROM papers';
  
    connectionPaperdb.query(query, (err, results) => {
      if (err) {
        console.error('Error fetching files from database:', err);
        return res.status(500).json({ error: 'Internal Server Error' });
      }
      res.status(200).json(results);
    });
  });

const port = process.env.PORT || 3000;


app.listen(port,()=>{
    console.log(`The website is running on port ${port}`);
  
});