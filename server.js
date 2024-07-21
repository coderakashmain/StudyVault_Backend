const express = require('express');
const cors = require('cors');
const connection = require('./db');
const jwt = require('jsonwebtoken');


const app = express();
const SECRET_KEY = '6370';

app.use(cors());
app.use(express.json());

app.post('/api/LogIn/Signup', (req, res) => {
    const { firstname, lastname, gmail, rollno, password, passwordcheck } = req.body;

    const checkQuery = 'SELECT * FROM users WHERE gmail = ?';
    connection.query(checkQuery, [gmail], (err, results) => {
        if (err) {
            console.error('Error checking email:', err);
            return res.status(500).json({ error: 'Internal server error' });
        }
        if (results.length > 0) {
            return res.status(409).json({ error: 'Email already exists' });
        }

        const query = 'INSERT INTO users (firstname, lastname, gmail, rollno, password, passwordcheck) VALUES(?,?,?,?,?,?)';
        connection.query(query, [firstname, lastname, gmail, rollno, password, passwordcheck], (err, results) => {
            if (err) {
                console.error('Error inserting data:', err);
                return res.status(500).json({ error: 'Internal server error' });
            }
            res.json({ message: 'User registered successfully' });
        });
    });
});
app.post('/api/LogIn', (req,res)=>{
    const {gmail,password} = req.body;

    const query = 'SELECT * FROM users WHERE gmail = ? AND PASSWORD =?';

    connection.query(query,[gmail,password], (err,results)=>{
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

const port = process.env.PORT || 3000;


app.listen(port,()=>{
    console.log(`The website is running on port ${port}`);
  
});