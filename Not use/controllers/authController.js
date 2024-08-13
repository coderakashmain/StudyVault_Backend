// const jwt = require('jsonwebtoken');
// const { connectionUserdb } = require('../db');
// const { hashPassword, comparePassword } = require('../services/passwordService');






const jwt = require('jsonwebtoken');
const { connectionUserdb } = require('../../db');
const { hashPassword, comparePassword } = require('../services/passwordService');

const signup = async (req, res) => {
  try {
    const { firstname, lastname, gmail, rollno, password, passwordcheck } = req.body;
    // Validate input
    if (password !== passwordcheck) {
      return res.status(400).json({ error: 'Passwords do not match' });
    }
    // Check if email or roll number exists
    const emailExists = await checkEmailExists(gmail);
    const rollnoExists = await checkRollnoExists(rollno);

    if (emailExists) {
      return res.status(409).json({ error: 'Email already exists' });
    }
    if (rollnoExists) {
      return res.status(409).json({ error: 'Roll number already exists' });
    }

    const hashedPassword = await hashPassword(password);
    const query = 'INSERT INTO users (firstname, lastname, gmail, rollno, password) VALUES(?,?,?,?,?)';
    connectionUserdb.query(query, [firstname, lastname, gmail, rollno, hashedPassword], (err, results) => {
      if (err) {
        console.error('Error inserting data:', err);
        return res.status(500).json({ error: 'Internal server error' });
      }
      res.status(201).json({ message: 'User registered successfully' });
    });
  } catch (error) {
    console.error('Error in signup:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
};

const login = async (req, res) => {
  try {
    const { gmail, password } = req.body;
    const query = 'SELECT * FROM users WHERE gmail = ?';

    connectionUserdb.query(query, [gmail], async (err, results) => {
      if (err) {
        console.error('Error retrieving data', err);
        return res.status(500).json({ error: 'Internal Server Error' });
      }
      if (results.length > 0) {
        const user = results[0];
        const passwordMatch = await comparePassword(password, user.password);

        if (!passwordMatch) {
          return res.status(401).json({ error: 'Invalid credentials' });
        }

        const token = jwt.sign({ id: user.id }, process.env.SECRET_KEY, { expiresIn: '1h' });
        res.status(200).json({ success: true, token, user });
      } else {
        res.status(401).json({ error: 'Invalid credentials' });
      }
    });
  } catch (error) {
    console.error('Error in login:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
};

const checkEmailExists = (email) => {
  return new Promise((resolve, reject) => {
    const query = 'SELECT * FROM users WHERE gmail = ?';
    connectionUserdb.query(query, [email], (err, results) => {
      if (err) reject(err);
      resolve(results.length > 0);
    });
  });
};

const checkRollnoExists = (rollno) => {
  return new Promise((resolve, reject) => {
    const query = 'SELECT * FROM users WHERE rollno = ?';
    connectionUserdb.query(query, [rollno], (err, results) => {
      if (err) reject(err);
      resolve(results.length > 0);
    });
  });
};

module.exports = {
  signup,
  login,
};