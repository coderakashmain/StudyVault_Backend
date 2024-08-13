const { connectionPaperdb } = require('../../db');

const filterPapers = async (req, res) => {
  try {
    const { department, year } = req.query;
    let query = 'SELECT * FROM papers WHERE 1=1';
    const params = [];

    if (department) {
      query += ' AND department = ?';
      params.push(department);
    }
    if (year) {
      query += ' AND year = ?';
      params.push(year);
    }

    connectionPaperdb.query(query, params, (err, results) => {
      if (err) {
        console.error('Error fetching papers:', err);
        return res.status(500).json({ error: 'Internal server error' });
      }
      res.status(200).json(results);
    });
  } catch (error) {
    console.error('Error in filterPapers:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
};

const uploadPaper = (req, res) => {
  try {
    const { title, department, year } = req.body;
    const filename = req.file.filename;

    const query = 'INSERT INTO papers (title, department, year, filename) VALUES (?, ?, ?, ?)';
    connectionPaperdb.query(query, [title, department, year, filename], (err, results) => {
      if (err) {
        console.error('Error uploading paper:', err);
        return res.status(500).json({ error: 'Internal server error' });
      }
      res.status(201).json({ message: 'Paper uploaded successfully' });
    });
  } catch (error) {
    console.error('Error in uploadPaper:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
};

const getPapers = async (req, res) => {
  try {
    const query = 'SELECT * FROM papers';
    connectionPaperdb.query(query, (err, results) => {
      if (err) {
        console.error('Error fetching papers:', err);
        return res.status(500).json({ error: 'Internal server error' });
      }
      res.status(200).json(results);
    });
  } catch (error) {
    console.error('Error in getPapers:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
};

module.exports = {
  filterPapers,
  uploadPaper,
  getPapers,
};