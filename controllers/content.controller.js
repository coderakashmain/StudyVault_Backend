const connectionUserdb = require("../config/db");

exports.filterPapers = async (req, res) => {
  let query = "SELECT * FROM papers WHERE 1=1";
  const params = [];
  let paramIndex = 1;

  try {
    if (req.query.departmentName) {
      query += ` AND departmentName = $${paramIndex++}`;
      params.push(req.query.departmentName);
    }

    if (req.query.educationLevelug === "ug" || req.query.educationLevelpg === "pg") {
      let educationLevels = [];
      if (req.query.educationLevelug === "ug") {
        educationLevels.push("ug");
      }
      if (req.query.educationLevelpg === "pg") {
        educationLevels.push("pg");
      }

      if (educationLevels.length > 0) {
        query += ` AND educationLevel = ANY($${paramIndex++}::text[])`; 
        params.push(educationLevels);
      }
    }

    if (req.query.fromDate) {
      query += ` AND years >= $${paramIndex++}`;
      params.push(req.query.fromDate);
    }

    if (req.query.toDate) {
      query += ` AND years <= $${paramIndex++}`;
      params.push(req.query.toDate);
    }

    if (req.query.departmentYear) {
      query += ` AND departmentYear = $${paramIndex++}`;
      params.push(req.query.departmentYear);
    }

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

    if (params.length === 0 && !req.query.sem && !req.query.midSem) {
      return res.status(400).json({ error: "No filter parameters provided" });
    }

    const [results] = await connectionUserdb.query(query, params);
    res.status(200).json(results);
  } catch (err) {
    console.error("Error fetching papers:", err);
    res.status(500).json({ error: "Internal Server Error" });
  }
};

exports.getSyllabus = async (req, res) => {
  let query = "SELECT * FROM syllabus WHERE 1=1";
  const params = [];
  let paramIndex = 1;

  try {
    if (req.query.Educationlavel) {
      query += ` AND EducationalLable = $${paramIndex++}`;
      params.push(req.query.Educationlavel);
    }
    
    if (req.query.Stream) {
      query += ` AND Stream = $${paramIndex++}`;
      params.push(req.query.Stream);
    }

    if (params.length === 0 && (!req.query.Educationlavel && !req.query.Stream)) {
      return res.status(400).json({ error: "No filter parameters provided" });
    }

    const [results] = await connectionUserdb.query(query, params);
    res.status(200).json(results);
  } catch (err) {
    console.error("Error fetching syllabus:", err);
    res.status(500).json({ error: "Internal Server Error" });
  }
};

exports.getNotes = async (req, res) => {
  let query = "SELECT * FROM notes";
  try {
    const [results] = await connectionUserdb.query(query); 
    res.status(200).json(results);
  } catch (err) {
    console.error("Error fetching notes:", err);
    return res.status(500).json({ error: "Internal Server Error" });
  }
};

exports.noteClickCount = async (req, res) => {
  const { id } = req.body;
  try {
    await connectionUserdb.query('UPDATE notes SET totalClicks = COALESCE(totalClicks, 0) + 1 WHERE id = $1', [id]);
    const [results] = await connectionUserdb.query('SELECT totalClicks FROM notes WHERE id = $1', [id]);
    
    res.json({ count: results[0]?.totalclicks || results[0]?.totalClicks });
  } catch (err) {
    console.error("Database error:", err);
    res.status(500).send("Error updating click count");
  }
};

exports.noteDownloadCount = async (req, res) => {
  const { id, filename, unit, fileUrl } = req.body;
  const userid = req.user.id;
 
  try {
    await connectionUserdb.query(
      'UPDATE notes SET totaldownload = COALESCE(totaldownload, 0) + 1 WHERE id = $1',
      [id]
    );

    await connectionUserdb.query(
      `
      INSERT INTO notedownloads (user_id, note_id, note_full_name, note_unit, download_url, downloaded_at)
      VALUES ($1, $2, $3, $4, $5, NOW())
      `,
      [userid, id, filename, unit, fileUrl]
    );

    const [results] = await connectionUserdb.query(
      'SELECT totaldownload FROM notes WHERE id = $1',
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
};
