const connectionUserdb = require("../config/db");

exports.filterPapers = async (req, res) => {
  let query = "SELECT * FROM papers WHERE 1=1";
  const params = [];
  let paramIndex = 1;

  try {
    if (req.query.departmentName) {
      query += ` AND departmentname = $${paramIndex++}`;
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
        query += ` AND educationlevel = ANY($${paramIndex++}::text[])`; 
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
      query += ` AND "departmentYear" = $${paramIndex++}`;
      params.push(req.query.departmentYear);
    }

    if (req.query.sem === "true" || req.query.midSem === "true") {
      let conditions = [];
      if (req.query.sem === "true") {
        conditions.push("sem = 1");
      }
      if (req.query.midSem === "true") {
        conditions.push('"midSem" = 1');
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
      query += ` AND "EducationalLable" = $${paramIndex++}`;
      params.push(req.query.Educationlavel);
    }
    
    if (req.query.Stream) {
      query += ` AND "Stream" = $${paramIndex++}`;
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
  const limit = parseInt(req.query.limit) || 10;
  const offset = parseInt(req.query.offset) || 0;
  
  let query = `SELECT id, notefullname, subjectname, unit, url, totaldownload, COALESCE("totalClicks", 0) AS totalclicks FROM notes ORDER BY id DESC LIMIT $1 OFFSET $2`;
  try {
    const [results] = await connectionUserdb.query(query, [limit, offset]); 
    res.status(200).json(results);
  } catch (err) {
    console.error("Error fetching notes:", err);
    return res.status(500).json({ error: "Internal Server Error" });
  }
};

exports.getHomeData = async (req, res) => {
  try {
    const [recentPapers] = await connectionUserdb.query(
      "SELECT * FROM papers ORDER BY id DESC LIMIT 5"
    );
    const [recentNotes] = await connectionUserdb.query(
      "SELECT * FROM notes ORDER BY id DESC LIMIT 5"
    );
    res.status(200).json({ recentPapers, recentNotes });
  } catch (err) {
    console.error("Error fetching home data:", err);
    res.status(500).json({ error: "Internal Server Error" });
  }
};


exports.noteClickCount = async (req, res) => {
  const { id } = req.body;
  if (!id) return res.status(400).json({ error: "Note ID is required" });

  try {
    await connectionUserdb.query('UPDATE notes SET "totalClicks" = COALESCE("totalClicks", 0) + 1 WHERE id = $1::int', [id]);
    const [results] = await connectionUserdb.query('SELECT COALESCE("totalClicks", 0) AS totalclicks FROM notes WHERE id = $1::int', [id]);
    
    res.json({ count: results[0]?.totalclicks || 0 });
  } catch (err) {
    console.error("Database error in noteClickCount:", err.message);
    res.status(500).json({ error: "Error updating click count", details: err.message });
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
