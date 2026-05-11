const connectionUserdb = require("../config/db");

// ─── GET all colleges (public) ───────────────────────────────────────────────
exports.getColleges = async (req, res) => {
  try {
    const [rows] = await connectionUserdb.query(
      "SELECT id, name, type, city, university_affiliation, created_at FROM colleges ORDER BY name ASC"
    );
    res.status(200).json(rows);
  } catch (err) {
    console.error("Error fetching colleges:", err);
    res.status(500).json({ error: "Internal Server Error" });
  }
};

// ─── POST create college (admin only) ────────────────────────────────────────
exports.createCollege = async (req, res) => {
  const { name, type, city, university_affiliation } = req.body;
  if (!name || !name.trim()) {
    return res.status(400).json({ error: "College name is required" });
  }
  try {
    const [existing] = await connectionUserdb.query(
      "SELECT id FROM colleges WHERE LOWER(name) = LOWER($1)",
      [name.trim()]
    );
    if (existing.length > 0) {
      return res.status(409).json({ error: "College with this name already exists" });
    }
    const [rows] = await connectionUserdb.query(
      "INSERT INTO colleges (name, type, city, university_affiliation) VALUES ($1, $2, $3, $4) RETURNING *",
      [name.trim(), type || "autonomous", city || null, university_affiliation || null]
    );
    res.status(201).json({ message: "College created successfully", college: rows[0] });
  } catch (err) {
    console.error("Error creating college:", err);
    res.status(500).json({ error: "Internal Server Error" });
  }
};

// ─── PUT update college (admin only) ─────────────────────────────────────────
exports.updateCollege = async (req, res) => {
  const { id } = req.params;
  const { name, type, city, university_affiliation } = req.body;
  if (!name || !name.trim()) {
    return res.status(400).json({ error: "College name is required" });
  }
  try {
    const [, result] = await connectionUserdb.query(
      "UPDATE colleges SET name = $1, type = $2, city = $3, university_affiliation = $4 WHERE id = $5",
      [name.trim(), type || "autonomous", city || null, university_affiliation || null, id]
    );
    if (result.rowCount === 0) {
      return res.status(404).json({ error: "College not found" });
    }
    res.status(200).json({ message: "College updated successfully" });
  } catch (err) {
    console.error("Error updating college:", err);
    res.status(500).json({ error: "Internal Server Error" });
  }
};

// ─── DELETE college (admin only) ──────────────────────────────────────────────
exports.deleteCollege = async (req, res) => {
  const { id } = req.params;
  try {
    const [, result] = await connectionUserdb.query(
      "DELETE FROM colleges WHERE id = $1",
      [id]
    );
    if (result.rowCount === 0) {
      return res.status(404).json({ error: "College not found" });
    }
    res.status(200).json({ message: "College deleted successfully" });
  } catch (err) {
    console.error("Error deleting college:", err);
    res.status(500).json({ error: "Internal Server Error" });
  }
};

// ─── PUT set/update user's college (authenticated user) ───────────────────────
exports.setUserCollege = async (req, res) => {
  const { college_id } = req.body;
  const userId = req.user?.id;

  if (!userId) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  if (!college_id) {
    return res.status(400).json({ error: "college_id is required" });
  }
  try {
    // Verify college exists
    const [colleges] = await connectionUserdb.query(
      "SELECT id, name FROM colleges WHERE id = $1",
      [college_id]
    );
    if (colleges.length === 0) {
      return res.status(404).json({ error: "College not found" });
    }
    await connectionUserdb.query(
      "UPDATE users SET college_id = $1 WHERE id = $2",
      [college_id, userId]
    );
    res.status(200).json({
      message: "College updated successfully",
      college_id,
      college_name: colleges[0].name,
    });
  } catch (err) {
    console.error("Error updating user college:", err);
    res.status(500).json({ error: "Internal Server Error" });
  }
};

// ─── GET college paper counts (admin only) ────────────────────────────────────
exports.getCollegePaperCounts = async (req, res) => {
  try {
    const [rows] = await connectionUserdb.query(`
      SELECT college_id, COUNT(*) as count 
      FROM papers 
      WHERE college_id IS NOT NULL 
      GROUP BY college_id
    `);
    res.status(200).json(rows);
  } catch (err) {
    console.error("Error fetching paper counts:", err);
    res.status(500).json({ error: "Internal Server Error" });
  }
};
