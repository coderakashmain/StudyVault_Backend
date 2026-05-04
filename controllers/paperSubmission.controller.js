const path = require("path");
const fs = require("fs");

const connectionUserdb = require("../config/db");
const { success, failure } = require("../utils/response");
const asyncHandler = require("../middleware/asyncHandler");


exports.getPendingUploads = asyncHandler(async (req, res) => {
  const sql = `
    SELECT
      ps.*,
      CONCAT(u.firstname, ' ', u.lastname) AS uploaded_by_name,
      u.gmail AS uploaded_by_email,

      -- Duplicate flag
      EXISTS (
        SELECT 1
        FROM papers p
        WHERE
          p.departmentName = ps.departmentName
          AND p.educationLevel = ps.educationLevel
          AND p.years = ps.years
          AND p.sem = ps.sem
          AND p.midSem = ps.midSem
          AND p.semester = ps.semester
      ) AS is_duplicate,

      -- Fetch matching titles as JSON array
      (
        SELECT COALESCE(json_agg(p.title), '[]'::json)
        FROM papers p
        WHERE
          p.departmentName = ps.departmentName
          AND p.educationLevel = ps.educationLevel
          AND p.years = ps.years
          AND p.sem = ps.sem
          AND p.midSem = ps.midSem
          AND p.semester = ps.semester
      ) AS duplicate_titles

    FROM paper_submissions ps
    JOIN users u ON u.id = ps.uploaded_by_user_id
    WHERE ps.status = 'pending' OR ps.status IS NULL
    ORDER BY ps.created_at DESC;
  `;

  const [rows] = await connectionUserdb.query(sql);
  return success(res, "Pending uploads fetched", rows);
});



exports.approvePaper = asyncHandler(async (req, res) => {
  const { id } = req.params;
  const adminId = req.admin.id;

  const connection = await connectionUserdb.getConnection();

  try {
    await connection.beginTransaction();

    // 1️ Insert into papers and get the new id
    const insertSql = `
      INSERT INTO papers
      (departmentName, educationLevel, years, departmentYear, sem, midSem,
       title, url, semester)
      SELECT
        departmentName, educationLevel, years, departmentYear, sem, midSem,
        title, url, semester
      FROM paper_submissions
      WHERE id = $1 AND (status = 'pending' OR status IS NULL)
      RETURNING id
    `;

    const [insertRows, insertResult] = await connection.query(insertSql, [id]);

    if (insertRows.length === 0) {
      await connection.rollback();
      return failure(res, "Invalid or already reviewed submission", 400);
    }

    const paperId = insertRows[0].id;

    // 2️ Get uploader user id
    const [submissionRows] = await connection.query(
      "SELECT uploaded_by_user_id FROM paper_submissions WHERE id = $1",
      [id]
    );

    if (!submissionRows.length) {
      await connection.rollback();
      return failure(res, "Submission not found", 404);
    }

    const uploadedByUserId = submissionRows[0].uploaded_by_user_id;

    // 3️ Get uploader name
    const [userRows] = await connection.query(
      "SELECT firstname, lastname FROM users WHERE id = $1",
      [uploadedByUserId]
    );

    const uploaderName = userRows.length
      ? `${userRows[0].firstname} ${userRows[0].lastname}`
      : "Unknown User";

    // 4️ [REMOVED] upload_details insertion to avoid migration
    // Tracking is fully handled by the paper_submissions 'approved' status and reviewed_by_admin_id

    // 5️ Mark submission approved
    await connection.query(
      `UPDATE paper_submissions
       SET status='approved',
           reviewed_by_admin_id=$1,
           reviewed_at=NOW()
       WHERE id=$2`,
      [adminId, id]
    );

    await connection.commit();
    return success(res, "Paper approved and published");
  } catch (err) {
    await connection.rollback();
    throw err;
  } finally {
    connection.release();
  }
});

exports.rejectPaper = asyncHandler(async (req, res) => {
  const { id } = req.params;
  const { remark } = req.body;
  const adminId = req.admin.id;

  if (!remark) {
    return failure(res, "Remark is required", 400);
  }

  const [, result] = await connectionUserdb.query(
    `UPDATE paper_submissions
     SET status='rejected',
         admin_remark=$1,
         reviewed_by_admin_id=$2,
         reviewed_at=NOW()
     WHERE id=$3 AND (status='pending' OR status IS NULL)`,
    [remark, adminId, id]
  );

  if (result.rowCount === 0) {
    return failure(res, "Invalid or already reviewed submission", 400);
  }

  return success(res, "Paper rejected with remark");
});

exports.updateRemark = asyncHandler(async (req, res) => {
  const { id } = req.params;
  const { remark } = req.body;

  const [, result] = await connectionUserdb.query(
    `UPDATE paper_submissions
     SET admin_remark=$1
     WHERE id=$2 AND status='rejected'`,
    [remark, id]
  );

  if (result.rowCount === 0) {
    return failure(res, "Only rejected submissions can be updated", 400);
  }

  return success(res, "Remark updated");
});


