const path = require("path");
const fs = require("fs");
const connectionUserdb = require("../config/db");
const { success, failure } = require("../utils/response");
const asyncHandler = require("../middleware/asyncHandler");

const {
  findFolderupload,
  createDriveFolder,
  uploadFileToDrive,
} = require("../utils/googleDrive");



exports.questionUpload = asyncHandler(async (req, res) => {
  const {
    departmentName,
    educationLevel,
    years,
    departmentYear,
    sem,
    midSem,
    title,
    semester,
    renamedFile
  } = req.body;

  
  
  const userId = req.user.id;

  if (!req.file) {
    return failure(res, "PDF file is required", 400);
  }

  //  find or create department folder
  let folderId = await findFolderupload(departmentName);
  if (!folderId) {
    folderId = await createDriveFolder(departmentName);
  }

  //  upload to Google Drive
  const fileId = await uploadFileToDrive(req.file.filename, folderId);
  const fileUrl = `https://drive.google.com/file/d/${fileId}/view`;

  //  delete local file (IMPORTANT)
  fs.unlinkSync(
    path.join(__dirname, "../utils/uploads", req?.file?.filename)
  );

  //  insert into submission table
  const sql = `
    INSERT INTO paper_submissions
    (departmentName, educationLevel, years, departmentYear, sem, midSem,
     paper_name, url, semester, uploaded_by_user_id, title)
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
  `;

  await connectionUserdb.query(sql, [
    departmentName,
    educationLevel,
    years,
    departmentYear,
    sem,
    midSem,
    title,
    fileUrl,
    semester,
    userId,
    req?.file?.filename
  ]);

  return success(
    res,
    "Paper uploaded successfully. Pending admin approval."
  );
});


exports.avatarUpdate = asyncHandler(async (req, res) => {
  const userId = req.user?.id;
  const { avatarUrl } = req.body;

  //  Auth check (safety)
  if (!userId) {
    return failure(res, "Unauthorized", 401);
  }

  //  Validation
  if (!avatarUrl || typeof avatarUrl !== "string") {
    return failure(res, "Avatar URL is required", 400);
  }

  if (!avatarUrl.startsWith("https://")) {
    return failure(res, "Invalid avatar URL", 400);
  }

  //  Optional but STRONGLY recommended
  if (!avatarUrl.includes("readyplayer.me")) {
    return failure(res, "Only Ready Player Me avatars are allowed", 400);
  }

  //  DB Update
  await connectionUserdb.query(
    "UPDATE users SET avatar_url = $1 WHERE id = $2",
    [avatarUrl, userId]
  );

  //  Response
  return success(res, "Avatar updated successfully", {
    avatar_url: avatarUrl,
  });
});

exports.getTopContributors = asyncHandler(async (req, res) => {
  const sql = `
    SELECT
      ud.upload_user_id,
      ud.upload_user_name AS full_name,

      -- avatar from users table
      u.avatar_url AS avatar_url,

      -- safely masked roll number
      CASE
        WHEN u.rollno IS NOT NULL AND LENGTH(u.rollno) >= 3
        THEN CONCAT(LEFT(u.rollno, 2), 'xxxx', RIGHT(u.rollno, 1))
        ELSE NULL
      END AS masked_rollno,

      COUNT(*) AS total_uploads

    FROM upload_details ud
    JOIN users u ON u.id = ud.upload_user_id
    WHERE ud.created_at >= NOW() - INTERVAL '7 days'
    GROUP BY
      ud.upload_user_id,
      ud.upload_user_name,
      u.avatar_url,
      u.rollno
    ORDER BY total_uploads DESC
    LIMIT 3;
  `;

  const [rows] = await connectionUserdb.query(sql);
  return success(res, "Top contributors fetched", rows);
});
