const connectionUserdb = require("../config/db");
const asyncHandler = require("../middleware/asyncHandler");
const { success, failure } = require("../utils/response");

// --- Credits Management ---

/**
 * Get user credits
 */
exports.getCredits = asyncHandler(async (req, res) => {
  const userId = req.user.id;
  const sql = "SELECT credits, last_renewal FROM users WHERE id = $1";
  const [rows] = await connectionUserdb.query(sql, [userId]);

  if (rows.length === 0) return failure(res, "User not found", 404);

  return success(res, "Credits fetched", {
    credits: rows[0].credits !== null ? rows[0].credits : 20,
    lastRenewal: rows[0].last_renewal
  });
});

/**
 * Deduct a credit
 */
exports.useCredit = asyncHandler(async (req, res) => {
  const userId = req.user.id;
  
  // Get current credits
  const [rows] = await connectionUserdb.query("SELECT credits FROM users WHERE id = $1", [userId]);
  if (rows.length === 0) return failure(res, "User not found", 404);

  const currentCredits = rows[0].credits !== null ? rows[0].credits : 20;
  if (currentCredits <= 0) return failure(res, "Insufficient credits", 403);

  // Update credits
  const newCredits = currentCredits - 1;
  await connectionUserdb.query("UPDATE users SET credits = $1 WHERE id = $2", [newCredits, userId]);

  return success(res, "Credit used", { credits: newCredits });
});

/**
 * Top up credits (called after successful payment)
 */
exports.topupCredits = asyncHandler(async (req, res) => {
  const userId = req.user.id;
  const { amount } = req.body; // number of credits to add

  if (!amount || amount <= 0) return failure(res, "Invalid amount", 400);

  const [rows] = await connectionUserdb.query("SELECT credits FROM users WHERE id = $1", [userId]);
  if (rows.length === 0) return failure(res, "User not found", 404);

  const currentCredits = rows[0].credits !== null ? rows[0].credits : 0;
  const newCredits = currentCredits + amount;
  await connectionUserdb.query("UPDATE users SET credits = $1 WHERE id = $2", [newCredits, userId]);

  return success(res, "Credits topped up", { credits: newCredits });
});

// --- Chat History Management ---

/**
 * Get paginated chat history
 */
exports.getChatHistory = asyncHandler(async (req, res) => {
  const userId = req.user.id;
  const { page = 1, limit = 10 } = req.query;
  const offset = (page - 1) * limit;

  const sql = `
    SELECT session_id, messages, timestamp 
    FROM ai_chat_history 
    WHERE user_id = $1 
    ORDER BY timestamp DESC 
    LIMIT $2 OFFSET $3
  `;
  const [rows] = await connectionUserdb.query(sql, [userId, limit, offset]);

  return success(res, "Chat history fetched", rows);
});

/**
 * Save chat session
 */
exports.saveChatSession = asyncHandler(async (req, res) => {
  const userId = req.user.id;
  const { sessionId, messages } = req.body;

  if (!sessionId || !messages) return failure(res, "Session ID and messages required", 400);

  // Use UPSERT (INSERT or UPDATE if session_id exists)
  const sql = `
    INSERT INTO ai_chat_history (user_id, session_id, messages, timestamp)
    VALUES ($1, $2, $3, $4)
    ON CONFLICT (session_id) 
    DO UPDATE SET messages = EXCLUDED.messages, timestamp = EXCLUDED.timestamp
  `;
  
  await connectionUserdb.query(sql, [userId, sessionId, JSON.stringify(messages), Date.now()]);

  return success(res, "Chat session saved");
});
