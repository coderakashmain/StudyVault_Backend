const { GoogleGenerativeAI } = require("@google/generative-ai");
const connectionUserdb = require("../config/db");
const asyncHandler = require("../middleware/asyncHandler");
const { success, failure } = require("../utils/response");

// Use the existing Gemini API Key
const apiKey = process.env.GEMINI_API_KEY;
const genAI = new GoogleGenerativeAI(apiKey);

// Helper to convert buffer to generative part
function fileToGenerativePart(buffer, mimeType) {
  return {
    inlineData: {
      data: buffer.toString("base64"),
      mimeType
    },
  };
}

exports.generateNotes = asyncHandler(async (req, res) => {
  const userId = req.user.id;
  const { type } = req.body; // 'short_notes', 'revision', 'mcq', 'flashcards'
  const file = req.file;

  if (!file) {
    return failure(res, "No file uploaded", 400);
  }

  // Determine credit cost based on file type
  const isPDF = file.mimetype === "application/pdf";
  const cost = isPDF ? 5 : 3;

  // Check user credits
  const [rows] = await connectionUserdb.query("SELECT credits FROM users WHERE id = $1", [userId]);
  if (rows.length === 0) return failure(res, "User not found", 404);

  const currentCredits = rows[0].credits !== null ? rows[0].credits : 20;
  if (currentCredits < cost) {
    return failure(res, `Insufficient credits. This requires ${cost} credits.`, 403);
  }

  try {
    // Determine the prompt based on type
    let promptText = "";
    if (type === "short_notes") {
      promptText = "Analyze this document and generate beautifully formatted Markdown short notes summarizing the key concepts. Use headings, bullet points, and bold text.";
    } else if (type === "revision") {
      promptText = "Create a quick revision cheat sheet from this document in Markdown format. Focus only on the most critical formulas, definitions, and concepts.";
    } else if (type === "mcq") {
      promptText = `Generate 10 multiple-choice questions from this document. 
      Return STRICTLY a JSON array of objects with the following format (no markdown code blocks, just raw JSON):
      [
        {
          "question": "The question text",
          "options": ["A", "B", "C", "D"],
          "answer": "The correct option text exactly as it appears in options"
        }
      ]`;
    } else if (type === "flashcards") {
      promptText = `Generate 10 flashcards from this document. 
      Return STRICTLY a JSON array of objects with the following format (no markdown code blocks, just raw JSON):
      [
        {
          "front": "Concept or Question",
          "back": "Definition or Answer"
        }
      ]`;
    } else {
      return failure(res, "Invalid generation type", 400);
    }

    // Call Gemini API
    const model = genAI.getGenerativeModel({ model: "gemini-1.5-flash-latest" });
    const imagePart = fileToGenerativePart(file.buffer, file.mimetype);

    const result = await model.generateContent([promptText, imagePart]);
    const response = await result.response;
    let text = response.text();

    // Clean up JSON if requested
    if (type === "mcq" || type === "flashcards") {
      // Remove markdown code blocks if the model accidentally included them
      text = text.replace(/```json/g, '').replace(/```/g, '').trim();
      try {
        text = JSON.parse(text);
      } catch (e) {
        console.error("Failed to parse Gemini JSON output", e, text);
        return failure(res, "Failed to parse AI output. Please try again.", 500);
      }
    }

    // Deduct credits
    const newCredits = currentCredits - cost;
    await connectionUserdb.query("UPDATE users SET credits = $1 WHERE id = $2", [newCredits, userId]);

    return success(res, "Generated successfully", {
      result: text,
      creditsRemaining: newCredits,
      cost
    });

  } catch (error) {
    console.error("Gemini API Error:", error);
    return failure(res, "Failed to generate notes. " + error.message, 500);
  }
});
