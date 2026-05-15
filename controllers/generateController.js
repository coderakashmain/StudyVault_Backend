const { GoogleGenerativeAI } = require("@google/generative-ai");
const connectionUserdb = require("../config/db");
const asyncHandler = require("../middleware/asyncHandler");
const { success, failure } = require("../utils/response");

// Use the existing Gemini API Key
const apiKey = process.env.GEMINI_API_KEY;
// Use v1 for more stable model availability
const genAI = new GoogleGenerativeAI(apiKey, { apiVersion: 'v1' });

// Fallback model chain: try these in order if one is overloaded, out of quota, or not found
const MODEL_FALLBACK_CHAIN = [
  "gemini-1.5-flash",
  "gemini-1.5-flash-8b",
  "gemini-2.0-flash",
  "gemini-1.5-pro",
];

// Helper to convert buffer to generative part
function fileToGenerativePart(buffer, mimeType) {
  return {
    inlineData: {
      data: buffer.toString("base64"),
      mimeType
    },
  };
}

// Smart generate with automatic fallback on 503 (overload), 429 (quota), or 404 (not found) errors
async function generateWithFallback(parts) {
  let lastError;
  for (const modelName of MODEL_FALLBACK_CHAIN) {
    let retriesForThisModel = 0;
    const maxRetriesPerModel = 1; // Try the same model twice if it's a 429

    while (retriesForThisModel <= maxRetriesPerModel) {
      try {
        console.log(`[Gemini] Trying model: ${modelName} (Attempt ${retriesForThisModel + 1})`);
        const model = genAI.getGenerativeModel({ model: modelName });
        const result = await model.generateContent(parts);
        console.log(`[Gemini] Success with model: ${modelName}`);
        return result;
      } catch (err) {
        lastError = err;
        const statusCode = err.status || (err.response && err.response.status);
        const isQuotaError = statusCode === 429 || err.message?.includes('429');
        const isRetryable = statusCode === 503 || isQuotaError || statusCode === 404 ||
                           err.message?.includes('503') || err.message?.includes('404');
        
        if (isQuotaError && retriesForThisModel < maxRetriesPerModel) {
          console.warn(`[Gemini] Model ${modelName} rate limited (429). Waiting 10.5s before retry...`);
          await new Promise(resolve => setTimeout(resolve, 10500));
          retriesForThisModel++;
          continue; // Retry the same model
        }

        if (isRetryable) {
          console.warn(`[Gemini] Model ${modelName} failed with ${statusCode || 'error'}, moving to next model...`);
          break; // Move to next model in MODEL_FALLBACK_CHAIN
        }
        // For other errors (400, etc.), throw immediately
        throw err;
      }
    }
  }
  // All models failed after all retries
  throw lastError;
}

exports.generateNotes = asyncHandler(async (req, res) => {
  const userId = req.user.id;
  const { type } = req.body; // 'short_notes', 'revision', 'mcq', 'flashcards'
  const file = req.file;

  if (!file) {
    return failure(res, "No file uploaded", 400);
  }

  // Determine credit cost based on type & file type
  const isPDF = file.mimetype === "application/pdf";
  const isNightBeforeExam = type === "night_before_exam";
  const cost = isNightBeforeExam ? 5 : (isPDF ? 5 : 3);

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
    } else if (type === "night_before_exam") {
      promptText = `You are an expert exam preparation assistant. Analyze this document thoroughly and generate a comprehensive "Night Before Exam" study kit.

Return STRICTLY a JSON object with the following format (no markdown code blocks, just raw JSON):
{
  "importantQuestions": [
    { "no": 1, "question": "Question text here", "hint": "Brief hint or key point for answering" }
  ],
  "revisionSheet": "# Quick Revision\\n\\n## Key Concepts\\n- Point 1\\n- Point 2\\n\\n## Important Definitions\\n...",
  "formulas": [
    { "name": "Formula name", "formula": "The formula or equation", "description": "What it is used for" }
  ],
  "derivations": [
    { "title": "Derivation title", "steps": ["Step 1", "Step 2", "Step 3"], "result": "Final result or conclusion" }
  ],
  "vivaQuestions": [
    { "q": "Viva question text?", "a": "Concise answer" }
  ]
}

Rules:
- importantQuestions: List 12-15 most likely exam questions with hints
- revisionSheet: A complete Markdown cheat sheet covering all key topics, definitions, formulas in summary form — suitable for 30-minute revision
- formulas: All important formulas/equations/laws — if no formulas exist in the document, provide at least the key definitions as formula-style entries
- derivations: Key derivations or proofs — if no derivations, provide step-by-step solution approaches for key problem types
- vivaQuestions: 12-15 oral exam Q&A pairs with concise answers
- Return ONLY the raw JSON. No markdown code blocks. No extra text.`;
    } else {
      return failure(res, "Invalid generation type", 400);
    }

    // Call Gemini API with automatic fallback on 503 overload
    const imagePart = fileToGenerativePart(file.buffer, file.mimetype);

    const result = await generateWithFallback([promptText, imagePart]);
    const response = await result.response;
    let text = response.text();

    // Clean up JSON for structured types
    if (type === "mcq" || type === "flashcards" || type === "night_before_exam") {
      // Find the first '[' or '{' and the last ']' or '}'
      const jsonMatch = text.match(/[\{\[]([\s\S]*?)[\}\]]/);
      if (jsonMatch) {
        text = jsonMatch[0];
      }
      
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

    // Save to history
    const resultDataToSave = typeof text === 'string' ? text : JSON.stringify(text);
    await connectionUserdb.query(
      "INSERT INTO generated_notes (user_id, generation_type, file_name, result_data) VALUES ($1, $2, $3, $4)",
      [userId, type, file.originalname || 'document', resultDataToSave]
    );

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

exports.getNotesHistory = asyncHandler(async (req, res) => {
  const userId = req.user.id;
  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 10;
  const offset = (page - 1) * limit;
  const type = req.query.type; // Optional filter

  let query = "SELECT id, generation_type, file_name, result_data, created_at FROM generated_notes WHERE user_id = $1";
  let countQuery = "SELECT COUNT(*) as total FROM generated_notes WHERE user_id = $1";
  let params = [userId];

  if (type && type !== 'all') {
    query += " AND generation_type = $2";
    countQuery += " AND generation_type = $2";
    params.push(type);
  }

  query += ` ORDER BY created_at DESC LIMIT $${params.length + 1} OFFSET $${params.length + 2}`;
  
  const [rows] = await connectionUserdb.query(query, [...params, limit, offset]);
  const [countRows] = await connectionUserdb.query(countQuery, params);
  
  const total = parseInt(countRows[0].total);

  return success(res, "History fetched successfully", {
    items: rows,
    pagination: {
      total,
      page,
      limit,
      totalPages: Math.ceil(total / limit),
      hasMore: page * limit < total
    }
  });
});
