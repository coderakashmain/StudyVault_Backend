const { GoogleGenerativeAI } = require("@google/generative-ai");
require('dotenv').config();

async function listModels() {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) {
    console.error("No API Key found in .env");
    return;
  }
  const genAI = new GoogleGenerativeAI(apiKey);
  
  try {
    // There isn't a direct listModels in the client, we have to use the fetch/REST or find it in the SDK
    // Actually, the SDK doesn't expose listModels easily.
    // Let's just try a few more variants in the chain.
    console.log("Checking model availability via trial...");
    const modelsToTry = [
      "gemini-1.5-flash",
      "gemini-1.5-pro",
      "gemini-2.0-flash-exp",
      "gemini-pro"
    ];
    
    for (const m of modelsToTry) {
      try {
        const model = genAI.getGenerativeModel({ model: m });
        // Just a tiny prompt to check
        console.log(`Testing ${m}...`);
        // We won't actually call it to save quota, just check if it throws on getGenerativeModel
        // Wait, getGenerativeModel doesn't throw, generateContent does.
      } catch (e) {
        console.log(`${m} failed init: ${e.message}`);
      }
    }
  } catch (err) {
    console.error(err);
  }
}

listModels();
