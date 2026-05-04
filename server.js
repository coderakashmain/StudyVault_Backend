const app = require("./app.js");
const connectionUserdb = require("./config/db");
require("dotenv").config();

/////////////

const port = process.env.PORT || 3000;
const ip = process.env.IP || "0.0.0.0";

app.get("/", (req, res) => {
  res.send("StudyVault Campus Backend is running successfully.");
});

// Health Check Endpoint - Test database connection anytime
app.get("/health", async (req, res) => {
  try {
    const [rows] = await connectionUserdb.query("SELECT 1 AS result");
    res.status(200).json({
      status: "success",
      message: "✅ Database connected successfully",
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    res.status(500).json({
      status: "error",
      message: "❌ Database connection failed",
      error: error.message,
      timestamp: new Date().toISOString(),
    });
  }
});

// Test database connection on startup
async function testDatabaseConnection() {
  try {
    const [rows] = await connectionUserdb.query("SELECT 1 AS result");
    console.log("✅ DATABASE CONNECTED SUCCESSFULLY!");
  } catch (error) {
    console.error("❌ DATABASE CONNECTION FAILED:", error.message);
    console.error("Please check your DATABASE_URL in .env file");
    process.exit(1); // Exit if database fails
  }
}

app.listen(port, async () => {
  console.log(`The website is running on port ${port}`);
  await testDatabaseConnection();
});
