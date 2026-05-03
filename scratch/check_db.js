const connectionUserdb = require("../config/db");

async function check() {
  try {
    const [results, result] = await connectionUserdb.query("SELECT * FROM papers LIMIT 1");
    if (results.length > 0) {
      console.log("Columns:", Object.keys(results[0]));
    } else {
      console.log("No papers found to check columns.");
      // Check table info via information_schema
      const [cols] = await connectionUserdb.query("SELECT column_name FROM information_schema.columns WHERE table_name = 'papers'");
      console.log("Columns from schema:", cols.map(c => c.column_name));
    }
    process.exit(0);
  } catch (err) {
    console.error("Error:", err);
    process.exit(1);
  }
}

check();
