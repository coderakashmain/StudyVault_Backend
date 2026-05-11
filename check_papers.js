const db = require('./config/db');

async function check() {
    try {
        const [result] = await db.query(`
            SELECT column_name, data_type 
            FROM information_schema.columns 
            WHERE table_name = 'papers'
        `);
        console.log(result);
        process.exit(0);
    } catch (e) {
        console.error(e);
        process.exit(1);
    }
}

check();
