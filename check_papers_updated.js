const db = require('./config/db');

async function check() {
    try {
        const [papers] = await db.query('SELECT COUNT(*) FROM papers WHERE college_id = 1');
        console.log('Papers with college_id=1:', papers[0].count);
        process.exit(0);
    } catch (e) {
        console.error(e);
        process.exit(1);
    }
}

check();
