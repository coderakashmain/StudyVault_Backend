const db = require('./config/db');

async function migrate() {
    try {
        console.log('Migrating legacy papers...');
        const [result] = await db.query('UPDATE papers SET college_id = 1 WHERE college_id IS NULL');
        console.log('Updated legacy papers:', result.rowCount || 'unknown number of rows');
        process.exit(0);
    } catch (e) {
        console.error('Error migrating papers:', e);
        process.exit(1);
    }
}

migrate();
