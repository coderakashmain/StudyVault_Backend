const db = require('./config/db');

async function fixSequence() {
    try {
        console.log('Fixing colleges ID sequence...');
        await db.query(`
            SELECT setval(
                pg_get_serial_sequence('colleges', 'id'), 
                (SELECT COALESCE(MAX(id), 1) FROM colleges)
            );
        `);
        console.log('Sequence fixed successfully!');
        process.exit(0);
    } catch (e) {
        console.error('Error fixing sequence:', e);
        process.exit(1);
    }
}

fixSequence();



