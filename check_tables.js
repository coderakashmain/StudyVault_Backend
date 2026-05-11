const db = require('./config/db');

async function check() {
    try {
        const [usersResult] = await db.query(`
            SELECT column_name, data_type 
            FROM information_schema.columns 
            WHERE table_name = 'users'
        `);
        console.log('users schema:', usersResult.map(c => c.column_name).join(', '));
        
        const [collegesResult] = await db.query(`
            SELECT column_name, data_type 
            FROM information_schema.columns 
            WHERE table_name = 'colleges'
        `);
        console.log('colleges schema:', collegesResult.map(c => c.column_name).join(', '));

        process.exit(0);
    } catch (e) {
        console.error(e);
        process.exit(1);
    }
}

check();
