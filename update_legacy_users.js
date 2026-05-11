const db = require('./config/db');

async function updateLegacyUsers() {
    try {
        console.log('Updating legacy users to have college_id = 1 (MPC Autonomous College)...');
        // Update all users where college_id is currently NULL
        const [result] = await db.query('UPDATE users SET college_id = 1 WHERE college_id IS NULL');
        console.log(`Successfully updated legacy users: ${result.rowCount}`);
        
        // Also let's check how many total users have college_id = 1 now
        const [totalCount] = await db.query('SELECT COUNT(*) FROM users WHERE college_id = 1');
        console.log(`Total users with college_id = 1: ${totalCount[0].count}`);
        
        process.exit(0);
    } catch (e) {
        console.error('Error updating legacy users:', e);
        process.exit(1);
    }
}

updateLegacyUsers();
