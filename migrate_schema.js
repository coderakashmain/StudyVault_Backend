const db = require('./config/db');

async function migrate() {
    try {
        console.log('Creating colleges table...');
        await db.query(`
            CREATE TABLE IF NOT EXISTS colleges (
                id SERIAL PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                type VARCHAR(50) DEFAULT 'autonomous',
                city VARCHAR(100),
                university_affiliation VARCHAR(255),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        console.log('Adding college_id to users...');
        await db.query(`
            ALTER TABLE users ADD COLUMN IF NOT EXISTS college_id INTEGER REFERENCES colleges(id) ON DELETE SET NULL
        `);

        console.log('Adding college_id to papers...');
        await db.query(`
            ALTER TABLE papers ADD COLUMN IF NOT EXISTS college_id INTEGER REFERENCES colleges(id) ON DELETE SET NULL
        `);

        console.log('Inserting default college...');
        await db.query(`
            INSERT INTO colleges (id, name, type, city, university_affiliation)
            VALUES (1, 'MPC Autonomous College', 'autonomous', 'Baripada', 'North Orissa University')
            ON CONFLICT (id) DO NOTHING
        `);

        console.log('Updating legacy papers...');
        const [result] = await db.query('UPDATE papers SET college_id = 1 WHERE college_id IS NULL');
        console.log(`Updated legacy papers: ${result.rowCount}`);

        console.log('Schema migration complete.');
        process.exit(0);
    } catch (e) {
        console.error('Migration failed:', e);
        process.exit(1);
    }
}

migrate();
