require('dotenv').config();
const mysql = require("mysql2/promise");

const connectionUserdb = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: 'userdb',
    waitForConnections: true,
    connectionLimit: 20,
    queueLimit: 0,
});

const connectionPaperdb = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: 'papersdb',
    waitForConnections: true,
    connectionLimit: 20,
    queueLimit: 0,
});

/**
 * Function to handle reconnections on connection error
 * @param {object} pool - The connection pool to monitor
 * @param {string} database - Database name for logging purposes
 */
const handleReconnection = (pool, database) => {
    pool.on('error', async (err) => {
        if (err.code === 'PROTOCOL_CONNECTION_LOST') {
            console.error(`[${database}] Connection lost. Attempting to reconnect...`);
            try {
                // Verify the pool is functional by querying the database
                await pool.query('SELECT 1');
                console.log(`[${database}] Reconnection successful.`);
            } catch (error) {
                console.error(`[${database}] Reconnection failed. Error: ${error.message}`);
                setTimeout(() => handleReconnection(pool, database), 5000); // Retry after 5 seconds
            }
        } else {
            console.error(`[${database}] Unexpected error: ${err.message}`);
        }
    });
};

// Attach reconnection handlers
handleReconnection(connectionUserdb, 'userdb');
handleReconnection(connectionPaperdb, 'papersdb');

module.exports = {
    connectionUserdb,
    connectionPaperdb,
};

