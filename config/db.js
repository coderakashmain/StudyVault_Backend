require('dotenv').config();
const { Pool } = require('pg');

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false, // Required for Supabase
    },
    max: 20,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 10000,
});

/**
 * Compatibility wrapper so existing code using MySQL-style destructuring
 *   const [rows] = await db.query(sql, params)
 * continues to work with pg (which returns { rows, rowCount }).
 */
const connectionUserdb = {
    /**
     * Run a query and return [rows, result] to match mysql2's [rows, fields] pattern.
     * @param {string} text  - SQL query with $1, $2... placeholders
     * @param {Array}  params - parameter values
     */
    query: async (text, params) => {
        const result = await pool.query(text, params);
        // Return [rows, fullResult] so destructuring const [rows] = ... works
        return [result.rows, result];
    },

    /**
     * Get a raw client from the pool (for transactions).
     * The returned client has a wrapped .query that also returns [rows, result].
     */
    getConnection: async () => {
        const client = await pool.connect();
        // Wrap the client to match the mysql2 pattern
        const wrappedClient = {
            query: async (text, params) => {
                const result = await client.query(text, params);
                return [result.rows, result];
            },
            beginTransaction: async () => {
                await client.query('BEGIN');
            },
            commit: async () => {
                await client.query('COMMIT');
            },
            rollback: async () => {
                await client.query('ROLLBACK');
            },
            release: () => {
                client.release();
            },
        };
        return wrappedClient;
    },
};

// Handle pool errors
pool.on('error', (err) => {
    console.error('Unexpected database pool error:', err.message);
});

module.exports = connectionUserdb;
