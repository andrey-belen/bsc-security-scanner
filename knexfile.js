// Knex configuration for SQLite database
require('dotenv').config();

module.exports = {
  development: {
    client: 'better-sqlite3',
    connection: {
      filename: './database/bsc_scanner.db'
    },
    useNullAsDefault: true,
    migrations: {
      directory: './database/migrations',
      tableName: 'knex_migrations'
    },
    pool: {
      afterCreate: (conn, cb) => {
        // Enable WAL mode for better concurrent access
        conn.pragma('journal_mode = WAL');
        cb();
      }
    }
  },

  production: {
    client: 'pg',
    connection: process.env.DATABASE_URL || {
      host: process.env.DB_HOST,
      port: process.env.DB_PORT || 5432,
      user: process.env.DB_USER,
      password: process.env.DB_PASSWORD,
      database: process.env.DB_NAME
    },
    pool: {
      min: 2,
      max: 10
    },
    migrations: {
      directory: './database/migrations',
      tableName: 'knex_migrations'
    }
  }
};
