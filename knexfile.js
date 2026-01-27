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
    client: 'better-sqlite3',
    connection: {
      filename: './database/bsc_scanner.db'
    },
    useNullAsDefault: true,
    migrations: {
      directory: './database/migrations',
      tableName: 'knex_migrations'
    }
  }
};
