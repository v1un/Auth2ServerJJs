// C:/Users/vini/WebstormProjects/jjguibotauthserver/src/config/database.js
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const logger = require('../utils/logger'); // Import logger

// Get database path from environment variables or use default
const DB_PATH = process.env.DB_PATH || path.join(__dirname, '..', '..', 'auth.db');

// Initialize database connection
const initializeDatabase = () => {
  return new Promise((resolve, reject) => {
    const db = new sqlite3.Database(DB_PATH, (err) => {
      if (err) {
        logger.error('Error opening database', { error: err.message });
        reject(err);
        return;
      }

      logger.info(`Connected to the SQLite database: ${DB_PATH}`);

      db.serialize(() => {
        // --- Create/Verify users table ---
        db.run(`
          CREATE TABLE IF NOT EXISTS users (
                                             id INTEGER PRIMARY KEY AUTOINCREMENT,
                                             username TEXT UNIQUE NOT NULL,
                                             password TEXT NOT NULL,
                                             role TEXT NOT NULL,
                                             created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                                             allowed_ip TEXT NULL,
                                             custom_name TEXT NULL -- <<< Add custom_name column
          )
        `, (err) => {
          if (err) {
            logger.error('Error creating users table', { error: err.message });
            return reject(err); // Stop if users table fails
          }
          logger.info('Users table schema verified.');

          // Add allowed_ip column if needed (idempotent check)
          db.run('ALTER TABLE users ADD COLUMN allowed_ip TEXT NULL', (alterErrIp) => {
            if (alterErrIp && !alterErrIp.message.includes('duplicate column name')) {
              logger.error('Error adding allowed_ip column', { error: alterErrIp.message });
            } else if (!alterErrIp) {
              logger.info('Added allowed_ip column to users table.');
            }

            // --- Add custom_name column if needed (idempotent check) ---
            db.run('ALTER TABLE users ADD COLUMN custom_name TEXT NULL', (alterErrName) => {
              if (alterErrName && !alterErrName.message.includes('duplicate column name')) {
                logger.error('Error adding custom_name column', { error: alterErrName.message });
                // Decide if this is fatal, for now just log
              } else if (!alterErrName) {
                logger.info('Added custom_name column to users table.');
              }

              // --- Create/Verify device_authorizations table ---
              db.run(`
                CREATE TABLE IF NOT EXISTS device_authorizations (
                  device_code TEXT PRIMARY KEY NOT NULL,
                  user_code TEXT UNIQUE NOT NULL,
                  status TEXT NOT NULL DEFAULT 'pending', -- pending, approved, denied, expired
                  expires_at INTEGER NOT NULL, -- Unix timestamp (milliseconds)
                  last_polled_at INTEGER DEFAULT 0, -- Unix timestamp (milliseconds)
                  interval INTEGER NOT NULL, -- Polling interval in seconds
                  user_id INTEGER NULL, -- Foreign key to users table (once approved)
                  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL -- Optional: handle user deletion
                )
              `, (errDevice) => {
                if (errDevice) {
                  logger.error('Error creating device_authorizations table', { error: errDevice.message });
                  return reject(errDevice); // Stop if device table fails
                }
                logger.info('Device authorizations table schema verified.');

                // --- Create index on user_code for faster lookups ---
                db.run('CREATE INDEX IF NOT EXISTS idx_device_auth_user_code ON device_authorizations (user_code)', (indexErr) => {
                  if (indexErr) {
                    logger.error('Error creating index on device_authorizations(user_code)', { error: indexErr.message });
                  } else {
                    logger.info('Index on device_authorizations(user_code) verified.');
                  }

                  // --- Create index on expires_at for cleanup ---
                  db.run('CREATE INDEX IF NOT EXISTS idx_device_auth_expires_at ON device_authorizations (expires_at)', (indexErr2) => {
                    if (indexErr2) {
                      logger.error('Error creating index on device_authorizations(expires_at)', { error: indexErr2.message });
                    } else {
                      logger.info('Index on device_authorizations(expires_at) verified.');
                    }

                    logger.info('Database schema initialization complete.');
                    resolve(db); // Resolve only after all tables/indexes are checked/created
                  });
                });
              }); // End device_authorizations table creation
            }); // End alter custom_name
          }); // End alter allowed_ip
        }); // End create users table
      }); // End serialize
    }); // End db connection callback
  }); // End Promise
};

// Helper function to run a query with parameters
const runQuery = (db, query, params = []) => {
  return new Promise((resolve, reject) => {
    db.run(query, params, function(err) { // Use function() to access 'this'
      if (err) {
        logger.error('Database run error', { query, params: JSON.stringify(params), error: err.message });
        reject(err);
        return;
      }
      resolve({ lastID: this.lastID, changes: this.changes });
    });
  });
};

// Helper function to get a single row
const getRow = (db, query, params = []) => {
  return new Promise((resolve, reject) => {
    db.get(query, params, (err, row) => {
      if (err) {
        logger.error('Database get error', { query, params: JSON.stringify(params), error: err.message });
        reject(err);
        return;
      }
      resolve(row);
    });
  });
};

// Helper function to get multiple rows
const getRows = (db, query, params = []) => {
  return new Promise((resolve, reject) => {
    db.all(query, params, (err, rows) => {
      if (err) {
        logger.error('Database all error', { query, params: JSON.stringify(params), error: err.message });
        reject(err);
        return;
      }
      resolve(rows);
    });
  });
};

// Close database connection
const closeDatabase = (db) => {
  return new Promise((resolve, reject) => {
    if (db) {
      db.close((err) => {
        if (err) {
          logger.error('Error closing database', { error: err.message });
          reject(err);
          return;
        }
        logger.info('Database connection closed.');
        resolve();
      });
    } else {
      resolve();
    }
  });
};

module.exports = {
  initializeDatabase,
  runQuery,
  getRow,
  getRows,
  closeDatabase,
  DB_PATH // Export DB_PATH for session store if needed
};