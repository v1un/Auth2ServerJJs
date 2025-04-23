const sqlite3 = require('sqlite3').verbose();
const path = require('path');

// Get database path from environment variables or use default
const DB_PATH = process.env.DB_PATH || path.join(__dirname, '..', '..', 'auth.db');

// Initialize database connection
const initializeDatabase = () => {
  return new Promise((resolve, reject) => {
    const db = new sqlite3.Database(DB_PATH, (err) => {
      if (err) {
        console.error('Error opening database:', err.message);
        reject(err);
        return;
      }
      
      console.log('Connected to the SQLite database.');
      
      // Create users table if it doesn't exist
      db.run(`
        CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          username TEXT UNIQUE NOT NULL,
          password TEXT NOT NULL,
          role TEXT NOT NULL,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
      `, (err) => {
        if (err) {
          console.error('Error creating users table:', err.message);
          reject(err);
          return;
        }
        
        console.log('Users table ready.');
        resolve(db);
      });
    });
  });
};

// Helper function to run a query with parameters
const runQuery = (db, query, params = []) => {
  return new Promise((resolve, reject) => {
    db.run(query, params, function(err) {
      if (err) {
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
          console.error('Error closing database:', err.message);
          reject(err);
          return;
        }
        console.log('Database connection closed.');
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
  closeDatabase
};