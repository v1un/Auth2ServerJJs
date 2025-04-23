const bcrypt = require('bcrypt');
const { config } = require('../config/env');
const logger = require('../utils/logger');

/**
 * User model for handling user-related database operations
 */
class UserModel {
  constructor(db) {
    this.db = db;
  }

  /**
   * Create a new user
   * @param {string} username - Username
   * @param {string} password - Plain text password
   * @param {string} role - User role (default: 'user')
   * @returns {Promise<Object>} Created user object
   * @throws {Error} If username already exists or other database error
   */
  async createUser(username, password, role = 'user') {
    try {
      // Hash the password
      const hashedPassword = await bcrypt.hash(password, config.BCRYPT_SALT_ROUNDS);
      
      // Insert user into database
      const result = await this.db.runQuery(
        'INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
        [username, hashedPassword, role]
      );
      
      logger.info(`User created: ${username} with role ${role}`, { userId: result.lastID });
      
      return {
        id: result.lastID,
        username,
        role,
        created_at: new Date().toISOString()
      };
    } catch (error) {
      // Check for unique constraint violation (username already exists)
      if (error.message.includes('UNIQUE constraint failed')) {
        logger.warn(`Failed to create user: Username ${username} already exists`);
        const err = new Error('Username already exists');
        err.code = 'USERNAME_EXISTS';
        throw err;
      }
      
      logger.error(`Failed to create user: ${error.message}`, { username, error: error.stack });
      throw error;
    }
  }

  /**
   * Get a user by username
   * @param {string} username - Username to find
   * @returns {Promise<Object|null>} User object or null if not found
   */
  async getUserByUsername(username) {
    try {
      const user = await this.db.getRow(
        'SELECT * FROM users WHERE username = ?',
        [username]
      );
      
      return user || null;
    } catch (error) {
      logger.error(`Failed to get user by username: ${error.message}`, { username, error: error.stack });
      throw error;
    }
  }

  /**
   * Get a user by ID
   * @param {number} id - User ID
   * @returns {Promise<Object|null>} User object or null if not found
   */
  async getUserById(id) {
    try {
      const user = await this.db.getRow(
        'SELECT * FROM users WHERE id = ?',
        [id]
      );
      
      return user || null;
    } catch (error) {
      logger.error(`Failed to get user by ID: ${error.message}`, { userId: id, error: error.stack });
      throw error;
    }
  }

  /**
   * Get all users
   * @returns {Promise<Array>} Array of user objects
   */
  async getAllUsers() {
    try {
      const users = await this.db.getRows(
        'SELECT id, username, role, created_at FROM users'
      );
      
      return users;
    } catch (error) {
      logger.error(`Failed to get all users: ${error.message}`, { error: error.stack });
      throw error;
    }
  }

  /**
   * Delete a user by ID
   * @param {number} id - User ID
   * @returns {Promise<boolean>} True if user was deleted, false if user not found
   */
  async deleteUser(id) {
    try {
      const result = await this.db.runQuery(
        'DELETE FROM users WHERE id = ?',
        [id]
      );
      
      if (result.changes > 0) {
        logger.info(`User deleted: ID ${id}`);
        return true;
      }
      
      logger.warn(`Failed to delete user: User ID ${id} not found`);
      return false;
    } catch (error) {
      logger.error(`Failed to delete user: ${error.message}`, { userId: id, error: error.stack });
      throw error;
    }
  }

  /**
   * Verify user credentials
   * @param {string} username - Username
   * @param {string} password - Plain text password
   * @returns {Promise<Object|null>} User object if credentials are valid, null otherwise
   */
  async verifyCredentials(username, password) {
    try {
      const user = await this.getUserByUsername(username);
      
      if (!user) {
        return null;
      }
      
      const isPasswordValid = await bcrypt.compare(password, user.password);
      
      if (isPasswordValid) {
        logger.info(`User authenticated: ${username}`);
        return user;
      }
      
      logger.warn(`Failed authentication attempt for user: ${username}`);
      return null;
    } catch (error) {
      logger.error(`Error verifying credentials: ${error.message}`, { username, error: error.stack });
      throw error;
    }
  }
}

module.exports = UserModel;