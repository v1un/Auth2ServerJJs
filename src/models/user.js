// C:/Users/vini/WebstormProjects/jjguibotauthserver/src/models/user.js
const bcrypt = require('bcrypt');
const crypto = require('crypto'); // Need crypto for random password
const { config } = require('../config/env');
const logger = require('../utils/logger');
const { runQuery, getRow, getRows } = require('../config/database');

class UserModel {
  constructor(db) {
    this.db = db;
  }

  // --- Modified createUser to include custom_name ---
  async createUser(username, password, role = 'user', allowed_ip = null, custom_name = null) { // Add custom_name
    try {
      const hashedPassword = await bcrypt.hash(password, config.BCRYPT_SALT_ROUNDS);
      const result = await runQuery(
          this.db,
          'INSERT INTO users (username, password, role, allowed_ip, custom_name) VALUES (?, ?, ?, ?, ?)', // Add custom_name
          [username, hashedPassword, role, allowed_ip, custom_name] // Pass custom_name
      );
      logger.info(`User created: ${username} with role ${role}`, { userId: result.lastID, allowedIp: allowed_ip, customName: custom_name });
      // Return the full user object (excluding password)
      return {
        id: result.lastID,
        username,
        role,
        allowed_ip,
        custom_name, // Include in returned object
        created_at: new Date().toISOString() // Approximate creation time
      };
    } catch (error) {
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

  async getUserByUsername(username) {
    try {
      // Select * includes the new columns
      const user = await getRow(
          this.db,
          'SELECT * FROM users WHERE username = ?',
          [username]
      );
      return user || null;
    } catch (error) {
      logger.error(`Failed to get user by username: ${error.message}`, { username, error: error.stack });
      throw error;
    }
  }

  async getUserById(id) {
    try {
      // Select * includes the new columns
      const user = await getRow(
          this.db,
          'SELECT * FROM users WHERE id = ?',
          [id]
      );
      return user || null;
    } catch (error) {
      logger.error(`Failed to get user by ID: ${error.message}`, { userId: id, error: error.stack });
      throw error;
    }
  }

  async getAllUsers() {
    try {
      // Explicitly select columns to exclude password
      const users = await getRows(
          this.db,
          'SELECT id, username, role, created_at, allowed_ip, custom_name FROM users'
      );
      return users;
    } catch (error) {
      logger.error(`Failed to get all users: ${error.message}`, { error: error.stack });
      throw error;
    }
  }

  async deleteUser(id) {
    try {
      const result = await runQuery(
          this.db,
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

  async verifyCredentials(username, password) {
    try {
      const user = await this.getUserByUsername(username);
      if (!user) {
        return null;
      }
      const isPasswordValid = await bcrypt.compare(password, user.password);
      if (isPasswordValid) {
        logger.info(`User authenticated: ${username}`);
        return user; // User object now includes custom_name and allowed_ip
      }
      logger.warn(`Failed authentication attempt for user: ${username}`);
      return null;
    } catch (error) {
      logger.error(`Error verifying credentials: ${error.message}`, { username, error: error.stack });
      throw error;
    }
  }

  async updateAllowedIp(userId, ipAddress) {
    try {
      const result = await runQuery(
          this.db,
          'UPDATE users SET allowed_ip = ? WHERE id = ?',
          [ipAddress, userId]
      );

      if (result.changes > 0) {
        logger.info(`Updated allowed IP for user ID ${userId}`, { allowedIp: ipAddress });
        return true;
      }
      const userExists = await this.getUserById(userId);
      if (!userExists) {
        logger.warn(`Failed to update allowed IP: User ID ${userId} not found`);
        return false; // Indicate user not found
      }
      logger.info(`Allowed IP for user ID ${userId} was already set to ${ipAddress || 'NULL'}. No changes made.`);
      return true; // Indicate success even if no rows changed

    } catch (error) {
      logger.error(`Failed to update allowed IP for user ID ${userId}: ${error.message}`, { userId, ipAddress, error: error.stack });
      throw error;
    }
  }

  // --- NEW: Update User Profile (Custom Name) ---
  async updateUserProfile(userId, customName) {
    try {
      // Basic validation/sanitization for customName
      const nameToSave = (typeof customName === 'string' && customName.trim().length > 0)
          ? customName.trim().substring(0, 50) // Limit length
          : null; // Store null if empty or invalid

      const result = await runQuery(
          this.db,
          'UPDATE users SET custom_name = ? WHERE id = ?',
          [nameToSave, userId]
      );

      if (result.changes > 0) {
        logger.info(`Updated profile for user ID ${userId}`, { customName: nameToSave });
        return { success: true, custom_name: nameToSave };
      }
      // Check if user exists
      const userExists = await this.getUserById(userId);
      if (!userExists) {
        logger.warn(`Failed to update profile: User ID ${userId} not found`);
        return { success: false, error: 'User not found' };
      }
      // Check if the name was already the same
      if (userExists.custom_name === nameToSave) {
        logger.info(`Profile for user ID ${userId} already had custom name ${nameToSave || 'NULL'}. No changes made.`);
        return { success: true, custom_name: nameToSave }; // Return current name even if no change
      }
      // If no changes but name is different, something went wrong
      logger.error(`Profile update query executed for user ID ${userId} but no rows changed unexpectedly.`);
      return { success: false, error: 'Profile could not be updated.' };


    } catch (error) {
      logger.error(`Failed to update profile for user ID ${userId}: ${error.message}`, { userId, customName, error: error.stack });
      throw error;
    }
  }

  // --- NEW: Reset User Password ---
  async resetUserPassword(userId) {
    try {
      // Generate a secure random password (e.g., 12 characters)
      // Generate 9 random bytes -> 12 Base64 characters
      const newPassword = crypto.randomBytes(9).toString('base64').replace(/[/+=]/g, ''); // Remove potentially confusing chars
      const hashedPassword = await bcrypt.hash(newPassword, config.BCRYPT_SALT_ROUNDS);

      const result = await runQuery(
          this.db,
          'UPDATE users SET password = ? WHERE id = ?',
          [hashedPassword, userId]
      );

      if (result.changes > 0) {
        logger.info(`Password reset successfully for user ID ${userId}`);
        // IMPORTANT: Return the *new plain text password* so the user can be informed.
        return { success: true, newPassword: newPassword };
      }
      // Check if user exists
      const userExists = await this.getUserById(userId);
      if (!userExists) {
        logger.warn(`Failed to reset password: User ID ${userId} not found`);
        return { success: false, error: 'User not found' };
      }
      // This case should ideally not happen if password was updated
      logger.warn(`Password reset query executed for user ID ${userId} but no rows changed.`);
      return { success: false, error: 'Password could not be updated.' };

    } catch (error) {
      logger.error(`Failed to reset password for user ID ${userId}: ${error.message}`, { userId, error: error.stack });
      throw error;
    }
  }

}

module.exports = UserModel;