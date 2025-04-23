const { config } = require('../config/env');
const { generateToken } = require('../middleware/auth');
const logger = require('../utils/logger');
const { ApiError } = require('../middleware/errorHandler');

/**
 * Authentication controller
 */
class AuthController {
  constructor(userModel) {
    this.userModel = userModel;
  }

  /**
   * Handle user login
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @param {Function} next - Express next middleware function
   */
  async login(req, res, next) {
    try {
      const { username, password } = req.body;
      
      // Verify user credentials
      const user = await this.userModel.verifyCredentials(username, password);
      
      if (!user) {
        throw new ApiError(401, 'Invalid credentials', 'INVALID_CREDENTIALS');
      }
      
      // Generate JWT token
      const token = generateToken(user);
      
      // Return token
      res.json({ 
        token,
        user: {
          id: user.id,
          username: user.username,
          role: user.role
        }
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Handle admin login
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @param {Function} next - Express next middleware function
   */
  async adminLogin(req, res, next) {
    try {
      const { username, password } = req.body;
      
      // Verify admin credentials from environment variables
      if (username === config.ADMIN_USERNAME && password === config.ADMIN_PASSWORD) {
        // Create admin user object
        const adminUser = {
          id: 0, // Special ID for environment-based admin
          username: config.ADMIN_USERNAME,
          role: 'admin'
        };
        
        // Generate JWT token
        const token = generateToken(adminUser);
        
        logger.info(`Admin login successful: ${username}`);
        
        // Return token
        return res.json({ 
          token,
          user: {
            username: adminUser.username,
            role: adminUser.role
          }
        });
      }
      
      // Check if this is a database admin user
      const user = await this.userModel.verifyCredentials(username, password);
      
      if (user && user.role === 'admin') {
        // Generate JWT token
        const token = generateToken(user);
        
        logger.info(`Database admin login successful: ${username}`);
        
        // Return token
        return res.json({ 
          token,
          user: {
            id: user.id,
            username: user.username,
            role: user.role
          }
        });
      }
      
      // If we get here, authentication failed
      logger.warn(`Failed admin login attempt: ${username}`);
      throw new ApiError(401, 'Invalid admin credentials', 'INVALID_ADMIN_CREDENTIALS');
    } catch (error) {
      next(error);
    }
  }
}

module.exports = AuthController;