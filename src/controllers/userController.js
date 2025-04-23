const logger = require('../utils/logger');
const { ApiError } = require('../middleware/errorHandler');

/**
 * User controller for handling user management operations
 */
class UserController {
  constructor(userModel) {
    this.userModel = userModel;
  }

  /**
   * Get all users
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @param {Function} next - Express next middleware function
   */
  async getAllUsers(req, res, next) {
    try {
      const users = await this.userModel.getAllUsers();
      res.json(users);
    } catch (error) {
      next(error);
    }
  }

  /**
   * Get user by ID
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @param {Function} next - Express next middleware function
   */
  async getUserById(req, res, next) {
    try {
      const userId = parseInt(req.params.id);
      const user = await this.userModel.getUserById(userId);
      
      if (!user) {
        throw new ApiError(404, 'User not found', 'USER_NOT_FOUND');
      }
      
      // Don't return password hash
      const { password, ...userWithoutPassword } = user;
      
      res.json(userWithoutPassword);
    } catch (error) {
      next(error);
    }
  }

  /**
   * Create a new user
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @param {Function} next - Express next middleware function
   */
  async createUser(req, res, next) {
    try {
      const { username, password, role = 'user' } = req.body;
      
      // Only allow admin role if the requesting user is an admin
      const userRole = req.user && req.user.role === 'admin' && role === 'admin' 
        ? 'admin' 
        : 'user';
      
      const newUser = await this.userModel.createUser(username, password, userRole);
      
      res.status(201).json({
        message: 'User created successfully',
        user: {
          id: newUser.id,
          username: newUser.username,
          role: newUser.role,
          created_at: newUser.created_at
        }
      });
    } catch (error) {
      // Handle specific error for duplicate username
      if (error.code === 'USERNAME_EXISTS') {
        return next(new ApiError(409, 'Username already exists', 'USERNAME_EXISTS'));
      }
      next(error);
    }
  }

  /**
   * Delete a user
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @param {Function} next - Express next middleware function
   */
  async deleteUser(req, res, next) {
    try {
      const userId = parseInt(req.params.id);
      
      // Prevent deleting the current user
      if (req.user && req.user.userId === userId) {
        throw new ApiError(400, 'Cannot delete your own account', 'CANNOT_DELETE_SELF');
      }
      
      const deleted = await this.userModel.deleteUser(userId);
      
      if (!deleted) {
        throw new ApiError(404, 'User not found', 'USER_NOT_FOUND');
      }
      
      res.json({ message: 'User deleted successfully' });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Get current user profile
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @param {Function} next - Express next middleware function
   */
  async getCurrentUser(req, res, next) {
    try {
      // For environment-based admin
      if (req.user.userId === 0) {
        return res.json({
          username: req.user.username,
          role: req.user.role
        });
      }
      
      const user = await this.userModel.getUserById(req.user.userId);
      
      if (!user) {
        throw new ApiError(404, 'User not found', 'USER_NOT_FOUND');
      }
      
      // Don't return password hash
      const { password, ...userWithoutPassword } = user;
      
      res.json(userWithoutPassword);
    } catch (error) {
      next(error);
    }
  }
}

module.exports = UserController;