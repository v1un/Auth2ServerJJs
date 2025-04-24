// C:/Users/vini/WebstormProjects/jjguibotauthserver/src/controllers/userController.js
const { ApiError } = require('../middleware/errorHandler');
const logger = require('../utils/logger');

class UserController {
  constructor(userModel) {
    this.userModel = userModel;
  }

  /**
   * Get all users (Admin only)
   */
  async getAllUsers(req, res, next) {
    try {
      const users = await this.userModel.getAllUsers();
      // Users already sanitized in model method
      res.json(users);
    } catch (error) {
      next(error);
    }
  }

  /**
   * Get a user by ID (Admin only)
   */
  async getUserById(req, res, next) {
    try {
      const userId = parseInt(req.params.id);
      const user = await this.userModel.getUserById(userId);
      if (!user) {
        throw new ApiError(404, 'User not found', 'USER_NOT_FOUND');
      }
      const { password, ...sanitizedUser } = user; // Sanitize password here
      res.json(sanitizedUser);
    } catch (error) {
      next(error);
    }
  }

  /**
   * Get the profile of the currently authenticated user
   */
  async getCurrentUser(req, res, next) {
    try {
      const { userId, username, role } = req.user;
      // Handle special admin case (ID 0) - doesn't have a DB entry
      if (userId === 0 && role === 'admin') {
        // Return basic info, indicate no custom name/IP applicable
        return res.json({
          id: 0,
          username,
          role,
          custom_name: 'Environment Admin', // Or null
          allowed_ip: null, // Or 'N/A'
          created_at: null // Or 'N/A'
        });
      }
      // Fetch regular user from DB
      const user = await this.userModel.getUserById(userId);
      if (!user) {
        logger.warn(`User ID ${userId} from token/session not found in DB during profile fetch.`);
        // Invalidate session if user doesn't exist
        if (req.session) {
          req.session.destroy((err) => {
            if (err) logger.error("Error destroying session after user not found", { userId });
          });
        }
        // Send 401 to trigger re-login on frontend
        throw new ApiError(401, 'User profile not found or session invalid', 'USER_NOT_FOUND');
      }
      const { password, ...sanitizedUser } = user; // Sanitize password
      res.json(sanitizedUser);
    } catch (error) {
      next(error);
    }
  }

  /**
   * Create a new user (Admin only)
   */
  async createUser(req, res, next) {
    try {
      const { username, password, role = 'user' } = req.body;
      const roleToSave = req.user?.role === 'admin' && role === 'admin' ? 'admin' : 'user';
      // Pass null for allowed_ip and custom_name initially
      const newUser = await this.userModel.createUser(username, password, roleToSave, null, null);
      const { password: _, ...sanitizedUser } = newUser; // Sanitize password
      res.status(201).json({
        message: 'User created successfully',
        user: sanitizedUser
      });
    } catch (error) {
      if (error.code === 'USERNAME_EXISTS') {
        return next(new ApiError(409, 'Username already exists', 'USERNAME_EXISTS'));
      }
      next(error);
    }
  }

  /**
   * Delete a user by ID (Admin only)
   */
  async deleteUser(req, res, next) {
    try {
      const userIdToDelete = parseInt(req.params.id);
      const requestingUserId = req.user.userId;
      if (userIdToDelete === requestingUserId) {
        throw new ApiError(400, 'Admin cannot delete their own account.', 'CANNOT_DELETE_SELF');
      }
      if (userIdToDelete === 0) {
        throw new ApiError(400, 'Cannot delete the primary environment administrator.', 'CANNOT_DELETE_ENV_ADMIN');
      }
      const deleted = await this.userModel.deleteUser(userIdToDelete);
      if (!deleted) {
        throw new ApiError(404, 'User not found', 'USER_NOT_FOUND');
      }
      res.json({ message: `User ID ${userIdToDelete} deleted successfully.` });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Reset the allowed IP for a user (Admin only), setting it to null.
   */
  async resetAllowedIp(req, res, next) {
    try {
      const userId = parseInt(req.params.id);
      if (userId === 0) {
        throw new ApiError(400, 'Cannot modify the primary environment administrator.', 'CANNOT_MODIFY_ENV_ADMIN');
      }
      const updated = await this.userModel.updateAllowedIp(userId, null);
      if (!updated) {
        throw new ApiError(404, 'User not found', 'USER_NOT_FOUND');
      }
      logger.info(`Reset allowed IP for user ID ${userId}.`);
      res.json({ message: `Allowed IP for user ID ${userId} has been reset. User can log in from any IP next.` });
    } catch (error) {
      next(error);
    }
  }

  // --- NEW: Update Current User's Profile ---
  async updateCurrentUserProfile(req, res, next) {
    try {
      const { userId } = req.user;
      const { custom_name } = req.body; // Get custom_name from request body

      // Cannot update profile for environment admin (ID 0)
      if (userId === 0) {
        throw new ApiError(400, 'Cannot modify the primary environment administrator profile.', 'CANNOT_MODIFY_ENV_ADMIN');
      }

      // Validation is handled by express-validator middleware now

      const result = await this.userModel.updateUserProfile(userId, custom_name);

      if (!result.success) {
        // Handle case where user might not be found (though unlikely if authenticated)
        throw new ApiError(404, result.error || 'Could not update profile.', 'UPDATE_FAILED');
      }

      res.json({
        message: 'Profile updated successfully.',
        custom_name: result.custom_name // Return the updated/current name
      });

    } catch (error) {
      next(error);
    }
  }

  // --- NEW: Reset Current User's Password ---
  async resetCurrentUserPassword(req, res, next) {
    try {
      const { userId, username } = req.user;

      // Cannot reset password for environment admin (ID 0) via this method
      if (userId === 0) {
        throw new ApiError(400, 'Password for the primary environment administrator must be changed via environment variables.', 'CANNOT_MODIFY_ENV_ADMIN');
      }

      const result = await this.userModel.resetUserPassword(userId);

      if (!result.success) {
        throw new ApiError(404, result.error || 'Could not reset password.', 'UPDATE_FAILED');
      }

      // IMPORTANT: Return the new password in the response for the user to copy.
      logger.warn(`Password reset for user ${username} (ID: ${userId}). New password returned in response.`);
      res.json({
        message: 'Password has been reset successfully. Please store the new password securely.',
        newPassword: result.newPassword
      });

    } catch (error) {
      next(error);
    }
  }

}

module.exports = UserController;