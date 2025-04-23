const express = require('express');
const { 
  authenticateToken, 
  requireAdminRole, 
  requireUserRole 
} = require('../middleware/auth');
const { 
  validate, 
  userValidationRules, 
  userIdValidationRules 
} = require('../middleware/validator');
const { validationErrorHandler } = require('../middleware/errorHandler');
const { adminLimiter, apiLimiter } = require('../middleware/rateLimiter');

/**
 * Create user routes
 * @param {Object} userController - User controller instance
 * @returns {Object} Express router
 */
const createUserRoutes = (userController) => {
  const router = express.Router();
  
  // GET /api/users - Get all users (Admin only)
  router.get(
    '/',
    authenticateToken,
    requireAdminRole,
    adminLimiter,
    (req, res, next) => userController.getAllUsers(req, res, next)
  );
  
  // GET /api/users/profile - Get current user profile (Authenticated users)
  router.get(
    '/profile',
    authenticateToken,
    requireUserRole,
    apiLimiter,
    (req, res, next) => userController.getCurrentUser(req, res, next)
  );
  
  // GET /api/users/:id - Get user by ID (Admin only)
  router.get(
    '/:id',
    authenticateToken,
    requireAdminRole,
    validate(userIdValidationRules),
    validationErrorHandler,
    adminLimiter,
    (req, res, next) => userController.getUserById(req, res, next)
  );
  
  // POST /api/users - Create a new user (Admin only)
  router.post(
    '/',
    authenticateToken,
    requireAdminRole,
    validate(userValidationRules),
    validationErrorHandler,
    adminLimiter,
    (req, res, next) => userController.createUser(req, res, next)
  );
  
  // DELETE /api/users/:id - Delete a user (Admin only)
  router.delete(
    '/:id',
    authenticateToken,
    requireAdminRole,
    validate(userIdValidationRules),
    validationErrorHandler,
    adminLimiter,
    (req, res, next) => userController.deleteUser(req, res, next)
  );
  
  return router;
};

module.exports = createUserRoutes;