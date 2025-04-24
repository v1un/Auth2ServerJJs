// C:/Users/vini/WebstormProjects/jjguibotauthserver/src/routes/userRoutes.js
const express = require('express');
const { body, param } = require('express-validator');
const { validate, userValidationRules, userIdValidationRules } = require('../middleware/validator');
const { validationErrorHandler } = require('../middleware/errorHandler');
const { apiLimiter, adminLimiter, loginLimiter } = require('../middleware/rateLimiter'); // Added loginLimiter just in case

/**
 * Create user management routes
 * @param {Object} userController - User controller instance
 * @param {Object} userModel - User model instance (needed for auth middleware)
 * @param {Object} authMiddleware - Auth middleware functions { authenticateToken, requireAdminRole, requireUserRole }
 * @returns {Object} Express router
 */
const createUserRoutes = (userController, userModel, authMiddleware) => {
    const router = express.Router();
    const { authenticateToken, requireAdminRole, requireUserRole } = authMiddleware;

    // --- Current User Routes ---

    // GET /profile
    router.get(
        '/profile',
        authenticateToken, // Checks session or JWT
        requireUserRole,   // Ensures user is at least 'user' role
        apiLimiter,
        (req, res, next) => userController.getCurrentUser(req, res, next)
    );

    // PUT /profile (Update current user's profile)
    router.put(
        '/profile',
        authenticateToken,
        requireUserRole,
        apiLimiter, // Apply general API limiter
        // Add validation for custom_name
        validate([
            body('custom_name')
                .optional({ nullable: true, checkFalsy: true }) // Allow null or empty string to clear the name
                .isString().withMessage('Custom name must be a string.')
                .isLength({ max: 50 }).withMessage('Custom name cannot exceed 50 characters.')
                .trim() // Trim whitespace
        ]),
        validationErrorHandler,
        (req, res, next) => userController.updateCurrentUserProfile(req, res, next)
    );

    // POST /profile/reset-password (Reset current user's password)
    router.post(
        '/profile/reset-password',
        authenticateToken,
        requireUserRole,
        loginLimiter, // Use loginLimiter as it's a sensitive action like login
        // No body validation needed for this specific action
        (req, res, next) => userController.resetCurrentUserPassword(req, res, next)
    );


    // --- Admin Routes ---

    // GET / (List all users)
    router.get(
        '/',
        authenticateToken,
        requireAdminRole,
        adminLimiter,
        (req, res, next) => userController.getAllUsers(req, res, next)
    );

    // GET /:id (Get specific user)
    router.get(
        '/:id',
        authenticateToken,
        requireAdminRole,
        validate(userIdValidationRules),
        validationErrorHandler,
        adminLimiter,
        (req, res, next) => userController.getUserById(req, res, next)
    );

    // POST / (Create User)
    const createUserValidationRules = [
        ...userValidationRules, // Includes username/password format
        body('role').optional().isIn(['user', 'admin']).withMessage('Invalid role specified'),
    ];
    router.post(
        '/',
        authenticateToken,
        requireAdminRole,
        validate(createUserValidationRules),
        validationErrorHandler,
        adminLimiter,
        (req, res, next) => userController.createUser(req, res, next)
    );

    // DELETE /:id (Delete User)
    router.delete(
        '/:id',
        authenticateToken,
        requireAdminRole,
        validate(userIdValidationRules),
        validationErrorHandler,
        adminLimiter,
        (req, res, next) => userController.deleteUser(req, res, next)
    );

    // PUT /:id/reset-ip (Admin reset user IP)
    router.put(
        '/:id/reset-ip',
        authenticateToken,
        requireAdminRole,
        validate([
            param('id').isInt({ min: 1 }).withMessage('User ID must be a positive integer')
        ]),
        validationErrorHandler,
        adminLimiter,
        (req, res, next) => userController.resetAllowedIp(req, res, next)
    );

    return router;
};

module.exports = createUserRoutes;