const express = require('express');
const { validate, loginValidationRules } = require('../middleware/validator');
const { validationErrorHandler } = require('../middleware/errorHandler');
const { authLimiter } = require('../middleware/rateLimiter');

/**
 * Create authentication routes
 * @param {Object} authController - Authentication controller instance
 * @returns {Object} Express router
 */
const createAuthRoutes = (authController) => {
  const router = express.Router();
  
  /**
   * @route POST /api/auth/login
   * @desc Authenticate user and get token
   * @access Public
   */
  router.post(
    '/login',
    authLimiter, // Apply rate limiting to prevent brute force attacks
    validate(loginValidationRules),
    validationErrorHandler,
    (req, res, next) => authController.login(req, res, next)
  );
  
  /**
   * @route POST /api/auth/admin/login
   * @desc Authenticate admin and get token
   * @access Public
   */
  router.post(
    '/admin/login',
    authLimiter, // Apply rate limiting to prevent brute force attacks
    validate(loginValidationRules),
    validationErrorHandler,
    (req, res, next) => authController.adminLogin(req, res, next)
  );
  
  return router;
};

module.exports = createAuthRoutes;