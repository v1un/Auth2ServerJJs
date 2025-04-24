// C:/Users/vini/WebstormProjects/jjguibotauthserver/src/routes/authRoutes.js
const express = require('express');
const { validate, loginValidationRules } = require('../middleware/validator');
const { validationErrorHandler } = require('../middleware/errorHandler');
const { loginLimiter, apiLimiter } = require('../middleware/rateLimiter');

/**
 * Create authentication routes
 * @param {Object} authController - Auth controller instance
 * @param {Object} authMiddleware - Auth middleware functions
 * @returns {Object} Express router
 */
module.exports = (authController, authMiddleware) => {
  const router = express.Router();
  // Destructure if needed: const { authenticateToken, requireUserRole } = authMiddleware;

  // --- Standard User Login ---
  router.post(
      '/login',
      loginLimiter,
      // Validation now happens within the controller or dedicated middleware if needed for rememberMe
      // validate(loginValidationRules), // Keep if validating username/password format
      validationErrorHandler,
      (req, res, next) => authController.login(req, res, next)
  );

  // --- Admin Login ---
  router.post(
      '/admin/login',
      loginLimiter,
      // validate(loginValidationRules), // Keep if validating username/password format
      validationErrorHandler,
      (req, res, next) => authController.adminLogin(req, res, next)
  );

  // --- NEW: Logout Route ---
  // Use POST for logout to prevent CSRF issues with GET requests
  router.post(
      '/logout',
      apiLimiter, // Apply a general limiter
      // No validation needed, relies on session
      (req, res, next) => authController.logout(req, res, next)
  );
  // --- End Logout Route ---


  // --- Device Flow Routes ---
  router.post(
      '/oauth/device/code',
      apiLimiter,
      (req, res, next) => authController.initiateDeviceAuth(req, res, next)
  );

  router.post(
      '/oauth/token',
      apiLimiter,
      // TODO: Add validation rules for grant_type, device_code
      // validationErrorHandler,
      (req, res, next) => authController.pollDeviceToken(req, res, next)
  );
  // --- End Device Flow Routes ---

  return router;
};