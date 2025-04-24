// C:/Users/vini/WebstormProjects/jjguibotauthserver/src/middleware/validator.js
const { body, param, validationResult } = require('express-validator');
const { isValidLoopbackRedirect } = require('../utils/validationHelpers'); // Import the helper

/**
 * Middleware to validate request data
 * @param {Array} validations - Array of express-validator validation chains
 * @returns {Function} Middleware function
 */
const validate = (validations) => {
  return async (req, res, next) => {
    await Promise.all(validations.map(validation => validation.run(req)));
    const errors = validationResult(req);
    if (errors.isEmpty()) {
      return next();
    }
    // Attach errors to request for the validationErrorHandler
    req.validationErrors = errors.array();
    // Call next *without* an error, let validationErrorHandler handle it
    next();
  };
};

// Common validation rules
const userValidationRules = [
  body('username')
      .trim()
      .isLength({ min: 3, max: 30 })
      .withMessage('Username must be between 3 and 30 characters')
      .matches(/^[a-zA-Z0-9_]+$/)
      .withMessage('Username can only contain letters, numbers, and underscores'),

  body('password')
      .isLength({ min: 8 })
      .withMessage('Password must be at least 8 characters long')
  // Add back specific character requirements if needed
  // .matches(/[a-z]/).withMessage('Password must contain a lowercase letter')
  // .matches(/[A-Z]/).withMessage('Password must contain an uppercase letter')
  // .matches(/[0-9]/).withMessage('Password must contain a number')
];

// User ID validation for route parameters
const userIdValidationRules = [
  param('id')
      .isInt({ min: 1 })
      .withMessage('User ID must be a positive integer')
];

// Login validation rules (less strict than user creation)
const loginValidationRules = [
  body('username')
      .trim()
      .notEmpty()
      .withMessage('Username is required'),

  body('password')
      .notEmpty()
      .withMessage('Password is required'),

  // --- Updated redirectUri validation ---
  body('redirectUri')
      // Use checkFalsy: true to skip subsequent checks if the value is '', null, undefined, or missing
      .optional({ checkFalsy: true })
      // These checks only run if redirectUri is provided and is not an empty string
      .isURL({
        protocols: ['http'],
        require_protocol: true,
        require_host: true,
        require_tld: false // <--- Allow localhost (no TLD)
      })
      // You can make the message slightly more specific if you like:
      .withMessage('If provided, redirect URI must be a valid HTTP URL (like http://localhost:port/path)')
      .custom((value) => {
        // This custom check also only runs if value is truthy
        if (!isValidLoopbackRedirect(value)) {
          // Make error message slightly more specific about the port requirement
          throw new Error('If provided, redirect URI must be to http://localhost:[port] or http://127.0.0.1:[port] with a valid port number');
        }
        return true; // Indicates validation success
      })
];

module.exports = {
  validate,
  userValidationRules,
  userIdValidationRules,
  loginValidationRules
};