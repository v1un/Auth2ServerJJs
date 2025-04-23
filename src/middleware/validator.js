const { body, param, validationResult } = require('express-validator');

/**
 * Middleware to validate request data
 * @param {Array} validations - Array of express-validator validation chains
 * @returns {Function} Middleware function
 */
const validate = (validations) => {
  return async (req, res, next) => {
    // Execute all validations
    await Promise.all(validations.map(validation => validation.run(req)));
    
    // Get validation errors
    const errors = validationResult(req);
    
    if (errors.isEmpty()) {
      return next();
    }
    
    // Store validation errors in request object for the error handler
    req.validationErrors = errors.array();
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
    .matches(/[a-z]/)
    .withMessage('Password must contain at least one lowercase letter')
    .matches(/[A-Z]/)
    .withMessage('Password must contain at least one uppercase letter')
    .matches(/[0-9]/)
    .withMessage('Password must contain at least one number')
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
    .withMessage('Password is required')
];

module.exports = {
  validate,
  userValidationRules,
  userIdValidationRules,
  loginValidationRules
};