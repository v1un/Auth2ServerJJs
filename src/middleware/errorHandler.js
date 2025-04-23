/**
 * Error handling middleware
 * Provides centralized error handling for the application
 */

// Custom error class for API errors
class ApiError extends Error {
  constructor(statusCode, message, code = 'INTERNAL_ERROR') {
    super(message);
    this.statusCode = statusCode;
    this.code = code;
    this.name = this.constructor.name;
    Error.captureStackTrace(this, this.constructor);
  }
}

// Not found error handler - for routes that don't exist
const notFoundHandler = (req, res, next) => {
  const error = new ApiError(404, `Route not found: ${req.originalUrl}`, 'NOT_FOUND');
  next(error);
};

// Global error handler
const errorHandler = (err, req, res, next) => {
  // Default to 500 server error
  const statusCode = err.statusCode || 500;
  const errorCode = err.code || 'INTERNAL_ERROR';
  
  // Log error details (in production, you might want to use a proper logging service)
  console.error(`[ERROR] ${statusCode} - ${errorCode}: ${err.message}`);
  if (statusCode === 500) {
    console.error(err.stack);
  }
  
  // Send error response
  res.status(statusCode).json({
    error: err.message,
    code: errorCode,
    // Only include stack trace in development
    ...(process.env.NODE_ENV !== 'production' && { stack: err.stack })
  });
};

// Validation error handler for express-validator
const validationErrorHandler = (req, res, next) => {
  const { validationErrors } = req;
  if (validationErrors && validationErrors.length > 0) {
    const error = new ApiError(
      400, 
      'Validation error', 
      'VALIDATION_ERROR'
    );
    error.validationErrors = validationErrors;
    return next(error);
  }
  next();
};

module.exports = {
  ApiError,
  notFoundHandler,
  errorHandler,
  validationErrorHandler
};