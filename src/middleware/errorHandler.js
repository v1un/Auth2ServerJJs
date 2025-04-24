/**
 * Error handling middleware
 * Provides centralized error handling for the application
 */

const logger = require('../utils/logger'); // Import your logger
const { config } = require('../config/env'); // Import config

// Custom error class for API errors
class ApiError extends Error {
  constructor(statusCode, message, code = 'INTERNAL_ERROR', details = null) {
    super(message);
    this.statusCode = statusCode;
    this.code = code;
    this.details = details; // Add a field for extra details
    this.name = this.constructor.name;
    Error.captureStackTrace(this, this.constructor);
  }
}

// Not found error handler - for routes that don't exist
const notFoundHandler = (req, res, next) => {
  const error = new ApiError(404, `Route not found: ${req.method} ${req.originalUrl}`, 'NOT_FOUND');
  next(error);
};

// Global error handler
const errorHandler = (err, req, res, next) => {
  // Determine status code and error code
  const statusCode = err instanceof ApiError ? err.statusCode : 500;
  const errorCode = err instanceof ApiError ? err.code : 'INTERNAL_ERROR';
  const message = err.message || 'An unexpected error occurred.';

  // Prepare log details
  const logDetails = {
    error: message,
    code: errorCode,
    statusCode: statusCode,
    method: req.method,
    url: req.originalUrl,
    ip: req.ip,
    user: req.user ? { id: req.user.userId, username: req.user.username, role: req.user.role } : undefined,
    validationErrors: err.validationErrors || undefined, // Include validation errors if present
    details: err.details || undefined, // Include custom details if present
    stack: (statusCode === 500 || config.isDev) ? err.stack : undefined // Log stack for 500s or in dev
  };

  // Log the error using the logger
  if (statusCode >= 500) {
    logger.error('Unhandled Error', logDetails);
  } else {
    // Log client errors (4xx) as warnings
    logger.warn('Client Error', logDetails);
  }

  // --- Potential Integration Point for Error Tracking (e.g., Sentry, Datadog) ---
  if (config.isProd && statusCode >= 500) {
    // Example: Sentry.captureException(err, { extra: logDetails });
    // Example: datadogLogger.error(message, logDetails);
  }
  // --- End Integration Point ---

  // Prepare response body
  const responseBody = {
    error: (config.isProd && statusCode >= 500) ? 'An internal server error occurred.' : message, // Generic message for 500s in prod
    code: errorCode,
  };

  // Include validation errors in the response if they exist
  if (err.validationErrors) {
    responseBody.validationErrors = err.validationErrors.map(e => ({
      field: e.path || e.param, // Use 'path' if available (newer express-validator), fallback to 'param'
      message: e.msg,
      value: e.value // Optionally include the invalid value
    }));
  }

  // Include custom details in development if they exist
  if (config.isDev && err.details) {
    responseBody.details = err.details;
  }

  // Include stack trace in development only (for non-validation errors)
  if (config.isDev && !err.validationErrors) {
    responseBody.stack = err.stack;
  }

  // Send error response
  // Check if headers have already been sent (e.g., by a stream error)
  if (res.headersSent) {
    return next(err); // Pass to default Express error handler
  }

  res.status(statusCode).json(responseBody);
};

// Validation error handler for express-validator
const validationErrorHandler = (req, res, next) => {
  const { validationErrors } = req; // Errors attached by the 'validate' middleware
  if (validationErrors && validationErrors.length > 0) {
    // Create a specific ApiError for validation failures
    const error = new ApiError(
        400,
        'Validation failed. Please check your input.', // More user-friendly message
        'VALIDATION_ERROR'
    );
    // Attach the raw validation errors for logging and detailed response
    error.validationErrors = validationErrors;
    return next(error); // Pass the structured error to the global errorHandler
  }
  // No validation errors, proceed to the next middleware/route handler
  next();
};

module.exports = {
  ApiError,
  notFoundHandler,
  errorHandler,
  validationErrorHandler
};