// C:/Users/vini/WebstormProjects/jjguibotauthserver/src/middleware/rateLimiter.js
const rateLimit = require('express-rate-limit');
const { config } = require('../config/env');
const { ApiError } = require('./errorHandler');

/**
 * Create a rate limiter middleware
 * @param {Object} options - Rate limiter options
 * @returns {Function} Rate limiter middleware
 */
const createRateLimiter = (options = {}) => {
  const defaultOptions = {
    windowMs: config.RATE_LIMIT_WINDOW_MS, // Default window from config
    max: config.RATE_LIMIT_MAX_REQUESTS, // Default max requests from config
    standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
    legacyHeaders: false, // Disable the `X-RateLimit-*` headers
    handler: (req, res, next, options) => {
      // Create a custom API error for rate limiting
      next(new ApiError(
          options.statusCode || 429, // Use statusCode from options if provided
          options.message || 'Too many requests, please try again later.',
          'RATE_LIMIT_EXCEEDED'
      ));
    }
  };

  // Merge default options with provided options
  const limiterOptions = { ...defaultOptions, ...options };

  return rateLimit(limiterOptions);
};

// Create standard rate limiters for different endpoints

// General API limiter (uses defaults from .env)
const apiLimiter = createRateLimiter();

// Specific limiter for login attempts
const loginLimiter = createRateLimiter({ // Renamed from authLimiter
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // Allow 10 login attempts per 15 minutes per IP
  message: 'Too many login attempts from this IP, please try again after 15 minutes',
  // Optional: You could add skipSuccessfulRequests: true if you only want to limit failed attempts
});

// Specific limiter for admin actions (can be stricter or looser depending on needs)
const adminLimiter = createRateLimiter({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 50, // Allow 50 admin actions per hour per IP (adjust as needed)
  message: 'Too many admin requests from this IP, please try again after an hour'
});

module.exports = {
  createRateLimiter,
  apiLimiter,
  loginLimiter, // Export the renamed limiter
  adminLimiter
};