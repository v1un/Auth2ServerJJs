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
        429, 
        'Too many requests, please try again later.', 
        'RATE_LIMIT_EXCEEDED'
      ));
    }
  };

  // Merge default options with provided options
  const limiterOptions = { ...defaultOptions, ...options };
  
  return rateLimit(limiterOptions);
};

// Create standard rate limiters for different endpoints
const apiLimiter = createRateLimiter();

const authLimiter = createRateLimiter({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // 10 requests per 15 minutes
  message: 'Too many login attempts, please try again later'
});

const adminLimiter = createRateLimiter({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 30 // 30 requests per hour for admin endpoints
});

module.exports = {
  createRateLimiter,
  apiLimiter,
  authLimiter,
  adminLimiter
};