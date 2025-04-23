/**
 * Simple logging utility
 * In a production environment, this could be replaced with a more robust logging solution
 * like Winston or Pino
 */

const { config } = require('../config/env');

// ANSI color codes for console output
const colors = {
  reset: '\x1b[0m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
  gray: '\x1b[90m'
};

// Log levels
const LOG_LEVELS = {
  ERROR: 0,
  WARN: 1,
  INFO: 2,
  DEBUG: 3
};

// Determine current log level from environment
const getCurrentLogLevel = () => {
  const envLogLevel = (process.env.LOG_LEVEL || '').toUpperCase();
  return LOG_LEVELS[envLogLevel] !== undefined 
    ? LOG_LEVELS[envLogLevel] 
    : (config.isProd ? LOG_LEVELS.INFO : LOG_LEVELS.DEBUG);
};

// Current log level
const currentLogLevel = getCurrentLogLevel();

/**
 * Format the log message with timestamp and optional metadata
 * @param {string} level - Log level
 * @param {string} message - Log message
 * @param {Object} meta - Additional metadata
 * @returns {string} Formatted log message
 */
const formatLogMessage = (level, message, meta = {}) => {
  const timestamp = new Date().toISOString();
  let formattedMessage = `[${timestamp}] [${level}] ${message}`;
  
  // Add metadata if present
  if (Object.keys(meta).length > 0) {
    try {
      formattedMessage += ` ${JSON.stringify(meta)}`;
    } catch (err) {
      formattedMessage += ` [Error serializing metadata: ${err.message}]`;
    }
  }
  
  return formattedMessage;
};

/**
 * Log an error message
 * @param {string} message - Error message
 * @param {Object} meta - Additional metadata
 */
const error = (message, meta = {}) => {
  if (currentLogLevel >= LOG_LEVELS.ERROR) {
    console.error(colors.red + formatLogMessage('ERROR', message, meta) + colors.reset);
  }
};

/**
 * Log a warning message
 * @param {string} message - Warning message
 * @param {Object} meta - Additional metadata
 */
const warn = (message, meta = {}) => {
  if (currentLogLevel >= LOG_LEVELS.WARN) {
    console.warn(colors.yellow + formatLogMessage('WARN', message, meta) + colors.reset);
  }
};

/**
 * Log an info message
 * @param {string} message - Info message
 * @param {Object} meta - Additional metadata
 */
const info = (message, meta = {}) => {
  if (currentLogLevel >= LOG_LEVELS.INFO) {
    console.info(colors.green + formatLogMessage('INFO', message, meta) + colors.reset);
  }
};

/**
 * Log a debug message
 * @param {string} message - Debug message
 * @param {Object} meta - Additional metadata
 */
const debug = (message, meta = {}) => {
  if (currentLogLevel >= LOG_LEVELS.DEBUG) {
    console.debug(colors.cyan + formatLogMessage('DEBUG', message, meta) + colors.reset);
  }
};

/**
 * Log HTTP request details
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 */
const httpRequest = (req, res) => {
  if (currentLogLevel >= LOG_LEVELS.INFO) {
    const meta = {
      method: req.method,
      url: req.originalUrl,
      ip: req.ip,
      statusCode: res.statusCode,
      userAgent: req.get('user-agent')
    };
    
    // Add user info if authenticated
    if (req.user) {
      meta.user = {
        username: req.user.username,
        role: req.user.role
      };
    }
    
    info('HTTP Request', meta);
  }
};

module.exports = {
  error,
  warn,
  info,
  debug,
  httpRequest,
  LOG_LEVELS
};