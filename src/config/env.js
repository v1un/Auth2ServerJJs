// C:/Users/vini/WebstormProjects/jjguibotauthserver/src/config/env.js
require('dotenv').config();
const logger = require('../utils/logger'); // Assuming logger is available early

const config = {
  PORT: process.env.PORT || 3000,
  NODE_ENV: process.env.NODE_ENV || 'development',
  JWT_SECRET: process.env.JWT_SECRET,
  JWT_EXPIRATION: process.env.JWT_EXPIRATION || '1h',
  JWT_EXPIRATION_SECONDS: parseInt(process.env.JWT_EXPIRATION_SECONDS, 10) || 3600, // Default 1 hour
  BCRYPT_SALT_ROUNDS: parseInt(process.env.BCRYPT_SALT_ROUNDS, 10) || 10,
  ADMIN_USERNAME: process.env.ADMIN_USERNAME,
  ADMIN_PASSWORD: process.env.ADMIN_PASSWORD,
  DB_PATH: process.env.DB_PATH || 'auth.db',
  LOG_LEVEL: process.env.LOG_LEVEL || 'INFO',
  RATE_LIMIT_WINDOW_MS: parseInt(process.env.RATE_LIMIT_WINDOW_MS, 10) || 15 * 60 * 1000, // 15 minutes
  RATE_LIMIT_MAX_REQUESTS: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS, 10) || 100,
  CORS_ALLOWED_ORIGINS: process.env.CORS_ALLOWED_ORIGINS || '*',
  SESSION_SECRET: process.env.SESSION_SECRET, // Added
};

// Derived config
config.isProd = config.NODE_ENV === 'production';
config.isDev = config.NODE_ENV === 'development';

// Validation function
const validateConfig = () => {
  const requiredEnvVars = [
    'JWT_SECRET',
    'ADMIN_USERNAME',
    'ADMIN_PASSWORD',
    'SESSION_SECRET', // Added
  ];

  const missingVars = requiredEnvVars.filter(key => !config[key]);

  if (missingVars.length > 0) {
    const message = `Missing required environment variables: ${missingVars.join(', ')}`;
    logger.error(message);
    throw new Error(message);
  }

  if (config.isProd && config.JWT_SECRET === 'your_super_secure_jwt_secret_key_change_this_in_production') {
    const message = 'Default JWT_SECRET detected in production environment. Please set a strong, unique secret.';
    logger.error(message);
    throw new Error(message);
  }

  if (config.isProd && config.SESSION_SECRET === 'your_very_secure_random_session_secret_change_this') {
    const message = 'Default SESSION_SECRET detected in production environment. Please set a strong, unique secret.';
    logger.error(message);
    throw new Error(message);
  }

  if (isNaN(config.JWT_EXPIRATION_SECONDS) || config.JWT_EXPIRATION_SECONDS <= 0) {
    const message = 'Invalid JWT_EXPIRATION_SECONDS. Must be a positive number.';
    logger.error(message);
    throw new Error(message);
  }

  // Add more validation as needed (e.g., BCRYPT_SALT_ROUNDS range)
  logger.info('Environment configuration validated successfully.');
};

module.exports = { config, validateConfig };