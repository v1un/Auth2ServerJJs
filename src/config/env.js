// Environment configuration
require('dotenv').config();

// Default configuration values
const defaults = {
  // Server settings
  PORT: 3000,
  NODE_ENV: 'development',
  
  // Security
  JWT_SECRET: 'default_jwt_secret_change_this',
  JWT_EXPIRATION: '1h',
  BCRYPT_SALT_ROUNDS: 10,
  
  // Admin credentials
  ADMIN_USERNAME: 'admin',
  ADMIN_PASSWORD: 'admin123',
  
  // Database
  DB_PATH: 'auth.db',
  
  // Rate limiting
  RATE_LIMIT_WINDOW_MS: 15 * 60 * 1000, // 15 minutes
  RATE_LIMIT_MAX_REQUESTS: 100 // 100 requests per window
};

// Environment configuration with defaults
const config = {
  // Server settings
  PORT: process.env.PORT || defaults.PORT,
  NODE_ENV: process.env.NODE_ENV || defaults.NODE_ENV,
  
  // Security
  JWT_SECRET: process.env.JWT_SECRET || defaults.JWT_SECRET,
  JWT_EXPIRATION: process.env.JWT_EXPIRATION || defaults.JWT_EXPIRATION,
  BCRYPT_SALT_ROUNDS: parseInt(process.env.BCRYPT_SALT_ROUNDS || defaults.BCRYPT_SALT_ROUNDS),
  
  // Admin credentials
  ADMIN_USERNAME: process.env.ADMIN_USERNAME || defaults.ADMIN_USERNAME,
  ADMIN_PASSWORD: process.env.ADMIN_PASSWORD || defaults.ADMIN_PASSWORD,
  
  // Database
  DB_PATH: process.env.DB_PATH || defaults.DB_PATH,
  
  // Rate limiting
  RATE_LIMIT_WINDOW_MS: parseInt(process.env.RATE_LIMIT_WINDOW_MS || defaults.RATE_LIMIT_WINDOW_MS),
  RATE_LIMIT_MAX_REQUESTS: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS || defaults.RATE_LIMIT_MAX_REQUESTS),
  
  // Computed properties
  isProd: (process.env.NODE_ENV || defaults.NODE_ENV) === 'production',
  isDev: (process.env.NODE_ENV || defaults.NODE_ENV) === 'development'
};

// Validate critical configuration
const validateConfig = () => {
  // In production, ensure JWT_SECRET is changed from default
  if (config.isProd && config.JWT_SECRET === defaults.JWT_SECRET) {
    console.error('ERROR: JWT_SECRET must be changed in production environment');
    process.exit(1);
  }
  
  // In production, ensure admin credentials are changed from defaults
  if (config.isProd && 
      config.ADMIN_USERNAME === defaults.ADMIN_USERNAME && 
      config.ADMIN_PASSWORD === defaults.ADMIN_PASSWORD) {
    console.error('ERROR: Default admin credentials must be changed in production environment');
    process.exit(1);
  }
  
  // Log warning if using default JWT_SECRET in development
  if (config.isDev && config.JWT_SECRET === defaults.JWT_SECRET) {
    console.warn('WARNING: Using default JWT_SECRET in development environment');
  }
};

module.exports = {
  config,
  validateConfig
};