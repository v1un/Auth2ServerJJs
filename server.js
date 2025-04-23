/**
 * Authentication Server using Node.js and Express
 * Main server file
 */

// Load environment variables
require('dotenv').config();

const { initializeApp } = require('./src/app');
const logger = require('./src/utils/logger');
const { config } = require('./src/config/env');

// Start the server
const startServer = async () => {
  try {
    // Initialize the application
    const app = await initializeApp();

    // Start listening for requests
    const server = app.listen(config.PORT, () => {
      logger.info(`Server running in ${config.NODE_ENV} mode on port ${config.PORT}`);

      if (config.isDev) {
        logger.info(`API available at http://localhost:${config.PORT}/api`);
        logger.info(`Admin interface available at http://localhost:${config.PORT}/admin.html`);
      }
    });

    // Handle graceful shutdown
    const gracefulShutdown = async (signal) => {
      logger.info(`Received ${signal}. Shutting down gracefully...`);

      server.close(() => {
        logger.info('HTTP server closed.');

        // Close database connection
        if (app.locals.db) {
          app.locals.db.close((err) => {
            if (err) {
              logger.error(`Error closing database: ${err.message}`);
              process.exit(1);
            } else {
              logger.info('Database connection closed.');
              process.exit(0);
            }
          });
        } else {
          process.exit(0);
        }
      });

      // Force close if graceful shutdown fails
      setTimeout(() => {
        logger.error('Could not close connections in time, forcefully shutting down');
        process.exit(1);
      }, 10000);
    };

    // Listen for termination signals
    process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
    process.on('SIGINT', () => gracefulShutdown('SIGINT'));

  } catch (error) {
    logger.error(`Failed to start server: ${error.message}`, { error: error.stack });
    process.exit(1);
  }
};

// Start the server
startServer();
