/**
 * Authentication Server using Node.js and Express
 * Main server file
 */

// Load environment variables first
require('dotenv').config();

const { initializeApp } = require('./src/app');
const logger = require('./src/utils/logger');
const { config } = require('./src/config/env');
const { closeDatabase } = require('./src/config/database'); // Import closeDatabase

// Start the server
const startServer = async () => {
  let app; // Declare app outside try block to access in shutdown
  try {
    // Initialize the application
    app = await initializeApp();

    // Start listening for requests
    const server = app.listen(config.PORT, () => {
      logger.info(`Server running in ${config.NODE_ENV} mode on port ${config.PORT}`);
      // ... other startup logs ...
    });

    // Handle graceful shutdown
    const gracefulShutdown = async (signal) => {
      logger.info(`Received ${signal}. Shutting down gracefully...`);

      // 1. Stop accepting new connections
      server.close(async () => {
        logger.info('HTTP server closed.');

        // 2. Stop background tasks (like controller cleanup)
        if (app.locals.authController && typeof app.locals.authController.stopCleanup === 'function') {
          app.locals.authController.stopCleanup();
        }

        // 3. Close database connection
        if (app.locals.db) {
          try {
            await closeDatabase(app.locals.db); // Use the promisified close
            logger.info('Database connection closed.');
            process.exit(0); // Exit cleanly
          } catch (dbErr) {
            logger.error(`Error closing database: ${dbErr.message}`);
            process.exit(1); // Exit with error
          }
        } else {
          process.exit(0); // Exit cleanly if no DB connection stored
        }
      });

      // Force close if graceful shutdown takes too long
      setTimeout(() => {
        logger.error('Could not close connections in time, forcefully shutting down');
        process.exit(1);
      }, 15000); // Increased timeout slightly
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