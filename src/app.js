const express = require('express');
const path = require('path');
const cors = require('cors');
const helmet = require('helmet');
const { config, validateConfig } = require('./config/env');
const { initializeDatabase } = require('./config/database');
const { errorHandler, notFoundHandler } = require('./middleware/errorHandler');
const logger = require('./utils/logger');

// Controllers
const AuthController = require('./controllers/authController');
const UserController = require('./controllers/userController');

// Routes
const createAuthRoutes = require('./routes/authRoutes');
const createUserRoutes = require('./routes/userRoutes');

// Models
const UserModel = require('./models/user');

/**
 * Initialize the Express application
 * @returns {Promise<Object>} Express application
 */
const initializeApp = async () => {
  // Validate environment configuration
  validateConfig();

  // Initialize database
  const db = await initializeDatabase();

  // Initialize models
  const userModel = new UserModel(db);

  // Initialize controllers
  const authController = new AuthController(userModel);
  const userController = new UserController(userModel);

  // Create Express app
  const app = express();

  // Middleware
  app.use(cors());
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));

  // Serve static files
  app.use(express.static(path.join(__dirname, '..', 'public')));

  // Request logging middleware
  app.use((req, res, next) => {
    // Log after response is sent
    res.on('finish', () => {
      logger.httpRequest(req, res);
    });
    next();
  });

  // API routes
  app.use('/api/auth', createAuthRoutes(authController));
  app.use('/api/users', createUserRoutes(userController));

  // Serve the login page
  app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'public', 'index.html'));
  });

  // Error handling
  app.use(notFoundHandler);
  app.use(errorHandler);

  // Store database connection for graceful shutdown
  app.locals.db = db;

  return app;
};

module.exports = { initializeApp };
