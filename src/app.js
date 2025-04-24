// C:/Users/vini/WebstormProjects/jjguibotauthserver/src/app.js
const express = require('express');
const path = require('path');
const cors = require('cors');
const helmet = require('helmet');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const csurf = require('csurf');
const cookieParser = require('cookie-parser');
// EJS is implicitly required by Express when set as view engine

const { config, validateConfig } = require('./config/env');
const { initializeDatabase, DB_PATH } = require('./config/database');
const { errorHandler, notFoundHandler } = require('./middleware/errorHandler'); // Removed validationErrorHandler import as it's used within routes
const logger = require('./utils/logger');
// Import rate limiters - they are used directly in routes, not globally here
// const { apiLimiter, loginLimiter } = require('./middleware/rateLimiter');

// Controllers
const AuthController = require('./controllers/authController');
const UserController = require('./controllers/userController');

// Routes
const createAuthRoutes = require('./routes/authRoutes');
const createUserRoutes = require('./routes/userRoutes');

// Models
const UserModel = require('./models/user');
const DeviceAuthModel = require('./models/deviceAuth');

// Import Auth Middleware Factory
const { createAuthMiddleware } = require('./middleware/auth');

const initializeApp = async () => {
  validateConfig();
  const db = await initializeDatabase();
  const userModel = new UserModel(db);
  const deviceAuthModel = new DeviceAuthModel(db);
  const authController = new AuthController(userModel, deviceAuthModel);
  const userController = new UserController(userModel);

  const app = express();

  // --- Trust Proxy ---
  // Important if running behind a reverse proxy (like Nginx) to get correct req.ip
  app.set('trust proxy', 1); // Adjust the number based on your proxy setup depth

  // --- View Engine Setup (EJS) ---
  app.set('view engine', 'ejs');
  app.set('views', path.join(__dirname, 'views')); // Directory for EJS templates

  // --- Standard Middleware ---

  // CORS Configuration
  const allowedOrigins = config.CORS_ALLOWED_ORIGINS === '*'
      ? '*'
      : config.CORS_ALLOWED_ORIGINS.split(',').map(origin => origin.trim());
  const corsOptions = {
    origin: function (origin, callback) {
      // Allow requests with no origin (like mobile apps, curl, same-origin)
      // In production, you might want to be stricter and disallow !origin if not needed.
      if (!origin) return callback(null, true);
      if (allowedOrigins === '*' || (origin && allowedOrigins.includes(origin))) {
        callback(null, true);
      } else {
        logger.warn('CORS: Origin denied', { origin });
        callback(new Error('Not allowed by CORS')); // Standard CORS error
      }
    },
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
    credentials: true // Allow cookies/sessions to be sent cross-origin if needed
  };
  app.use(cors(corsOptions));

  // Helmet for Security Headers
  app.use(
      helmet({
        contentSecurityPolicy: {
          directives: {
            ...helmet.contentSecurityPolicy.getDefaultDirectives(),
            // Allow connections to self (API calls from frontend) and localhost during dev
            'connect-src': ["'self'", "http://127.0.0.1:*", "http://localhost:*"],
            // Allow inline styles (needed for basic templates/error pages) and self
            'style-src': ["'self'", "'unsafe-inline'", /* Add CDN font/style links if used */],
            // Allow scripts from self. Avoid 'unsafe-inline' in production if possible.
            // Use nonces or hashes for inline scripts if needed.
            'script-src': ["'self'", /* Add CDN script links if used */],
            // Allow form submissions to self (for /verify page)
            'form-action': ["'self'"],
            // Allow loading images from self and data URIs (common for favicons)
            'img-src': ["'self'", "data:"],
            // Set a default source to 'self' to restrict loading from other origins
            'default-src': ["'self'"],
          },
        },
        // Consider other Helmet policies like:
        // referrerPolicy: { policy: "strict-origin-when-cross-origin" },
        // crossOriginEmbedderPolicy: false, // Set to true if needed, might break things
        // crossOriginOpenerPolicy: { policy: "same-origin-allow-popups" }, // Adjust as needed
      })
  );

  // Body Parsers
  app.use(express.json()); // For parsing application/json
  app.use(express.urlencoded({ extended: true })); // For parsing application/x-www-form-urlencoded

  // Cookie Parser (Needed for csurf/session)
  app.use(cookieParser());

  // Session Middleware
  const sessionMiddleware = session({ // Assign to variable
    store: new SQLiteStore({
      db: path.basename(DB_PATH), // Use just the filename
      dir: path.dirname(DB_PATH), // Directory where the DB file is located
      table: 'sessions' // Name of the sessions table in SQLite
    }),
    secret: config.SESSION_SECRET, // Use a strong secret from .env
    resave: false, // Don't save session if unmodified
    saveUninitialized: false, // Don't create session until something stored
    cookie: {
      secure: config.isProd, // Use secure cookies in production (requires HTTPS)
      httpOnly: true, // Prevent client-side JS from accessing the cookie
      maxAge: 24 * 60 * 60 * 1000, // Session duration (e.g., 1 day) - Will be overridden by rememberMe
      name: config.SESSION_COOKIE_NAME || 'connect.sid', // Use a configurable name
      sameSite: 'lax' // Recommended for CSRF protection and usability
    }
  });
  app.use(sessionMiddleware); // Use the session middleware

  // --- CSRF Protection Middleware ---
  // Apply CSRF *after* cookie/session middleware
  // Use session-based storage since we have sessions
  const csrfProtection = csurf({ cookie: false }); // Store secret in session

  // --- Static Files ---
  // Serve static files (CSS, JS, HTML) from 'public' directory
  // IMPORTANT: Place static middleware *before* session-protected routes like /admin.html /profile.html
  // if you want CSS/JS to load without needing a session.
  app.use(express.static(path.join(__dirname, '..', 'public')));

  // --- Request Logging ---
  // Log details after the request finishes
  app.use((req, res, next) => {
    res.on('finish', () => { logger.httpRequest(req, res); });
    next();
  });

  // --- API Routes ---
  // These routes handle API logic and typically use JWT or session for auth
  const authMiddleware = createAuthMiddleware(userModel);
  // API routes generally don't need CSRF protection if using token auth exclusively,
  // but since our web frontend uses sessions, API calls from it *will* have session cookies.
  // If APIs are *only* for external JWT clients, CSRF isn't needed. If used by web frontend, it might be.
  // For simplicity, let's assume API routes might be called by the web frontend and apply session checks.
  app.use('/api/auth', createAuthRoutes(authController, authMiddleware));
  app.use('/api/users', createUserRoutes(userController, userModel, authMiddleware)); // Pass userModel here too

  // --- Frontend & Verification Routes ---

  // Middleware to check session for protected pages
  const requireSession = (req, res, next) => {
    if (!req.session || !req.session.user) {
      logger.warn('Access denied to protected page: No active session.', { url: req.originalUrl, ip: req.ip });
      // Redirect to login, maybe preserving the intended destination
      const originalUrl = encodeURIComponent(req.originalUrl);
      return res.redirect(`/login?redirect_after=${originalUrl}&reason=session_required`);
    }
    next();
  };
  // Middleware to check for admin role in session
  const requireAdminSession = (req, res, next) => {
    if (!req.session || !req.session.user || req.session.user.role !== 'admin') {
      logger.warn('Access denied to admin page: Not an admin session.', { url: req.originalUrl, ip: req.ip, user: req.session?.user?.username });
      // Send 403 or redirect to login/profile
      // return res.status(403).send('Forbidden: Admin access required.');
      return res.redirect('/profile.html?reason=admin_required'); // Redirect non-admins to profile
    }
    next();
  };


  // Serve index.html for root and /login requests (Public)
  app.get(['/', '/login'], (req, res) => {
    // If already logged in, redirect away from login page
    if (req.session.user) {
      return res.redirect(req.session.user.role === 'admin' ? '/admin.html' : '/profile.html');
    }
    res.sendFile(path.join(__dirname, '..', 'public', 'index.html'));
  });

  // Serve admin.html - Protected by session and admin role check
  app.get('/admin.html', requireSession, requireAdminSession, (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'public', 'admin.html'));
  });

  // --- NEW: Serve profile.html - Protected by session ---
  app.get('/profile.html', requireSession, (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'public', 'profile.html'));
  });
  // --- End New Profile Route ---

  // Note: express.static handles serving CSS/JS without session checks if placed before requireSession routes.

  // --- Verification Page Routes (Using CSRF and EJS) ---
  // These routes use sessions and require CSRF protection

  // GET /verify - Display the verification page
  // Apply CSRF middleware first to generate the token for the form
  app.get('/verify', csrfProtection, (req, res, next) => {
    // Controller handles rendering the EJS template
    authController.showVerificationPage(req, res, next);
  });

  // POST /verify - Handle the verification form submission
  // Apply CSRF middleware first to validate the token submitted with the form
  app.post('/verify', csrfProtection, (req, res, next) => {
    // Controller handles the logic and renders EJS on error/success
    authController.handleVerification(req, res, next);
  });
  // --- End Verification Routes ---


  // --- Error Handling ---
  // Apply error handlers *after* all other routes and middleware

  // 404 Handler (Route Not Found)
  app.use(notFoundHandler);

  // CSRF Error Handler
  app.use((err, req, res, next) => {
    if (err.code === 'EBADCSRFTOKEN') {
      logger.warn('Invalid CSRF token detected', { ip: req.ip, url: req.originalUrl, method: req.method });
      // Check if the request expects HTML (likely from the /verify form)
      if (req.accepts('html')) {
        // Re-render the verification page with an error message
        // We need a CSRF token even for the error page render
        const newCsrfToken = req.csrfToken ? req.csrfToken() : null; // Attempt to regenerate token
        res.status(403).render('verify', { // Use 403 Forbidden for CSRF errors
          csrfToken: newCsrfToken,
          error: 'Invalid form submission token. Please refresh the page and try again.',
          success: null,
          user_code: req.body?.user_code || '' // Preserve user input if available
        });
      } else {
        // Send JSON error for non-HTML requests (e.g., API clients mistakenly hitting this)
        res.status(403).json({ error: 'Invalid CSRF token.', code: 'INVALID_CSRF_TOKEN' });
      }
    } else {
      next(err); // Pass other errors to the general error handler
    }
  });

  // General Error Handler (Must be the last middleware)
  app.use(errorHandler);

  // Store db connection and controller instance for graceful shutdown
  app.locals.db = db;
  app.locals.authController = authController; // Used to stop cleanup interval

  return app;
};

module.exports = { initializeApp };