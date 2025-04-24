// C:/Users/vini/WebstormProjects/jjguibotauthserver/src/middleware/auth.js
const jwt = require('jsonwebtoken');
const { config } = require('../config/env');
const { ApiError } = require('./errorHandler');
const logger = require('../utils/logger');

// --- Auth Middleware Factory ---
const createAuthMiddleware = (userModel) => {

  /**
   * Middleware to authenticate API requests via Session or JWT Token.
   * Checks for a valid session first. If found, populates req.user from session.
   * If no session, checks for a 'Bearer' token in the Authorization header.
   * Also performs IP binding check based on the authenticated user.
   */
  const authenticateApiRequest = async (req, res, next) => {
    let authenticated = false;
    let authMethod = 'none';

    // 1. Check for Session Authentication
    if (req.session && req.session.user) {
      // Session found, verify user still exists and is valid (optional, but good practice)
      try {
        const sessionUser = req.session.user;
        // Minimal user object for req.user from session
        req.user = {
          userId: sessionUser.userId,
          username: sessionUser.username,
          role: sessionUser.role
        };
        authenticated = true;
        authMethod = 'session';
        logger.debug(`Authentication successful via session for user: ${req.user.username}`);

        // --- IP Binding Check (Session) ---
        // Fetch full user details only if needed for IP check (non-admin)
        if (req.user.role !== 'admin' && userModel) {
          const dbUser = await userModel.getUserById(req.user.userId);
          if (!dbUser) {
            logger.warn(`Session user ID ${req.user.userId} not found in DB. Invalidating session.`);
            // Destroy session if user doesn't exist
            req.session.destroy();
            return next(new ApiError(401, 'Invalid session user', 'INVALID_SESSION'));
          }
          // Check IP only if allowed_ip is set
          const requestIp = req.ip;
          if (dbUser.allowed_ip && dbUser.allowed_ip !== requestIp) {
            logger.warn(`Session request denied for user ${req.user.username}: IP ${requestIp} not allowed. Expected ${dbUser.allowed_ip}.`);
            return next(new ApiError(403, 'Access denied from this IP address.', 'IP_NOT_ALLOWED'));
          }
        }
        // --- End IP Binding Check (Session) ---

      } catch (sessionCheckError) {
        logger.error('Error during session user validation', { error: sessionCheckError.message });
        authenticated = false; // Treat error as authentication failure
        // Optionally destroy session here if validation fails critically
        // req.session.destroy();
      }
    }

    // 2. Check for JWT Token Authentication (if not authenticated by session)
    if (!authenticated) {
      const authHeader = req.headers['authorization'];
      const token = authHeader && authHeader.startsWith('Bearer ') && authHeader.split(' ')[1];

      if (token) {
        try {
          const decoded = jwt.verify(token, config.JWT_SECRET);
          // Ensure decoded token has necessary fields
          if (!decoded.userId || !decoded.username || !decoded.role) {
            throw new jwt.JsonWebTokenError('Invalid token payload');
          }
          req.user = decoded; // Add decoded payload to request
          authenticated = true;
          authMethod = 'jwt';
          logger.debug(`Authentication successful via JWT for user: ${req.user.username}`);

          // --- IP Binding Check (JWT) ---
          // Skip check for admins or if userModel is not available
          if (req.user.role !== 'admin' && userModel) {
            const requestIp = req.ip;
            const dbUser = await userModel.getUserById(req.user.userId);

            if (!dbUser) {
              logger.warn(`JWT user ID ${req.user.userId} from token not found in DB.`);
              return next(new ApiError(401, 'Invalid token user', 'INVALID_TOKEN'));
            }
            // Check IP only if allowed_ip is set
            if (dbUser.allowed_ip && dbUser.allowed_ip !== requestIp) {
              logger.warn(`JWT request denied for user ${req.user.username}: IP ${requestIp} not allowed. Expected ${dbUser.allowed_ip}.`);
              return next(new ApiError(403, 'Access denied from this IP address.', 'IP_NOT_ALLOWED'));
            }
          }
          // --- End IP Binding Check (JWT) ---

        } catch (err) {
          authenticated = false; // Ensure authenticated is false on error
          authMethod = 'jwt_error';
          if (err.name === 'TokenExpiredError') {
            return next(new ApiError(401, 'Token expired', 'TOKEN_EXPIRED'));
          }
          if (err.name === 'JsonWebTokenError') {
            logger.warn('Invalid JWT token received', { error: err.message });
            return next(new ApiError(401, 'Invalid token', 'INVALID_TOKEN'));
          }
          // Handle other potential errors during verification
          logger.error('Error verifying JWT token', { error: err.message });
          return next(new ApiError(500, 'Could not verify token', 'TOKEN_VERIFICATION_FAILED'));
        }
      }
    }

    // 3. Handle Final Authentication Status
    if (authenticated) {
      next(); // Proceed to the next middleware (e.g., role check) or route handler
    } else {
      // If neither session nor valid JWT was found
      logger.warn('Authentication failed: No valid session or JWT token provided.', { url: req.originalUrl, ip: req.ip });
      return next(new ApiError(401, 'Authentication required', 'AUTH_REQUIRED'));
    }
  };

  /**
   * Middleware to require admin role (checks req.user populated by authenticateApiRequest)
   */
  const requireAdminRole = (req, res, next) => {
    // Check req.user which should be populated by authenticateApiRequest
    if (req.user && req.user.role === 'admin') {
      next();
    } else {
      logger.warn('Admin access denied', { user: req.user?.username, role: req.user?.role, url: req.originalUrl, ip: req.ip });
      next(new ApiError(403, 'Admin access required', 'FORBIDDEN'));
    }
  };

  /**
   * Middleware to require at least user role (user or admin)
   */
  const requireUserRole = (req, res, next) => {
    // Check req.user which should be populated by authenticateApiRequest
    if (req.user && (req.user.role === 'user' || req.user.role === 'admin')) {
      next();
    } else {
      logger.warn('User access denied', { user: req.user?.username, role: req.user?.role, url: req.originalUrl, ip: req.ip });
      next(new ApiError(403, 'User access required', 'FORBIDDEN'));
    }
  };

  // Return the middleware functions
  return {
    // Rename the exported function to reflect its dual nature (or keep as authenticateToken if preferred)
    authenticateToken: authenticateApiRequest, // <-- Use the new combined function
    requireAdminRole,
    requireUserRole,
  };
};


// --- Original generateToken function (ensure it includes userId) ---
// This remains unchanged as it's used for generating tokens, not verifying requests.
const generateToken = (user) => {
  const payload = {
    userId: user.id ?? user.userId, // Handle both possible ID field names
    username: user.username,
    role: user.role
  };
  // Ensure JWT_EXPIRATION is defined in config, fallback if necessary
  const expiresIn = config.JWT_EXPIRATION || '1h';
  return jwt.sign(payload, config.JWT_SECRET, { expiresIn });
};


// Export the factory and the generator
module.exports = { createAuthMiddleware, generateToken };