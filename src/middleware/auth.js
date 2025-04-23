const jwt = require('jsonwebtoken');
const { config } = require('../config/env');

/**
 * Middleware to authenticate JWT token
 * Verifies the token from the Authorization header and adds the user to the request object
 */
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Authentication token required' });
  }

  jwt.verify(token, config.JWT_SECRET, (err, user) => {
    if (err) {
      if (err.name === 'TokenExpiredError') {
        return res.status(401).json({ error: 'Token expired', code: 'TOKEN_EXPIRED' });
      }
      return res.status(403).json({ error: 'Invalid token', code: 'INVALID_TOKEN' });
    }
    req.user = user;
    next();
  });
};

/**
 * Middleware to require admin role
 * Must be used after authenticateToken middleware
 */
const requireAdminRole = (req, res, next) => {
  if (req.user && req.user.role === 'admin') {
    next();
  } else {
    res.status(403).json({ error: 'Admin privileges required', code: 'ADMIN_REQUIRED' });
  }
};

/**
 * Middleware to require user role
 * Must be used after authenticateToken middleware
 */
const requireUserRole = (req, res, next) => {
  if (req.user && (req.user.role === 'user' || req.user.role === 'admin')) {
    next();
  } else {
    res.status(403).json({ error: 'User privileges required', code: 'USER_REQUIRED' });
  }
};

/**
 * Generate JWT token for a user
 * @param {Object} user - User object with username, role, and userId
 * @returns {string} JWT token
 */
const generateToken = (user) => {
  return jwt.sign(
    { 
      username: user.username, 
      role: user.role,
      userId: user.id || user.userId
    },
    config.JWT_SECRET,
    { expiresIn: config.JWT_EXPIRATION }
  );
};

module.exports = {
  authenticateToken,
  requireAdminRole,
  requireUserRole,
  generateToken
};