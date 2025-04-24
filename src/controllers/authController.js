// C:/Users/vini/WebstormProjects/jjguibotauthserver/src/controllers/authController.js
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const { generateToken } = require('../middleware/auth');
const { ApiError } = require('../middleware/errorHandler');
const logger = require('../utils/logger');
const { config } = require('../config/env');
const path = require('path');

// --- Helper functions (generateSecureCode, generateUserCode) remain the same ---
function generateSecureCode(length = 32) {
  return crypto.randomBytes(length).toString('hex');
}
function generateUserCode(length = 8) {
  const chars = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
  let result = '';
  for (let i = 0; i < length; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  if (length === 8) {
    result = result.substring(0, 4) + '-' + result.substring(4);
  }
  return result;
}
// --- End Helper Functions ---

class AuthController {
  constructor(userModel, deviceAuthModel) {
    this.userModel = userModel;
    this.deviceAuthModel = deviceAuthModel;
    // Get default maxAge from config (convert '1h' style if needed, or use seconds)
    // For simplicity, let's assume config.SESSION_MAX_AGE_MS exists or use the one from app.js
    this.defaultSessionMaxAge = 24 * 60 * 60 * 1000; // Default: 1 day (match app.js)
    this.rememberMeMaxAge = 30 * 24 * 60 * 60 * 1000; // Example: 30 days for "Remember Me"

    this.cleanupInterval = setInterval(
        () => this.deviceAuthModel.cleanupExpiredCodes(),
        60 * 60 * 1000
    );
    logger.info('Device code cleanup interval started.');
  }


  stopCleanup() {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      logger.info('Device code cleanup interval stopped.');
    }
  }

  // --- Standard Login ---
  async login(req, res, next) {
    // Get rememberMe flag from body
    const { username, password, rememberMe } = req.body;
    const redirectUri = req.query.redirect_uri;

    try {
      const user = await this.userModel.getUserByUsername(username);
      if (!user) {
        logger.warn(`Login failed: User not found - ${username}`);
        return next(new ApiError(401, 'Invalid credentials', 'INVALID_CREDENTIALS'));
      }

      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        logger.warn(`Login failed: Invalid password for user - ${username}`);
        return next(new ApiError(401, 'Invalid credentials', 'INVALID_CREDENTIALS'));
      }

      // --- IP Binding Logic ---
      const requestIp = req.ip;
      let ipToSet = user.allowed_ip;
      if (!user.allowed_ip) {
        ipToSet = requestIp;
        logger.info(`Binding IP ${requestIp} to user ${username} (ID: ${user.id}) on first login/reset.`);
        await this.userModel.updateUserIp(user.id, ipToSet);
      } else if (user.allowed_ip !== requestIp && user.role !== 'admin') {
        logger.warn(`Login denied for user ${username}: IP ${requestIp} not allowed. Expected ${user.allowed_ip}.`);
        return next(new ApiError(403, 'Access denied from this IP address.', 'IP_NOT_ALLOWED'));
      }
      // --- End IP Binding Logic ---

      // User authenticated
      // Store user in session
      req.session.user = { userId: user.id, username: user.username, role: user.role };

      // --- Set Cookie Max Age based on Remember Me ---
      if (rememberMe) {
        req.session.cookie.maxAge = this.rememberMeMaxAge; // Longer duration
        logger.debug(`Setting 'Remember Me' cookie maxAge for user ${username}`);
      } else {
        // Use null for session-only cookie OR the default configured maxAge
        // Setting to null makes it a browser-session cookie
        req.session.cookie.maxAge = null;
        // Or keep the default: req.session.cookie.maxAge = this.defaultSessionMaxAge;
        logger.debug(`Setting session cookie maxAge for user ${username}`);
      }
      // --- End Cookie Max Age ---


      // --- Check for pending device verification ---
      if (req.session.pendingUserCode) {
        const pendingCode = req.session.pendingUserCode;
        delete req.session.pendingUserCode;

        try {
          const approvalResult = await this.deviceAuthModel.approveDeviceCode(pendingCode, user.id);

          // Save session changes (user, cookie maxAge, pending code removed)
          req.session.save(err => {
            if (err) {
              logger.error('Session save error after attempting device approval', { userId: user.id, code: pendingCode, error: err.message });
              return res.redirect(`/verify?post_login_status=error&code_error=${encodeURIComponent('Session error')}`);
            }
            if (approvalResult.success) {
              logger.info(`Device auto-approved after login for user ${user.username} (ID: ${user.id}), code: ${pendingCode}`);
              return res.redirect(`/verify?post_login_status=success`);
            } else {
              logger.warn(`Device auto-approval failed after login for user ${user.username} (ID: ${user.id}), code: ${pendingCode}, error: ${approvalResult.error}`);
              return res.redirect(`/verify?post_login_status=error&code_error=${encodeURIComponent(approvalResult.error || 'Approval failed')}`);
            }
          });
          return;

        } catch (approvalError) {
          logger.error('Error during post-login device approval', { userId: user.id, code: pendingCode, error: approvalError.message });
          req.session.save(err => { // Still try to save session (pending code removed)
            return res.redirect(`/verify?post_login_status=error&code_error=${encodeURIComponent('Server error during approval')}`);
          });
          return;
        }
      }
      // --- End Check for pending device verification ---

      // --- Original login logic continues if no pending code ---
      const tokenPayload = { userId: user.id, username: user.username, role: user.role };
      const token = generateToken(tokenPayload); // Still generate token for potential external use
      logger.info(`User login successful: ${username}`);

      // Save session (including user and cookie maxAge)
      req.session.save(err => {
        if (err) {
          return next(new ApiError(500, 'Session save error after login.'));
        }
        // Handle redirect for external app OR send JSON for direct web login
        if (redirectUri) {
          try {
            const redirectUrl = new URL(redirectUri);
            redirectUrl.searchParams.set('token', token); // Send token in redirect for external app
            return res.redirect(302, redirectUrl.toString());
          } catch(urlError) {
            logger.error('Invalid redirect URI provided during login', { redirectUri, error: urlError.message });
            // Fallback to sending JSON response if redirect URI is invalid
            return res.status(200).json({
              message: "Login successful (invalid redirect URI provided)",
              token: token, // Still provide token
              user: { id: user.id, username: user.username, role: user.role }
            });
          }
        } else {
          // No redirectUri - this is a direct web login. Send user info.
          // The session cookie is already set.
          logger.info(`User web login for ${username} successful.`);
          return res.status(200).json({
            message: "Login successful",
            // Optionally include token here too if web app might use it, but session is primary
            // token: token,
            user: { id: user.id, username: user.username, role: user.role }
          });
        }
      });

    } catch (error) {
      logger.error('Login error', { username, error: error.message, stack: error.stack });
      if (req.session) delete req.session.user; // Clear partial session on error
      next(new ApiError(500, 'Login failed due to server error', 'LOGIN_SERVER_ERROR'));
    }
  }

  // --- Admin Login ---
  async adminLogin(req, res, next) {
    // Get rememberMe flag from body
    const { username, password, rememberMe } = req.body;
    const redirectUri = req.query.redirect_uri;

    try {
      const isAdminUser = (username === config.ADMIN_USERNAME);
      const isAdminPassCorrect = (password === config.ADMIN_PASSWORD);

      if (!isAdminUser || !isAdminPassCorrect) {
        logger.warn(`Admin login failed for user: ${username}`);
        return next(new ApiError(401, 'Invalid admin credentials', 'INVALID_ADMIN_CREDENTIALS'));
      }

      // Admin authenticated
      const adminPayload = { userId: 0, username: config.ADMIN_USERNAME, role: 'admin' };
      req.session.user = { userId: adminPayload.userId, username: adminPayload.username, role: adminPayload.role };

      // --- Set Cookie Max Age based on Remember Me ---
      if (rememberMe) {
        req.session.cookie.maxAge = this.rememberMeMaxAge;
        logger.debug(`Setting 'Remember Me' cookie maxAge for admin ${username}`);
      } else {
        req.session.cookie.maxAge = null; // Browser session cookie
        logger.debug(`Setting session cookie maxAge for admin ${username}`);
      }
      // --- End Cookie Max Age ---

      // --- Check for pending device verification ---
      if (req.session.pendingUserCode) {
        const pendingCode = req.session.pendingUserCode;
        delete req.session.pendingUserCode;

        try {
          const approvalResult = await this.deviceAuthModel.approveDeviceCode(pendingCode, adminPayload.userId);

          req.session.save(err => { // Save session changes
            if (err) {
              logger.error('Session save error after attempting device approval (admin)', { userId: adminPayload.userId, code: pendingCode, error: err.message });
              return res.redirect(`/verify?post_login_status=error&code_error=${encodeURIComponent('Session error')}`);
            }
            if (approvalResult.success) {
              logger.info(`Device auto-approved after admin login for user ${config.ADMIN_USERNAME} (ID: ${adminPayload.userId}), code: ${pendingCode}`);
              return res.redirect(`/verify?post_login_status=success`);
            } else {
              logger.warn(`Device auto-approval failed after admin login for user ${config.ADMIN_USERNAME} (ID: ${adminPayload.userId}), code: ${pendingCode}, error: ${approvalResult.error}`);
              return res.redirect(`/verify?post_login_status=error&code_error=${encodeURIComponent(approvalResult.error || 'Approval failed')}`);
            }
          });
          return;

        } catch (approvalError) {
          logger.error('Error during post-admin-login device approval', { userId: adminPayload.userId, code: pendingCode, error: approvalError.message });
          req.session.save(err => { // Still try to save session
            return res.redirect(`/verify?post_login_status=error&code_error=${encodeURIComponent('Server error during approval')}`);
          });
          return;
        }
      }
      // --- End Check for pending device verification ---

      // --- Original admin login logic continues ---
      const token = generateToken(adminPayload); // Still generate token
      logger.info(`Admin login successful: ${username}`);

      // Save session (including user and cookie maxAge)
      req.session.save(err => {
        if (err) {
          return next(new ApiError(500, 'Session save error after admin login.'));
        }
        // Handle redirect for external app OR send JSON for direct web login
        if (redirectUri) {
          try {
            const redirectUrl = new URL(redirectUri);
            redirectUrl.searchParams.set('token', token);
            return res.redirect(302, redirectUrl.toString());
          } catch(urlError) {
            logger.error('Invalid redirect URI provided during admin login', { redirectUri, error: urlError.message });
            // Fallback for invalid redirect URI
            return res.status(200).json({
              message: 'Admin login successful (invalid redirect URI provided)',
              token: token,
              user: adminPayload
            });
          }
        } else {
          // Direct web login for admin
          logger.info(`Admin web login for ${username} successful.`);
          return res.json({
            message: 'Admin login successful',
            // token: token, // Optionally include token
            user: adminPayload
          });
        }
      });

    } catch (error) {
      logger.error('Admin login error', { username, error: error.message, stack: error.stack });
      if (req.session) delete req.session.user; // Clear partial session
      next(new ApiError(500, 'Admin login failed due to server error', 'ADMIN_LOGIN_SERVER_ERROR'));
    }
  }

  // --- NEW: Logout Method ---
  async logout(req, res, next) {
    if (req.session) {
      const username = req.session.user?.username || 'Unknown user';
      req.session.destroy(err => {
        if (err) {
          logger.error('Error destroying session during logout', { username, error: err.message });
          return next(new ApiError(500, 'Could not log out, please try again.'));
        }
        // Clear the session cookie on the client
        res.clearCookie(config.SESSION_COOKIE_NAME || 'connect.sid'); // Use name from session config if customized
        logger.info(`User logged out successfully: ${username}`);
        res.status(200).json({ message: 'Logout successful' });
      });
    } else {
      // No session to destroy
      res.status(200).json({ message: 'No active session found' });
    }
  }
  // --- End Logout Method ---


  // --- Device Flow Methods (initiateDeviceAuth, pollDeviceToken, showVerificationPage, handleVerification) ---
  async initiateDeviceAuth(req, res, next) {
    const maxRetries = 3;
    let retries = 0;
    while (retries < maxRetries) {
      try {
        const device_code = generateSecureCode();
        const user_code = generateUserCode();
        const expiresInSeconds = config.JWT_EXPIRATION_SECONDS;
        const expires_at = Date.now() + expiresInSeconds * 1000;
        const interval = 5;
        await this.deviceAuthModel.createDeviceAuth(device_code, user_code, expires_at, interval);
        const verification_uri = `${req.protocol}://${req.get('host')}/verify`;
        logger.info(`Device flow initiated: device_code=${device_code.substring(0, 8)}..., user_code=${user_code}`);
        return res.status(200).json({ device_code, user_code, verification_uri, expires_in: expiresInSeconds, interval });
      } catch (error) {
        if (error.code === 'USER_CODE_COLLISION' && retries < maxRetries - 1) {
          retries++;
          logger.warn(`User code collision detected, retrying generation (attempt ${retries + 1}/${maxRetries})`);
        } else {
          logger.error('Device auth initiation error', { error: error.message, stack: error.stack, retries });
          return next(new ApiError(500, 'Could not initiate device authorization', 'DEVICE_AUTH_INIT_FAILED'));
        }
      }
    }
    logger.error(`Failed to generate unique user code after ${maxRetries} attempts.`);
    return next(new ApiError(500, 'Could not generate unique user code', 'USER_CODE_GENERATION_FAILED'));
  }

  async pollDeviceToken(req, res, next) {
    const { grant_type, device_code } = req.body;
    if (grant_type !== 'urn:ietf:params:oauth:grant-type:device_code') {
      return next(new ApiError(400, 'Unsupported grant type', 'unsupported_grant_type'));
    }
    if (!device_code) {
      return next(new ApiError(400, 'Device code is required', 'invalid_request'));
    }
    try {
      const result = await this.deviceAuthModel.pollDeviceCode(device_code);
      switch (result.status) {
        case 'authorization_pending':
          return next(new ApiError(400, 'Authorization pending', 'authorization_pending', { interval: result.interval }));
        case 'access_denied':
          return next(new ApiError(400, 'Access denied by user', 'access_denied'));
        case 'expired_token':
          return next(new ApiError(400, 'Device code expired', 'expired_token'));
        case 'approved':
          if (!result.user) {
            logger.error(`Device code ${device_code} approved but no user data found.`);
            return next(new ApiError(500, 'Internal server error during token generation', 'server_error'));
          }
          const tokenPayload = { userId: result.user.id, username: result.user.username, role: result.user.role };
          const token = generateToken(tokenPayload);
          logger.info(`Device code ${device_code.substring(0, 8)}... approved for user ${result.user.username}. Token issued.`);
          return res.status(200).json({ access_token: token, token_type: 'Bearer', expires_in: config.JWT_EXPIRATION_SECONDS });
        case 'invalid_grant':
          return next(new ApiError(400, 'Invalid device code', 'invalid_grant'));
        default:
          logger.error(`Unexpected status '${result.status}' during device code polling for ${device_code}`);
          return next(new ApiError(500, 'Internal server error', 'server_error'));
      }
    } catch (error) {
      if (error instanceof ApiError) return next(error);
      logger.error('Device token polling error', { device_code, error: error.message, stack: error.stack });
      next(new ApiError(500, 'Error polling for device token', 'DEVICE_POLL_ERROR'));
    }
  }

  showVerificationPage(req, res, next) {
    try {
      let errorMsg = null;
      let successMsg = null;
      const status = req.query.post_login_status;
      const codeError = req.query.code_error;

      if (status === 'success') {
        successMsg = 'Device successfully authorized after login! You can now return to your device.';
      } else if (status === 'error') {
        errorMsg = codeError ? `Post-login approval failed: ${decodeURIComponent(codeError)}` : 'Post-login device approval failed.';
      }

      res.render('verify', {
        csrfToken: req.csrfToken(),
        error: errorMsg,
        success: successMsg,
        user_code: ''
      });
    } catch (error) {
      logger.error('Error rendering verification page', { error: error.message, stack: error.stack });
      next(new ApiError(500, 'Could not display verification page'));
    }
  }

  async handleVerification(req, res, next) {
    const { user_code } = req.body;
    const csrfToken = req.csrfToken();

    if (!user_code || typeof user_code !== 'string' || user_code.trim().length === 0) {
      const errorMsg = 'User code is required.';
      logger.warn('Verification attempt failed: Missing user code.');
      if (req.accepts('html')) {
        return res.status(400).render('verify', { csrfToken, error: errorMsg, success: null, user_code });
      } else {
        return next(new ApiError(400, errorMsg, 'invalid_request'));
      }
    }

    const trimmedCode = user_code.trim().toUpperCase();

    if (!req.session || !req.session.user) {
      logger.warn(`Device verification attempt failed: User not logged in. User code: ${trimmedCode}`);
      req.session.pendingUserCode = trimmedCode;
      req.session.save(err => {
        if (err) {
          logger.error('Session save error before redirecting to login', { error: err.message });
          return next(new ApiError(500, 'Session error before redirecting to login.'));
        }
        return res.redirect(`/login?reason=device_verify`);
      });
      return;
    }

    const userId = req.session.user.userId;
    const username = req.session.user.username;

    try {
      const result = await this.deviceAuthModel.approveDeviceCode(trimmedCode, userId);

      if (result.success) {
        logger.info(`Device approved by user ${username} (ID: ${userId}) for user code ${trimmedCode}`);
        if (req.accepts('html')) {
          return res.render('verify', {
            csrfToken,
            error: null,
            success: 'Device successfully authorized! You can now return to your device.',
            user_code: ''
          });
        } else {
          return res.status(200).json({ message: 'Device approved successfully.' });
        }
      } else {
        const errorMsg = result.error || 'Invalid or expired user code.';
        logger.warn(`Device verification failed: ${errorMsg}. User code: ${trimmedCode}, User ID: ${userId}`);
        if (req.accepts('html')) {
          return res.status(400).render('verify', { csrfToken, error: errorMsg, success: null, user_code: user_code.trim() });
        } else {
          return next(new ApiError(400, errorMsg, result.code || 'invalid_request'));
        }
      }
    } catch (error) {
      logger.error('Device verification handling error', { user_code: trimmedCode, userId, error: error.message, stack: error.stack });
      const errorMsg = 'An error occurred while verifying the code.';
      if (req.accepts('html')) {
        return res.status(500).render('verify', { csrfToken, error: errorMsg, success: null, user_code: user_code.trim() });
      } else {
        return next(new ApiError(500, errorMsg, 'VERIFICATION_FAILED'));
      }
    }
  }
  // --- End Device Flow Methods ---

}

module.exports = AuthController;