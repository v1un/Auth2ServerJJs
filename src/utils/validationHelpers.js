// C:/Users/vini/WebstormProjects/jjguibotauthserver/src/utils/validationHelpers.js
const logger = require('./logger');

/**
 * Validates if a given URI string is a valid HTTP loopback address
 * (http://localhost[:port] or http://127.0.0.1[:port]) with an optional port.
 * If no port is specified, it's assumed to be port 80.
 *
 * @param {string} uriString - The URI string to validate.
 * @returns {boolean} True if the URI is a valid loopback redirect target, false otherwise.
 */
function isValidLoopbackRedirect(uriString) {
    if (!uriString) {
        return false;
    }
    try {
        const uri = new URL(uriString);

        // Check protocol and hostname
        const isLoopbackHost = (uri.hostname === '127.0.0.1' || uri.hostname === 'localhost');
        if (uri.protocol !== 'http:' || !isLoopbackHost) {
            logger.warn('Invalid loopback redirect URI: Incorrect protocol or hostname', { uri: uriString, hostname: uri.hostname, protocol: uri.protocol });
            return false;
        }

        // Check port: It's either absent (implies port 80) or a valid port number
        const portIsValid = !uri.port || // Port is optional
            ( /^\d+$/.test(uri.port) && // If present, must be digits
                parseInt(uri.port, 10) > 0 && parseInt(uri.port, 10) <= 65535 ); // and in valid range

        if (!portIsValid) {
            logger.warn('Invalid loopback redirect URI: Invalid port specified', { uri: uriString, port: uri.port });
            return false;
        }

        // If all checks pass
        return true;

    } catch (error) {
        logger.warn('Error parsing redirect URI', { uri: uriString, error: error.message });
        return false;
    }
}

module.exports = {
    isValidLoopbackRedirect
};