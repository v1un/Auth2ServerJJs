// C:/Users/vini/WebstormProjects/jjguibotauthserver/src/models/deviceAuth.js
const logger = require('../utils/logger');
const { runQuery, getRow } = require('../config/database');
// Assuming UserModel is needed to fetch user details on approval
const UserModel = require('./user'); // Adjust path if necessary

class DeviceAuthModel {
    constructor(db) {
        this.db = db;
        // Instantiate UserModel if needed within this model (or pass it in)
        this.userModel = new UserModel(db);
    }

    /**
     * Creates a new device authorization record.
     * @param {string} deviceCode - The unique device code.
     * @param {string} userCode - The user-facing code.
     * @param {number} expiresAt - Unix timestamp (ms) when the codes expire.
     * @param {number} interval - Recommended polling interval in seconds.
     * @returns {Promise<object>} The created record details.
     * @throws {Error} with code 'USER_CODE_COLLISION' if userCode already exists.
     */
    async createDeviceAuth(deviceCode, userCode, expiresAt, interval) {
        const query = `
            INSERT INTO device_authorizations (device_code, user_code, expires_at, interval, status)
            VALUES (?, ?, ?, ?, 'pending')
        `;
        try {
            await runQuery(this.db, query, [deviceCode, userCode, expiresAt, interval]);
            logger.info('Created new device authorization record', { deviceCode: deviceCode.substring(0, 8) + '...', userCode });
            return { deviceCode, userCode, expiresAt, interval, status: 'pending' };
        } catch (error) {
            // Check for unique constraint violation on user_code specifically
            if (error.message && error.message.includes('UNIQUE constraint failed: device_authorizations.user_code')) {
                logger.warn('User code collision during device auth creation', { userCode });
                const err = new Error('User code collision');
                err.code = 'USER_CODE_COLLISION';
                throw err;
            }
            logger.error('Failed to create device authorization record', { error: error.message, deviceCode, userCode });
            throw error; // Re-throw other errors
        }
    }

    /**
     * Finds a device authorization record by device code.
     * @param {string} deviceCode - The device code.
     * @returns {Promise<object|null>} The authorization record or null if not found.
     */
    async findByDeviceCode(deviceCode) {
        const query = 'SELECT * FROM device_authorizations WHERE device_code = ?';
        try {
            const record = await getRow(this.db, query, [deviceCode]);
            return record || null;
        } catch (error) {
            logger.error('Failed to find device auth by device code', { error: error.message, deviceCode });
            throw error;
        }
    }

    /**
     * Finds a pending device authorization record by user code.
     * @param {string} userCode - The user code.
     * @returns {Promise<object|null>} The authorization record or null if not found or not pending.
     */
    async findPendingByUserCode(userCode) {
        const query = 'SELECT * FROM device_authorizations WHERE user_code = ? AND status = \'pending\'';
        try {
            const record = await getRow(this.db, query, [userCode]);
            return record || null;
        } catch (error) {
            logger.error('Failed to find pending device auth by user code', { error: error.message, userCode });
            throw error;
        }
    }

    /**
     * Updates the last polled timestamp for a device code.
     * @param {string} deviceCode - The device code.
     * @returns {Promise<boolean>} True if updated, false otherwise.
     */
    async updateLastPolled(deviceCode) {
        const polledAt = Date.now();
        const query = 'UPDATE device_authorizations SET last_polled_at = ? WHERE device_code = ?';
        try {
            const result = await runQuery(this.db, query, [polledAt, deviceCode]);
            return result.changes > 0;
        } catch (error) {
            logger.error('Failed to update last polled time', { error: error.message, deviceCode });
            throw error;
        }
    }

    /**
     * Marks a device authorization as approved by a user, based on the user_code.
     * @param {string} userCode - The user-facing code entered by the user.
     * @param {number} userId - The ID of the approving user (from session).
     * @returns {Promise<{success: boolean, error?: string, code?: string}>} Result object.
     */
    async approveDeviceCode(userCode, userId) {
        const now = Date.now();
        try {
            // Find the record by user code, ensuring it's still pending
            const record = await this.findPendingByUserCode(userCode);

            if (!record) {
                return { success: false, error: 'Invalid or already used user code.', code: 'invalid_request' };
            }

            // Check if expired
            if (record.expires_at < now) {
                // Optionally update status to 'expired' here or rely on cleanup
                await this.updateStatus(record.device_code, 'expired');
                return { success: false, error: 'User code has expired.', code: 'expired_token' };
            }

            // Update status to 'approved' and set user_id
            const query = `
                UPDATE device_authorizations
                SET status = 'approved', user_id = ?
                WHERE device_code = ? AND status = 'pending' AND expires_at >= ?
            `;
            const result = await runQuery(this.db, query, [userId, record.device_code, now]);

            if (result.changes > 0) {
                logger.info('Device authorization approved via user code', { deviceCode: record.device_code, userCode, userId });
                return { success: true };
            } else {
                // This might happen in a race condition if polled and expired/approved simultaneously
                logger.warn('Failed to approve device via user code (record changed state or expired during update)', { deviceCode: record.device_code, userCode, userId });
                // Re-fetch to check current status
                const currentRecord = await this.findByDeviceCode(record.device_code);
                if (currentRecord && currentRecord.expires_at < now) {
                    return { success: false, error: 'User code has expired.', code: 'expired_token' };
                }
                return { success: false, error: 'Could not approve the code. It might have been used or expired.', code: 'invalid_request' };
            }
        } catch (error) {
            logger.error('Failed to approve device authorization via user code', { error: error.message, userCode, userId });
            throw error; // Let the controller handle generic server errors
        }
    }

    /**
     * Marks a device authorization as denied.
     * @param {string} deviceCode - The device code.
     * @returns {Promise<boolean>} True if updated, false otherwise.
     */
    async denyDevice(deviceCode) {
        const query = `
            UPDATE device_authorizations
            SET status = 'denied'
            WHERE device_code = ? AND status = 'pending'
        `;
        try {
            const result = await runQuery(this.db, query, [deviceCode]);
            if (result.changes > 0) {
                logger.info('Device authorization denied', { deviceCode });
                return true;
            }
            logger.warn('Failed to deny device authorization (not found or not pending)', { deviceCode });
            return false;
        } catch (error) {
            logger.error('Failed to deny device authorization', { error: error.message, deviceCode });
            throw error;
        }
    }

    /**
     * Updates the status of a device authorization record.
     * @param {string} deviceCode - The device code.
     * @param {string} status - The new status ('pending', 'approved', 'denied', 'expired').
     * @returns {Promise<boolean>} True if updated, false otherwise.
     */
    async updateStatus(deviceCode, status) {
        const query = 'UPDATE device_authorizations SET status = ? WHERE device_code = ?';
        try {
            const result = await runQuery(this.db, query, [status, deviceCode]);
            return result.changes > 0;
        } catch (error) {
            logger.error('Failed to update device auth status', { error: error.message, deviceCode, status });
            throw error;
        }
    }


    /**
     * Polls the status of a device code.
     * @param {string} deviceCode - The device code being polled.
     * @returns {Promise<object>} An object indicating the status ('authorization_pending', 'access_denied', 'expired_token', 'approved', 'invalid_grant') and potentially user data.
     */
    async pollDeviceCode(deviceCode) {
        const now = Date.now();
        try {
            const record = await this.findByDeviceCode(deviceCode);

            if (!record) {
                return { status: 'invalid_grant' }; // Code not found
            }

            // Check expiration first
            if (record.expires_at < now) {
                // Optionally update status to 'expired' if not already done
                if (record.status !== 'expired') {
                    await this.updateStatus(deviceCode, 'expired');
                }
                return { status: 'expired_token' };
            }

            // Update last polled time
            await this.updateLastPolled(deviceCode);

            // Check status
            switch (record.status) {
                case 'pending':
                    // Implement slow_down logic if desired (optional)
                    // const timeSinceLastPoll = now - record.last_polled_at;
                    // if (record.last_polled_at > 0 && timeSinceLastPoll < (record.interval * 1000)) {
                    //    return { status: 'slow_down', interval: record.interval };
                    // }
                    return { status: 'authorization_pending', interval: record.interval };
                case 'approved':
                    // Fetch user details using the stored user_id
                    const user = await this.userModel.getUserById(record.user_id);
                    if (!user) {
                        // Data inconsistency: approved but user deleted?
                        logger.error(`User ID ${record.user_id} not found for approved device code ${deviceCode}`);
                        // Treat as an error, maybe deny the code?
                        await this.denyDevice(deviceCode); // Or set to a specific error state
                        return { status: 'invalid_grant' }; // Or a custom error status
                    }
                    // Return approved status along with user info needed for token generation
                    return {
                        status: 'approved',
                        user: {
                            id: user.id,
                            username: user.username,
                            role: user.role
                        }
                    };
                case 'denied':
                    return { status: 'access_denied' };
                case 'expired': // Already handled by expiration check above, but good to include
                    return { status: 'expired_token' };
                default:
                    logger.error(`Unknown status '${record.status}' for device code ${deviceCode}`);
                    return { status: 'invalid_grant' }; // Treat unknown status as invalid
            }
        } catch (error) {
            logger.error('Error during device code polling', { error: error.message, deviceCode });
            // Depending on the error, might return 'invalid_grant' or rethrow
            throw error; // Let the controller handle generic server errors
        }
    }


    /**
     * Deletes a device authorization record. (Useful for testing or manual cleanup)
     * @param {string} deviceCode - The device code.
     * @returns {Promise<boolean>} True if deleted, false otherwise.
     */
    async deleteDeviceAuth(deviceCode) {
        const query = 'DELETE FROM device_authorizations WHERE device_code = ?';
        try {
            const result = await runQuery(this.db, query, [deviceCode]);
            if (result.changes > 0) {
                logger.info('Deleted device authorization record', { deviceCode });
                return true;
            }
            return false;
        } catch (error) {
            logger.error('Failed to delete device authorization record', { error: error.message, deviceCode });
            throw error;
        }
    }

    /**
     * Deletes all expired device authorization records.
     * @returns {Promise<number>} The number of records deleted.
     */
    async cleanupExpiredCodes() {
        const now = Date.now();
        // Also clean up codes that are very old, regardless of status, to prevent indefinite growth
        const cutoffTime = now - (3 * 24 * 60 * 60 * 1000); // e.g., 3 days old
        const query = 'DELETE FROM device_authorizations WHERE expires_at < ? OR created_at < datetime(?, \'unixepoch\', \'-3 days\')'; // Adjust time as needed

        try {
            // Using Date.now() directly might be slightly off due to JS vs SQLite time, but generally okay
            // For more precision, calculate cutoff timestamp in JS first
            const result = await runQuery(this.db, query, [now, Math.floor(now / 1000)]);
            if (result.changes > 0) {
                logger.info(`Cleaned up ${result.changes} expired/old device codes from database.`);
            }
            return result.changes;
        } catch (error) {
            logger.error('Failed to cleanup expired device codes', { error: error.message });
            // Don't throw error here, as it's a background task. Just log it.
            return 0;
        }
    }
}

module.exports = DeviceAuthModel;