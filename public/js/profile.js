// C:/Users/vini/WebstormProjects/jjguibotauthserver/public/js/profile.js
document.addEventListener('DOMContentLoaded', function() {

    // --- Get Elements ---
    const profileContainer = document.querySelector('.profile-container');
    const profileContent = document.getElementById('profile-content'); // Content area
    const profileDetailsDl = profileContent?.querySelector('.profile-details'); // Use optional chaining
    const loadingMessage = profileContainer?.querySelector('.loading');
    const errorMessageElement = profileContainer?.querySelector('.error-message');
    const successMessageElement = profileContainer?.querySelector('.success-message');
    const logoutBtn = document.getElementById('logout-btn');
    const adminLink = document.getElementById('admin-dashboard-link');

    // Profile Edit Elements
    const profileEditForm = document.getElementById('profile-edit-form');
    const customNameInput = document.getElementById('custom-name-input');
    const saveProfileBtn = document.getElementById('save-profile-btn');
    const resetPasswordBtn = document.getElementById('reset-password-btn');
    const newPasswordDisplay = document.getElementById('new-password-display');

    // Profile Prompt Elements
    const profilePrompt = document.getElementById('profile-prompt');
    const promptYesBtn = document.getElementById('prompt-yes-btn');
    const promptNoBtn = document.getElementById('prompt-no-btn');

    // --- Helper: Show Message (Error or Success) ---
    const showMessage = (message, type = 'error') => {
        const element = type === 'error' ? errorMessageElement : successMessageElement;
        const otherElement = type === 'error' ? successMessageElement : errorMessageElement;

        if (otherElement) otherElement.style.display = 'none'; // Hide other message type

        if (element) {
            element.textContent = message;
            element.style.display = 'block';
            // Auto-hide success messages after a delay
            if (type === 'success') {
                setTimeout(() => {
                    element.style.display = 'none';
                }, 5000); // Hide after 5 seconds
            }
        } else {
            console.warn(`Cannot display ${type} message: Element not found.`);
            alert(`${type.toUpperCase()}: ${message}`); // Fallback alert
        }
        // Log errors to console
        if (type === 'error') {
            console.error("Profile Page Error:", message);
        }
    };

    // --- Helper: Handle Unauthorized/Forbidden ---
    const handleAuthError = (response, data) => {
        if (response.status === 401 || response.status === 403) {
            const errorMsg = data?.error || (response.status === 401 ? 'Authentication required. Please log in again.' : 'Access denied.');
            // Display error message first
            showMessage(`Authentication error: ${errorMsg}`, 'error');
            // Redirect after a short delay
            setTimeout(() => {
                localStorage.removeItem('adminToken'); // Clear any potential leftovers
                localStorage.removeItem('adminUser');
                window.location.href = '/index.html?reason=auth_error'; // Redirect to login
            }, 2000); // Delay 2 seconds
            return true; // Indicate auth error handled
        }
        return false;
    };

    // --- Fetch and Display Profile ---
    const fetchProfile = async () => {
        // Reset UI state
        if (errorMessageElement) errorMessageElement.style.display = 'none';
        if (successMessageElement) successMessageElement.style.display = 'none';
        if (loadingMessage) loadingMessage.style.display = 'block';
        if (profileContent) profileContent.style.display = 'none'; // Hide main content area
        if (profilePrompt) profilePrompt.style.display = 'none'; // Hide prompt initially

        try {
            console.log("Fetching profile data..."); // Debug log
            const response = await fetch('/api/users/profile', {
                method: 'GET',
                headers: {
                    'Accept': 'application/json'
                    // No Authorization header needed, relies on session cookie
                }
            });

            console.log("Profile fetch response status:", response.status); // Debug log

            // Try to parse JSON regardless of status for error messages
            const user = await response.json().catch(err => {
                console.error("Failed to parse JSON response:", err);
                // Throw a more specific error if parsing fails
                throw new Error(`Server returned non-JSON response (Status: ${response.status})`);
            });

            console.log("Profile data received:", user); // Debug log

            // Check if response is OK *after* parsing JSON
            if (!response.ok) {
                // Handle auth errors first (will redirect)
                if (handleAuthError(response, user)) return;
                // Handle other non-OK responses using the parsed error message
                throw new Error(user?.error || `Failed to load profile (Status: ${response.status})`);
            }

            // --- Populate Profile Details ---
            if (loadingMessage) loadingMessage.style.display = 'none';

            // Check if user object is valid
            if (!user || typeof user !== 'object') {
                throw new Error("Received invalid user data format.");
            }

            // Safely access elements before setting textContent/innerHTML
            const userIdEl = document.getElementById('user-id');
            const usernameEl = document.getElementById('user-username');
            const roleEl = document.getElementById('user-role');
            const createdAtEl = document.getElementById('user-created-at');
            const allowedIpEl = document.getElementById('user-allowed-ip');
            const customNameDisplay = document.getElementById('user-custom-name');

            if (userIdEl) userIdEl.textContent = user.id ?? 'N/A';
            if (usernameEl) usernameEl.textContent = user.username || 'N/A';
            if (roleEl) roleEl.textContent = user.role || 'N/A';
            if (createdAtEl) createdAtEl.textContent = user.created_at ? new Date(user.created_at).toLocaleString() : 'N/A';
            if (allowedIpEl) allowedIpEl.innerHTML = user.allowed_ip ? user.allowed_ip : '<i>Not set</i>';

            // Populate custom name display and input field
            if (customNameDisplay) {
                if (user.custom_name) {
                    customNameDisplay.textContent = user.custom_name;
                    if (customNameInput) customNameInput.value = user.custom_name;
                } else {
                    customNameDisplay.innerHTML = '<i>Not set</i>';
                    if (customNameInput) customNameInput.value = ''; // Ensure input is empty if not set
                }
            }

            // Show admin dashboard link if user is admin
            if (user.role === 'admin' && adminLink) {
                adminLink.style.display = 'inline-block';
            }

            // Show the main profile content
            if (profileContent) profileContent.style.display = 'block';

            // --- Initial Profile Prompt Logic ---
            // Show prompt only if custom_name is not set and user is not the env admin (ID 0)
            if (!user.custom_name && user.id !== 0 && profilePrompt) {
                profilePrompt.style.display = 'block';
            }

        } catch (error) {
            console.error('Error fetching or processing profile:', error); // Log the full error
            showMessage(error.message || 'An unexpected error occurred while loading your profile.', 'error');
            if (loadingMessage) loadingMessage.style.display = 'none'; // Ensure loading is hidden on error
        }
    };

    // --- Handle Profile Prompt Buttons ---
    if (promptYesBtn) {
        promptYesBtn.addEventListener('click', () => {
            if (profilePrompt) profilePrompt.style.display = 'none';
            if (customNameInput) customNameInput.focus(); // Focus the input field
        });
    }
    if (promptNoBtn) {
        promptNoBtn.addEventListener('click', () => {
            if (profilePrompt) profilePrompt.style.display = 'none';
        });
    }

    // --- Handle Profile Edit Form Submission ---
    if (profileEditForm) {
        profileEditForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const newCustomName = customNameInput ? customNameInput.value.trim() : '';
            if (saveProfileBtn) {
                saveProfileBtn.disabled = true;
                saveProfileBtn.textContent = 'Saving...';
            }
            if (errorMessageElement) errorMessageElement.style.display = 'none';
            if (successMessageElement) successMessageElement.style.display = 'none';
            if (newPasswordDisplay) newPasswordDisplay.style.display = 'none'; // Hide password display

            try {
                const response = await fetch('/api/users/profile', {
                    method: 'PUT',
                    headers: {
                        'Content-Type': 'application/json',
                        'Accept': 'application/json'
                    },
                    body: JSON.stringify({ custom_name: newCustomName })
                });

                const data = await response.json().catch(err => ({ error: `Server returned non-JSON response (Status: ${response.status})` }));

                if (!response.ok) {
                    if (handleAuthError(response, data)) return; // Handles 401/403
                    const errorMsg = data.validationErrors ? data.validationErrors[0].message : (data.error || `Failed to save profile (Status: ${response.status})`);
                    throw new Error(errorMsg);
                }

                // Update display on success
                const customNameDisplay = document.getElementById('user-custom-name');
                if (customNameDisplay) {
                    if (data.custom_name) {
                        customNameDisplay.textContent = data.custom_name;
                    } else {
                        customNameDisplay.innerHTML = '<i>Not set</i>';
                    }
                }
                showMessage(data.message || 'Profile updated successfully!', 'success');

            } catch (error) {
                showMessage(error.message || 'An error occurred while saving the profile.', 'error');
            } finally {
                if (saveProfileBtn) {
                    saveProfileBtn.disabled = false;
                    saveProfileBtn.textContent = 'Save Profile';
                }
            }
        });
    } else {
        console.warn("Profile edit form not found.");
    }

    // --- Handle Password Reset Button ---
    if (resetPasswordBtn) {
        resetPasswordBtn.addEventListener('click', async () => {
            if (!confirm('Are you sure you want to reset your password? A new random password will be generated.')) {
                return;
            }

            resetPasswordBtn.disabled = true;
            resetPasswordBtn.textContent = 'Resetting...';
            if (newPasswordDisplay) newPasswordDisplay.style.display = 'none'; // Hide previous password
            if (errorMessageElement) errorMessageElement.style.display = 'none';
            if (successMessageElement) successMessageElement.style.display = 'none';

            try {
                const response = await fetch('/api/users/profile/reset-password', {
                    method: 'POST',
                    headers: {
                        'Accept': 'application/json'
                    }
                });

                const data = await response.json().catch(err => ({ error: `Server returned non-JSON response (Status: ${response.status})` }));

                if (!response.ok) {
                    if (handleAuthError(response, data)) return;
                    throw new Error(data.error || `Failed to reset password (Status: ${response.status})`);
                }

                // Display the new password securely
                if (newPasswordDisplay && data.newPassword) {
                    newPasswordDisplay.innerHTML = `<strong>IMPORTANT: Your new password is:</strong> ${data.newPassword}<br>Please copy it somewhere safe and log in again.`;
                    newPasswordDisplay.style.display = 'block';
                    showMessage('Password reset successfully. Please copy your new password shown below.', 'success');
                } else {
                    showMessage(data.message || 'Password reset successfully, but new password not returned.', 'success');
                }

            } catch (error) {
                showMessage(error.message || 'An error occurred while resetting the password.', 'error');
            } finally {
                resetPasswordBtn.disabled = false;
                resetPasswordBtn.textContent = 'Reset Password';
            }
        });
    } else {
        console.warn("Reset password button not found.");
    }


    // --- Handle Logout ---
    if (logoutBtn) {
        logoutBtn.addEventListener('click', async () => {
            console.log("Logout button clicked"); // Debug log
            logoutBtn.disabled = true;
            logoutBtn.textContent = 'Logging out...';
            if (errorMessageElement) errorMessageElement.style.display = 'none'; // Clear messages
            if (successMessageElement) successMessageElement.style.display = 'none';

            localStorage.removeItem('adminToken');
            localStorage.removeItem('adminUser');

            try {
                console.log("Sending logout request..."); // Debug log
                const response = await fetch('/api/auth/logout', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' }
                });

                console.log("Logout response status:", response.status); // Debug log
                const data = await response.json().catch(err => {
                    console.error("Failed to parse logout JSON response:", err);
                    return { error: `Server returned non-JSON response (Status: ${response.status})` };
                });
                console.log("Logout response data:", data); // Debug log

                if (!response.ok) {
                    showMessage(`Logout failed: ${data.error || 'Unknown error'}`, 'error');
                    logoutBtn.disabled = false; // Re-enable button on failure
                    logoutBtn.textContent = 'Logout';
                } else {
                    // Success - show message and redirect
                    showMessage(data.message || 'Logged out successfully. Redirecting...', 'success');
                    setTimeout(() => {
                        window.location.href = '/index.html'; // Redirect to login page
                    }, 1500); // Delay 1.5 seconds
                }
            } catch (error) {
                console.error('Logout network error:', error);
                showMessage('Logout failed due to a network error.', 'error');
                logoutBtn.disabled = false; // Re-enable button on failure
                logoutBtn.textContent = 'Logout';
            }
        });
    } else {
        console.error("Logout button not found!");
    }

    // --- Initial Load ---
    fetchProfile();
});