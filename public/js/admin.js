// C:/Users/vini/WebstormProjects/jjguibotauthserver/public/js/admin.js
document.addEventListener('DOMContentLoaded', function() {
    // --- Authentication Check ---
    // This check now relies on the server session being active.
    // We'll verify by trying to fetch data. If it fails with 401/403, we redirect.

    const userListBody = document.getElementById('user-list');
    const userTable = document.getElementById('user-table');
    const addUserForm = document.getElementById('add-user-form');
    const addUserMessage = document.getElementById('add-user-message');
    const logoutBtn = document.getElementById('logout-btn');
    // const profileLink = document.getElementById('profile-link'); // Get profile link if needed for JS actions

    // --- Helper: Display Messages ---
    const showMessage = (element, text, type = 'error') => {
        if (!element) return; // Guard against missing elements
        element.textContent = text;
        element.className = `message ${type}`;
    };

    // --- Helper: Handle Unauthorized/Forbidden ---
    const handleAuthError = (response, data) => {
        // This function now correctly handles session-based auth failures
        if (response.status === 401 || response.status === 403) {
            alert(`Authentication error: ${data?.error || 'Session expired or access denied. Please log in again.'}`);
            // Clear any potential leftover JWT tokens (though not used for web session)
            localStorage.removeItem('adminToken');
            localStorage.removeItem('adminUser');
            window.location.href = '/index.html'; // Redirect to login
            return true;
        }
        return false;
    };

    // --- Fetch and Display Users ---
    const fetchUsers = async () => {
        try {
            const response = await fetch('/api/users', {
                method: 'GET',
                headers: {
                    // No Authorization header needed for session-based auth
                    'Accept': 'application/json'
                }
            });

            const users = await response.json();

            if (!response.ok) {
                // If fetch fails due to auth, handleAuthError will redirect
                if (handleAuthError(response, users)) return;
                throw new Error(users?.error || `HTTP error! status: ${response.status}`);
            }

            renderUserList(users);

        } catch (error) {
            console.error('Error fetching users:', error);
            // If the initial fetch fails (e.g., network error before auth check),
            // we might still want to redirect or show a generic error.
            // For now, just log the error in the table.
            if (userListBody) {
                userListBody.innerHTML = `<tr><td colspan="6" class="error">Error loading users: ${error.message}</td></tr>`;
            }
            // Consider redirecting here too if the error suggests no connection or severe issue
            // window.location.href = '/index.html';
        }
    };

    // --- Render User List in the Table ---
    const renderUserList = (users) => {
        if (!userListBody) return;
        userListBody.innerHTML = '';

        if (!users || users.length === 0) {
            userListBody.innerHTML = '<tr><td colspan="6">No users found.</td></tr>';
            return;
        }

        users.forEach(user => {
            const row = document.createElement('tr');
            row.dataset.userId = user.id;
            // Display allowed IP or 'Not set'
            const allowedIpDisplay = user.allowed_ip ? user.allowed_ip : '<i>Not set</i>';
            // Disable buttons for the special admin user (ID 0)
            const isDisabled = user.id === 0;
            const disabledAttr = isDisabled ? 'disabled' : '';

            row.innerHTML = `
                <td>${user.id}</td>
                <td>${user.username}</td>
                <td>${user.role}</td>
                <td>${new Date(user.created_at).toLocaleString()}</td>
                <td class="ip-cell">${allowedIpDisplay}</td>
                <td class="actions-cell">
                    <button class="btn btn-sm btn-warning btn-reset-ip" data-user-id="${user.id}" ${disabledAttr}>Reset IP</button>
                    <span class="ip-reset-status" data-user-id="${user.id}"></span>
                    <button class="btn btn-danger btn-sm delete-user-btn" data-user-id="${user.id}" ${disabledAttr}>Delete</button>
                </td>
            `;
            userListBody.appendChild(row);
        });
    };

    // --- Handle Adding a New User ---
    if (addUserForm) {
        addUserForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const username = document.getElementById('new-username').value;
            const password = document.getElementById('new-password').value;
            showMessage(addUserMessage, '', '');

            if (!username || !password) {
                return showMessage(addUserMessage, 'Username and password are required.');
            }
            if (password.length < 8) { // Basic client-side length check
                return showMessage(addUserMessage, 'Password must be at least 8 characters long.');
            }

            try {
                const response = await fetch('/api/users', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                        // No Authorization header needed
                    },
                    body: JSON.stringify({ username, password, role: 'user' })
                });
                const data = await response.json();

                if (response.ok) {
                    showMessage(addUserMessage, data.message || 'User added successfully!', 'success');
                    addUserForm.reset();
                    fetchUsers(); // Refresh list
                } else {
                    if (handleAuthError(response, data)) return; // Handles session expiry etc.
                    showMessage(addUserMessage, data.error || 'Failed to add user.');
                }
            } catch (error) {
                console.error('Error adding user:', error);
                showMessage(addUserMessage, 'An error occurred. Please try again.');
            }
        });
    }

    // --- Handle User Actions (Delete, Reset IP) using Event Delegation ---
    if (userTable) {
        userTable.addEventListener('click', async (e) => {
            const target = e.target;
            const userId = target.dataset.userId;

            // Ignore clicks not on relevant buttons or if user ID is 0
            if (!userId || userId === '0' || !(target.classList.contains('delete-user-btn') || target.classList.contains('btn-reset-ip'))) {
                return;
            }

            // --- Delete User ---
            if (target.classList.contains('delete-user-btn')) {
                if (confirm(`Are you sure you want to delete user ID ${userId}?`)) {
                    try {
                        const response = await fetch(`/api/users/${userId}`, {
                            method: 'DELETE',
                            headers: { /* No Auth header */ }
                        });
                        const data = await response.json();
                        if (response.ok) {
                            alert(data.message || 'User deleted successfully!');
                            fetchUsers(); // Refresh list
                        } else {
                            if (handleAuthError(response, data)) return;
                            alert(`Error: ${data.error || 'Failed to delete user.'}`);
                        }
                    } catch (error) {
                        console.error('Error deleting user:', error);
                        alert('An error occurred while deleting the user.');
                    }
                }
            }

            // --- Reset Allowed IP ---
            if (target.classList.contains('btn-reset-ip')) {
                const statusSpan = userTable.querySelector(`.ip-reset-status[data-user-id="${userId}"]`);
                if (!statusSpan) return; // Should not happen

                if (confirm(`Are you sure you want to reset the allowed IP for user ID ${userId}? They will be able to log in from any IP next, which will then become their new allowed IP.`)) {
                    statusSpan.textContent = 'Resetting...';
                    statusSpan.className = 'ip-reset-status saving';

                    try {
                        // Call the new reset endpoint
                        const response = await fetch(`/api/users/${userId}/reset-ip`, {
                            method: 'PUT', // Use PUT for update/reset actions
                            headers: {
                                // No Authorization header needed
                                // No Content-Type or body needed
                            }
                        });

                        const data = await response.json();

                        if (response.ok) {
                            statusSpan.textContent = 'Reset!';
                            statusSpan.className = 'ip-reset-status success';
                            fetchUsers(); // Refresh the list to show 'Not set'
                        } else {
                            if (handleAuthError(response, data)) return;
                            statusSpan.textContent = `Error: ${data.error || 'Failed'}`;
                            statusSpan.className = 'ip-reset-status error';
                        }
                    } catch (error) {
                        console.error('Error resetting IP:', error);
                        statusSpan.textContent = 'Network Error';
                        statusSpan.className = 'ip-reset-status error';
                    } finally {
                        // Clear status message after a few seconds
                        setTimeout(() => {
                            if (statusSpan.textContent !== 'Resetting...') {
                                statusSpan.textContent = '';
                                statusSpan.className = 'ip-reset-status';
                            }
                        }, 3000);
                    }
                }
            }
        });
    }

    // --- Handle Logout ---
    if (logoutBtn) {
        logoutBtn.addEventListener('click', async () => { // Make async
            // Clear local storage just in case (good practice)
            localStorage.removeItem('adminToken');
            localStorage.removeItem('adminUser');

            try {
                // Call the server-side logout endpoint
                const response = await fetch('/api/auth/logout', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json' // Optional, but good practice
                    }
                });

                const data = await response.json();

                if (response.ok) {
                    alert(data.message || 'Logged out successfully.');
                } else {
                    // Show error from server if logout failed
                    alert(`Logout failed: ${data.error || 'Unknown error'}`);
                }
            } catch (error) {
                console.error('Logout network error:', error);
                alert('Logout failed due to a network error.');
            } finally {
                // Always redirect to login page after attempting logout
                window.location.href = '/index.html';
            }
        });
    }

    // --- Initial Load ---
    // fetchUsers will now implicitly check if the session is valid
    fetchUsers();
});