// C:/Users/vini/WebstormProjects/jjguibotauthserver/public/js/login.js
document.addEventListener('DOMContentLoaded', async function() { // Make async for initial check
    // --- Get redirect_uri from URL query parameters ---
    const urlParams = new URLSearchParams(window.location.search);
    const redirectUriFromQuery = urlParams.get('redirect_uri');
    const reason = urlParams.get('reason'); // Check if redirected from /verify

    // --- Populate hidden fields ---
    const userRedirectInput = document.getElementById('user-redirect-uri');
    const adminRedirectInput = document.getElementById('admin-redirect-uri');

    if (redirectUriFromQuery) {
        if (userRedirectInput) userRedirectInput.value = redirectUriFromQuery;
        if (adminRedirectInput) adminRedirectInput.value = redirectUriFromQuery;
        console.log("Redirect URI found in query:", redirectUriFromQuery);
    } else {
        console.log("No redirect URI found in query parameters.");
    }

    // --- Helper to display messages ---
    const showMessage = (element, text, type = 'error') => {
        if (!element) return;
        element.textContent = text;
        element.className = `message ${type}`;
    };

    // --- Elements ---
    const userLoginForm = document.getElementById('user-login-form');
    const userMessage = document.getElementById('user-message');
    const adminLoginForm = document.getElementById('admin-login-form');
    const adminMessage = document.getElementById('admin-message');

    // --- Check if already logged in via session on page load ---
    // We only do this if NOT being redirected from /verify needing login
    if (!reason || reason !== 'device_verify') {
        try {
            // Use a lightweight protected endpoint that relies on the session cookie
            const response = await fetch('/api/users/profile', {
                method: 'GET',
                headers: {
                    // No Authorization header needed, relies on session cookie
                    'Accept': 'application/json'
                }
            });

            if (response.ok) {
                const user = await response.json();
                console.log('User already logged in via session:', user);
                // Redirect based on role
                if (user.role === 'admin') {
                    window.location.href = '/admin.html'; // Redirect admin to admin page
                } else {
                    // Redirect regular user to their profile page
                    window.location.href = '/profile.html';
                }
                // Prevent further script execution if redirecting
                return;
            } else {
                // Not logged in or session expired, continue showing the login page.
                console.log('No active session found or session expired.');
            }
        } catch (error) {
            console.error('Error checking session status:', error);
            // Proceed to show login page on error
        }
    } else {
        console.log('Skipping auto-login check due to device verification redirect.');
        // Optionally show a message indicating why they need to log in
        showMessage(userMessage, 'Please log in to complete device verification.', 'info');
    }


    // --- Tab switching functionality ---
    const tabBtns = document.querySelectorAll('.tab-btn');
    const tabContents = document.querySelectorAll('.tab-content');

    tabBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            tabBtns.forEach(b => b.classList.remove('active'));
            tabContents.forEach(c => c.classList.remove('active'));
            btn.classList.add('active');
            const tabId = `${btn.dataset.tab}-tab`;
            const targetTabContent = document.getElementById(tabId);
            if (targetTabContent) {
                targetTabContent.classList.add('active');
            } else {
                console.error(`Tab content with ID ${tabId} not found.`);
            }
        });
    });


    // --- User login form submission ---
    if (userLoginForm) {
        userLoginForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            showMessage(userMessage, '', ''); // Clear message

            const username = document.getElementById('user-username').value;
            const password = document.getElementById('user-password').value;
            const rememberMe = document.getElementById('user-remember-me').checked; // Get checkbox state

            if (!username || !password) {
                return showMessage(userMessage, 'Username and password are required.');
            }

            let response; // Define response outside try block for broader scope if needed
            try {
                // Construct the URL, including redirect_uri if present
                const loginUrl = new URL('/api/auth/login', window.location.origin);
                if (redirectUriFromQuery) {
                    loginUrl.searchParams.set('redirect_uri', redirectUriFromQuery);
                }

                response = await fetch(loginUrl.toString(), { // Assign to outer scope response
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    // Send rememberMe status in the body
                    body: JSON.stringify({ username, password, rememberMe })
                });

                // If redirectUri was provided, a successful login (2xx or 3xx) should result in a browser redirect handled by the server.
                // We only need to handle errors (4xx, 5xx) or unexpected 2xx responses here.

                if (!response.ok) {
                    // Server might return JSON error even on failed login
                    const data = await response.json().catch(() => ({ error: `Server returned status ${response.status}` }));
                    showMessage(userMessage, data.error || `Login failed (Status: ${response.status})`);
                    return; // Stop execution on error
                }

                // Check if the server handled the redirect (status code 3xx or fetch's redirected flag)
                // Note: fetch API doesn't automatically follow redirects unless `redirect: 'follow'` is set,
                // but the server sends a 302 status and Location header, which the *browser* follows.
                // The `response.redirected` flag might not be true here if the browser handles it transparently.
                // A safer check is often just seeing if the response is OK and *not* expecting JSON for redirects.
                if (redirectUriFromQuery && response.ok) {
                    // If redirectUri was given and response is OK (200), assume server handled redirect.
                    // Browser should be navigating away. Log and do nothing else.
                    console.log('Login successful, server should be initiating redirect.');
                    // Potentially disable the form briefly
                    userLoginForm.querySelector('button[type="submit"]').disabled = true;
                    return; // Stop further processing
                }

                // --- Handle direct web login success (No redirectUri) ---
                if (response.ok) {
                    const data = await response.json().catch(() => null); // Try to parse JSON
                    if (data && data.user) {
                        // Logged in successfully, but no redirect_uri was involved.
                        // Manually redirect based on role for web login.
                        if (data.user.role === 'admin') {
                            window.location.href = '/admin.html';
                        } else {
                            // Redirect regular user to their profile page
                            window.location.href = '/profile.html';
                        }
                        return; // Stop execution after initiating redirect
                    } else {
                        // Unexpected 2xx response without user data
                        showMessage(userMessage, 'Login processed, but unexpected response format.', 'warning');
                    }
                }

            } catch (error) {
                // This catch block handles network errors or errors thrown explicitly above
                showMessage(userMessage, `An error occurred: ${error.message || 'Please check network or try again.'}`);
                console.error('User login error:', error);
            }
        });
    } else {
        console.error('User login form not found.');
    }

    // --- Admin login form submission ---
    if (adminLoginForm) {
        adminLoginForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            showMessage(adminMessage, '', ''); // Clear message

            const username = document.getElementById('admin-username').value;
            const password = document.getElementById('admin-password').value;
            const rememberMe = document.getElementById('admin-remember-me').checked; // Get checkbox state

            if (!username || !password) {
                return showMessage(adminMessage, 'Username and password are required.');
            }

            let response;
            try {
                // Construct the URL, including redirect_uri if present
                const loginUrl = new URL('/api/auth/admin/login', window.location.origin);
                if (redirectUriFromQuery) {
                    loginUrl.searchParams.set('redirect_uri', redirectUriFromQuery);
                }

                response = await fetch(loginUrl.toString(), { // Use the constructed URL
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    // Send rememberMe status in the body
                    body: JSON.stringify({ username, password, rememberMe })
                });

                // Similar logic to user login: Server should redirect if redirectUri was present.
                // Handle errors or direct web login success.

                if (!response.ok) {
                    const data = await response.json().catch(() => ({ error: `Server returned status ${response.status}` }));
                    showMessage(adminMessage, data.error || `Admin login failed (Status: ${response.status})`);
                    return; // Stop execution
                }

                // Check for server-handled redirect
                if (redirectUriFromQuery && response.ok) {
                    console.log('Admin login successful, server should be initiating redirect.');
                    adminLoginForm.querySelector('button[type="submit"]').disabled = true;
                    return; // Stop further processing
                }

                // --- Handle direct web login success (No redirectUri) ---
                if (response.ok) {
                    const data = await response.json().catch(() => null);
                    if (data && data.user && data.user.role === 'admin') {
                        // Admin logged in directly via web page. Redirect to admin dashboard.
                        window.location.href = '/admin.html';
                        return; // Stop execution
                    } else {
                        // Unexpected 2xx response
                        showMessage(adminMessage, 'Admin login processed, but unexpected response format.', 'warning');
                    }
                }

            } catch (error) {
                showMessage(adminMessage, `An error occurred: ${error.message || 'Please check network or try again.'}`);
                console.error('Admin login error:', error);
            }
        });
    } else {
        console.error('Admin login form not found.');
    }
});