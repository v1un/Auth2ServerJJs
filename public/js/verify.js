// C:/Users/vini/WebstormProjects/jjguibotauthserver/public/js/verify.js
document.addEventListener('DOMContentLoaded', function() {
    // --- Elements ---
    const loginSection = document.getElementById('login-section');
    const verificationSection = document.getElementById('verification-section');
    const resultSection = document.getElementById('result-section');
    const messageArea = document.getElementById('message-area');
    const loginForm = document.getElementById('login-form');
    const verificationForm = document.getElementById('verification-form');
    const loginMessage = document.getElementById('login-message');
    const verificationMessage = document.getElementById('verification-message');
    const welcomeMessage = document.getElementById('welcome-message');
    const loggedInUsernameSpan = document.getElementById('logged-in-username');
    const csrfInputLogin = document.getElementById('csrf-token-login');
    const csrfInputVerify = document.getElementById('csrf-token-verify');
    const userCodeInput = document.getElementById('user-code');
    const resultTitle = document.getElementById('result-title');
    const resultMessage = document.getElementById('result-message');

    let csrfToken = null; // Store fetched CSRF token

    // --- Helper: Display Messages ---
    const showMessage = (element, text, type = 'error') => {
        if (!element) return;
        element.textContent = text;
        element.className = `message ${type}`;
        element.classList.remove('hidden');
    };

    // --- Helper: Hide Messages ---
    const hideMessage = (element) => {
        if (!element) return;
        element.textContent = '';
        element.classList.add('hidden');
    };

    // --- Fetch CSRF Token ---
    // We need a simple endpoint to just get the token if not rendering via template
    // Let's assume for now the token is embedded in the HTML or fetched separately.
    // **Placeholder:** Manually get token from meta tag or initial data if using template engine.
    // **Alternative:** Create a GET /api/csrf-token endpoint on the server.
    // For now, we'll assume it's somehow available. A common way is a meta tag:
    // <meta name="csrf-token" content="<%= csrfToken %>"> (if using EJS)
    const metaCsrf = document.querySelector('meta[name="csrf-token"]');
    if (metaCsrf) {
        csrfToken = metaCsrf.getAttribute('content');
        if (csrfInputLogin) csrfInputLogin.value = csrfToken;
        if (csrfInputVerify) csrfInputVerify.value = csrfToken;
    } else {
        console.warn('CSRF token meta tag not found. Form submissions might fail.');
        // You might need to fetch it from a dedicated endpoint here
        // fetch('/api/csrf-token').then(res => res.json()).then(data => { ... });
        showMessage(messageArea, 'Security token missing. Please refresh.', 'error');
    }

    // --- Initial State Check (Simulated - Needs Server Interaction) ---
    // Ideally, the server would tell us if the user is logged in when rendering the page.
    // Since we're using static HTML, we might need an initial check.
    // **Placeholder:** Check for a session cookie or make a quick /api/users/profile call?
    // For simplicity, we'll initially assume the user needs to log in.
    const checkLoginStatus = async () => {
        // This is a basic check, real session check is server-side
        // Let's assume if a session exists, the server knows.
        // We'll show the verification form by default and login if needed.
        loginSection.classList.add('hidden');
        verificationSection.classList.remove('hidden');
        // If server rendered user info (e.g., via template), display it:
        // if (loggedInUsernameSpan && serverProvidedUsername) {
        //    loggedInUsernameSpan.textContent = serverProvidedUsername;
        //    welcomeMessage.classList.remove('hidden');
        // }
    };

    // --- Handle Login Form Submission ---
    if (loginForm) {
        loginForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            hideMessage(loginMessage);
            if (!csrfToken) return showMessage(loginMessage, 'Security token missing. Please refresh.');

            const username = document.getElementById('login-username').value;
            const password = document.getElementById('login-password').value;
            const userCode = userCodeInput.value; // Get user code to pass along

            try {
                const response = await fetch('/verify', { // Post to /verify to handle login *and* check code
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'CSRF-Token': csrfToken // Send CSRF token in header if not using form input
                    },
                    body: JSON.stringify({
                        username,
                        password,
                        user_code: userCode, // Include user code
                        _csrf: csrfToken // Send CSRF token in body as well
                        // Action will be determined by button click later
                    })
                });

                const data = await response.json();

                if (response.ok) {
                    // Login was successful, server should have set session.
                    // Now show verification section.
                    showMessage(messageArea, 'Login successful. Please approve or deny the request.', 'success');
                    loginSection.classList.add('hidden');
                    verificationSection.classList.remove('hidden');
                    if (loggedInUsernameSpan) loggedInUsernameSpan.textContent = username; // Display username
                    welcomeMessage.classList.remove('hidden');
                } else {
                    showMessage(loginMessage, data.error || `Login failed (Status: ${response.status})`, 'error');
                }
            } catch (error) {
                console.error('Login error during verification:', error);
                showMessage(loginMessage, 'An network error occurred during login.', 'error');
            }
        });
    }

    // --- Handle Verification Form Submission (Approve/Deny) ---
    if (verificationForm) {
        // Use click listener on buttons to determine action
        verificationForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            hideMessage(verificationMessage);
            if (!csrfToken) return showMessage(verificationMessage, 'Security token missing. Please refresh.');

            const userCode = userCodeInput.value;
            // Determine which button was clicked (requires adding name="action" to buttons)
            const action = e.submitter ? e.submitter.value : null; // 'approve' or 'deny'

            if (!action) {
                return showMessage(verificationMessage, 'Could not determine action.', 'error');
            }
            if (!userCode) {
                return showMessage(verificationMessage, 'Please enter the user code.', 'error');
            }

            try {
                const response = await fetch('/verify', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'CSRF-Token': csrfToken
                    },
                    body: JSON.stringify({
                        user_code: userCode.toUpperCase(), // Send code uppercase
                        action: action,
                        _csrf: csrfToken
                    })
                });

                const data = await response.json();

                if (response.ok) {
                    // Show success/denied message
                    verificationSection.classList.add('hidden');
                    loginSection.classList.add('hidden'); // Ensure login is hidden too
                    messageArea.classList.add('hidden');
                    resultSection.classList.remove('hidden');
                    resultTitle.textContent = data.success ? 'Device Approved' : 'Request Denied';
                    resultMessage.textContent = data.message;
                    messageArea.className = data.success ? 'message success' : 'message info'; // Style result area
                } else {
                    // Show error message (e.g., invalid code, expired, already used, login required)
                    if (response.status === 401) {
                        // User session likely expired or wasn't established
                        showMessage(verificationMessage, data.error || 'Login required. Please log in again.', 'error');
                        verificationSection.classList.add('hidden'); // Hide verification
                        loginSection.classList.remove('hidden'); // Show login
                    } else {
                        showMessage(verificationMessage, data.error || `Verification failed (Status: ${response.status})`, 'error');
                    }
                }
            } catch (error) {
                console.error('Verification error:', error);
                showMessage(verificationMessage, 'A network error occurred during verification.', 'error');
            }
        });
    }

    // --- Initial Setup ---
    checkLoginStatus(); // Check if user might already be logged in

});