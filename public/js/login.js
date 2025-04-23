document.addEventListener('DOMContentLoaded', function() {
    // Tab switching functionality
    const tabBtns = document.querySelectorAll('.tab-btn');
    const tabContents = document.querySelectorAll('.tab-content');
    
    tabBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            // Remove active class from all buttons and contents
            tabBtns.forEach(b => b.classList.remove('active'));
            tabContents.forEach(c => c.classList.remove('active'));
            
            // Add active class to clicked button and corresponding content
            btn.classList.add('active');
            const tabId = `${btn.dataset.tab}-tab`;
            document.getElementById(tabId).classList.add('active');
        });
    });
    
    // User login form submission
    const userLoginForm = document.getElementById('user-login-form');
    const userMessage = document.getElementById('user-message');
    
    userLoginForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const username = document.getElementById('user-username').value;
        const password = document.getElementById('user-password').value;
        
        try {
            const response = await fetch('/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ username, password })
            });
            
            const data = await response.json();
            
            if (response.ok) {
                // Login successful
                userMessage.textContent = 'Login successful!';
                userMessage.className = 'message success';
                
                // Store token in localStorage
                localStorage.setItem('authToken', data.token);
                
                // Redirect to a protected page or show success message
                alert('User login successful!');
                // You can redirect to a user dashboard here if needed
            } else {
                // Login failed
                userMessage.textContent = data.error || 'Login failed';
                userMessage.className = 'message error';
            }
        } catch (error) {
            userMessage.textContent = 'An error occurred. Please try again.';
            userMessage.className = 'message error';
            console.error('Login error:', error);
        }
    });
    
    // Admin login form submission
    const adminLoginForm = document.getElementById('admin-login-form');
    const adminMessage = document.getElementById('admin-message');
    
    adminLoginForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const username = document.getElementById('admin-username').value;
        const password = document.getElementById('admin-password').value;
        
        try {
            const response = await fetch('/admin/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ username, password })
            });
            
            const data = await response.json();
            
            if (response.ok) {
                // Login successful
                adminMessage.textContent = 'Admin login successful!';
                adminMessage.className = 'message success';
                
                // Store token in localStorage
                localStorage.setItem('adminToken', data.token);
                
                // Redirect to admin dashboard
                window.location.href = '/admin.html';
            } else {
                // Login failed
                adminMessage.textContent = data.error || 'Admin login failed';
                adminMessage.className = 'message error';
            }
        } catch (error) {
            adminMessage.textContent = 'An error occurred. Please try again.';
            adminMessage.className = 'message error';
            console.error('Admin login error:', error);
        }
    });
});