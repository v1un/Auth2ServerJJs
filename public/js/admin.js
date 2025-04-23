document.addEventListener('DOMContentLoaded', function() {
    // Check if admin is logged in
    const adminToken = localStorage.getItem('adminToken');
    if (!adminToken) {
        // Redirect to login page if not logged in
        window.location.href = '/index.html';
        return;
    }
    
    // Logout functionality
    const logoutBtn = document.getElementById('logout-btn');
    logoutBtn.addEventListener('click', () => {
        localStorage.removeItem('adminToken');
        window.location.href = '/index.html';
    });
    
    // Add user form submission
    const addUserForm = document.getElementById('add-user-form');
    const addUserMessage = document.getElementById('add-user-message');
    
    addUserForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const username = document.getElementById('new-username').value;
        const password = document.getElementById('new-password').value;
        
        try {
            const response = await fetch('/admin/add-user', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${adminToken}`
                },
                body: JSON.stringify({ username, password })
            });
            
            const data = await response.json();
            
            if (response.ok) {
                // User added successfully
                addUserMessage.textContent = 'User added successfully!';
                addUserMessage.className = 'message success';
                
                // Clear form
                addUserForm.reset();
                
                // Refresh user list
                fetchUsers();
            } else {
                // Failed to add user
                addUserMessage.textContent = data.error || 'Failed to add user';
                addUserMessage.className = 'message error';
            }
        } catch (error) {
            addUserMessage.textContent = 'An error occurred. Please try again.';
            addUserMessage.className = 'message error';
            console.error('Add user error:', error);
        }
    });
    
    // Function to fetch and display users
    async function fetchUsers() {
        const userList = document.getElementById('user-list');
        
        try {
            const response = await fetch('/admin/users', {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${adminToken}`
                }
            });
            
            if (response.ok) {
                const users = await response.json();
                
                // Clear current list
                userList.innerHTML = '';
                
                // Add users to table
                users.forEach(user => {
                    const row = document.createElement('tr');
                    
                    row.innerHTML = `
                        <td>${user.id}</td>
                        <td>${user.username}</td>
                        <td>${user.role}</td>
                        <td>${new Date(user.created_at).toLocaleString()}</td>
                        <td>
                            <button class="btn btn-danger action-btn delete-btn" data-id="${user.id}">Delete</button>
                        </td>
                    `;
                    
                    userList.appendChild(row);
                });
                
                // Add event listeners to delete buttons
                document.querySelectorAll('.delete-btn').forEach(btn => {
                    btn.addEventListener('click', deleteUser);
                });
            } else {
                console.error('Failed to fetch users');
            }
        } catch (error) {
            console.error('Error fetching users:', error);
        }
    }
    
    // Function to delete a user
    async function deleteUser(e) {
        const userId = e.target.dataset.id;
        
        if (confirm('Are you sure you want to delete this user?')) {
            try {
                const response = await fetch(`/admin/users/${userId}`, {
                    method: 'DELETE',
                    headers: {
                        'Authorization': `Bearer ${adminToken}`
                    }
                });
                
                if (response.ok) {
                    // User deleted successfully
                    alert('User deleted successfully');
                    
                    // Refresh user list
                    fetchUsers();
                } else {
                    const data = await response.json();
                    alert(data.error || 'Failed to delete user');
                }
            } catch (error) {
                console.error('Error deleting user:', error);
                alert('An error occurred. Please try again.');
            }
        }
    }
    
    // Initial fetch of users
    fetchUsers();
});