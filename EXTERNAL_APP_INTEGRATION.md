# Using the Authentication Server with External Applications

This guide explains how to integrate your external application with the authentication server.

## Overview

The authentication server provides JWT-based authentication for your applications. It supports:

- User authentication with username/password
- Admin authentication with special privileges
- Role-based access control
- Secure token generation and validation

## Configuration

### CORS Configuration

By default, the server allows requests from any origin (`*`). For production environments, you should restrict this to only the domains that need access to the authentication server.

Edit the `.env` file to specify allowed origins:

```
# Use '*' to allow all origins, or a comma-separated list of allowed origins
CORS_ALLOWED_ORIGINS=https://myapp.example.com,https://admin.example.com
```

### JWT Secret

Ensure you set a strong, unique JWT secret in the `.env` file:

```
JWT_SECRET=your_super_secure_jwt_secret_key
```

## Integration Steps

### 1. Authentication Flow

1. **User Login**:
   - Send a POST request to `/api/auth/login` with username and password
   - Receive a JWT token in response
   - Store this token securely in your application

2. **Admin Login**:
   - Send a POST request to `/api/auth/admin/login` with admin credentials
   - Receive a JWT token with admin privileges
   - Store this token securely in your application

3. **Using the Token**:
   - Include the token in the Authorization header for subsequent requests:
   - `Authorization: Bearer <your_token>`

### 2. API Endpoints

#### Authentication Endpoints

- **User Login**
  - URL: `/api/auth/login`
  - Method: `POST`
  - Body: `{ "username": "user", "password": "password123" }`
  - Response: `{ "token": "jwt_token_here", "user": { "id": 1, "username": "user", "role": "user" } }`

- **Admin Login**
  - URL: `/api/auth/admin/login`
  - Method: `POST`
  - Body: `{ "username": "admin", "password": "admin123" }`
  - Response: `{ "token": "jwt_token_here", "user": { "username": "admin", "role": "admin" } }`

#### User Management Endpoints (Admin Only)

- **Get All Users**
  - URL: `/api/users`
  - Method: `GET`
  - Headers: `Authorization: Bearer <admin_token>`
  - Response: Array of user objects

- **Add User**
  - URL: `/api/users`
  - Method: `POST`
  - Headers: `Authorization: Bearer <admin_token>`
  - Body: `{ "username": "newuser", "password": "password123", "role": "user" }`
  - Response: Created user object

- **Delete User**
  - URL: `/api/users/:id`
  - Method: `DELETE`
  - Headers: `Authorization: Bearer <admin_token>`
  - Response: Success message

### 3. Example Integration (JavaScript)

```javascript
// Login function
async function login(username, password) {
  try {
    const response = await fetch('http://your-auth-server.com/api/auth/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ username, password })
    });
    
    const data = await response.json();
    
    if (response.ok) {
      // Store token in localStorage or secure cookie
      localStorage.setItem('authToken', data.token);
      localStorage.setItem('user', JSON.stringify(data.user));
      return data;
    } else {
      throw new Error(data.error || 'Authentication failed');
    }
  } catch (error) {
    console.error('Login error:', error);
    throw error;
  }
}

// Function to make authenticated requests
async function authenticatedRequest(url, method = 'GET', body = null) {
  const token = localStorage.getItem('authToken');
  
  if (!token) {
    throw new Error('No authentication token found');
  }
  
  const options = {
    method,
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json'
    }
  };
  
  if (body) {
    options.body = JSON.stringify(body);
  }
  
  const response = await fetch(url, options);
  const data = await response.json();
  
  if (!response.ok) {
    // Handle token expiration
    if (response.status === 401 && data.code === 'TOKEN_EXPIRED') {
      // Redirect to login or refresh token
      localStorage.removeItem('authToken');
      window.location.href = '/login';
    }
    throw new Error(data.error || 'Request failed');
  }
  
  return data;
}

// Example usage
async function getUserProfile() {
  return authenticatedRequest('http://your-auth-server.com/api/users/profile');
}
```

## Security Considerations

1. **Always use HTTPS** in production to protect tokens in transit
2. **Store tokens securely** in your application (HttpOnly cookies are recommended)
3. **Implement token refresh** for long-lived sessions
4. **Validate user permissions** on both client and server sides
5. **Set appropriate CORS restrictions** in production

## Troubleshooting

### Common Issues

1. **CORS Errors**:
   - Ensure your application's domain is included in the `CORS_ALLOWED_ORIGINS` setting
   - Check that your requests include the correct headers

2. **Authentication Failures**:
   - Verify credentials are correct
   - Check that the JWT_SECRET is consistent between environments

3. **Token Expiration**:
   - Implement token refresh or redirect to login when tokens expire
   - Check the JWT_EXPIRATION setting if tokens expire too quickly