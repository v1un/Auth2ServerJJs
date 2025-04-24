# Authentication Server Project Guidelines

## Project Overview

This project is an authentication server built with Node.js and Express.js, designed for a low-resource Linux Google Compute Engine instance. The server manages users with 'admin' and 'user' roles stored in a SQLite database and provides JWT-based authentication.

### Key Features

- Admin and user authentication with JWT
- User management (add, list, delete users)
- Secure password storage with bcrypt
- Role-based access control
- SQLite database for data persistence
- Simple web interface for login and administration

## Project Structure

```
jjguibotauthserver/
??? .env                  # Environment configuration
??? server.js             # Main server file
??? package.json          # Project metadata and dependencies
??? auth.db               # SQLite database (created on first run)
??? public/               # Frontend files
?   ??? css/              # Stylesheets
?   ??? js/               # Frontend JavaScript
?   ??? index.html        # Login page
?   ??? admin.html        # Admin dashboard
??? node_modules/         # Dependencies (created by npm install)
```

## Setup Instructions

### Prerequisites

- Node.js (v14 or higher)
- npm (v6 or higher)

### Installation

1. Clone the repository:
   ```
   git clone <repository-url>
   cd jjguibotauthserver
   ```

2. Install dependencies:
   ```
   npm install
   ```

3. Configure environment variables:
   - Copy the example .env file or create a new one
   - Modify the values for security:
     ```
     PORT=3000
     JWT_SECRET=your_secure_secret_key
     ADMIN_USERNAME=your_admin_username
     ADMIN_PASSWORD=your_secure_admin_password
     DB_PATH=auth.db
     ```

4. Start the server:
   - For development:
     ```
     npm run dev
     ```
   - For production:
     ```
     npm start
     ```

5. Access the application:
   - Main login page: http://localhost:3000
   - Admin dashboard (after login): http://localhost:3000/admin.html

## API Documentation

### Authentication Endpoints

#### Admin Login
- **URL**: `/admin/login`
- **Method**: `POST`
- **Request Body**:
  ```json
  {
    "username": "admin",
    "password": "admin123"
  }
  ```
- **Success Response**:
  ```json
  {
    "token": "jwt_token_here"
  }
  ```
- **Error Response**:
  ```json
  {
    "error": "Invalid admin credentials"
  }
  ```

#### User Login
- **URL**: `/login`
- **Method**: `POST`
- **Request Body**:
  ```json
  {
    "username": "user",
    "password": "password123"
  }
  ```
- **Success Response**:
  ```json
  {
    "token": "jwt_token_here"
  }
  ```
- **Error Response**:
  ```json
  {
    "error": "Invalid credentials"
  }
  ```

### User Management Endpoints

#### Add User (Admin only)
- **URL**: `/admin/add-user`
- **Method**: `POST`
- **Headers**: `Authorization: Bearer <admin_token>`
- **Request Body**:
  ```json
  {
    "username": "newuser",
    "password": "password123"
  }
  ```
- **Success Response**:
  ```json
  {
    "message": "User created successfully",
    "userId": 1
  }
  ```
- **Error Response**:
  ```json
  {
    "error": "Username already exists"
  }
  ```

#### Get All Users (Admin only)
- **URL**: `/admin/users`
- **Method**: `GET`
- **Headers**: `Authorization: Bearer <admin_token>`
- **Success Response**:
  ```json
  [
    {
      "id": 1,
      "username": "user1",
      "role": "user",
      "created_at": "2023-01-01T00:00:00.000Z"
    }
  ]
  ```

#### Delete User (Admin only)
- **URL**: `/admin/users/:id`
- **Method**: `DELETE`
- **Headers**: `Authorization: Bearer <admin_token>`
- **Success Response**:
  ```json
  {
    "message": "User deleted successfully"
  }
  ```
- **Error Response**:
  ```json
  {
    "error": "User not found"
  }
  ```

## Development Guidelines

### Code Style

- Use consistent indentation (2 spaces)
- Follow JavaScript ES6+ conventions
- Use meaningful variable and function names
- Add comments for complex logic

### Error Handling

- Always use try/catch blocks for async operations
- Return appropriate HTTP status codes
- Provide meaningful error messages
- Log errors to the console for debugging

### Security Best Practices

- Always change default credentials in production
- Use a strong, unique JWT secret
- Set appropriate token expiration times
- Validate and sanitize all user inputs
- Use HTTPS in production
- Keep dependencies updated

## Deployment Instructions

### Deploying to Google Compute Engine

1. Create a new VM instance:
   - Choose a small instance type (e.g., e2-micro)
   - Select a Linux-based OS (e.g., Debian, Ubuntu)
   - Configure firewall to allow HTTP/HTTPS traffic

2. Connect to your instance via SSH

3. Install Node.js and npm:
   ```
   sudo apt update
   sudo apt install -y nodejs npm
   ```

4. Clone your repository or upload your code

5. Install dependencies:
   ```
   cd jjguibotauthserver
   npm install --production
   ```

6. Create and configure your .env file:
   ```
   nano .env
   ```
   Add your production configuration

7. Install PM2 for process management:
   ```
   sudo npm install -g pm2
   ```

8. Start your application with PM2:
   ```
   pm2 start server.js
   ```

9. Configure PM2 to start on boot:
   ```
   pm2 startup
   pm2 save
   ```

10. Set up a reverse proxy (optional but recommended):
    - Install Nginx: `sudo apt install -y nginx`
    - Configure Nginx to proxy requests to your Node.js app
    - Set up SSL with Let's Encrypt for HTTPS

### Monitoring and Maintenance

- Use PM2 to monitor your application: `pm2 monit`
- Set up log rotation: `pm2 install pm2-logrotate`
- Regularly update dependencies: `npm update`
- Back up your SQLite database regularly

## Troubleshooting

### Common Issues

1. **Database errors**:
   - Check file permissions for the SQLite database
   - Ensure the database path is correct in .env

2. **Authentication failures**:
   - Verify admin credentials in .env
   - Check JWT_SECRET consistency
   - Ensure token expiration hasn't occurred

3. **Server won't start**:
   - Check for port conflicts
   - Verify Node.js and npm versions
   - Check for syntax errors in code

### Getting Help

If you encounter issues not covered in this guide:
1. Check the error logs
2. Review the Express.js and SQLite documentation
3. Search for similar issues on Stack Overflow
4. Open an issue in the project repository