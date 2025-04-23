# Authentication Server

A secure authentication server built with Node.js and Express.js, designed for easy deployment on a VPS.

## Features

- **User Authentication**: Secure JWT-based authentication system
- **Role-Based Access Control**: Admin and user roles with appropriate permissions
- **API Security**:
  - Rate limiting to prevent brute force attacks
  - Input validation for all endpoints
  - Password hashing with bcrypt
  - JWT token authentication
  - CORS protection
- **Error Handling**: Centralized error handling with detailed error messages
- **Logging**: Comprehensive logging system for debugging and monitoring
- **Database**: SQLite database for data persistence
- **VPS Deployment**: Easy deployment on a VPS with provided scripts

## Project Structure

```
jjguibotauthserver/
├── .env                  # Environment configuration
├── server.js             # Server startup file
├── package.json          # Project metadata and dependencies
├── auth.db               # SQLite database (created on first run)
├── public/               # Frontend files
│   ├── css/              # Stylesheets
│   ├── js/               # Frontend JavaScript
│   ├── index.html        # Login page
│   └── admin.html        # Admin dashboard
├── scripts/              # Utility scripts
│   └── setup-vps.sh      # VPS setup script
└── src/                  # Application source code
    ├── app.js            # Main application setup
    ├── config/           # Configuration files
    │   ├── database.js   # Database configuration
    │   └── env.js        # Environment configuration
    ├── controllers/      # Request handlers
    │   ├── authController.js  # Authentication controller
    │   └── userController.js  # User management controller
    ├── middleware/       # Express middleware
    │   ├── auth.js       # Authentication middleware
    │   ├── errorHandler.js  # Error handling middleware
    │   ├── rateLimiter.js   # Rate limiting middleware
    │   └── validator.js     # Input validation middleware
    ├── models/           # Data models
    │   └── user.js       # User model
    ├── routes/           # API routes
    │   ├── authRoutes.js # Authentication routes
    │   └── userRoutes.js # User management routes
    └── utils/            # Utility functions
        └── logger.js     # Logging utility
```

## API Endpoints

### Authentication Endpoints

#### User Login
- **URL**: `/api/auth/login`
- **Method**: `POST`
- **Body**:
  ```json
  {
    "username": "user",
    "password": "password123"
  }
  ```
- **Success Response**: `200 OK`
  ```json
  {
    "token": "jwt_token_here",
    "user": {
      "id": 1,
      "username": "user",
      "role": "user"
    }
  }
  ```

#### Admin Login
- **URL**: `/api/auth/admin/login`
- **Method**: `POST`
- **Body**:
  ```json
  {
    "username": "admin",
    "password": "admin_password"
  }
  ```
- **Success Response**: `200 OK`
  ```json
  {
    "token": "jwt_token_here",
    "user": {
      "username": "admin",
      "role": "admin"
    }
  }
  ```

### User Management Endpoints

#### Get Current User
- **URL**: `/api/users/profile`
- **Method**: `GET`
- **Headers**: `Authorization: Bearer <token>`
- **Success Response**: `200 OK`
  ```json
  {
    "id": 1,
    "username": "user",
    "role": "user",
    "created_at": "2023-01-01T00:00:00.000Z"
  }
  ```

#### Get All Users (Admin only)
- **URL**: `/api/users`
- **Method**: `GET`
- **Headers**: `Authorization: Bearer <admin_token>`
- **Success Response**: `200 OK`
  ```json
  [
    {
      "id": 1,
      "username": "user1",
      "role": "user",
      "created_at": "2023-01-01T00:00:00.000Z"
    },
    {
      "id": 2,
      "username": "user2",
      "role": "user",
      "created_at": "2023-01-02T00:00:00.000Z"
    }
  ]
  ```

#### Create User (Admin only)
- **URL**: `/api/users`
- **Method**: `POST`
- **Headers**: `Authorization: Bearer <admin_token>`
- **Body**:
  ```json
  {
    "username": "newuser",
    "password": "Password123",
    "role": "user"
  }
  ```
- **Success Response**: `201 Created`
  ```json
  {
    "message": "User created successfully",
    "user": {
      "id": 3,
      "username": "newuser",
      "role": "user",
      "created_at": "2023-01-03T00:00:00.000Z"
    }
  }
  ```

#### Delete User (Admin only)
- **URL**: `/api/users/:id`
- **Method**: `DELETE`
- **Headers**: `Authorization: Bearer <admin_token>`
- **Success Response**: `200 OK`
  ```json
  {
    "message": "User deleted successfully"
  }
  ```

## Setup Instructions

### Prerequisites

- Node.js (v14 or higher)
- npm (v6 or higher)

### Local Development Setup

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd jjguibotauthserver
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Create a `.env` file in the root directory with the following variables:
   ```
   # Server settings
   PORT=3000
   NODE_ENV=development

   # Security
   JWT_SECRET=your_super_secure_jwt_secret_key
   JWT_EXPIRATION=1h
   BCRYPT_SALT_ROUNDS=10

   # Admin credentials
   ADMIN_USERNAME=admin
   ADMIN_PASSWORD=your_secure_admin_password

   # Database
   DB_PATH=auth.db

   # Logging
   LOG_LEVEL=DEBUG

   # Rate limiting
   RATE_LIMIT_WINDOW_MS=900000
   RATE_LIMIT_MAX_REQUESTS=100
   ```

   **Important:** Change the default admin credentials and JWT secret in production!

4. Start the development server:
   ```bash
   npm run dev
   ```

5. Access the application:
   - Main login page: http://localhost:3000
   - Admin dashboard (after login): http://localhost:3000/admin.html
   - API endpoints: http://localhost:3000/api

## VPS Deployment

### Automatic Setup

1. Upload the project to your VPS or clone it from the repository.

2. Make the setup script executable:
   ```bash
   chmod +x scripts/setup-vps.sh
   ```

3. Run the setup script as root:
   ```bash
   sudo ./scripts/setup-vps.sh
   ```

4. Follow the prompts to configure your domain and other settings.

5. Deploy your application to the specified directory (default: `/opt/authserver`).

6. Create a production `.env` file with secure settings:
   ```bash
   nano /opt/authserver/.env
   ```

   Add the following with your secure values:
   ```
   # Server settings
   PORT=3000
   NODE_ENV=production

   # Security
   JWT_SECRET=your_very_secure_random_string
   JWT_EXPIRATION=1h
   BCRYPT_SALT_ROUNDS=12

   # Admin credentials
   ADMIN_USERNAME=your_admin_username
   ADMIN_PASSWORD=your_secure_admin_password

   # Database
   DB_PATH=auth.db

   # Logging
   LOG_LEVEL=INFO

   # Rate limiting
   RATE_LIMIT_WINDOW_MS=900000
   RATE_LIMIT_MAX_REQUESTS=50
   ```

7. Start the service:
   ```bash
   sudo systemctl start authserver
   sudo systemctl enable authserver
   ```

### Manual Setup

If you prefer to set up your VPS manually, follow these steps:

1. Install Node.js, npm, and other dependencies:
   ```bash
   sudo apt update
   sudo apt install -y nodejs npm nginx
   ```

2. Install PM2 globally:
   ```bash
   sudo npm install -g pm2
   ```

3. Set up Nginx as a reverse proxy:
   - Create a new site configuration in `/etc/nginx/sites-available/`
   - Configure it to proxy requests to your Node.js application
   - Enable the site and reload Nginx

4. Set up SSL with Let's Encrypt (recommended):
   ```bash
   sudo apt install -y certbot python3-certbot-nginx
   sudo certbot --nginx -d yourdomain.com
   ```

5. Create a systemd service for your application.

6. Deploy your application and start the service.

## Security Considerations

- **Change default credentials**: Always change the admin username and password in production
- **Use a strong JWT secret**: Generate a random string for your JWT secret
- **Set appropriate token expiration**: Adjust JWT_EXPIRATION based on your security requirements
- **Enable HTTPS**: Always use HTTPS in production to protect data in transit
- **Regular updates**: Keep dependencies updated to patch security vulnerabilities
- **Database backups**: Regularly back up your SQLite database
- **Firewall configuration**: Restrict access to your server using a firewall
- **Monitoring**: Set up monitoring for your application to detect unusual activity

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

## License

ISC
