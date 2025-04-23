#!/bin/bash
# VPS Setup Script for Authentication Server
# This script helps set up the authentication server on a Linux VPS

# Exit on error
set -e

echo "=========================================="
echo "Authentication Server VPS Setup"
echo "=========================================="

# Check if running as root
if [ "$(id -u)" != "0" ]; then
   echo "This script must be run as root" 1>&2
   exit 1
fi

# Update system packages
echo "Updating system packages..."
apt update
apt upgrade -y

# Install required dependencies
echo "Installing dependencies..."
apt install -y nodejs npm nginx certbot python3-certbot-nginx ufw

# Check Node.js version
NODE_VERSION=$(node -v)
echo "Node.js version: $NODE_VERSION"

# Install PM2 globally
echo "Installing PM2 process manager..."
npm install -g pm2

# Create app directory if it doesn't exist
APP_DIR="/opt/authserver"
if [ ! -d "$APP_DIR" ]; then
    echo "Creating application directory..."
    mkdir -p $APP_DIR
fi

# Ask for domain name
read -p "Enter your domain name (e.g., auth.example.com): " DOMAIN_NAME

# Configure Nginx
echo "Setting up Nginx reverse proxy..."
cat > /etc/nginx/sites-available/$DOMAIN_NAME <<EOF
server {
    listen 80;
    server_name $DOMAIN_NAME;

    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_cache_bypass \$http_upgrade;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF

# Enable the site
ln -sf /etc/nginx/sites-available/$DOMAIN_NAME /etc/nginx/sites-enabled/

# Test Nginx configuration
nginx -t

# Reload Nginx
systemctl reload nginx

# Set up SSL with Let's Encrypt
echo "Setting up SSL with Let's Encrypt..."
certbot --nginx -d $DOMAIN_NAME --non-interactive --agree-tos --email admin@$DOMAIN_NAME

# Configure firewall
echo "Configuring firewall..."
ufw allow 'Nginx Full'
ufw allow OpenSSH
ufw --force enable

# Create a systemd service file for the application
echo "Creating systemd service..."
cat > /etc/systemd/system/authserver.service <<EOF
[Unit]
Description=Authentication Server
After=network.target

[Service]
Type=forking
User=www-data
WorkingDirectory=$APP_DIR
ExecStart=/usr/local/bin/pm2 start server.js --name authserver
ExecReload=/usr/local/bin/pm2 reload authserver
ExecStop=/usr/local/bin/pm2 stop authserver
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd
systemctl daemon-reload

# Set proper permissions
echo "Setting permissions..."
chown -R www-data:www-data $APP_DIR
chmod -R 755 $APP_DIR

# Instructions for deploying the application
echo "=========================================="
echo "VPS setup completed!"
echo "=========================================="
echo "Next steps:"
echo "1. Deploy your application to $APP_DIR"
echo "2. Create a .env file in $APP_DIR with your production settings"
echo "3. Start the service: systemctl start authserver"
echo "4. Enable the service to start on boot: systemctl enable authserver"
echo ""
echo "Your application will be available at: https://$DOMAIN_NAME"
echo "=========================================="