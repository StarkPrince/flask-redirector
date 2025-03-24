#!/bin/bash

# Create necessary directories
mkdir -p logs

# Load environment variables
source .env

# Check if required environment variables are set
if [ -z "$ADMIN_USERNAME" ] || [ -z "$ADMIN_PASSWORD" ]; then
    echo "Error: ADMIN_USERNAME and ADMIN_PASSWORD must be set in .env file"
    exit 1
fi

# Initialize database and create admin user
echo "Setting up database and admin user..."
python setup.py

# Start Gunicorn
echo "Starting Gunicorn server..."
gunicorn -c gunicorn.conf.py app:app 