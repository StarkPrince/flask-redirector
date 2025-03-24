#!/bin/bash

# Create necessary directories
mkdir -p logs

# Install dependencies
echo "Installing dependencies..."
pip3 install -r requirements.txt

# Initialize database and create admin user
echo "Setting up database and admin user..."
python3 setup.py

# Set default port if PORT environment variable is not set
PORT=${PORT:-8000}

# Start Gunicorn
echo "Starting Gunicorn server on port $PORT..."
python3 -m gunicorn --bind 0.0.0.0:$PORT --workers 4 --timeout 120 app:app 