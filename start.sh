#!/bin/bash
echo "Starting DarkVault application..."
echo "WARNING: This application contains deliberate security vulnerabilities!"
echo "         Use only for educational purposes."
echo ""

# Check if Node.js is installed
if ! command -v node &> /dev/null; then
    echo "Error: Node.js is not installed. Please install Node.js to run this application."
    exit 1
fi

# Create necessary directories
mkdir -p data assets uploads

# Install dependencies if node_modules doesn't exist
if [ ! -d "node_modules" ]; then
    echo "Installing dependencies..."
    npm install
fi

# Initialize the database and create default users
echo "Initializing database and creating default users..."
node init-db.js

# Start the application
echo "Starting the application..."
npm start 