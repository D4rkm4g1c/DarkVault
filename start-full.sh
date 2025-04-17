#!/bin/bash
echo "Starting DarkVault Full Environment..."
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

# Start the API server in the background
echo "Starting the API server..."
node local-api-server.js > api-server.log 2>&1 &
API_PID=$!
echo "API server started with PID $API_PID"
echo "API logs will be written to api-server.log"

# Give the API server a moment to start
sleep 2

# Start the web application
echo "Starting the web application..."
node app.js

# When the web application stops, kill the API server
echo "Stopping the API server (PID $API_PID)..."
kill $API_PID 