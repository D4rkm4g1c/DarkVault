#!/bin/bash

# Initialize the database if needed
echo "Initializing database (if needed)..."
node init-db.js

# Start the API server
echo "Starting DarkVault Local API Server..."
node local-api-server.js 