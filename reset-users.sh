#!/bin/bash

echo "Resetting DarkVault database..."

# Remove the database file
rm -f bank.db

# Start the application to recreate the database with default users
node server.js &
SERVER_PID=$!

# Wait for server to start
sleep 3

# Kill the server
kill $SERVER_PID

echo "Database reset complete. Default users have been recreated."
echo "- Admin: username 'admin', password 'admin123'"
echo "- User: username 'alice', password 'password123'"
