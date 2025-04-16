/**
 * Database Initialization Script
 * 
 * This script ensures that all default users exist in the database.
 * It can be run separately to reset users or before starting the application.
 */

const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');
const md5 = require('md5');

console.log('🔧 Running database initialization script...');

// Create database directory if it doesn't exist
const dbDir = path.join(__dirname, 'data');
if (!fs.existsSync(dbDir)) {
  fs.mkdirSync(dbDir, { recursive: true });
  console.log('✅ Created database directory:', dbDir);
}

// Initialize database connection
const dbPath = path.join(dbDir, 'darkvault.db');
console.log('📂 Database path:', dbPath);
const db = new sqlite3.Database(dbPath);

// Initialize tables
db.serialize(() => {
  console.log('🔄 Creating tables if they don\'t exist...');
  
  // Users table
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    email TEXT,
    role TEXT DEFAULT 'user',
    isAdmin INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )`);

  console.log('👤 Setting up default users...');

  // First, delete existing users with these usernames to avoid conflicts
  const usernamesToReset = ['admin', 'user1', 'manager', 'test'];
  
  db.run(`DELETE FROM users WHERE username IN ('${usernamesToReset.join("','")}')`, (err) => {
    if (err) {
      console.error('❌ Error deleting existing users:', err);
    } else {
      console.log('🗑️ Cleaned up existing default users');
      
      // Now create all default users
      const users = [
        {
          username: 'admin',
          password: md5('SecretPassword123!'),
          email: 'admin@darkvault.local',
          role: 'admin',
          isAdmin: 1
        },
        {
          username: 'user1',
          password: md5('Password123'),
          email: 'user1@darkvault.local',
          role: 'user',
          isAdmin: 0
        },
        {
          username: 'manager',
          password: md5('ManageIt!2023'),
          email: 'manager@darkvault.local',
          role: 'manager',
          isAdmin: 0
        },
        {
          username: 'test',
          password: md5('test123'),
          email: 'test@darkvault.local',
          role: 'user',
          isAdmin: 0
        }
      ];

      // Insert each user
      users.forEach(user => {
        db.run(
          "INSERT INTO users (username, password, email, role, isAdmin) VALUES (?, ?, ?, ?, ?)",
          [user.username, user.password, user.email, user.role, user.isAdmin],
          function(err) {
            if (err) {
              console.error(`❌ Error creating ${user.username}:`, err);
            } else {
              console.log(`✅ Created user ${user.username} with password ${user.username === 'admin' ? 'SecretPassword123!' : user.username === 'user1' ? 'Password123' : user.username === 'manager' ? 'ManageIt!2023' : 'test123'}`);
            }
          }
        );
      });
    }
  });
});

// Close the database connection after a delay to ensure all operations complete
setTimeout(() => {
  db.close((err) => {
    if (err) {
      console.error('❌ Error closing database:', err);
    } else {
      console.log('✅ Database initialization complete and connection closed');
    }
  });
}, 2000); 