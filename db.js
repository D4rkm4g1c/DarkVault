const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');

// Create database directory if it doesn't exist
const dbDir = path.join(__dirname, 'data');
if (!fs.existsSync(dbDir)) {
  fs.mkdirSync(dbDir);
}

// Initialize database connection
const db = new sqlite3.Database(path.join(dbDir, 'darkvault.db'));

// Initialize tables
db.serialize(() => {
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

  // Todos table
  db.run(`CREATE TABLE IF NOT EXISTS todos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    completed BOOLEAN DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id)
  )`);

  // Messages table
  db.run(`CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    content TEXT NOT NULL,
    title TEXT,
    author TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id)
  )`);

  // Products table
  db.run(`CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    description TEXT,
    price REAL,
    category TEXT
  )`);

  // User preferences table
  db.run(`CREATE TABLE IF NOT EXISTS user_preferences (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    display_name TEXT,
    bio TEXT,
    avatar TEXT,
    theme TEXT DEFAULT 'dark',
    favorite_category TEXT,
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);

  // Files table
  db.run(`CREATE TABLE IF NOT EXISTS files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT,
    path TEXT,
    uploaded_by INTEGER,
    upload_date DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(uploaded_by) REFERENCES users(id)
  )`);

  // Logs table
  db.run(`CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    action TEXT,
    ip_address TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);

  // Insert default admin user if it doesn't exist
  db.get("SELECT * FROM users WHERE username = 'admin'", (err, row) => {
    if (!row) {
      db.run("INSERT INTO users (username, password, email, role, isAdmin) VALUES (?, ?, ?, ?, ?)", 
        ['admin', 'admin123', 'admin@darkvault.local', 'admin', 1]);
      console.log('Default admin user created');
    }
  });

  // Insert default user if it doesn't exist
  db.get("SELECT * FROM users WHERE username = 'user'", (err, row) => {
    if (!row) {
      db.run("INSERT INTO users (username, password, email, role, isAdmin) VALUES (?, ?, ?, ?, ?)", 
        ['user', 'password123', 'user@darkvault.local', 'user', 0]);
      console.log('Default regular user created');
    }
  });

  // Insert sample products if the products table is empty
  db.get("SELECT COUNT(*) as count FROM products", (err, row) => {
    if (!err && row && row.count === 0) {
      db.run("INSERT INTO products (name, description, price, category) VALUES (?, ?, ?, ?)",
        ['Laptop', 'High-end laptop', 1299.99, 'Electronics']);
      db.run("INSERT INTO products (name, description, price, category) VALUES (?, ?, ?, ?)",
        ['Smartphone', 'Latest model', 899.99, 'Electronics']);
      db.run("INSERT INTO products (name, description, price, category) VALUES (?, ?, ?, ?)",
        ['Headphones', 'Noise cancelling', 199.99, 'Electronics']);
      console.log('Sample products created');
    }
  });
});

// Export the database connection
module.exports = db; 