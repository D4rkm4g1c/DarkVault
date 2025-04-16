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

  // Product filters table
  db.run(`CREATE TABLE IF NOT EXISTS product_filters (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    filter_name TEXT,
    filter_query TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);

  // Insert default admin user if it doesn't exist
  db.get("SELECT * FROM users WHERE username = 'admin'", (err, row) => {
    if (!row) {
      db.run("INSERT INTO users (username, password, email, role, isAdmin) VALUES (?, ?, ?, ?, ?)", 
        ['admin', '5f4dcc3b5aa765d61d8327deb882cf99', 'admin@darkvault.local', 'admin', 1]);
      console.log('Default admin user created with password: SecretPassword123!');
    }
  });

  // Insert default user1 if it doesn't exist
  db.get("SELECT * FROM users WHERE username = 'user1'", (err, row) => {
    if (!row) {
      db.run("INSERT INTO users (username, password, email, role, isAdmin) VALUES (?, ?, ?, ?, ?)", 
        ['user1', '482c811da5d5b4bc6d497ffa98491e38', 'user1@darkvault.local', 'user', 0]);
      console.log('Default user1 created with password: Password123');
    }
  });

  // Insert manager user if it doesn't exist
  db.get("SELECT * FROM users WHERE username = 'manager'", (err, row) => {
    if (!row) {
      db.run("INSERT INTO users (username, password, email, role, isAdmin) VALUES (?, ?, ?, ?, ?)", 
        ['manager', 'e1f72e3f0be347798eff44e298a31368', 'manager@darkvault.local', 'manager', 0]);
      console.log('Default manager user created with password: ManageIt!2023');
    }
  });

  // Insert test user if it doesn't exist
  db.get("SELECT * FROM users WHERE username = 'test'", (err, row) => {
    if (!row) {
      db.run("INSERT INTO users (username, password, email, role, isAdmin) VALUES (?, ?, ?, ?, ?)", 
        ['test', 'cc03e747a6afbbcbf8be7668acfebee5', 'test@darkvault.local', 'user', 0]);
      console.log('Default test user created with password: test123');
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

// Helper database functions

// Find user by credentials - vulnerable to SQL injection but with basic protection
db.findUserByCredentials = function(username, password, callback) {
  // Basic protection against simple SQL injection
  if (username.toLowerCase().includes(' or ') || 
      username.includes('--') || 
      username.includes('1=1') || 
      password.toLowerCase().includes(' or ') || 
      password.includes('--') || 
      password.includes('1=1')) {
    console.log('Basic SQL injection attempt blocked:', username, password);
    return callback(null, null); // Return no user found
  }
  
  // Still vulnerable to more sophisticated SQL injection
  const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
  this.get(query, callback);
};

// Find user by username
db.findUserByUsername = function(username, callback) {
  this.get("SELECT * FROM users WHERE username = ?", [username], callback);
};

// Create a new user
db.createUser = function(username, password, email, callback) {
  this.run("INSERT INTO users (username, password, email) VALUES (?, ?, ?)", 
    [username, password, email], callback);
};

// Get todos by user ID
db.getTodosByUserId = function(userId, callback) {
  this.all("SELECT * FROM todos WHERE user_id = ? ORDER BY created_at DESC", [userId], callback);
};

// Create a new todo
db.createTodo = function(userId, title, callback) {
  this.run("INSERT INTO todos (user_id, title) VALUES (?, ?)", [userId, title], callback);
};

// Get todo by ID
db.getTodoById = function(todoId, callback) {
  this.get("SELECT * FROM todos WHERE id = ?", [todoId], callback);
};

// Delete todo
db.deleteTodo = function(todoId, callback) {
  this.run("DELETE FROM todos WHERE id = ?", [todoId], callback);
};

// Get all messages
db.getAllMessages = function(callback) {
  this.all("SELECT m.*, u.username FROM messages m LEFT JOIN users u ON m.user_id = u.id ORDER BY m.created_at DESC", callback);
};

// Create a new message
db.createMessage = function(userId, content, callback) {
  this.run("INSERT INTO messages (user_id, content) VALUES (?, ?)", [userId, content], callback);
};

// Delete message
db.deleteMessage = function(messageId, callback) {
  this.run("DELETE FROM messages WHERE id = ?", [messageId], callback);
};

// Get all users
db.getAllUsers = function(callback) {
  this.all("SELECT id, username, email, role, isAdmin, created_at FROM users", callback);
};

// Export the database connection
module.exports = db; 