const express = require('express');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const path = require('path');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const jwt = require('jsonwebtoken');
const multer = require('multer');
const fs = require('fs');
const { exec } = require('child_process');

// Insecure JWT secret
const JWT_SECRET = 'darkvault-super-secret-key';

// Create the app
const app = express();
const PORT = process.env.PORT || 3000;

// Vulnerable CORS configuration - allows any origin
app.use(cors({
  origin: '*',
  credentials: true
}));

// Insecure cookie settings
app.use(cookieParser());
app.use(session({
  secret: 'session-secret-key',
  resave: true,
  saveUninitialized: true,
  cookie: {
    httpOnly: false,
    secure: false // Not using HTTPS
  }
}));

// Bodyparser setup with high limit
app.use(bodyParser.json({ limit: '50mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '50mb' }));

// Serve static files
app.use(express.static(path.join(__dirname, 'public')));

// Vulnerable file upload configuration
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'uploads/');
  },
  filename: function (req, file, cb) {
    // No validation on filename - vulnerable to path traversal
    cb(null, file.originalname);
  }
});
const upload = multer({ storage: storage });

// Create uploads directory if it doesn't exist
if (!fs.existsSync('uploads')) {
  fs.mkdirSync('uploads');
}

// Setup Database
const db = new sqlite3.Database('./bank.db', (err) => {
  if (err) {
    console.error(err.message);
  }
  console.log('Connected to the SQLite database.');
});

// Create tables with initial data
db.serialize(() => {
  // Users table
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT,
    email TEXT,
    role TEXT DEFAULT 'user',
    balance REAL DEFAULT 1000.00
  )`);

  // Transactions table
  db.run(`CREATE TABLE IF NOT EXISTS transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id INTEGER,
    receiver_id INTEGER,
    amount REAL,
    date TEXT,
    note TEXT
  )`);

  // Admin messages table
  db.run(`CREATE TABLE IF NOT EXISTS admin_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    message TEXT,
    date TEXT
  )`);

  // Insert admin and test users if they don't exist
  db.get("SELECT * FROM users WHERE username = 'admin'", (err, row) => {
    if (!row) {
      // Plaintext password storage
      db.run("INSERT INTO users (username, password, email, role, balance) VALUES ('admin', 'admin123', 'admin@darkvault.com', 'admin', 100000.00)");
      db.run("INSERT INTO users (username, password, email, role) VALUES ('alice', 'password123', 'alice@example.com', 'user')");
      db.run("INSERT INTO users (username, password, email, role) VALUES ('bob', 'bobpassword', 'bob@example.com', 'user')");
      console.log("Added default users");
    }
  });
});

// Middleware to log requests - information disclosure
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} [${req.method}] ${req.url} - Body:`, req.body);
  next();
});

// --- Vulnerable Endpoints ---

// Insecure login - SQL Injection
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  
  // Vulnerable SQL query - no parameterization
  const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
  
  db.get(query, (err, user) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    
    if (user) {
      // Create JWT token with excessive privileges data
      const token = jwt.sign(
        { id: user.id, username: user.username, role: user.role },
        JWT_SECRET,
        { expiresIn: '24h' }
      );
      
      // Set token in cookie
      res.cookie('token', token, { httpOnly: false });
      
      return res.status(200).json({
        success: true,
        message: 'Login successful',
        user: {
          id: user.id,
          username: user.username,
          email: user.email,
          role: user.role,
          balance: user.balance
        },
        token
      });
    } else {
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials'
      });
    }
  });
});

// Register endpoint with no validation
app.post('/api/register', (req, res) => {
  const { username, password, email } = req.body;
  
  // No validation on inputs
  const query = `INSERT INTO users (username, password, email) VALUES ('${username}', '${password}', '${email}')`;
  
  db.run(query, function(err) {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    
    return res.status(201).json({
      success: true,
      message: 'User registered successfully',
      userId: this.lastID
    });
  });
});

// Middleware for token verification - with bypass
const verifyToken = (req, res, next) => {
  const token = req.cookies.token || req.headers['authorization'];
  
  if (!token) {
    // Vulnerable bypass - allows debug mode
    if (req.query.debug === 'true') {
      req.user = { id: 1, username: 'admin', role: 'admin' };
      return next();
    }
    return res.status(401).json({ message: 'No token provided' });
  }
  
  try {
    const decoded = jwt.verify(token.replace('Bearer ', ''), JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ message: 'Invalid token' });
  }
};

// Get user profile - Information disclosure
app.get('/api/users/:id', verifyToken, (req, res) => {
  const id = req.params.id;
  
  // No authorization check - any authenticated user can access any profile
  db.get(`SELECT * FROM users WHERE id = ${id}`, (err, user) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    // Returns all user data including sensitive information
    return res.status(200).json(user);
  });
});

// Transfer money - CSRF vulnerable, no origin check
app.post('/api/transfer', verifyToken, (req, res) => {
  const { to, amount, note } = req.body;
  const fromId = req.user.id;
  
  // Vulnerable to XSS in the note field (will be displayed to receiver)
  
  // Vulnerable SQL that doesn't check balance
  const transferQuery = `
    INSERT INTO transactions (sender_id, receiver_id, amount, date, note) 
    VALUES (${fromId}, ${to}, ${amount}, '${new Date().toISOString()}', '${note}')
  `;
  
  // Update balances
  const updateSenderQuery = `UPDATE users SET balance = balance - ${amount} WHERE id = ${fromId}`;
  const updateReceiverQuery = `UPDATE users SET balance = balance + ${amount} WHERE id = ${to}`;
  
  db.run(transferQuery, function(err) {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    
    db.run(updateSenderQuery, function(err) {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      
      db.run(updateReceiverQuery, function(err) {
        if (err) {
          return res.status(500).json({ error: err.message });
        }
        
        return res.status(200).json({
          success: true,
          message: 'Transfer successful',
          transactionId: this.lastID
        });
      });
    });
  });
});

// Admin feature - Vulnerable to command injection
app.post('/api/admin/run-report', verifyToken, (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Unauthorized' });
  }
  
  const { report_name } = req.body;
  
  // Vulnerable to command injection
  exec(`node scripts/reports/${report_name}.js`, (error, stdout, stderr) => {
    if (error) {
      return res.status(500).json({ error: error.message });
    }
    
    return res.status(200).json({
      success: true,
      output: stdout
    });
  });
});

// File upload endpoint - vulnerable to unrestricted file upload
app.post('/api/upload', verifyToken, upload.single('file'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ message: 'No file uploaded' });
  }
  
  // Return path with no sanitization
  return res.status(200).json({
    success: true,
    file_path: '/uploads/' + req.file.originalname
  });
});

// Search for users - XSS vulnerable
app.get('/api/search', verifyToken, (req, res) => {
  const { term } = req.query;
  
  // Vulnerable SQL query
  const query = `SELECT id, username, email FROM users WHERE username LIKE '%${term}%' OR email LIKE '%${term}%'`;
  
  db.all(query, (err, users) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    
    return res.status(200).json(users);
  });
});

// Admin message endpoint - IDOR vulnerable
app.post('/api/messages', verifyToken, (req, res) => {
  const { user_id, message } = req.body;
  
  // No validation if the authenticated user owns the message
  const query = `
    INSERT INTO admin_messages (user_id, message, date) 
    VALUES (${user_id}, '${message}', '${new Date().toISOString()}')
  `;
  
  db.run(query, function(err) {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    
    return res.status(201).json({
      success: true,
      message: 'Message sent to admin',
      messageId: this.lastID
    });
  });
});

// Route to export all user data - Information disclosure
app.get('/api/admin/export-users', verifyToken, (req, res) => {
  // Broken access control - no proper role check
  if (req.query.isAdmin === 'true') {
    db.all(`SELECT * FROM users`, (err, users) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      
      return res.status(200).json(users);
    });
  } else {
    return res.status(403).json({ message: 'Unauthorized' });
  }
});

// Start the server
app.listen(PORT, () => {
  console.log(`DarkVault app running on port ${PORT}`);
  console.log(`WARNING: This application contains intentional security vulnerabilities!`);
  console.log(`It is intended for educational purposes only.`);
}); 