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

// Create logs directory if it doesn't exist
if (!fs.existsSync('logs')) {
  fs.mkdirSync('logs');
}

// Error logging function
function logError(location, error, data = {}) {
  const timestamp = new Date().toISOString();
  const logEntry = `${timestamp} - ${location} - ${error.message}\nData: ${JSON.stringify(data)}\nStack: ${error.stack}\n\n`;
  
  fs.appendFile('logs/error.log', logEntry, (err) => {
    if (err) console.error('Failed to write to log file:', err);
  });
  
  console.error(`${timestamp} - ${location} - ${error.message}`);
}

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
    console.error('Database connection error:', err.message);
    process.exit(1); // Exit if we can't connect to the database
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
      db.run(`INSERT INTO users (username, password, email, role, balance) VALUES ("admin", "admin123", "admin@darkvault.com", "admin", 100000.00)`);
      db.run(`INSERT INTO users (username, password, email, role) VALUES ("alice", "password123", "alice@example.com", "user")`);
      db.run(`INSERT INTO users (username, password, email, role) VALUES ("bob", "bobpassword", "bob@example.com", "user")`);
      console.log("Added default users");
      
      // Add some sample messages
      const now = new Date().toISOString();
      db.run(`INSERT INTO admin_messages (user_id, message, date) VALUES (2, "Hello admin, I can't access my account. Please help!", "${now}")`);
      db.run(`INSERT INTO admin_messages (user_id, message, date) VALUES (3, "<script>alert('XSS in admin message')</script>", "${now}")`);
      db.run(`INSERT INTO admin_messages (user_id, message, date) VALUES (2, "Is there a way to increase my transfer limit?", "${now}")`);
      console.log("Added sample messages");
      
      // Add some sample transactions
      const yesterday = new Date(Date.now() - 86400000).toISOString();
      const twoDaysAgo = new Date(Date.now() - 172800000).toISOString();
      db.run(`INSERT INTO transactions (sender_id, receiver_id, amount, date, note) VALUES (2, 3, 150.00, "${yesterday}", "Dinner payment")`);
      db.run(`INSERT INTO transactions (sender_id, receiver_id, amount, date, note) VALUES (3, 2, 250.00, "${twoDaysAgo}", "Concert tickets")`);
      db.run(`INSERT INTO transactions (sender_id, receiver_id, amount, date, note) VALUES (1, 2, 1000.00, "${now}", "Welcome bonus! <script>alert('XSS in transaction')</script>")`);
      console.log("Added sample transactions");
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
  // Using double quotes for string literals to avoid issues with apostrophes
  // Example exploit: username = "admin" --" will bypass password check
  const query = `SELECT * FROM users WHERE username = "${username}" AND password = "${password}"`;
  
  db.get(query, (err, user) => {
    if (err) {
      console.error('Login error:', err.message);
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
  
  // Log registration attempt
  console.log(`Registration attempt: username=${username}, email=${email}`);
  
  // Double quotes instead of single quotes to avoid SQL errors with apostrophes
  // Still vulnerable to SQL injection but will work for most inputs
  const query = `INSERT INTO users (username, password, email) VALUES ("${username}", "${password}", "${email}")`;
  
  console.log('Executing SQL query:', query);
  
  db.run(query, function(err) {
    if (err) {
      // Log the detailed error
      console.error('Registration error:', err.message);
      logError('Registration', err, { username, email, query });
      return res.status(500).json({ error: err.message });
    }
    
    console.log(`User registered successfully: username=${username}, userId=${this.lastID}`);
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
  // Using double quotes for string literals to avoid issues with apostrophes
  // XSS payload example: <img src=x onerror="alert('XSS in transfer')">
  
  const transferQuery = `
    INSERT INTO transactions (sender_id, receiver_id, amount, date, note) 
    VALUES (${fromId}, ${to}, ${amount}, "${new Date().toISOString()}", "${note}")
  `;
  
  // Update balances
  const updateSenderQuery = `UPDATE users SET balance = balance - ${amount} WHERE id = ${fromId}`;
  const updateReceiverQuery = `UPDATE users SET balance = balance + ${amount} WHERE id = ${to}`;
  
  db.run(transferQuery, function(err) {
    if (err) {
      console.error('Transfer error:', err.message);
      return res.status(500).json({ error: err.message });
    }
    
    db.run(updateSenderQuery, function(err) {
      if (err) {
        console.error('Update sender balance error:', err.message);
        return res.status(500).json({ error: err.message });
      }
      
      db.run(updateReceiverQuery, function(err) {
        if (err) {
          console.error('Update receiver balance error:', err.message);
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
  // Example payloads:
  // Linux: "fake; cat /etc/passwd"
  // Windows: "fake & whoami"
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
  
  console.log('Search term:', term);
  
  // Vulnerable SQL query - extremely vulnerable to SQL injection
  // Example exploit: " OR 1=1 --
  // Example exploit: " UNION SELECT id, username, password FROM users --
  const query = `SELECT id, username, email FROM users WHERE username LIKE "%${term}%" OR email LIKE "%${term}%"`;
  
  console.log('Executing search query:', query);
  
  db.all(query, (err, users) => {
    if (err) {
      console.error('Search error:', err.message);
      return res.status(500).json({ error: err.message });
    }
    
    console.log('Search results:', users.length);
    return res.status(200).json(users);
  });
});

// Admin message endpoint - IDOR vulnerable
app.post('/api/messages', verifyToken, (req, res) => {
  const { user_id, message } = req.body;
  
  // No validation if the authenticated user owns the message
  // Using double quotes for string literals to avoid issues with apostrophes
  // XSS payload example: <script>alert("Admin hacked!");</script>
  const query = `
    INSERT INTO admin_messages (user_id, message, date) 
    VALUES (${user_id}, "${message}", "${new Date().toISOString()}")
  `;
  
  db.run(query, function(err) {
    if (err) {
      console.error('Message error:', err.message);
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

// Fetch admin messages - Added endpoint
app.get('/api/admin/messages', verifyToken, (req, res) => {
  // Weak role check that can be bypassed
  if (req.user.role !== 'admin' && req.query.isAdmin !== 'true') {
    return res.status(403).json({ message: 'Unauthorized' });
  }
  
  // Get all messages with user information
  db.all(`
    SELECT m.*, u.username 
    FROM admin_messages m
    LEFT JOIN users u ON m.user_id = u.id
    ORDER BY m.date DESC
  `, (err, messages) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    
    return res.status(200).json(messages);
  });
});

// Get transaction history - Missing endpoint
app.get('/api/transactions', verifyToken, (req, res) => {
  const user_id = req.query.user_id;
  
  if (!user_id) {
    return res.status(400).json({ message: 'User ID is required' });
  }
  
  // Vulnerable SQL - no check if the user_id matches the authenticated user
  // Allows any authenticated user to see any other user's transactions
  // Example exploit: 2 OR 1=1 -- returns all transactions
  const query = `
    SELECT * FROM transactions 
    WHERE sender_id = ${user_id} OR receiver_id = ${user_id}
    ORDER BY date DESC
  `;
  
  db.all(query, (err, transactions) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    
    return res.status(200).json(transactions);
  });
});

// Add a debug endpoint to list users (deliberately insecure)
app.get('/api/debug/users', (req, res) => {
  console.log('Debug endpoint called to check users table');
  db.all('SELECT id, username, password, email, role FROM users', (err, rows) => {
    if (err) {
      console.error('Debug endpoint error:', err);
      return res.status(500).json({ error: err.message });
    }
    return res.status(200).json({ users: rows });
  });
});

// Add a simple health check endpoint
app.get('/api/health', (req, res) => {
  res.status(200).json({ status: 'up', time: new Date().toISOString() });
});

// Add error handling middleware at the end of the file, before app.listen
// Error handling middleware
app.use((err, req, res, next) => {
  logError('Global Error Handler', err, { 
    path: req.path, 
    method: req.method, 
    body: req.body, 
    query: req.query 
  });
  
  res.status(500).json({ error: 'An internal server error occurred' });
});

// Simulate an admin bot that automatically checks messages - vulnerable to XSS
function setupAdminBot() {
  console.log('Setting up vulnerable admin bot that checks messages every 5 minutes');
  
  // This is intentionally vulnerable!
  // The admin bot "runs" JavaScript in messages by executing them in a simulated browser environment
  function simulateAdminViewingMessages() {
    console.log('Secret admin bot is checking messages...');
    
    // Generate admin JWT token
    const adminToken = jwt.sign(
      { id: 1, username: 'admin', role: 'admin' },
      JWT_SECRET,
      { expiresIn: '1h' }
    );
    
    // Log admin token (in a real app, this would be a secret)
    console.log('Admin bot using token:', adminToken);
    
    // Fetch all messages
    db.all(`
      SELECT m.*, u.username 
      FROM admin_messages m
      LEFT JOIN users u ON m.user_id = u.id
      ORDER BY m.date DESC
    `, (err, messages) => {
      if (err) {
        console.error('Admin bot error:', err.message);
        return;
      }
      
      console.log(`Admin bot found ${messages.length} messages to review`);
      
      // "Process" each message - in a real browser, this would execute any JavaScript
      messages.forEach(msg => {
        console.log(`Admin bot reading message from ${msg.username || 'Unknown'}: ${msg.message.substring(0, 30)}...`);
        
        // This simulates a vulnerable browser that would execute JavaScript in the message
        // In a real exploitation scenario, the JavaScript would steal the admin's token
        if (msg.message.includes('<script>') || msg.message.includes('onerror=') || msg.message.includes('onload=')) {
          console.log('VULNERABILITY: Admin bot executed JavaScript in message!');
          console.log('In a real browser, this would allow stealing the JWT token: ' + adminToken);
        }
      });
      
      console.log('Admin bot finished checking messages');
    });
  }
  
  // Run immediately on startup
  setTimeout(simulateAdminViewingMessages, 10000); // 10 seconds after server start
  
  // Then every 5 minutes
  setInterval(simulateAdminViewingMessages, 5 * 60 * 1000);
}

// Add a blind second-order SQL injection vulnerability in profile updates
app.post('/api/users/update-profile', verifyToken, (req, res) => {
  const { bio, website, location } = req.body;
  const userId = req.user.id;
  
  // Store user input in the database without sanitization
  const updateQuery = `UPDATE users SET bio = "${bio}", website = "${website}", location = "${location}" WHERE id = ${userId}`;
  
  db.run(updateQuery, function(err) {
    if (err) {
      console.error('Profile update error:', err.message);
      return res.status(500).json({ error: err.message });
    }
    
    // Successfully stored potentially malicious input
    console.log(`Updated profile for user ${userId}`);
    return res.status(200).json({ success: true, message: 'Profile updated successfully' });
  });
});

// Add an admin report endpoint that uses the stored data in a second query (blind)
// This creates a second-order SQL injection vulnerability
app.get('/api/admin/user-report', verifyToken, (req, res) => {
  // Weak authorization check
  if (req.user.role !== 'admin' && req.query.isAdmin !== 'true') {
    return res.status(403).json({ message: 'Unauthorized' });
  }
  
  // This query uses user-supplied data from the database in another query
  // The 'location' field can contain a SQL injection that will be triggered here
  const reportQuery = `
    SELECT u.id, u.username, u.email, u.role, u.bio,
    (SELECT COUNT(*) FROM transactions WHERE sender_id = u.id OR receiver_id = u.id) as transaction_count,
    (SELECT COUNT(*) FROM admin_messages WHERE user_id = u.id) as message_count,
    (SELECT COUNT(*) FROM users WHERE location = u.location) as users_same_location
    FROM users u
    ORDER BY u.id
  `;
  
  db.all(reportQuery, (err, users) => {
    if (err) {
      console.error('Admin report error:', err.message);
      // The error will be silent to the user - making it a blind vulnerability
      return res.status(500).json({ error: 'An error occurred generating the report' });
    }
    
    return res.status(200).json(users);
  });
});

// Add a stored XSS vulnerability that can target a headless browser admin bot
// This simulates a realistic automated backoffice admin panel
app.post('/api/feedback', (req, res) => {
  const { email, message, rating } = req.body;
  
  // Store feedback including user-supplied email and message
  // No validation/sanitization - intentionally vulnerable
  const query = `
    INSERT INTO feedback (email, message, rating, date, reviewed) 
    VALUES ("${email}", "${message}", ${rating || 0}, "${new Date().toISOString()}", 0)
  `;
  
  db.run(query, function(err) {
    if (err) {
      console.error('Feedback error:', err.message);
      return res.status(500).json({ error: err.message });
    }
    
    console.log(`New feedback stored with ID ${this.lastID}`);
    return res.status(201).json({
      success: true,
      message: 'Feedback submitted successfully',
      feedbackId: this.lastID
    });
  });
});

// Create feedback table if it doesn't exist
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS feedback (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT,
    message TEXT,
    rating INTEGER,
    date TEXT,
    reviewed INTEGER DEFAULT 0
  )`);
  
  // Add bio/website/location columns to users table if they don't exist
  db.all(`PRAGMA table_info(users)`, (err, columns) => {
    if (err) {
      console.error('Error checking table columns:', err);
      return;
    }
    
    if (!columns.some(col => col.name === 'bio')) {
      db.run(`ALTER TABLE users ADD COLUMN bio TEXT`);
    }
    if (!columns.some(col => col.name === 'website')) {
      db.run(`ALTER TABLE users ADD COLUMN website TEXT`);
    }
    if (!columns.some(col => col.name === 'location')) {
      db.run(`ALTER TABLE users ADD COLUMN location TEXT`);
    }
  });
});

// Initialize a headless Chrome bot that reviews feedback in the admin panel
// This represents a realistic automated admin interface
// It's vulnerable to stored XSS with capability to steal JWTs and send them to external servers
function setupHeadlessFeedbackBot() {
  console.log('Setting up vulnerable headless feedback review bot - runs every 7 minutes');
  
  function simulateHeadlessBrowser() {
    console.log('Headless admin browser starting to review feedback...');
    
    // Generate admin JWT token with extended privileges  
    const adminToken = jwt.sign(
      { id: 1, username: 'admin', role: 'admin', privilegeLevel: 'system' },
      JWT_SECRET,
      { expiresIn: '1h' }
    );
    
    // In a real implementation, this token would be used for API calls
    console.log('Headless browser using SYSTEM ADMIN token:', adminToken);
    
    // Store token in simulated browser localStorage
    const browserLocalStorage = {
      'token': adminToken,
      'adminPreferences': JSON.stringify({
        'autoApprove': true,
        'notifyOnUrgent': true,
        'refreshInterval': 300000
      }),
      'adminId': '1',
      'sessionStarted': new Date().toISOString()
    };
    
    // Fetch all unreviewed feedback
    db.all(`
      SELECT * FROM feedback WHERE reviewed = 0 ORDER BY date DESC
    `, (err, feedbackItems) => {
      if (err) {
        console.error('Headless browser error:', err.message);
        return;
      }
      
      console.log(`Headless browser found ${feedbackItems.length} feedback items to review`);
      
      // Process each feedback entry - simulating a headless browser rendering HTML
      feedbackItems.forEach(item => {
        console.log(`Reviewing feedback #${item.id} from ${item.email}`);
        
        // This is where XSS would occur in a real headless browser
        // The email and message fields could contain JavaScript that would execute
        const dangerousFields = [item.email, item.message];
        
        // Check for potential XSS payloads
        dangerousFields.forEach(field => {
          if (field && (
              field.includes('<script') || 
              field.includes('javascript:') || 
              field.includes('onerror=') || 
              field.includes('onload=')
          )) {
            console.log('CRITICAL VULNERABILITY: Headless browser executed JavaScript in feedback!');
            console.log(`Potential data exposure: ${JSON.stringify(browserLocalStorage)}`);
            console.log('This could lead to system-level admin token theft and complete compromise');
          }
        });
        
        // Mark as reviewed
        db.run(`UPDATE feedback SET reviewed = 1 WHERE id = ${item.id}`);
      });
      
      console.log('Headless browser finished reviewing feedback');
    });
  }
  
  // Run on a different schedule than the message bot (7 minutes)
  setTimeout(simulateHeadlessBrowser, 15000); // 15 seconds after server start
  setInterval(simulateHeadlessBrowser, 7 * 60 * 1000); // Every 7 minutes
}

// Start the server
app.listen(PORT, () => {
  console.log(`DarkVault app running on port ${PORT}`);
  console.log(`WARNING: This application contains intentional security vulnerabilities!`);
  console.log(`It is intended for educational purposes only.`);
  console.log(`Error logs will be written to logs/error.log`);
  
  // Start the bots
  setupAdminBot();
  setupHeadlessFeedbackBot();
}); 