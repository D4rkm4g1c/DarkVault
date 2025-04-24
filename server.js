const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const jwt = require('jsonwebtoken');
const multer = require('multer');
const fs = require('fs');
const { exec } = require('child_process');
const axios = require('axios');
const cookieParser = require('cookie-parser');
const os = require('os');

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
const WEAK_KEY = 'dev-key'; // Secondary weak key for testing

// Create the app
const app = express();
const PORT = process.env.PORT || 3000;

// Create an internal admin service for SSRF targets
const internalAdminApp = express();

// Setup internal admin endpoints
internalAdminApp.get('/admin-dashboard', (req, res) => {
  res.json({
    message: 'Internal Admin Dashboard', 
    secretKeys: {
      mainJwtSecret: JWT_SECRET,
      backupSecret: WEAK_KEY
    },
    admins: ['admin']
  });
});

internalAdminApp.get('/system-info', (req, res) => {
  res.json({
    environment: process.env.NODE_ENV || 'development',
    platform: process.platform,
    nodeVersion: process.version,
    memory: process.memoryUsage(),
    databaseLocation: './bank.db',
    secretsPath: '/app/secrets/'
  });
});

internalAdminApp.get('/api-keys', (req, res) => {
  res.json({
    stripeKey: 'sk_test_4eC39HqLyjWDarjtT1zdp7dc',
    mailgunKey: 'key-3ax6xnjp29jd6fds4gc373sgvjxteol0',
    awsAccessKey: 'AKIAIOSFODNN7EXAMPLE',
    awsSecretKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
  });
});

// Start the internal service on a different port
const INTERNAL_PORT = 3001;
internalAdminApp.listen(INTERNAL_PORT, '127.0.0.1', () => {
  console.log(`Internal admin service running on http://127.0.0.1:${INTERNAL_PORT}`);
  console.log('This service is not meant to be directly accessible');
});

// Create internal endpoints on the main app that shouldn't be directly accessible
app.get('/internal/config', (req, res) => {
  // This should only be accessible by the app itself
  const config = {
    database: {
      path: './bank.db',
      backupFrequency: '24h'
    },
    secrets: {
      jwtSecret: JWT_SECRET,
      weakSecret: WEAK_KEY
    },
    adminCredentials: {
      username: 'admin',
      password: 'admin123'
    }
  };
  
  res.json(config);
});

app.get('/internal/users/all', (req, res) => {
  // Another internal endpoint with sensitive data
  db.all('SELECT id, username, password, email, role FROM users', (err, rows) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    return res.status(200).json({ users: rows });
  });
});

// Secure CORS configuration
app.use(cors({
  origin: 'http://localhost:3000', // Restrict to known origins
  credentials: true
}));

// Bodyparser setup with reasonable limit
app.use(bodyParser.json({ limit: '2mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '2mb' }));
app.use(cookieParser());

// Serve static files
app.use(express.static(path.join(__dirname, 'public')));

// Secure file upload configuration
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    // Safe upload path
    const uploadDir = 'uploads';
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }
    cb(null, uploadDir);
  },
  filename: function (req, file, cb) {
    // Sanitize filename to prevent path traversal
    const sanitizedName = path.basename(file.originalname).replace(/[^a-zA-Z0-9_.-]/g, '_');
    cb(null, Date.now() + '-' + sanitizedName);
  }
});

// Secure file filter
const fileFilter = function(req, file, cb) {
  // Check mime type and extension
  const allowedMimeTypes = ['image/jpeg', 'image/png', 'application/pdf', 'text/plain'];
  const allowedExtensions = ['.jpg', '.jpeg', '.png', '.pdf', '.txt'];
  
  const ext = path.extname(file.originalname).toLowerCase();
  
  if (allowedMimeTypes.includes(file.mimetype) && allowedExtensions.includes(ext)) {
    cb(null, true);
  } else {
    cb(null, false);
  }
};

const upload = multer({ 
  storage: storage,
  fileFilter: fileFilter,
  limits: {
    fileSize: 5 * 1024 * 1024 // 5MB
  }
});

// Setup Database
const db = new sqlite3.Database('./bank.db', (err) => {
  if (err) {
    console.error('Database connection error:', err.message);
    process.exit(1); // Exit if we can't connect to the database
  }
  console.log('Connected to the SQLite database.');
});

// Create necessary database tables
function setupDatabase() {
  console.log('Setting up database...');
  
  // Create users table
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE,
    password TEXT,
    email TEXT,
    role TEXT DEFAULT 'user',
    balance REAL DEFAULT 1000.0,
    bio TEXT,
    website TEXT,
    location TEXT
  )`);
  
  // Create transactions table
  db.run(`CREATE TABLE IF NOT EXISTS transactions (
    id INTEGER PRIMARY KEY,
    sender_id INTEGER,
    receiver_id INTEGER,
    amount REAL,
    date TEXT,
    note TEXT
  )`);
  
  // Create admin messages table
  db.run(`CREATE TABLE IF NOT EXISTS admin_messages (
    id INTEGER PRIMARY KEY,
    user_id INTEGER,
    message TEXT,
    date TEXT
  )`);
  
  // Create exploit_chain table to track user progress
  db.run(`CREATE TABLE IF NOT EXISTS exploit_chain (
    user_id INTEGER PRIMARY KEY,
    stage TEXT DEFAULT 'not_started',
    discovered_secrets TEXT,
    last_updated TEXT
  )`);
  
  // Create secrets table for chain requirements
  db.run(`CREATE TABLE IF NOT EXISTS secrets (
    id INTEGER PRIMARY KEY,
    key_name TEXT UNIQUE,
    key_value TEXT
  )`, function(err) {
    if (err) {
      console.error('Error creating secrets table:', err.message);
    } else {
      // Insert initial secrets
      db.get("SELECT * FROM secrets WHERE key_name = 'chain_key'", (err, row) => {
        if (!row) {
          db.run("INSERT INTO secrets (key_name, key_value) VALUES ('chain_key', 'chain_key')");
          db.run("INSERT INTO secrets (key_name, key_value) VALUES ('advanced_chain_key', 'chain_9a74c8')");
          db.run("INSERT INTO secrets (key_name, key_value) VALUES ('idor_token', 'access')");
          db.run("INSERT INTO secrets (key_name, key_value) VALUES ('x_exploit_token', 'cmd_token')");
        }
      });
    }
  });
  
  // Create themes table for cookie-based SQL injection
  db.run(`CREATE TABLE IF NOT EXISTS themes (
    id INTEGER PRIMARY KEY,
    name TEXT UNIQUE,
    description TEXT,
    custom_css TEXT
  )`, function(err) {
    if (err) {
      console.error('Error creating themes table:', err.message);
    } else {
      // Insert some default themes
      db.run("INSERT OR IGNORE INTO themes (name, description, custom_css) VALUES ('default', 'Default theme', 'body { background-color: white; }')");
      db.run("INSERT OR IGNORE INTO themes (name, description, custom_css) VALUES ('dark', 'Dark theme', 'body { background-color: #222; color: #eee; }')");
      db.run("INSERT OR IGNORE INTO themes (name, description, custom_css) VALUES ('light', 'Light theme', 'body { background-color: #f8f9fa; }')");
      console.log('Themes table created and populated');
    }
  });
  
  // Create user_settings table for prototype pollution
  db.run(`CREATE TABLE IF NOT EXISTS user_settings (
    user_id INTEGER PRIMARY KEY,
    settings TEXT
  )`, function(err) {
    if (err) {
      console.error('Error creating user_settings table:', err.message);
    } else {
      console.log('User settings table created');
    }
  });
  
  // Create profile_updates table for second-order SQL injection
  db.run(`CREATE TABLE IF NOT EXISTS profile_updates (
    id INTEGER PRIMARY KEY,
    user_id INTEGER,
    field TEXT,
    old_value TEXT,
    new_value TEXT,
    date TEXT
  )`, function(err) {
    if (err) {
      console.error('Error creating profile_updates table:', err.message);
    } else {
      console.log('Profile updates table created');
    }
  });
  
  // Insert admin user if not exists
  db.get("SELECT * FROM users WHERE username = 'admin'", (err, user) => {
    if (err) {
      console.error('Error checking for admin user:', err.message);
    } else if (!user) {
      db.run("INSERT INTO users (username, password, email, role, balance) VALUES ('admin', 'admin123', 'admin@darkvault.com', 'admin', 9999.99)");
      console.log('Admin user created');
    }
  });
  
  // Insert regular users if not exists
  const users = [
    { username: 'alice', password: 'password123', email: 'alice@example.com', role: 'user' },
    { username: 'bob', password: 'password123', email: 'bob@example.com', role: 'user' }
  ];
  
  users.forEach(user => {
    db.get(`SELECT * FROM users WHERE username = '${user.username}'`, (err, existingUser) => {
      if (err) {
        console.error(`Error checking for user ${user.username}:`, err.message);
      } else if (!existingUser) {
        db.run(`INSERT INTO users (username, password, email, role, balance) VALUES ('${user.username}', '${user.password}', '${user.email}', '${user.role}', 1000.0)`);
        console.log(`User ${user.username} created`);
      }
    });
  });
  
  // Add admin bots for automation
  db.get("SELECT * FROM users WHERE username = 'admin_message_bot'", (err, user) => {
    if (err) {
      console.error('Error checking for bot user:', err.message);
    } else if (!user) {
      db.run("INSERT INTO users (username, password, email, role) VALUES ('admin_message_bot', 'botpassword1', 'message_bot@darkvault.com', 'bot')");
      db.run("INSERT INTO users (username, password, email, role) VALUES ('admin_feedback_bot', 'botpassword2', 'feedback_bot@darkvault.com', 'bot')");
      console.log('Bot users created');
    }
  });
}

// Call setupDatabase at startup
setupDatabase();

// Middleware to log requests - information disclosure
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} [${req.method}] ${req.url} - Body:`, req.body);
  next();
});

// --- Vulnerable Endpoints ---

// Login endpoint - secure version but still allows JWT manipulation later
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ 
      error: 'Missing credentials',
      message: 'Username and password are required'
    });
  }

  // Use parameterized query instead of string concatenation
  const query = `SELECT * FROM users WHERE username = ? AND password = ?`;
  
  db.get(query, [username, password], async (err, user) => {
    if (err) {
      console.error('Login error:', err.message);
      return res.status(500).json({ error: 'Database error' });
    }
    
    if (!user) {
      return res.status(401).json({
        error: 'Authentication failed',
        message: 'Invalid username or password'
      });
    }

    // Check if the account is locked
    if (user.status === 'locked') {
      return res.status(403).json({
        error: 'Account locked',
        message: 'Your account has been locked. Please contact an administrator.'
      });
    }

    // Generate token - still vulnerable to JWT manipulation by design
    const token = jwt.sign(
      { 
        id: user.id, 
        username: user.username, 
        role: user.role,
        status: user.status
      }, 
      JWT_SECRET,
      { expiresIn: '1h' }
    );

    // Update user's last login
    db.run('UPDATE users SET last_login = ? WHERE id = ?', [new Date().toISOString(), user.id]);
    
    // Log successful login attempts
    console.log(`User login successful: ${user.username} (ID: ${user.id})`);
    
    // Return token and user info
    return res.json({
      success: true,
      message: 'Login successful',
      token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role,
        status: user.status
      }
    });
  });
});

// Register endpoint with proper validation
app.post('/api/register', (req, res) => {
  const { username, password, email } = req.body;
  
  // Input validation
  if (!username || !password || !email) {
    return res.status(400).json({ 
      error: 'Missing data',
      message: 'Username, password and email are required' 
    });
  }
  
  // Use parameterized query instead of string concatenation
  const query = `INSERT INTO users (username, password, email) VALUES (?, ?, ?)`;
  
  db.run(query, [username, password, email], function(err) {
    if (err) {
      console.error('Registration error:', err.message);
      logError('Registration', err, { username, email });
      return res.status(500).json({ error: 'Registration failed' });
    }
    
    console.log(`User registered successfully: username=${username}, userId=${this.lastID}`);
    return res.status(201).json({
      success: true,
      message: 'User registered successfully',
      userId: this.lastID
    });
  });
});

// Middleware for token verification - Keep the JWT vulnerability by design
const verifyToken = (req, res, next) => {
  const token = req.headers['authorization'];
  
  if (!token) {
    return res.status(401).json({ 
      message: 'No token provided',
      hint: 'Authentication required' 
    });
  } else {
    try {
      // VULNERABLE BY DESIGN: JWT verification still accepts multiple secrets
      // and doesn't properly validate role claims against the database
      let decoded;
      try {
        decoded = jwt.verify(token, JWT_SECRET);
      } catch (mainErr) {
        // If main secret fails, try the weak testing key
        try {
          decoded = jwt.verify(token, WEAK_KEY);
          console.log('WARNING: JWT verified with weak dev key!');
        } catch (devErr) {
          throw mainErr;
        }
      }
      
      // Successfully verified the token
      req.user = decoded;
      
      // Load the user's real data from the database to compare with token claims
      db.get(`SELECT * FROM users WHERE id = ?`, [decoded.id], (err, user) => {
        if (err) {
          return res.status(500).json({ error: 'Database error' });
        }
        
        if (!user) {
          return res.status(404).json({ message: 'User not found' });
        }
        
        // VULNERABLE BY DESIGN: Does not validate token role against database role
        // This allows privilege escalation by manipulating the JWT payload
        req.user.username = user.username;
        req.user.email = user.email;
        // req.user.role is not overwritten from DB, allowing token role to be used
        req.user.balance = user.balance;
        
        // Add user's discovered secrets if any
        loadExploitChainProgress(req, res, next);
      });
    } catch (error) {
      console.error('Token verification error:', error.message);
      return res.status(401).json({
        message: 'Invalid token',
        error: 'Authentication failed'
      });
    }
  }
};

// Helper function to load and track exploit chain progress
function loadExploitChainProgress(req, res, next) {
  const userId = req.user.id;
  
  if (!userId) {
    next();
    return;
  }
  
  // Check if user has exploit chain progress entry
  db.get('SELECT * FROM exploit_chain WHERE user_id = ?', [userId], (err, row) => {
    if (err) {
      console.error('Error checking exploit chain progress:', err.message);
      next();
      return;
    }
    
    if (!row) {
      // Create new entry if not exists
      const now = new Date().toISOString();
      db.run(
        'INSERT INTO exploit_chain (user_id, stage, discovered_secrets, last_updated) VALUES (?, ?, ?, ?)',
        [userId, 'not_started', '{}', now],
        function(err) {
          if (err) {
            console.error('Error creating exploit chain record:', err.message);
          }
          
          req.user.exploitStage = 'not_started';
          req.user.discoveredSecrets = {};
          
          // Add a helper method for updating exploit stage
          req.user.updateExploitStage = function(stage, secret = null) {
            const now = new Date().toISOString();
            
            // Don't go backwards in the chain
            const stages = ['not_started', 'found_chain_key', 'idor_success', 'upload_success', 'command_ready', 'command_success'];
            const currentIndex = stages.indexOf(req.user.exploitStage);
            const newIndex = stages.indexOf(stage);
            
            if (newIndex <= currentIndex && req.user.exploitStage !== 'not_started') {
              console.log(`Not updating stage: ${req.user.exploitStage} -> ${stage} (would go backwards)`);
              return;
            }
            
            // Update in memory
            req.user.exploitStage = stage;
            
            // Update discovered secrets if provided
            if (secret) {
              if (!req.user.discoveredSecrets) {
                req.user.discoveredSecrets = {};
              }
              req.user.discoveredSecrets[secret.key] = secret.value;
            }
            
            // Update in database
            db.run(
              'UPDATE exploit_chain SET stage = ?, discovered_secrets = ?, last_updated = ? WHERE user_id = ?',
              [stage, JSON.stringify(req.user.discoveredSecrets || {}), now, userId],
              function(err) {
                if (err) {
                  console.error('Error updating exploit chain stage:', err.message);
                }
              }
            );
          };
          
          next();
        }
      );
    } else {
      // Load existing entry
      req.user.exploitStage = row.stage;
      
      try {
        req.user.discoveredSecrets = JSON.parse(row.discovered_secrets);
      } catch (e) {
        req.user.discoveredSecrets = {};
        console.error('Error parsing discovered secrets:', e);
      }
      
      // Add a helper method for updating exploit stage
      req.user.updateExploitStage = function(stage, secret = null) {
        const now = new Date().toISOString();
        
        // Don't go backwards in the chain
        const stages = ['not_started', 'found_chain_key', 'idor_success', 'upload_success', 'command_ready', 'command_success'];
        const currentIndex = stages.indexOf(req.user.exploitStage);
        const newIndex = stages.indexOf(stage);
        
        if (newIndex <= currentIndex && req.user.exploitStage !== 'not_started') {
          console.log(`Not updating stage: ${req.user.exploitStage} -> ${stage} (would go backwards)`);
          return;
        }
        
        // Update in memory
        req.user.exploitStage = stage;
        
        // Update discovered secrets if provided
        if (secret) {
          if (!req.user.discoveredSecrets) {
            req.user.discoveredSecrets = {};
          }
          req.user.discoveredSecrets[secret.key] = secret.value;
        }
        
        // Update in database
        db.run(
          'UPDATE exploit_chain SET stage = ?, discovered_secrets = ?, last_updated = ? WHERE user_id = ?',
          [stage, JSON.stringify(req.user.discoveredSecrets || {}), now, userId],
          function(err) {
            if (err) {
              console.error('Error updating exploit chain stage:', err.message);
            }
          }
        );
      };
      
      next();
    }
  });
}

// Get user profile - Fixed IDOR vulnerability
app.get('/api/users/:id', verifyToken, (req, res) => {
  const id = req.params.id;
  
  // Only allow users to access their own profile or admins to access any profile
  if (req.user.id.toString() !== id && req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Unauthorized - You can only access your own profile' });
  }
  
  // Use parameterized query instead of string concatenation
  db.get(`SELECT * FROM users WHERE id = ?`, [id], (err, user) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    // Add bot secrets to the response if appropriate (for admins only)
    if (user.role === 'bot' && req.user.role === 'admin') {
      user.secretInfo = 'This bot is used for automated admin tasks. It has elevated privileges.';
    }
    
    return res.status(200).json(user);
  });
});

// Transfer money - Fix CSRF vulnerability in this endpoint (but keep it in update-email)
app.post('/api/transfer', verifyToken, (req, res) => {
  const { to, amount, note, csrf_token } = req.body;
  const fromId = req.user.id;
  
  // Check CSRF token
  if (!csrf_token || csrf_token !== req.user.id.toString()) {
    return res.status(403).json({ error: 'Invalid CSRF token' });
  }
  
  // Validate inputs
  if (!to || !amount || isNaN(parseFloat(amount))) {
    return res.status(400).json({ error: 'Invalid transfer parameters' });
  }
  
  // Sanitize note to prevent XSS
  const sanitizedNote = note ? note.replace(/</g, '&lt;').replace(/>/g, '&gt;') : 'Transfer';
  
  // Use parameterized queries for all database operations
  db.serialize(() => {
    // Begin transaction
    db.run('BEGIN TRANSACTION');
    
    // Insert the transaction
    db.run(
      `INSERT INTO transactions (sender_id, receiver_id, amount, date, note) 
      VALUES (?, ?, ?, ?, ?)`,
      [fromId, to, parseFloat(amount), new Date().toISOString(), sanitizedNote],
      function(err) {
        if (err) {
          db.run('ROLLBACK');
          console.error('Transfer error:', err.message);
          return res.status(500).json({ error: 'Failed to record transaction' });
        }
        
        const transactionId = this.lastID;
        
        // Update sender balance
        db.run(
          `UPDATE users SET balance = balance - ? WHERE id = ? AND balance >= ?`,
          [parseFloat(amount), fromId, parseFloat(amount)],
          function(err) {
            if (err || this.changes === 0) {
              db.run('ROLLBACK');
              console.error('Update sender balance error:', err ? err.message : 'Insufficient funds');
              return res.status(400).json({ error: 'Insufficient funds or failed to update balance' });
            }
            
            // Update receiver balance
            db.run(
              `UPDATE users SET balance = balance + ? WHERE id = ?`,
              [parseFloat(amount), to],
              function(err) {
                if (err) {
                  db.run('ROLLBACK');
                  console.error('Update receiver balance error:', err.message);
                  return res.status(500).json({ error: 'Failed to update receiver balance' });
                }
                
                // Commit the transaction
                db.run('COMMIT', function(err) {
                  if (err) {
                    db.run('ROLLBACK');
                    console.error('Commit error:', err.message);
                    return res.status(500).json({ error: 'Failed to complete transaction' });
                  }
                  
                  return res.status(200).json({
                    success: true,
                    message: 'Transfer successful',
                    transactionId: transactionId
                  });
                });
              }
            );
          }
        );
      }
    );
  });
});

// Secure admin report endpoint - fixed command injection
app.post('/api/admin/report', verifyToken, (req, res) => {
  // Only allow admin users
  if (req.user.role !== 'admin') {
    return res.status(403).json({
      error: 'Unauthorized',
      message: 'Only admins can run reports'
    });
  }

  // Get report parameters from request body
  const { report_name, report_type } = req.body;
  
  if (!report_name) {
    return res.status(400).json({
      error: 'Missing parameters',
      message: 'Report name is required'
    });
  }

  // Validate report name to prevent command injection
  if (!/^[a-zA-Z0-9_-]+$/.test(report_name)) {
    return res.status(400).json({
      error: 'Invalid report name',
      message: 'Report name can only contain alphanumeric characters, underscores, and hyphens'
    });
  }

  // Generate a report safely without command injection
  const reportContent = `Report: ${report_name}\nType: ${report_type || 'standard'}\nGenerated: ${new Date().toISOString()}`;
  const reportFile = path.join(os.tmpdir(), `report_${Date.now()}.txt`);
  
  try {
    fs.writeFileSync(reportFile, reportContent);
    
    // Read the generated report
    const data = fs.readFileSync(reportFile, 'utf8');
    
    return res.json({
      success: true,
      report: {
        name: report_name,
        type: report_type || 'standard',
        content: data,
        created: new Date().toISOString()
      },
      message: 'Report generated successfully'
    });
  } catch (err) {
    return res.status(500).json({
      error: 'Server error',
      message: 'Failed to generate report'
    });
  }
});

// Secure file upload endpoint
app.post('/api/upload', verifyToken, upload.single('file'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ 
      error: 'No file uploaded or invalid file type',
      message: 'Please upload a valid file (JPEG, PNG, PDF, or TXT)'
    });
  }

  const uploadedFile = req.file;
  
  return res.json({
    success: true,
    file: {
      name: uploadedFile.originalname,
      path: uploadedFile.path,
      size: uploadedFile.size
    },
    message: 'File uploaded successfully'
  });
});

// Search endpoint - secure version
app.get('/api/search', (req, res) => {
  const searchTerm = req.query.q;
  
  if (!searchTerm) {
    return res.status(400).json({ 
      error: 'Missing search term',
      message: 'Search term is required'
    });
  }

  // Use parameterized query
  const query = `SELECT * FROM items WHERE name LIKE ? OR description LIKE ?`;
  const param = `%${searchTerm}%`;
  
  db.all(query, [param, param], (err, items) => {
    if (err) {
      console.error('Search error:', err.message);
      return res.status(500).json({ error: 'Search failed' });
    }
    
    return res.json({ 
      results: items,
      count: items.length
    });
  });
});

// Admin message endpoint - Fix IDOR vulnerability
app.post('/api/messages', verifyToken, (req, res) => {
  const { message } = req.body;
  const user_id = req.user.id; // Only allow sending messages for the authenticated user
  
  // Validate input
  if (!message) {
    return res.status(400).json({ error: 'Message is required' });
  }
  
  // Sanitize message to prevent XSS
  const sanitizedMessage = message.replace(/</g, '&lt;').replace(/>/g, '&gt;');
  
  // Use parameterized query
  const query = `
    INSERT INTO admin_messages (user_id, message, date) 
    VALUES (?, ?, ?)
  `;
  
  db.run(query, [user_id, sanitizedMessage, new Date().toISOString()], function(err) {
    if (err) {
      console.error('Message error:', err.message);
      return res.status(500).json({ error: 'Failed to send message' });
    }
    
    return res.status(201).json({
      success: true,
      message: 'Message sent to admin',
      messageId: this.lastID
    });
  });
});

// Route to export all user data - Fix information disclosure
app.get('/api/admin/export-users', verifyToken, (req, res) => {
  // Proper role check
  if (req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Unauthorized - Admin access required' });
  }
  
  db.all(`SELECT id, username, email, role, balance FROM users`, (err, users) => {
    if (err) {
      return res.status(500).json({ error: 'Failed to fetch users' });
    }
    
    return res.status(200).json(users);
  });
});

// Fetch admin messages - Fix access control
app.get('/api/admin/messages', verifyToken, (req, res) => {
  // Proper role check
  if (req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Unauthorized - Admin access required' });
  }
  
  // Get all messages with user information
  db.all(`
    SELECT m.*, u.username 
    FROM admin_messages m
    LEFT JOIN users u ON m.user_id = u.id
    ORDER BY m.date DESC
  `, (err, messages) => {
    if (err) {
      return res.status(500).json({ error: 'Failed to fetch messages' });
    }
    
    return res.status(200).json(messages);
  });
});

// Get transaction history - Fix SQL injection
app.get('/api/transactions', verifyToken, (req, res) => {
  const user_id = req.query.user_id;
  
  // Ensure user can only see their own transactions
  if (!user_id || user_id !== req.user.id.toString()) {
    return res.status(403).json({ error: 'Unauthorized - You can only view your own transactions' });
  }
  
  // Use parameterized query
  const query = `
    SELECT * FROM transactions 
    WHERE sender_id = ? OR receiver_id = ?
    ORDER BY date DESC
  `;
  
  db.all(query, [user_id, user_id], (err, transactions) => {
    if (err) {
      return res.status(500).json({ error: 'Failed to fetch transactions' });
    }
    
    return res.status(200).json(transactions);
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
  console.log('Setting up vulnerable admin bot that checks messages every 1 minute');
  
  // This is intentionally vulnerable!
  // The admin bot "runs" JavaScript in messages by executing them in a simulated browser environment
  function simulateAdminViewingMessages() {
    console.log('Secret admin bot is checking messages...');
    
    // Get the bot user ID
    db.get("SELECT id, username, role FROM users WHERE username = 'admin_message_bot'", (err, botUser) => {
      if (err || !botUser) {
        console.error('Could not find admin message bot user:', err ? err.message : 'User not found');
        return;
      }
      
      // Generate bot JWT token
      const sessionToken = jwt.sign(
        { id: botUser.id, username: botUser.username, role: botUser.role, botType: 'message_bot' },
        JWT_SECRET,
        { expiresIn: '1h' }
      );
      
      // Log bot token (in a real app, this would be a secret)
      console.log('Admin bot using token:', sessionToken);
      
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
          
          // Check for potentially malicious content
          if (msg.message.includes('<script>') || msg.message.includes('onerror=') || msg.message.includes('onload=')) {
            console.log('VULNERABILITY: Admin bot executed JavaScript in message!');
            console.log('In a real browser, this would allow stealing the JWT token: ' + sessionToken);
            
            // Extract URLs from the message (basic extraction for common patterns)
            const urlRegex = /(https?:\/\/[^\s'"]+)/g;
            const urls = msg.message.match(urlRegex);
            
            if (urls && urls.length > 0) {
              console.log(`Found URLs in XSS payload: ${urls.join(', ')}`);
              
              // Actually make the HTTP request to the extracted URL
              urls.forEach(url => {
                try {
                  console.log(`Making actual HTTP request to: ${url}`);
                  // Add token as query parameter
                  const requestUrl = url.includes('?') 
                    ? `${url}&t=${sessionToken}` 
                    : `${url}?t=${sessionToken}`;
                    
                  axios.get(requestUrl)
                    .then(response => console.log(`Successfully sent admin token to: ${url}`))
                    .catch(error => console.log(`Error sending data to ${url}: ${error.message}`));
                } catch (error) {
                  console.error(`Failed to make request to ${url}: ${error.message}`);
                }
              });
            }
          }
        });
        
        console.log('Admin bot finished checking messages');
      });
    });
  }
  
  // Run immediately on startup
  setTimeout(simulateAdminViewingMessages, 10000); // 10 seconds after server start
  
  // Then every 1 minute
  setInterval(simulateAdminViewingMessages, 1 * 60 * 1000);
}

// Blind second-order SQL injection vulnerability - PRESERVED BY DESIGN
app.post('/api/users/update-profile', verifyToken, (req, res) => {
  const { bio, website, location } = req.body;
  
  // Log the profile update attempt
  console.log(`Profile update for user ${req.user.id}:`, { bio, website, location });
  
  // First part uses parameterized query and appears secure
  try {
    db.run(
      `UPDATE users SET bio = ?, website = ?, location = ? WHERE id = ?`,
      [bio, website, location, req.user.id],
      function(err) {
        if (err) {
          console.error('Error updating profile:', err.message);
          return res.status(500).json({ error: 'Failed to update profile' });
        }
        
        // Create a profile_updates table if it doesn't exist
        db.run(`CREATE TABLE IF NOT EXISTS profile_updates (
          id INTEGER PRIMARY KEY,
          user_id INTEGER,
          field TEXT,
          old_value TEXT,
          new_value TEXT,
          date TEXT
        )`, function(err) {
          if (err) {
            console.error('Error creating profile_updates table:', err.message);
          }
          
          // VULNERABLE BY DESIGN: Second-order SQL injection happens here
          if (location) {
            // Directly concatenating user input into SQL query
            const dateStr = new Date().toISOString();
            const updateQuery = `INSERT INTO profile_updates (user_id, field, new_value, date) 
              VALUES (${req.user.id}, 'location', '${location}', '${dateStr}')`;
            
            // Execute the vulnerable query
            db.run(updateQuery, function(err) {
              if (err) {
                // The error is hidden from the user, making this a blind injection
                console.error('Error logging profile update:', err.message);
              }
            });
          }
        });
        
        return res.status(200).json({ 
          success: true, 
          message: 'Profile updated successfully'
        });
      }
    );
  } catch (error) {
    console.error('Profile update error:', error.message);
    return res.status(500).json({ error: 'Failed to update profile' });
  }
});

// Admin endpoint to view profile updates - executes second-order SQL injection
app.get('/api/admin/profile-updates', verifyToken, (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Unauthorized' });
  }
  
  // This query executes any SQL injection payloads in the profile_updates table
  // with admin privileges, completing the second-order injection
  db.all(`SELECT * FROM profile_updates ORDER BY date DESC`, (err, updates) => {
    if (err) {
      console.error('Error fetching profile updates:', err.message);
      return res.status(500).json({ error: 'Failed to fetch profile updates' });
    }
    
    return res.status(200).json(updates);
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
  console.log('Setting up vulnerable headless feedback review bot - runs every 2 minutes');
  
  function simulateHeadlessBrowser() {
    console.log('Headless admin browser starting to review feedback...');
    
    // Get the bot user ID
    db.get("SELECT id, username, role FROM users WHERE username = 'admin_feedback_bot'", (err, botUser) => {
      if (err || !botUser) {
        console.error('Could not find admin feedback bot user:', err ? err.message : 'User not found');
        return;
      }
      
      // Generate bot JWT token with extended privileges  
      const accessToken = jwt.sign(
        { id: botUser.id, username: botUser.username, role: botUser.role, botType: 'feedback_bot', privilegeLevel: 'system' },
        JWT_SECRET,
        { expiresIn: '1h' }
      );
      
      // In a real implementation, this token would be used for API calls
      console.log('Headless browser using SYSTEM BOT token:', accessToken);
      
      // Store token in simulated browser localStorage
      const browserLocalStorage = {
        'authToken': accessToken,
        'adminPreferences': JSON.stringify({
          'autoApprove': true,
          'notifyOnUrgent': true,
          'refreshInterval': 300000
        }),
        'botId': botUser.id.toString(),
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
              
              // Extract URLs from the field (basic extraction for common patterns)
              const urlRegex = /(https?:\/\/[^\s'"]+)/g;
              const urls = field.match(urlRegex);
              
              if (urls && urls.length > 0) {
                console.log(`Found URLs in feedback XSS payload: ${urls.join(', ')}`);
                
                // Actually make the HTTP request to the extracted URL
                urls.forEach(url => {
                  try {
                    console.log(`Making actual HTTP request to: ${url}`);
                    // Add token and localStorage data as query parameters
                    const requestUrl = url.includes('?') 
                      ? `${url}&t=${accessToken}&data=${encodeURIComponent(JSON.stringify(browserLocalStorage))}` 
                      : `${url}?t=${accessToken}&data=${encodeURIComponent(JSON.stringify(browserLocalStorage))}`;
                      
                    axios.get(requestUrl)
                      .then(response => console.log(`Successfully sent admin data to: ${url}`))
                      .catch(error => console.log(`Error sending data to ${url}: ${error.message}`));
                  } catch (error) {
                    console.error(`Failed to make request to ${url}: ${error.message}`);
                  }
                });
              }
            }
          });
          
          // Mark as reviewed
          db.run(`UPDATE feedback SET reviewed = 1 WHERE id = ${item.id}`);
        });
        
        console.log('Headless browser finished reviewing feedback');
      });
    });
  }
  
  // Run on a different schedule than the message bot (2 minutes)
  setTimeout(simulateHeadlessBrowser, 15000); // 15 seconds after server start
  setInterval(simulateHeadlessBrowser, 2 * 60 * 1000); // Every 2 minutes
}

// Endpoint to check exploit chain status
app.get('/api/exploit-status', verifyToken, (req, res) => {
  const stages = [
    'not_started',
    'found_chain_key',
    'idor_success',
    'upload_success',
    'command_ready',
    'command_success'
  ];
  
  if (!req.user) {
    return res.status(401).json({ message: 'Unauthorized' });
  }
  
  const currentStage = req.user.exploitStage || 'not_started';
  const currentIndex = stages.indexOf(currentStage);
  const completion = Math.round((currentIndex / (stages.length - 1)) * 100) + '%';
  
  let hint = '';
  let nextStage = '';
  
  switch (currentStage) {
    case 'not_started':
      hint = 'Try looking for SQL injection vulnerabilities in the search function';
      nextStage = 'found_chain_key';
      break;
    case 'found_chain_key':
      hint = 'Now try to access another user\'s profile with IDOR using the x-profile-access header';
      nextStage = 'idor_success';
      break;
    case 'idor_success':
      hint = 'Try uploading a file to a special directory using x-upload-path header and xMode=true';
      nextStage = 'upload_success';
      break;
    case 'upload_success':
      hint = 'Try adding x-exploit-token to access admin command injection';
      nextStage = 'command_ready';
      break;
    case 'command_ready':
      hint = 'Execute commands through the Run Report feature';
      nextStage = 'command_success';
      break;
    case 'command_success':
      hint = 'You\'ve completed the main exploit chain! Now try other vulnerabilities like JWT manipulation, prototype pollution, and cookie-based SQL injection.';
      nextStage = 'complete';
      break;
    default:
      hint = 'Unknown stage';
      nextStage = '';
  }
  
  res.status(200).json({
    status: currentStage,
    nextStage: nextStage,
    hint: hint,
    completion: completion,
    discoveredSecrets: req.user.discoveredSecrets || {}
  });
});

// Helper function to extract JWT token from login endpoint
app.get('/api/get-jwt-info', (req, res) => {
  // Information disclosure vulnerability - reveals JWT details
  // This helps users understand the JWT structure for the challenge
  const token = req.headers['authorization'];
  if (!token) {
    return res.status(400).json({ message: 'No token provided' });
  }
  
  try {
    // Don't verify, just decode to show structure
    const decoded = jwt.decode(token, { complete: true });
    
    // Intentionally leak information about the JWT
    return res.status(200).json({
      header: decoded.header,
      payload: decoded.payload,
      hint: 'JWT tokens are signed with a secret. The secret might be exposed in the source code or error messages.'
    });
  } catch (error) {
    return res.status(400).json({ error: error.message });
  }
});

// Cookie-based SQL injection - adding a vulnerability where SQL injection can be performed via cookies
app.get('/api/user-preferences', verifyToken, (req, res) => {
  // Get theme from cookie - VULNERABLE TO SQL INJECTION BY DESIGN
  const theme = req.cookies?.theme || 'default';
  
  console.log(`Loading preferences with theme: ${theme}`);
  
  // VULNERABLE BY DESIGN: Direct use of cookie value in SQL query
  // This can be exploited with a cookie like: theme=dark' UNION SELECT password,username,email FROM users--
  const query = `SELECT * FROM themes WHERE name = '${theme}'`;
  
  db.all(query, (err, themes) => {
    if (err) {
      // Suppresses the error but logs it - making this blind
      console.error('Error in theme loading:', err.message);
      return res.status(200).json({ 
        theme: 'default',
        message: 'Error loading theme, using default'
      });
    }
    
    // Success response
    return res.status(200).json({
      theme: theme,
      settings: themes,
      customCss: theme !== 'default' ? themes[0]?.custom_css : ''
    });
  });
});

// DOM-based XSS vulnerability - PRESERVED BY DESIGN
app.get('/api/documentation', verifyToken, (req, res) => {
  // Send HTML with JavaScript that uses fragment identifier (hash)
  // This is vulnerable to DOM-based XSS via the URL fragment
  // Example: /api/documentation#<img src=x onerror=alert(document.cookie)>
  const htmlContent = `
    <!DOCTYPE html>
    <html>
    <head>
      <title>API Documentation</title>
      <script>
        // VULNERABLE BY DESIGN: Directly using location.hash without sanitization
        window.onload = function() {
          // Get the hash value from the URL (without the # symbol)
          var section = window.location.hash.substring(1);
          
          // Use it to navigate to a section - DOM-based XSS vulnerability
          if(section) {
            // This is vulnerable - directly writing the hash to innerHTML
            document.getElementById('section-title').innerHTML = 'Section: ' + section;
            document.getElementById('content').innerHTML = 'Loading content for ' + section + '...';
          }
        };
      </script>
    </head>
    <body>
      <h1>API Documentation</h1>
      <h2 id="section-title">Welcome</h2>
      <div id="content">
        <p>Select a section from the URL hash to view documentation.</p>
        <p>Example: <code>#authentication</code>, <code>#endpoints</code>, etc.</p>
      </div>
    </body>
    </html>
  `;
  
  res.setHeader('Content-Type', 'text/html');
  return res.status(200).send(htmlContent);
});

// CSRF vulnerability for email updates - PRESERVED BY DESIGN
app.post('/api/update-email', verifyToken, (req, res) => {
  const { email } = req.body;
  const userId = req.user.id;
  
  // VULNERABLE BY DESIGN: No CSRF token validation
  // This can be exploited with a form on an attacker's site
  db.run(
    'UPDATE users SET email = ? WHERE id = ?',
    [email, userId],
    function(err) {
      if (err) {
        return res.status(500).json({ error: 'Failed to update email' });
      }
      
      return res.status(200).json({
        success: true,
        message: 'Email updated successfully'
      });
    }
  );
});

// Race condition vulnerability - PRESERVED BY DESIGN
app.post('/api/quick-transfer', verifyToken, async (req, res) => {
  const { to, amount } = req.body;
  const from = req.user.id;
  
  // Parse amount as float
  const parsedAmount = parseFloat(amount);
  
  if (isNaN(parsedAmount) || parsedAmount <= 0) {
    return res.status(400).json({ error: 'Invalid amount' });
  }
  
  console.log(`Transfer requested: $${parsedAmount} from user ${from} to user ${to}`);
  
  // VULNERABLE BY DESIGN: No transaction lock - vulnerable to race conditions
  try {
    // Get sender's current balance
    db.get('SELECT balance FROM users WHERE id = ?', [from], (err, sender) => {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }
      
      if (!sender) {
        return res.status(404).json({ error: 'Sender not found' });
      }
      
      if (sender.balance < parsedAmount) {
        return res.status(400).json({ error: 'Insufficient funds' });
      }
      
      // Add an artificial delay to make race condition easier to exploit
      setTimeout(() => {
        // Update sender balance
        db.run(
          'UPDATE users SET balance = balance - ? WHERE id = ?',
          [parsedAmount, from],
          function(err) {
            if (err) {
              return res.status(500).json({ error: 'Failed to update sender balance' });
            }
            
            // Update receiver balance
            db.run(
              'UPDATE users SET balance = balance + ? WHERE id = ?',
              [parsedAmount, to],
              function(err) {
                if (err) {
                  return res.status(500).json({ error: 'Failed to update receiver balance' });
                }
                
                // Create transaction record
                const date = new Date().toISOString();
                db.run(
                  'INSERT INTO transactions (sender_id, receiver_id, amount, date, note) VALUES (?, ?, ?, ?, ?)',
                  [from, to, parsedAmount, date, 'Quick transfer'],
                  function(err) {
                    if (err) {
                      return res.status(500).json({ error: 'Failed to record transaction' });
                    }
                    
                    return res.status(200).json({
                      success: true,
                      message: 'Transfer successful',
                      newBalance: sender.balance - parsedAmount
                    });
                  }
                );
              }
            );
          }
        );
      }, 500); // 500ms delay to make race condition exploitable
    });
  } catch (error) {
    return res.status(500).json({ error: 'Transfer failed' });
  }
});

// Prototype pollution vulnerability - PRESERVED BY DESIGN
app.post('/api/merge-settings', verifyToken, (req, res) => {
  const userSettings = req.body;
  
  // Validate if the input is an object
  if (!userSettings || typeof userSettings !== 'object') {
    return res.status(400).json({ error: 'Settings must be an object' });
  }
  
  console.log('Merging user settings:', userSettings);
  
  // Get current user settings from database
  db.get('SELECT settings FROM user_settings WHERE user_id = ?', [req.user.id], (err, row) => {
    let currentSettings = {};
    
    if (row && row.settings) {
      try {
        currentSettings = JSON.parse(row.settings);
      } catch (e) {
        console.error('Error parsing settings:', e);
      }
    }
    
    // VULNERABLE BY DESIGN: Unsafe recursive merge that allows prototype pollution
    function unsafeMerge(target, source) {
      for (const key in source) {
        if (source[key] && typeof source[key] === 'object') {
          if (!target[key]) target[key] = {};
          unsafeMerge(target[key], source[key]);
        } else {
          target[key] = source[key];
        }
      }
      return target;
    }
    
    // Perform the unsafe merge
    const mergedSettings = unsafeMerge(currentSettings, userSettings);
    
    // Save merged settings back to database
    const settingsStr = JSON.stringify(mergedSettings);
    
    db.run(
      'INSERT OR REPLACE INTO user_settings (user_id, settings) VALUES (?, ?)',
      [req.user.id, settingsStr],
      function(err) {
        if (err) {
          return res.status(500).json({ error: 'Failed to save settings' });
        }
        
        return res.status(200).json({
          success: true,
          message: 'Settings updated successfully',
          settings: mergedSettings
        });
      }
    );
  });
});

// API for checking if user is admin - vulnerable to prototype pollution
app.get('/api/check-admin', verifyToken, (req, res) => {
  // VULNERABLE BY DESIGN: This endpoint is affected by prototype pollution
  // If Object.prototype.isAdmin has been polluted, this will return true
  const isAdmin = req.user.role === 'admin' || {};  // The empty object can be polluted
  
  return res.status(200).json({
    admin: isAdmin,
    message: isAdmin ? 'User is admin' : 'User is not admin'
  });
});

// Theme setting endpoint - demonstrates a normal operation for the cookie functionality
app.post('/api/set-theme', verifyToken, (req, res) => {
  const { theme } = req.body;
  
  if (!theme) {
    return res.status(400).json({ message: 'Theme name is required' });
  }
  
  // Set a cookie - this will later be used in the vulnerable endpoint
  res.cookie('theme', theme, { 
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    httpOnly: true 
  });
  
  return res.status(200).json({ 
    success: true, 
    message: 'Theme set successfully',
    note: 'Your theme preference has been saved as a cookie'
  });
});

// Endpoint to set a theme via direct cookie manipulation - helpful for testing
app.get('/api/theme/:name', (req, res) => {
  const theme = req.params.name;
  
  // Set a cookie directly - makes it easier to test the vulnerability
  res.cookie('theme', theme, { 
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    httpOnly: true 
  });
  
  return res.status(200).json({ 
    success: true, 
    message: `Theme cookie set to: ${theme}`,
    hint: 'Try visiting /api/user-preferences to see how this cookie is used'
  });
});

// Enable cookie setting through an HTML form
app.get('/api/cookie-form', (req, res) => {
  const html = `
    <!DOCTYPE html>
    <html>
    <head>
      <title>Set Theme Cookie</title>
    </head>
    <body>
      <h1>Set Theme Cookie</h1>
      <p>This form allows you to set the theme cookie directly. You can use this to test the SQL injection vulnerability.</p>
      
      <form action="/api/theme-form-submit" method="post">
        <label for="theme">Theme Value:</label>
        <input type="text" id="theme" name="theme" value="dark">
        <br><br>
        <p><strong>SQL Injection Examples:</strong></p>
        <ul>
          <li><code>dark' UNION SELECT 1,2,3--</code></li>
          <li><code>dark' UNION SELECT username,password,email FROM users--</code></li>
        </ul>
        <br>
        <input type="submit" value="Set Cookie">
      </form>
    </body>
    </html>
  `;
  
  res.setHeader('Content-Type', 'text/html');
  return res.status(200).send(html);
});

// Handle the form submission
app.post('/api/theme-form-submit', (req, res) => {
  const { theme } = req.body;
  
  if (!theme) {
    return res.status(400).send('Theme is required');
  }
  
  // Set the cookie
  res.cookie('theme', theme, { 
    maxAge: 24 * 60 * 60 * 1000, 
    httpOnly: true 
  });
  
  // Redirect to the vulnerable endpoint
  res.redirect('/api/user-preferences');
});

// SSRF vulnerability - ENHANCED BY DESIGN
app.get('/api/proxy', verifyToken, (req, res) => {
  const { url } = req.query;
  
  if (!url) {
    return res.status(400).json({ 
      error: 'URL parameter is required',
      example: '/api/proxy?url=https://api.github.com/users'
    });
  }
  
  console.log(`Proxy request to: ${url}`);
  
  // VULNERABLE BY DESIGN: Support for file:// protocol
  if (url.startsWith('file://')) {
    try {
      // Extract the file path from the URL
      const filePath = url.substring(7);
      
      // Read the file
      const fileContent = fs.readFileSync(filePath, 'utf8');
      
      // Send the file content as response
      return res.status(200).send(fileContent);
    } catch (error) {
      return res.status(500).json({ 
        error: 'File read error', 
        message: error.message
      });
    }
  }
  
  // VULNERABLE BY DESIGN: No validation of URL - allows access to internal resources
  fetch(url)
    .then(response => response.text())
    .then(data => {
      res.setHeader('Content-Type', 'text/plain');
      return res.status(200).send(data);
    })
    .catch(error => {
      return res.status(500).json({ error: 'Failed to fetch URL' });
    });
});

// Start the server
app.listen(PORT, () => {
  console.log(`DarkVault app running on port ${PORT}`);
  console.log(`WARNING: This application contains intentional security vulnerabilities!`);
  console.log(`It is intended for educational purposes only.`);
  console.log(`Error logs will be written to logs/error.log`);
  
  // Bots disabled
  // setupAdminBot();
  // setupHeadlessFeedbackBot();
}); 