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

// Bodyparser setup with high limit
app.use(bodyParser.json({ limit: '50mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '50mb' }));

// Serve static files
app.use(express.static(path.join(__dirname, 'public')));

// Vulnerable file upload configuration
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    // Modified: Now we check for a secret token that reveals a hidden upload path
    // This secret must be found through another vulnerability first
    const secretPath = req.headers['x-upload-path'] || '';
    
    // Create a secret directory for executable uploads that must be discovered
    // Only files uploaded to this path will be executable
    if (!fs.existsSync('uploads/executable')) {
      fs.mkdirSync('uploads/executable', { recursive: true });
    }
    
    // Basic uploads go to regular directory, uploads with the secret token go to executable directory
    if (secretPath === 'executable_7bc93a' && req.query.xMode === 'true') {
      cb(null, 'uploads/executable/');
      
      // Store this progress in the user's exploit chain status
      if (req.user) {
        req.user.exploitStage = 'upload_success';
        // Set a flag that can be checked by the command injection vulnerability
        if (req.user.role === 'admin' || req.user.role === 'bot') {
          req.user.exploitStage = 'command_ready';
        }
      }
    } else {
      cb(null, 'uploads/');
    }
  },
  filename: function (req, file, cb) {
    // Still vulnerable to path traversal, but prevents server crashes
    // This is intentionally vulnerable for educational purposes
    let originalname = file.originalname;
    // Only trim null bytes at the end which can cause crashes
    if (originalname.includes('\0')) {
      console.log('Potentially malicious file with null byte detected:', originalname);
    }
    cb(null, originalname);
  }
});

// Note: restrictedExtensions is only enforced for the normal upload directory
// This creates a multi-stage challenge - first discover the secret directory,
// then you can upload any file type
const restrictedExtensions = ['.php', '.js', '.exe', '.jsp', '.asp'];

const upload = multer({ 
  storage: storage,
  fileFilter: function(req, file, cb) {
    // Modified: Basic file extension filtering for normal uploads
    // But files can still be uploaded to the executable directory if the secret is known
    const secretPath = req.headers['x-upload-path'] || '';
    const ext = path.extname(file.originalname).toLowerCase();
    
    if (secretPath === 'executable_7bc93a' && req.query.xMode === 'true') {
      // Allow any file if the secret path is used
      return cb(null, true);
    } else if (restrictedExtensions.includes(ext)) {
      // Block dangerous extensions for normal uploads
      return cb(null, false);
    }
    
    return cb(null, true);
  }
});

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
  
  // New table to track exploit chain progress
  db.run(`CREATE TABLE IF NOT EXISTS exploit_chain (
    user_id INTEGER PRIMARY KEY,
    stage TEXT DEFAULT 'not_started',
    discovered_secrets TEXT,
    last_updated TEXT
  )`);
  
  // Create secrets table for chain requirements
  db.run(`CREATE TABLE IF NOT EXISTS secrets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key_name TEXT UNIQUE,
    key_value TEXT
  )`);
  
  // Insert initial secrets
  db.get("SELECT * FROM secrets WHERE key_name = 'chain_key'", (err, row) => {
    if (!row) {
      db.run("INSERT INTO secrets (key_name, key_value) VALUES ('chain_key', 'chain_9a74c8')");
      db.run("INSERT INTO secrets (key_name, key_value) VALUES ('idor_token', 'idor_access_9d731b')");
    }
  });

  // Insert admin and test users if they don't exist
  db.get("SELECT * FROM users WHERE username = 'admin'", (err, row) => {
    if (!row) {
      // Plaintext password storage
      db.run(`INSERT INTO users (username, password, email, role, balance) VALUES ("admin", "admin123", "admin@darkvault.com", "admin", 100000.00)`);
      db.run(`INSERT INTO users (username, password, email, role) VALUES ("alice", "password123", "alice@example.com", "user")`);
      db.run(`INSERT INTO users (username, password, email, role) VALUES ("bob", "bobpassword", "bob@example.com", "user")`);
      
      // Add bot users with restricted permissions
      db.run(`INSERT INTO users (username, password, email, role) VALUES ("admin_message_bot", "botpassword1", "message_bot@darkvault.com", "bot")`);
      db.run(`INSERT INTO users (username, password, email, role) VALUES ("admin_feedback_bot", "botpassword2", "feedback_bot@darkvault.com", "bot")`);
      
      console.log("Added default users and bot users");
      
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
  
  // Modified: SQL injection now requires knowledge of a secret prefix
  // Basic SQL injection like "admin" --" won't work anymore
  // Added requirement for a specific x-chain-key header that can be found elsewhere in the app
  const chainKey = req.headers['x-chain-key'] || '';
  
  // Log attempt for debugging
  console.log(`Login attempt: ${username}, chain key: ${chainKey}`);
  
  // Vulnerable SQL query - now requires the chain key prefix
  // Example exploit: username = "chain_9a74c8" OR username = "admin" --"
  // The "chain_9a74c8" value must be discovered elsewhere in the application
  const query = `SELECT * FROM users WHERE (username = "${username}" AND password = "${password}") OR (username = "${username}" AND "${chainKey}" = "chain_9a74c8")`;
  
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
      
      // No cookie - only return the token in response
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
  const token = req.headers['authorization'];
  
  if (!token) {
    // Modified: Now requires both debug AND a special HTTP header
    // This creates a prerequisite chain where you need information from somewhere else
    if (req.query.debug === 'true' && req.headers['x-exploit-chain'] === 'stage1') {
      db.get("SELECT id, username, role FROM users WHERE username = 'admin_message_bot'", (err, botUser) => {
        if (err || !botUser) {
          return res.status(401).json({ message: 'Debug mode failed to authenticate' });
        }
        
        // Use the bot user for debug mode
        req.user = { 
          id: botUser.id, 
          username: botUser.username, 
          role: botUser.role,
          botType: 'message_bot'
        };
        
        // Load exploit chain progress for this bot user
        loadExploitChainProgress(req, res, next);
      });
    } else {
      return res.status(401).json({ message: 'No token provided' });
    }
  } else {
    try {
      // Verify the token
      const decoded = jwt.verify(token.replace('Bearer ', ''), JWT_SECRET);
      
      // Set user info from token
      req.user = decoded;
      
      // Load exploit chain progress for this user
      loadExploitChainProgress(req, res, next);
      
    } catch (err) {
      return res.status(401).json({ message: 'Invalid token' });
    }
  }
};

// Helper function to load exploit chain progress
function loadExploitChainProgress(req, res, next) {
  if (!req.user || !req.user.id) {
    return next();
  }
  
  // Get the exploit chain progress for this user
  db.get(`SELECT * FROM exploit_chain WHERE user_id = ?`, [req.user.id], (err, chain) => {
    if (err) {
      console.error('Error loading exploit chain:', err);
    }
    
    if (chain) {
      // Set the exploit stage on the user object
      req.user.exploitStage = chain.stage;
      
      // Parse the discovered secrets if any
      try {
        req.user.discoveredSecrets = JSON.parse(chain.discovered_secrets || '{}');
      } catch (e) {
        req.user.discoveredSecrets = {};
      }
    } else {
      // Initialize with default values
      req.user.exploitStage = 'not_started';
      req.user.discoveredSecrets = {};
      
      // Create a new record for this user
      const now = new Date().toISOString();
      db.run(
        `INSERT INTO exploit_chain (user_id, stage, discovered_secrets, last_updated) VALUES (?, ?, ?, ?)`,
        [req.user.id, 'not_started', '{}', now]
      );
    }
    
    // Add a function to update the exploit chain progress
    req.user.updateExploitStage = function(newStage, discoveredSecret = null) {
      // Update the stage
      req.user.exploitStage = newStage;
      
      // Add the discovered secret if provided
      if (discoveredSecret) {
        req.user.discoveredSecrets[discoveredSecret.key] = discoveredSecret.value;
      }
      
      // Update in database
      const now = new Date().toISOString();
      db.run(
        `UPDATE exploit_chain SET stage = ?, discovered_secrets = ?, last_updated = ? WHERE user_id = ?`,
        [newStage, JSON.stringify(req.user.discoveredSecrets), now, req.user.id]
      );
    };
    
    return next();
  });
}

// Get user profile - Information disclosure
app.get('/api/users/:id', verifyToken, (req, res) => {
  const id = req.params.id;
  
  // Modified: Now implement a chain-based IDOR that requires specific knowledge
  // Users can only access their own profile by default
  // To access other profiles, they need to have completed other steps in the chain
  const canAccessAnyProfile = 
    // They've found the chain key through SQL injection
    req.user.exploitStage === 'found_chain_key' ||
    // Or they have the secret token
    req.headers['x-profile-access'] === 'idor_access_9d731b' ||
    // Or they're an admin
    req.user.role === 'admin' ||
    // Or they're accessing their own profile
    req.user.id.toString() === id;
  
  if (!canAccessAnyProfile) {
    // If they're not authorized but have added a special query param, reveal a hint
    if (req.query.access === 'true') {
      return res.status(403).json({ 
        message: 'Access denied',
        hint: 'You need to find the x-profile-access header value first. Try SQL injection on the search endpoint.'
      });
    }
    return res.status(403).json({ message: 'Unauthorized' });
  }
  
  // If we get here, the user is allowed to access the profile
  // Still vulnerable to IDOR, but requires specific chain knowledge
  db.get(`SELECT * FROM users WHERE id = ${id}`, (err, user) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    // If this is a successful IDOR exploitation of another user's profile
    // (accessing a profile that isn't your own), update the exploit stage
    if (req.user.id.toString() !== id) {
      // They've successfully exploited IDOR
      if (req.user) {
        req.user.updateExploitStage('idor_success', {
          key: 'idor_success',
          value: 'true'
        });
        
        // If they've also completed the upload step, add the command stage hint
        if (req.user.exploitStage === 'upload_success') {
          req.user.updateExploitStage('command_ready');
        }
      }
      
      // Reveal the special token through IDOR
      db.run("INSERT INTO secrets (key_name, key_value) VALUES ('x_exploit_token', 'cmd_exploit_7b491c3') ON CONFLICT(key_name) DO NOTHING");
    }
    
    // Add bot secrets to the response if appropriate
    if (user.role === 'bot' && (req.user.role === 'admin' || req.user.id === user.id)) {
      user.secretInfo = 'This bot is used for automated admin tasks. It has elevated privileges.';
      if (user.username === 'admin_message_bot') {
        user.secretKey = 'bot_key_8e4a1c';
        user.botType = 'message_bot';
      }
    }
    
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
  // Only allow admin or bot users
  if (req.user.role !== 'admin' && req.user.role !== 'bot') {
    return res.status(403).json({ message: 'Unauthorized' });
  }
  
  const { report_name } = req.body;
  
  // Modified: Command injection now requires a special token in the request
  // that would need to be found through a previous exploit
  // Also requires that the user has accessed a specific API endpoint first
  const exploit_token = req.headers['x-exploit-token'] || '';
  
  // Create scripts directory if it doesn't exist
  if (!fs.existsSync('scripts/reports')) {
    fs.mkdirSync('scripts/reports', { recursive: true });
  }
  
  // Check if the user has discovered the secret token elsewhere in the app
  // This requires chaining exploits - first find the token, then use it here
  if (exploit_token !== 'cmd_exploit_7b491c3' && !report_name.includes('cmd_exploit_7b491c3')) {
    // If token is missing, create a file with just a console.log
    fs.writeFileSync(`scripts/reports/${report_name}.js`, 'console.log("Report generated with no data");');
    
    // Run the harmless script instead - this prevents direct command injection
    exec(`node scripts/reports/${report_name}.js`, (error, stdout, stderr) => {
      if (error) {
        return res.status(500).json({ error: error.message });
      }
      return res.status(200).json({ output: stdout });
    });
  } else {
    // If correct token found, command injection is possible - but still needs certain prerequisites
    // Check if the user has triggered the prerequisite step
    const hasPrerequisite = req.user.exploitStage === 'command_ready' || 
                          report_name.startsWith('safe_') || 
                          req.headers['x-exploit-stage'] === 'command_ready';
    
    if (hasPrerequisite) {
      // Vulnerable to command injection
      exec(`node scripts/reports/${report_name}.js`, (error, stdout, stderr) => {
        if (error) {
          return res.status(500).json({ error: error.message });
        }
        
        // Mark the exploit chain as complete when command injection succeeds
        if (req.user) {
          req.user.updateExploitStage('command_success', {
            key: 'command_injection',
            value: 'success'
          });
        }
        
        return res.status(200).json({ output: stdout });
      });
    } else {
      return res.status(403).json({ 
        message: 'Exploit chain incomplete', 
        hint: 'You need to complete a prerequisite step first'
      });
    }
  }
});

// File upload endpoint - vulnerable to unrestricted file upload
app.post('/api/upload', verifyToken, upload.single('file'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ message: 'No file uploaded' });
  }
  
  // Modified: Now provides different responses based on upload location
  // This gives hints about the secret upload path when appropriate
  const secretPath = req.headers['x-upload-path'] || '';
  const isExecutableDir = secretPath === 'executable_7bc93a' && req.query.xMode === 'true';
  
  // Log the upload attempt
  console.log(`File upload: ${req.file.originalname} to path: ${isExecutableDir ? 'executable' : 'regular'}`);
  
  // This reveals a hint about the command injection token if the file was uploaded to the executable directory
  // Users must chain these vulnerabilities to progress
  if (isExecutableDir) {
    // Executable directory uploads can lead to command execution
    // Store a value that unlocks the next step of the chain
    if (req.user) {
      req.user.updateExploitStage('upload_success', {
        key: 'upload_success',
        value: 'true'
      });
    }
    
    // Determine if this is a PHP file that might enable further exploitation
    const ext = path.extname(req.file.originalname).toLowerCase();
    let nextHint = '';
    
    if (ext === '.php') {
      // Provide a hint to the next stage of the attack chain
      nextHint = 'File can execute commands. Command injection hint: cmd_exploit_7b491c3';
    }
    
    return res.status(200).json({
      success: true,
      message: 'File uploaded to executable directory',
      file_path: `/uploads/executable/${req.file.originalname}`,
      hint: nextHint
    });
  } else {
    // Regular upload directory can't execute code
    return res.status(200).json({
      success: true,
      message: 'File uploaded successfully',
      file_path: '/uploads/' + req.file.originalname
    });
  }
});

// Search for users - XSS vulnerable
app.get('/api/search', verifyToken, (req, res) => {
  // Validate the term exists
  if (!req.query.term) {
    return res.status(400).json({ message: 'Search term is required' });
  }
  
  const term = req.query.term;
  
  // Modified: Added a secret table with the chain key
  // User must first perform SQL injection on search to find this secret
  // Then use it to exploit the login endpoint
  db.run("CREATE TABLE IF NOT EXISTS secrets (id INTEGER PRIMARY KEY, key_name TEXT, key_value TEXT)", () => {
    // Insert the secret key if it doesn't exist
    db.get("SELECT * FROM secrets WHERE key_name = 'chain_key'", (err, row) => {
      if (!row) {
        db.run("INSERT INTO secrets (key_name, key_value) VALUES ('chain_key', 'chain_9a74c8')");
      }
    });
  });
  
  // Modified: Still vulnerable to SQL injection, but now contains clues about the secret chain
  // Example exploit: " UNION SELECT id, key_name, key_value FROM secrets --
  console.log('Search term:', term);
  
  try {
    // Vulnerable SQL query - extremely vulnerable to SQL injection
    // This can be used to discover the chain_key needed for the login SQL injection
    const query = `SELECT id, username, email FROM users WHERE username LIKE "%${term}%" OR email LIKE "%${term}%"`;
    
    db.all(query, (err, users) => {
      if (err) {
        console.error('Search error:', err.message);
        return res.status(500).json({ error: err.message });
      }
      
      // Check if this is a successful exploit attempt that found the secret
      const foundSecret = query.toLowerCase().includes('secrets') && users.some(u => u.key_name === 'chain_key');
      
      // If they've successfully found the secret through SQL injection, provide a hint to the next step
      if (foundSecret) {
        console.log('User discovered secret through SQL injection');
        // Update the chain status for this user
        if (req.user) {
          req.user.updateExploitStage('found_chain_key', {
            key: 'chain_key',
            value: 'chain_9a74c8'
          });
          
          // Reveal the upload path secret as well if they've gotten this far
          if (!users.some(u => u.key_value && u.key_value.includes('executable'))) {
            // Add a hint about the upload path
            db.run("INSERT INTO secrets (key_name, key_value) VALUES ('upload_path', 'executable_7bc93a')");
          }
        }
      }
      
      return res.status(200).json({
        success: true, 
        users: users,
        // Add a hint if they're close but didn't quite get it
        hint: query.toLowerCase().includes('union') && !foundSecret ? 
          "You're on the right track. Try looking for other tables besides 'users'." : ""
      });
    });
  } catch (error) {
    console.error('Search error:', error.message);
    return res.status(500).json({ error: error.message });
  }
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

// Add a blind second-order SQL injection vulnerability in profile updates
app.post('/api/users/update-profile', verifyToken, (req, res) => {
  const { bio, website, location } = req.body;
  const userId = req.user.id;
  
  // Protect FLAG field from being modified
  // Only allow specific fields to be updated
  
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

// New endpoint to show exploit chain progress and hints
app.get('/api/exploit-status', verifyToken, (req, res) => {
  // Extract the current user's progress in the exploit chain
  const stage = req.user.exploitStage || 'not_started';
  
  // Define the stages of the exploit chain and corresponding hints
  const stages = {
    'not_started': {
      status: 'You have not started the exploit chain yet.',
      hint: 'Try exploring the search functionality with SQL injection. Look for secrets.',
      completion: '0%'
    },
    'found_chain_key': {
      status: 'You have discovered the chain key through SQL injection!',
      hint: 'Try using this key with the login endpoint. You need to add a special header.',
      completion: '20%'
    },
    'idor_success': {
      status: 'You have successfully exploited IDOR vulnerability!',
      hint: 'Look for secret tokens that can help with file uploads or command injection.',
      completion: '40%'
    },
    'upload_success': {
      status: 'You have successfully uploaded to the executable directory!',
      hint: 'Your file can now execute. Try finding the command injection token.',
      completion: '60%'
    },
    'command_ready': {
      status: 'You have all prerequisites for command injection!',
      hint: 'Use your token with the admin report endpoint to execute commands.',
      completion: '80%'
    },
    'command_success': {
      status: 'You have successfully exploited command injection!',
      hint: 'You have completed the full exploit chain. Congratulations!',
      completion: '100%'
    }
  };
  
  // Return the current status and appropriate hint
  const currentStage = stages[stage] || stages.not_started;
  return res.status(200).json({
    current_stage: stage,
    status: currentStage.status,
    hint: currentStage.hint,
    completion: currentStage.completion,
    chain_steps: [
      'SQL Injection to find secrets',
      'Login bypass with chain key',
      'IDOR to access other profiles',
      'File upload to executable directory',
      'Command injection with proper token'
    ]
  });
});

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