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
const UglifyJS = require('uglify-js');
const crypto = require('crypto');
const { graphqlHTTP } = require('express-graphql');
const { buildSchema } = require('graphql');
const lodash = require('lodash');
const { errorHandler, validateRequestBody, handleLargePayloads } = require('./error-handler');

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

// Add middleware to serve obfuscated JS in production
if (process.env.NODE_ENV === 'production') {
  // Middleware to intercept .js file requests
  app.use((req, res, next) => {
    if (req.path.endsWith('.js')) {
      const filePath = path.join(__dirname, 'public', req.path);
      try {
        const source = fs.readFileSync(filePath, 'utf8');
        // Obfuscate the JS file
        const result = UglifyJS.minify(source, {
          mangle: true,
          compress: true
        });
        if (result.error) throw result.error;
        
        res.type('application/javascript');
        res.send(result.code);
      } catch (err) {
        next(); // Let static middleware handle it if there's an error
      }
    } else {
      next();
    }
  });
}

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

// Add request validation middleware
app.use(validateRequestBody);
app.use(handleLargePayloads);

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

// ----------------
// GraphQL Vulnerability Setup
// ----------------

// Define GraphQL schema - deliberately missing proper authorization controls
const graphqlSchema = buildSchema(`
  type User {
    id: ID!
    username: String!
    email: String
    balance: Float
    role: String
    sessionData: String
    password: String
  }
  
  type Transaction {
    id: ID!
    from: User
    to: User
    amount: Float
    date: String
    note: String
  }
  
  type Query {
    user(id: ID!): User
    users: [User]
    transactions(limit: Int): [Transaction]
    balances: [User]
  }
`);

// GraphQL resolvers with missing access controls
const graphqlResolvers = {
  // Vulnerable resolver - no proper authorization checks
  user: ({ id }) => {
    return new Promise((resolve, reject) => {
      db.get('SELECT * FROM users WHERE id = ?', [id], (err, row) => {
        if (err) {
          reject(err);
          return;
        }
        
        // Log potential attack attempt
        console.log(`GraphQL user query for ID: ${id}`);
        
        // Track the query in the vulnerability tracking system
        const systemId = global.exploitContext ? global.exploitContext.systemId : null;
        const username = global.exploitContext ? global.exploitContext.username : 'anonymous';
        
        if (systemId) {
          updateLeaderboard(systemId, username, 'graphql_direct_user_query');
        }
        
        resolve(row);
      });
    });
  },
  
  // Intentionally vulnerable - returns all users including admin accounts and passwords
  users: () => {
    return new Promise((resolve, reject) => {
      // Check if user might have bypassed GraphQL access controls
      const isAdminCheck = {} // an empty object that can be affected by prototype pollution
      
      // If user appears to be admin due to prototype pollution, track it
      if (isAdminCheck.canAccessGraphQL) {
        if (global.exploitContext && global.exploitContext.systemId) {
          updateLeaderboard(global.exploitContext.systemId, 
            global.exploitContext.username || 'anonymous', 
            'graphql_pollution_access_success');
        }
      }
      
      db.all('SELECT * FROM users', (err, rows) => {
        if (err) {
          reject(err);
          return;
        }
        
        // Log potential attack - fetching all users
        console.log('GraphQL users query executed - potential data exfiltration attempt');
        
        // Track the mass data query in the exploitation tracking system
        if (global.exploitContext && global.exploitContext.systemId) {
          updateLeaderboard(global.exploitContext.systemId, 
            global.exploitContext.username || 'anonymous', 
            'graphql_mass_data_query');
        }
        
        // Add session data for users to facilitate token extraction
        rows.forEach(user => {
          // Create a fake session token for the user - in a real app this would be dangerous!
          user.sessionData = jwt.sign({ id: user.id, username: user.username, role: user.role }, 
                                      JWT_SECRET, { expiresIn: '1h' });
        });
        
        resolve(rows);
      });
    });
  },
  
  // Vulnerable resolver for transactions - no authorization or rate limiting
  transactions: ({ limit = 100 }) => {
    return new Promise((resolve, reject) => {
      // Deliberately vulnerable - allows unlimited transaction data retrieval
      // with no ownership checks
      db.all('SELECT * FROM transactions LIMIT ?', [limit], async (err, rows) => {
        if (err) {
          reject(err);
          return;
        }
        
        // Log potential attack
        console.log(`GraphQL transactions query executed with limit: ${limit}`);
        
        // Track the transaction data query with more robust tracking
        const systemId = global.exploitContext ? global.exploitContext.systemId : null;
        const username = global.exploitContext ? global.exploitContext.username : 'anonymous';
        
        if (systemId) {
          updateLeaderboard(systemId, username, 'graphql_transaction_exfiltration', { 
            limit: limit,
            timestamp: new Date().toISOString()
          });
          
          // If they're requesting a large number of transactions, consider it mass data exfiltration
          if (limit > 50) {
            updateLeaderboard(systemId, username, 'graphql_mass_data_query');
          }
        }
        
        // Hydrate the from/to fields with user data
        for (const tx of rows) {
          if (tx.from_id) {
            tx.from = await new Promise((resolve) => {
              db.get('SELECT * FROM users WHERE id = ?', [tx.from_id], (err, row) => {
                resolve(row || null);
              });
            });
          }
          
          if (tx.to_id) {
            tx.to = await new Promise((resolve) => {
              db.get('SELECT * FROM users WHERE id = ?', [tx.to_id], (err, row) => {
                resolve(row || null);
              });
            });
          }
        }
        
        resolve(rows);
      });
    });
  }
};

// Setup GraphQL endpoint with introspection enabled (vulnerable on purpose)
// No authentication check - relying solely on the frontend to prevent access
app.use('/api/graphql', (req, res, next) => {
  // Store request context for vulnerability tracking
  global.exploitContext = {
    systemId: req.headers['x-system-id'] || generateSystemId(req),
    username: req.user ? req.user.username : 'anonymous'
  };
  
  // Check if this is a batch query attempt (potential rate limiting bypass)
  if (Array.isArray(req.body)) {
    console.log('GraphQL batch query detected - potential rate limiting bypass');
    updateLeaderboard(global.exploitContext.systemId, 
      global.exploitContext.username, 
      'graphql_batch_attack');
    
    // Still allow it to proceed (vulnerable by design)
  }
  
  // Check for introspection queries (schema mapping attempts)
  if (req.body && typeof req.body.query === 'string' && 
      req.body.query.includes('__schema')) {
    console.log('GraphQL introspection query detected - potential schema mapping attempt');
    updateLeaderboard(global.exploitContext.systemId, 
      global.exploitContext.username, 
      'discovered_vulnerable_dependency');
  }
  
  next();
}, graphqlHTTP({
  schema: graphqlSchema,
  rootValue: graphqlResolvers,
  graphiql: true, // Enable GraphiQL interface - intentionally exposing schema
  customFormatErrorFn: (error) => {
    // Intentionally verbose error messages that leak implementation details
    return {
      message: error.message,
      locations: error.locations,
      stack: error.stack ? error.stack.split('\n') : [],
      path: error.path
    };
  }
}));

// Add the vulnerable user settings endpoint that's susceptible to prototype pollution
app.post('/api/user-settings', (req, res) => {
  const userSettings = req.body;
  
  // Check for potential prototype pollution attempts
  if (userSettings && userSettings.__proto__) {
    console.log('Potential prototype pollution attempt detected');
    
    // Track the prototype pollution attempt
    if (req.headers['x-system-id']) {
      updateLeaderboard(req.headers['x-system-id'], 
        req.user ? req.user.username : 'anonymous', 
        'client_side_pollution_success');
    }
  }
  
  // Vulnerable merge using lodash (intentionally outdated version)
  const mergedSettings = lodash.merge({}, userSettings);
  
  // Store settings in the user session
  if (req.user) {
    // In a real app, this would update a database
    console.log(`Updated settings for user ${req.user.username}`);
  }
  
  res.json({
    success: true,
    message: 'Settings updated successfully',
    settings: mergedSettings
  });
});

// Add endpoint to check if GraphQL access was successfully gained through prototype pollution
app.get('/api/check-graphql-access', (req, res) => {
  const testObj = {};
  
  if (testObj.canAccessGraphQL) {
    // Prototype pollution successful
    console.log('User appears to have GraphQL access via prototype pollution');
    
    // Track successful prototype pollution
    if (req.headers['x-system-id']) {
      updateLeaderboard(req.headers['x-system-id'], 
        req.user ? req.user.username : 'anonymous', 
        'graphql_access');
    }
    
    return res.json({
      success: true,
      message: 'You have successfully gained GraphQL access through prototype pollution!',
      hint: 'Now try accessing the /api/graphql endpoint to query sensitive data.'
    });
  }
  
  res.json({
    success: false,
    message: 'No GraphQL access detected.',
    hint: 'Try exploiting the prototype pollution vulnerability first.'
  });
});

// Add token validation endpoint for horizontal privilege escalation tracking
app.post('/api/validate-token', (req, res) => {
  const { token } = req.body;
  const systemId = req.headers['x-system-id'] || generateSystemId(req);
  
  if (!token) {
    return res.status(400).json({ success: false, message: 'No token provided' });
  }
  
  try {
    // Verify the token
    const decoded = jwt.verify(token, JWT_SECRET);
    
    // Check if this token belongs to someone else (horizontal privilege escalation)
    if (req.user && decoded.id !== req.user.id) {
      console.log(`Potential token theft detected! User ${req.user.username} using token for user ID ${decoded.id}`);
      
      // Track successful token extraction and account compromise
      updateLeaderboard(systemId, req.user.username, 'token_extraction_success', {
        compromised_user_id: decoded.id,
        compromised_username: decoded.username
      });
      
      // Track unique compromised accounts for this system ID
      db.all(
        `SELECT DISTINCT exploit_details FROM exploitation_tracking 
         WHERE system_id = ? AND exploit_type = 'token_extraction_success'`,
        [systemId],
        (err, rows) => {
          if (err) {
            console.error("Error checking compromised accounts:", err);
            return;
          }
          
          // Parse the JSON to count unique compromised accounts
          let uniqueCompromisedAccounts = new Set();
          rows.forEach(row => {
            try {
              const details = JSON.parse(row.exploit_details || "{}");
              if (details.compromised_user_id) {
                uniqueCompromisedAccounts.add(details.compromised_user_id);
              }
            } catch (e) {
              console.error("Error parsing exploit details:", e);
            }
          });
          
          // If 3 or more accounts have been compromised, record mass compromise
          if (uniqueCompromisedAccounts.size >= 3) {
            updateLeaderboard(systemId, req.user.username, 'mass_compromise_success', {
              total_compromised: uniqueCompromisedAccounts.size,
              accounts: Array.from(uniqueCompromisedAccounts)
            });
          }
        }
      );
      
      return res.json({
        success: true,
        message: 'Horizontal privilege escalation detected!',
        userCompromised: decoded.username,
        hint: 'You have successfully used another user\'s token.'
      });
    }
    
    // Normal case - user's own token
    return res.json({
      success: true,
      userId: decoded.id,
      username: decoded.username,
      role: decoded.role
    });
    
  } catch (error) {
    return res.status(401).json({ success: false, message: 'Invalid token' });
  }
});

// Create necessary database tables
function setupDatabase() {
  console.log('Setting up database...');
  
  // Create users table first, then create other tables
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE,
    password TEXT,
    email TEXT,
    role TEXT DEFAULT 'user',
    balance REAL DEFAULT 1000.0,
    bio TEXT,
    website TEXT,
    location TEXT,
    last_login TEXT
  )`, function(err) {
    if (err) {
      console.error('Error creating users table:', err.message);
      return;
    }
    console.log('Users table created successfully');
    
    // Create transactions table
    db.run(`CREATE TABLE IF NOT EXISTS transactions (
      id INTEGER PRIMARY KEY,
      sender_id INTEGER,
      receiver_id INTEGER,
      amount REAL,
      date TEXT,
      note TEXT
    )`, function(err) {
      if (err) {
        console.error('Error creating transactions table:', err.message);
        return;
      }
      console.log('Transactions table created successfully');
      
      // Create admin messages table
      db.run(`CREATE TABLE IF NOT EXISTS admin_messages (
        id INTEGER PRIMARY KEY,
        user_id INTEGER,
        message TEXT,
        date TEXT
      )`, function(err) {
        if (err) {
          console.error('Error creating admin_messages table:', err.message);
          return;
        }
        console.log('Admin messages table created successfully');
        
        // Create exploit_chain table
        db.run(`CREATE TABLE IF NOT EXISTS exploit_chain (
          user_id INTEGER PRIMARY KEY,
          stage TEXT DEFAULT 'not_started',
          discovered_secrets TEXT,
          last_updated TEXT
        )`, function(err) {
          if (err) {
            console.error('Error creating exploit_chain table:', err.message);
            return;
          }
          console.log('Exploit chain table created successfully');
          
          // Create leaderboard table
          db.run(`CREATE TABLE IF NOT EXISTS leaderboard (
            id INTEGER PRIMARY KEY,
            system_id TEXT UNIQUE,
            username TEXT,
            score INTEGER DEFAULT 0,
            completed_vulns TEXT DEFAULT '{}',
            last_updated TEXT,
            first_seen TEXT
          )`, function(err) {
            if (err) {
              console.error('Error creating leaderboard table:', err.message);
              return;
            }
            console.log('Leaderboard table created successfully');
          
          // Create secrets table
          db.run(`CREATE TABLE IF NOT EXISTS secrets (
            id INTEGER PRIMARY KEY,
            key_name TEXT UNIQUE,
            key_value TEXT
          )`, function(err) {
            if (err) {
              console.error('Error creating secrets table:', err.message);
              return;
            }
            console.log('Secrets table created successfully');
            
            // Insert initial secrets
            db.get("SELECT * FROM secrets WHERE key_name = 'chain_key'", (err, row) => {
              if (!row) {
                db.run("INSERT INTO secrets (key_name, key_value) VALUES ('chain_key', 'chain_key')");
                db.run("INSERT INTO secrets (key_name, key_value) VALUES ('advanced_chain_key', 'chain_9a74c8')");
                db.run("INSERT INTO secrets (key_name, key_value) VALUES ('idor_token', 'access')");
                db.run("INSERT INTO secrets (key_name, key_value) VALUES ('x_exploit_token', 'cmd_token')");
              }
            });
            
            // Create themes table
            db.run(`CREATE TABLE IF NOT EXISTS themes (
              id INTEGER PRIMARY KEY,
              name TEXT UNIQUE,
              description TEXT,
              custom_css TEXT
            )`, function(err) {
              if (err) {
                console.error('Error creating themes table:', err.message);
                return;
              }
              
              // Insert default themes
              db.run("INSERT OR IGNORE INTO themes (name, description, custom_css) VALUES ('default', 'Default theme', 'body { background-color: white; }')");
              db.run("INSERT OR IGNORE INTO themes (name, description, custom_css) VALUES ('dark', 'Dark theme', 'body { background-color: #222; color: #eee; }')");
              db.run("INSERT OR IGNORE INTO themes (name, description, custom_css) VALUES ('light', 'Light theme', 'body { background-color: #f8f9fa; }')");
              console.log('Themes table created and populated');
              
              // Create user_settings table
              db.run(`CREATE TABLE IF NOT EXISTS user_settings (
                user_id INTEGER PRIMARY KEY,
                settings TEXT
              )`, function(err) {
                if (err) {
                  console.error('Error creating user_settings table:', err.message);
                  return;
                }
                console.log('User settings table created');
                
                // Create profile_updates table
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
                    return;
                  }
                  console.log('Profile updates table created');
                  
                  // Create feedback table
                  db.run(`CREATE TABLE IF NOT EXISTS feedback (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT,
                    message TEXT,
                    rating INTEGER,
                    date TEXT,
                    reviewed INTEGER DEFAULT 0
                  )`, function(err) {
                    if (err) {
                      console.error('Error creating feedback table:', err.message);
                      return;
                    }
                    console.log('Feedback table created');
                    
                    // Check if there are any users in the database first
                    db.get("SELECT COUNT(*) as count FROM users", (err, result) => {
                      if (err) {
                        console.error('Error checking users table:', err.message);
                        return;
                      }
                      
                      // Only insert users if the users table is empty
                      if (result.count === 0) {
                        console.log('Users table is empty, creating default users');
                        
                        // Insert admin user
                        db.run("INSERT INTO users (username, password, email, role, balance) VALUES ('admin', 'admin123', 'admin@darkvault.com', 'admin', 9999.99)");
                        console.log('Admin user created');
                        
                          // Insert only one regular user for testing
                          const user = { username: 'alice', password: 'password123', email: 'alice@example.com', role: 'user' };
                          db.run("INSERT INTO users (username, password, email, role, balance) VALUES (?, ?, ?, ?, ?)",
                            [user.username, user.password, user.email, user.role, 1000.0], 
                            function(err) {
                              if (err) {
                                console.error(`Error creating user ${user.username}:`, err.message);
                              } else {
                                console.log(`User ${user.username} created`);
                              }
                              console.log('Database setup completed successfully');
                            }
                          );
                      } else {
                        console.log('Users already exist in the database, skipping user creation');
                        console.log('Database setup completed successfully');
                      }
                      });
                    });
                  });
                });
              });
            });
          });
        });
      });
    });
  });
}

// Call setupDatabase at startup
setupDatabase();

// Middleware to log requests - information disclosure
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} [${req.method}] ${req.url} - Body:`, req.body);
  next();
});

// At the top of the file, add a helper to generate system IDs
function generateSystemId(req) {
  // Use a combination of IP, user agent, and a server secret to make it harder to spoof
  const ipAddress = req.ip || req.connection.remoteAddress;
  const userAgent = req.headers['user-agent'] || '';
  const serverSecret = 'darkVault-unique-identifier-salt';
  
  const dataToHash = `${ipAddress}|${userAgent}|${serverSecret}`;
  return crypto.createHash('sha256').update(dataToHash).digest('hex');
}

// Middleware to handle system ID verification and tracking
function trackSystem(req, res, next) {
  // Get or create a unique system ID
  const clientSystemId = req.cookies?.system_id;
  const generatedSystemId = generateSystemId(req);
  
  // Combine both for stronger identification - client provided + server calculated
  let combinedSystemId;
  
  if (clientSystemId) {
    // If client has a system ID cookie, use a combination
    combinedSystemId = crypto.createHash('sha256')
      .update(`${clientSystemId}|${generatedSystemId}`)
      .digest('hex');
    
    // Attach system ID to the request for later use
    req.systemId = combinedSystemId;
    next();
  } else {
    // If no client ID yet, generate one and set cookie
    const newClientId = crypto.randomUUID();
    combinedSystemId = crypto.createHash('sha256')
      .update(`${newClientId}|${generatedSystemId}`)
      .digest('hex');
    
    // Set a long-lived cookie
    res.cookie('system_id', newClientId, {
      maxAge: 10 * 365 * 24 * 60 * 60 * 1000, // 10 years
      httpOnly: true,
      sameSite: 'strict'
    });
    
    // Register this system ID in the leaderboard
    const now = new Date().toISOString();
    db.run(
      'INSERT OR IGNORE INTO leaderboard (system_id, score, completed_vulns, last_updated, first_seen) VALUES (?, 0, ?, ?, ?)',
      [combinedSystemId, '{}', now, now],
      (err) => {
        if (err) {
          console.error('Error registering system in leaderboard:', err.message);
        }
        
        // Attach system ID to the request for later use
        req.systemId = combinedSystemId;
        next();
      }
    );
  }
}

// Add the middleware after cookie parsing
app.use(trackSystem);

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
  
  // Use the safe query helper to prevent crashes during scanning
  safeSqliteQuery(db, 'get', query, [username, password], (err, user) => {
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
    try {
      safeSqliteQuery(db, 'run', 'UPDATE users SET last_login = ? WHERE id = ?', 
        [new Date().toISOString(), user.id], 
        function(err) {
          if (err) {
            // If there's an error updating last_login, just log it but don't fail the login
            console.warn('Warning: Could not update last_login:', err.message);
          }
        }
      );
    } catch (error) {
      console.warn('Warning: Exception when updating last_login:', error.message);
    }
    
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
  
  // Use safe SQLite query to prevent crashes during scanning
  safeSqliteQuery(db, 'run', query, [username, password, email], function(err, result) {
    if (err) {
      console.error('Registration error:', err.message);
      logError('Registration', err, { username, email });
      return res.status(500).json({ error: 'Registration failed' });
    }
    
    // In our wrapper, this.lastID isn't available, so use a generic user ID for response
    console.log(`User registered successfully: username=${username}`);
    return res.status(201).json({
      success: true,
      message: 'User registered successfully'
    });
  });
});

// Middleware for token verification - Keep the JWT vulnerability by design
const verifyToken = (req, res, next) => {
  const bearerHeader = req.headers['authorization'];
  
  if (!bearerHeader) {
    return res.status(401).json({ message: 'Access denied. No token provided.' });
  }
  
  // Handle various authorization header formats
  let token;
  if (bearerHeader.startsWith('Bearer ')) {
    token = bearerHeader.split(' ')[1];
  } else {
    token = bearerHeader;
  }
  
  const systemId = req.headers['x-system-id'] || generateSystemId(req);
  
  if (!token) {
    return res.status(401).json({ message: 'Access denied. Invalid token format.' });
  }
  
  try {
    // Track JWT token information access if this is the JWT info endpoint
    if (req.path === '/api/get-jwt-info') {
      updateLeaderboard(systemId, 'anonymous', 'jwt_info_access', {
        endpoint: req.path,
        method: req.method
      });
    }
    
    // First attempt to decode without verification (to check for tampering)
    let decodedWithoutVerification;
    try {
      // Check if token contains three parts (header.payload.signature)
      if (!token.includes('.')) {
        // Malformed token - handle gracefully
        return res.status(401).json({ message: 'Invalid token format.' });
      }
      
      decodedWithoutVerification = jwt.decode(token);
      
      // Track successful decoding
      if (decodedWithoutVerification) {
        updateLeaderboard(systemId, decodedWithoutVerification.username || 'anonymous', 'jwt_decode_success');
      }
      
      // Check for algorithm tampering
      const tokenParts = token.split('.');
      if (tokenParts.length === 3) {
        try {
          const headerStr = Buffer.from(tokenParts[0], 'base64').toString();
          const header = JSON.parse(headerStr);
          if (header.alg === 'none' || (header.alg === 'HS256' && decodedWithoutVerification.role === 'admin')) {
            // Track algorithm confusion attempt
            updateLeaderboard(systemId, decodedWithoutVerification.username || 'anonymous', 'jwt_algorithm_confusion', {
              algorithm: header.alg,
              claimedRole: decodedWithoutVerification.role
            });
          }
        } catch (headerParseError) {
          console.error('Error parsing JWT header:', headerParseError);
        }
      }
    } catch (decodeErr) {
      console.error('Error decoding token (non-fatal):', decodeErr);
    }
    
    // Try to verify with the main secret
      try {
        decoded = jwt.verify(token, JWT_SECRET);
      // Continue with the request if verification is successful
    } catch (err) {
      // If verification fails with the main secret, try with the weak key
        try {
          decoded = jwt.verify(token, WEAK_KEY);
          console.log('WARNING: JWT verified with weak dev key!');
        
        // Track successful use of weak key (potential vulnerability exploitation)
        updateLeaderboard(systemId, decoded.username || 'anonymous', 'jwt_weak_key_success', {
          claimedRole: decoded.role
        });
      } catch (weakKeyErr) {
        // If that also fails, reject the request
        return res.status(401).json({ message: 'Invalid token.' });
      }
    }
    
    // Check for potential privilege escalation via token manipulation
    if (decoded.role === 'admin') {
      db.get('SELECT role FROM users WHERE id = ?', [decoded.id], (err, row) => {
        if (err) {
          console.error('Error checking user role:', err);
        } else if (row && row.role !== 'admin') {
          // This is a successful privilege escalation through JWT manipulation!
          console.log(`⚠️ JWT privilege escalation detected: User ${decoded.username} (${decoded.id}) claiming admin role!`);
          
          // Track admin forge success
          updateLeaderboard(systemId, decoded.username, 'jwt_admin_forge', {
            userId: decoded.id,
            actualRole: row.role,
            claimedRole: 'admin'
          });
        }
      });
    }
    
    // Attach user info to request
    req.user = decoded;
    next();
    } catch (error) {
    res.status(401).json({ message: 'Invalid token.' });
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
          
          // Add a method to record additional exploited vulnerabilities
          req.user.recordVulnerability = function(vulnType, details = {}) {
            const now = new Date().toISOString();
            
            if (!req.user.discoveredSecrets) {
              req.user.discoveredSecrets = {};
            }
            
            if (!req.user.discoveredSecrets.vulnerabilities) {
              req.user.discoveredSecrets.vulnerabilities = {};
            }
            
            // Record this vulnerability with timestamp and details
            req.user.discoveredSecrets.vulnerabilities[vulnType] = {
              discovered: now,
              details: details
            };
            
            // Update in database
            db.run(
              'UPDATE exploit_chain SET discovered_secrets = ?, last_updated = ? WHERE user_id = ?',
              [JSON.stringify(req.user.discoveredSecrets || {}), now, userId],
              function(err) {
                if (err) {
                  console.error('Error updating exploit discoveries:', err.message);
                }
              }
            );
            
            // Also update the leaderboard if we have a system ID
            if (req.systemId) {
              updateLeaderboard(req.systemId, req.user.username, vulnType, details);
            }
            
            return true;
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
      
      // Add a method to record additional exploited vulnerabilities
      req.user.recordVulnerability = function(vulnType, details = {}) {
        const now = new Date().toISOString();
        
        if (!req.user.discoveredSecrets) {
          req.user.discoveredSecrets = {};
        }
        
        if (!req.user.discoveredSecrets.vulnerabilities) {
          req.user.discoveredSecrets.vulnerabilities = {};
        }
        
        // Record this vulnerability with timestamp and details
        req.user.discoveredSecrets.vulnerabilities[vulnType] = {
          discovered: now,
          details: details
        };
        
        // Update in database
        db.run(
          'UPDATE exploit_chain SET discovered_secrets = ?, last_updated = ? WHERE user_id = ?',
          [JSON.stringify(req.user.discoveredSecrets || {}), now, userId],
          function(err) {
            if (err) {
              console.error('Error updating exploit discoveries:', err.message);
            }
          }
        );
        
        // Also update the leaderboard if we have a system ID
        if (req.systemId) {
          updateLeaderboard(req.systemId, req.user.username, vulnType, details);
        }
        
        return true;
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
  const { report_name } = req.body;
  
  if (!report_name) {
    return res.status(400).json({
      error: 'Missing parameters',
      message: 'Report name is required'
    });
  }

  // VULNERABLE BY DESIGN: Unsanitized input goes directly to command
  const cmd = `generate_report ${report_name} > /tmp/report.txt`;
  
  console.log(`Executing report command: ${cmd}`);
  
  exec(cmd, (error, stdout, stderr) => {
    if (error) {
      return res.status(500).json({
        error: 'Report generation failed',
        message: stderr
      });
    }
    
    // Read and return the report
    fs.readFile('/tmp/report.txt', 'utf8', (err, data) => {
      if (err) {
        // If the file doesn't exist, just return whatever output we got
        return res.json({
          success: true,
          report: {
            name: report_name,
            content: stdout || "No output generated"
          }
        });
      }
      
      return res.json({
        success: true,
        report: {
          name: report_name,
          content: data
        }
      });
    });
  });
});

// Secure file upload endpoint
app.post('/api/upload', verifyToken, (req, res, next) => {
  // VULNERABLE BY DESIGN: Use user-supplied path from headers if provided
  const uploadPath = req.headers['x-upload-path'] || 'uploads';
  const useOriginalFilename = req.headers['x-use-original-filename'] === 'true';
  const skipValidation = req.headers['x-skip-validation'] === 'true';
  
  console.log(`Upload request to path: ${uploadPath}, useOriginalFilename: ${useOriginalFilename}, skipValidation: ${skipValidation}`);
  
  // Create custom storage for this request
  const customStorage = multer.diskStorage({
    destination: function (req, file, cb) {
      try {
        if (!fs.existsSync(uploadPath)) {
          fs.mkdirSync(uploadPath, { recursive: true });
        }
        cb(null, uploadPath);
      } catch (error) {
        console.error('Error creating upload directory:', error);
        cb(new Error('Invalid upload path'));
      }
    },
    filename: function (req, file, cb) {
      if (useOriginalFilename) {
        // Use original filename without sanitization
        cb(null, file.originalname);
      } else {
        // VULNERABLE BY DESIGN: Poor sanitization that can be bypassed
        // This preserves null bytes and doesn't handle double extensions properly
        let filename = file.originalname;
        
        // Try to sanitize but with exploitable flaws
        if (filename.includes('../') || filename.includes('..\\')) {
          filename = filename.replace(/\.\.\//g, '').replace(/\.\.\\/g, '');
        }
        
        cb(null, Date.now() + '-' + filename);
      }
    }
  });
  
  // VULNERABLE BY DESIGN: Vulnerable file filter that can be bypassed
  const vulnerableFileFilter = function(req, file, cb) {
    // Store original content type for logging
    const originalContentType = file.mimetype;
    
    // Check if Content-Type is being spoofed
    const fileExt = path.extname(file.originalname).toLowerCase();
    const dangerousExtensions = ['.php', '.phtml', '.php5', '.php4', '.php3', '.phar', '.js', '.asp', '.aspx', '.jsp', '.cgi', '.pl', '.sh', '.py', '.exe'];
    
    // VULNERABILITY #1: Accepting a file based on mimetype only, regardless of extension
    if (skipValidation || file.mimetype.startsWith('image/')) {
      console.log(`Accepting file based on mimetype: ${file.mimetype}, filename: ${file.originalname}`);
      return cb(null, true);
    }
    
    // VULNERABILITY #2: Null byte injection bypass
    // This check can be bypassed with filenames like shell.php%00.png
    if (file.originalname.includes('\0') || file.originalname.includes('%00')) {
      console.log(`⚠️ Potential null byte injection detected in filename: ${file.originalname}`);
      // Still accept the file (vulnerable by design)
      return cb(null, true);
    }
    
    // VULNERABILITY #3: Double extension check bypass
    // Only checks the last extension and ignores file.php.png
    if (['.jpg', '.jpeg', '.png', '.gif', '.pdf', '.txt', '.doc', '.docx'].includes(fileExt)) {
      console.log(`Accepting file with allowed extension: ${fileExt}`);
      return cb(null, true);
    }
    
    // VULNERABILITY #4: Client-provided MIME type is trusted over content
    if (req.body.allowFile === 'true') {
      console.log(`Accepting file with explicit allowFile parameter, bypassing checks`);
      return cb(null, true);
    }
    
    // Log potential attack attempt with dangerous file
    if (dangerousExtensions.includes(fileExt)) {
      console.log(`⚠️ Rejected dangerous file: ${file.originalname} (${file.mimetype})`);
    }
    
    // Default deny (but can be bypassed through multiple methods above)
    return cb(null, false);
  };
  
  // Create upload middleware with the vulnerable filter
  const uploadMiddleware = multer({ 
    storage: customStorage,
    fileFilter: vulnerableFileFilter,
    limits: {
      fileSize: 10 * 1024 * 1024 // 10MB
    }
  }).single('file');
  
  uploadMiddleware(req, res, (err) => {
    if (err) {
      console.error('File upload error:', err.message);
      return res.status(400).json({ 
        error: 'File upload error',
        message: err.message
      });
    }
    
    if (!req.file) {
      return res.status(400).json({ 
        error: 'No file uploaded or invalid file type',
        message: 'Please upload a valid file'
      });
    }

    const uploadedFile = req.file;
    
    // Check for potential exploitation attempts
    const fileExt = path.extname(uploadedFile.originalname).toLowerCase();
    const dangerousExtensions = ['.php', '.phtml', '.php5', '.php3', '.phar', '.js', '.asp', '.aspx', '.jsp', '.cgi', '.pl', '.sh', '.py', '.exe'];
    const hasNullByte = uploadedFile.originalname.includes('\0') || uploadedFile.originalname.includes('%00');
    const hasDoubleExtension = uploadedFile.originalname.split('.').length > 2;
    
    if (dangerousExtensions.includes(fileExt) || hasNullByte || hasDoubleExtension || 
        uploadPath !== 'uploads' || useOriginalFilename || skipValidation) {
      console.log(`⚠️ Potential file upload vulnerability exploitation detected!`);
      console.log(`  File: ${uploadedFile.originalname}`);
      console.log(`  MIME type: ${uploadedFile.mimetype}`);
      console.log(`  Path: ${uploadedFile.path}`);
      console.log(`  Size: ${uploadedFile.size} bytes`);
      
      if (dangerousExtensions.includes(fileExt)) {
        console.log(`  ⚠️ Dangerous extension: ${fileExt}`);
      }
      if (hasNullByte) {
        console.log(`  ⚠️ Null byte detected in filename`);
      }
      if (hasDoubleExtension) {
        console.log(`  ⚠️ Multiple extensions detected`);
      }
      if (uploadPath !== 'uploads') {
        console.log(`  ⚠️ Custom upload path: ${uploadPath}`);
      }
    }
    
    return res.json({
      success: true,
      file: {
        name: uploadedFile.originalname,
        path: uploadedFile.path,
        size: uploadedFile.size,
        mimetype: uploadedFile.mimetype
      },
      message: 'File uploaded successfully'
    });
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
  
  // Use safe SQL query helper to prevent crashes during scanning
  safeSqliteQuery(db, 'all', query, [param, param], (err, items) => {
    if (err) {
      console.error('Search error:', err.message);
      return res.status(500).json({ error: 'Search failed' });
    }
    
    // If no items found (which is common for SQL injection attempts), return empty array
    const results = items || [];
    
    return res.json({ 
      results: results,
      count: results.length
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

// Add a feedback submission endpoint (without the XSS vulnerability)
app.post('/api/feedback', (req, res) => {
  const { email, message, rating } = req.body;
  
  // Use parameterized query instead of string concatenation for security
  const query = `
    INSERT INTO feedback (email, message, rating, date, reviewed) 
    VALUES (?, ?, ?, ?, ?)
  `;
  
  db.run(query, [email, message, rating || 0, new Date().toISOString(), 1], function(err) {
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
      hint = 'You\'ve completed the main exploit chain! Now explore these additional vulnerabilities:\n' +
             '- JWT manipulation: Try modifying your JWT token\n' +
             '- Cookie-based SQL injection: Check the theme cookie in /api/user-preferences\n' +
             '- DOM-based XSS: Visit the /api/documentation endpoint\n' +
             '- CSRF vulnerability: See how /api/update-email lacks protection\n' +
             '- Prototype pollution: Try /api/merge-settings with crafted JSON\n' +
             '- Second-order SQL injection: Update your profile location field\n' +
             '- Race condition: Make concurrent requests to /api/quick-transfer\n' +
             '- SSRF: Use the /api/proxy endpoint';
      nextStage = 'complete';
      break;
    default:
      hint = 'Unknown stage';
      nextStage = '';
  }
  
  // Add full list of available vulnerabilities for reference
  const availableVulnerabilities = [
    'SQL Injection',
    'Insecure Direct Object Reference (IDOR)',
    'File Upload Vulnerabilities',
    'Command Injection',
    'JWT Token Manipulation',
    'Cookie-based SQL Injection',
    'DOM-based XSS',
    'CSRF (Cross-Site Request Forgery)',
    'Prototype Pollution',
    'Second-order SQL Injection',
    'Race Condition',
    'SSRF (Server-Side Request Forgery)'
  ];
  
  res.status(200).json({
    status: currentStage,
    nextStage: nextStage,
    hint: hint,
    completion: completion,
    discoveredSecrets: req.user.discoveredSecrets || {},
    availableVulnerabilities: availableVulnerabilities
  });
});

// Helper function to extract JWT token from login endpoint
app.get('/api/get-jwt-info', verifyToken, (req, res) => {
  // Information disclosure vulnerability - reveals JWT details
  // This helps users understand the JWT structure for the challenge
  // The token is already verified and available as req.user
  try {
    // Get the original token from the authorization header
    const token = req.headers['authorization'];
    
    // Just decode without verification to show structure
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

// Enhance the Cookie-based SQL injection tracking in the user preferences endpoint
app.get('/api/user-preferences', verifyToken, (req, res) => {
  const theme = req.cookies.theme || 'light';
  const systemId = req.headers['x-system-id'] || generateSystemId(req);
  
  // Get theme from cookie - VULNERABLE TO SQL INJECTION BY DESIGN
  try {
    // DANGEROUS: Direct use of user-controlled cookie value in SQL query
    const query = `SELECT * FROM themes WHERE name = '${theme}'`;
    
    // Check if this might be a SQL injection attempt
    const sqlInjectionPatterns = [
      "'--",
      "' OR ",
      "' UNION ",
      "' AND ",
      "';",
      "' SELECT ",
      "' FROM ",
      "INSERT ",
      "UPDATE ",
      "DELETE "
    ];
    
    // Check for SQL injection patterns
    let sqlInjectionDetected = false;
    let detectedPattern = '';
    
    sqlInjectionPatterns.forEach(pattern => {
      if (theme.includes(pattern)) {
        sqlInjectionDetected = true;
        detectedPattern = pattern;
      }
    });
    
    if (sqlInjectionDetected) {
        console.log('Potential SQL injection detected in theme cookie');
      updateLeaderboard(systemId, req.user ? req.user.username : 'anonymous', 'cookie_sqli_attempt', {
        cookie_value: theme,
        pattern: detectedPattern
      });
    }
    
    // Execute the query (vulnerable by design)
    db.all(query, (err, rows) => {
      if (err) {
        console.error('SQL error:', err.message);
        return res.status(500).json({ error: 'Database error', details: err.message });
      }
      
      // Check if this might be a successful SQL injection
      if (rows.length > 1) {
        // Multiple rows returned from a query that should only return one row
        console.log('Potential SQL injection success detected - multiple rows returned from theme query');
        updateLeaderboard(systemId, req.user ? req.user.username : 'anonymous', 'cookie_sqli_success', {
          cookie_value: theme,
          rows_returned: rows.length
      });
    }
    
    // Check for potential SQL injection based on suspicious result patterns
      const sensitiveDataPatterns = [
        'username', 'password', 'email', 'credit', 'admin', 'secret', 'key'
      ];
      
      // Convert rows to JSON for easier inspection
      const rowsJson = JSON.stringify(rows);
      
      // Check if response might contain sensitive data
      let sensitiveDataLeakage = false;
      sensitiveDataPatterns.forEach(pattern => {
        if (rowsJson.toLowerCase().includes(pattern)) {
          sensitiveDataLeakage = true;
          updateLeaderboard(systemId, req.user ? req.user.username : 'anonymous', 'cookie_sqli_data_leak', {
            cookie_value: theme,
            pattern_leaked: pattern
          });
        }
      });
      
      // Extract the theme data or use default
      const themeData = rows.length > 0 ? rows[0] : { 
        name: 'light', 
        background: '#ffffff', 
        text: '#000000',
        primary: '#007bff'
      };
      
      res.json({ 
        theme: themeData,
        preferences: {
          notifications: req.user ? true : false,
          language: 'en',
          timezone: 'UTC'
        }
    });
  });
  } catch (error) {
    console.error('Theme preferences error:', error);
    res.status(500).json({ error: 'An error occurred while fetching preferences' });
  }
});

// DOM-based XSS vulnerability - PRESERVED BY DESIGN
app.get('/api/documentation', verifyToken, (req, res) => {
  // Record potential attempts to exploit XSS via URL fragment
  const referer = req.headers.referer || '';
  if (referer.includes('#') && 
      (referer.includes('<script') || 
       referer.includes('javascript:') || 
       referer.includes('onerror=') || 
       referer.includes('onload='))) {
    console.log('Potential DOM XSS attempt detected in referer:', referer);
    
    // Record the exploitation if user is authenticated
    if (req.user && req.user.recordVulnerability) {
      req.user.recordVulnerability('dom_xss', {
        payload: referer.substring(referer.indexOf('#') + 1)
      });
    }
  }
  
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
            
            // Add detection and reporting of XSS attempts
            if (section.includes('<script') || 
                section.includes('javascript:') || 
                section.includes('onerror=') || 
                section.includes('onload=')) {
              // Send an AJAX request to record the exploitation
              var xhr = new XMLHttpRequest();
              xhr.open('POST', '/api/record-vulnerability', true);
              xhr.setRequestHeader('Content-Type', 'application/json');
              xhr.send(JSON.stringify({
                type: 'dom_xss_executed',
                payload: section
              }));
            }
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

// Endpoint to record vulnerability exploitation from client-side
app.post('/api/record-vulnerability', verifyToken, (req, res) => {
  const { type, payload } = req.body;
  
  if (!type) {
    return res.status(400).json({ error: 'Missing vulnerability type' });
  }
  
  // Record the vulnerability
  if (req.user && req.user.recordVulnerability) {
    req.user.recordVulnerability(type, { payload });
    console.log(`Recorded vulnerability exploitation: ${type}`);
  }
  
  // Return empty response to avoid leaking information
  return res.status(204).end();
});

// CSRF vulnerability for email updates - PRESERVED BY DESIGN
app.post('/api/update-email', verifyToken, (req, res) => {
  const { email } = req.body;
  const userId = req.user.id;
  const systemId = req.headers['x-system-id'] || generateSystemId(req);
  
  // Validate email format
  if (!email || !email.includes('@')) {
    return res.status(400).json({ error: 'Valid email is required' });
  }
  
  // CSRF vulnerability detection - Check for missing or suspicious headers
  const origin = req.headers['origin'];
  const referer = req.headers['referer'];
  
  // Check if request might be a CSRF attempt
  let csrfSuspected = false;
  
  // If the origin or referer is missing or from a different domain
  if (!origin && !referer) {
    csrfSuspected = true;
    console.log(`Potential CSRF detected: Missing origin and referer headers`);
    updateLeaderboard(systemId, req.user.username, 'csrf_detection', {
      email: email,
      missing_headers: true
    });
  } 
  // If origin exists but doesn't match our domain
  else if (origin && !origin.includes('localhost') && !origin.includes('darkvault')) {
    csrfSuspected = true;
    console.log(`Potential CSRF detected: Invalid origin ${origin}`);
    updateLeaderboard(systemId, req.user.username, 'csrf_detection', {
      email: email,
      origin: origin
    });
  }
  // If referer exists but doesn't match our domain 
  else if (referer && !referer.includes('localhost') && !referer.includes('darkvault')) {
    csrfSuspected = true;
    console.log(`Potential CSRF detected: Invalid referer ${referer}`);
    updateLeaderboard(systemId, req.user.username, 'csrf_detection', {
      email: email,
      referer: referer
    });
  }
  
  // VULNERABLE BY DESIGN: No CSRF token validation
  // Process the email update even if CSRF is suspected
  db.run(
    'UPDATE users SET email = ? WHERE id = ?',
    [email, userId],
    function(err) {
      if (err) {
        console.error('Error updating email:', err);
        return res.status(500).json({ error: 'Database error' });
      }
      
      if (csrfSuspected) {
        // Track successful email change via potential CSRF
        updateLeaderboard(systemId, req.user.username, 'csrf_email_change', {
          email: email,
          origin: origin || 'none',
          referer: referer || 'none'
        });
        
        // If email is changed to a suspicious domain (likely for account takeover)
        if (email.includes('evil') || email.includes('hack') || email.includes('attacker')) {
          updateLeaderboard(systemId, req.user.username, 'csrf_account_takeover', {
            email: email
          });
        }
      }
      
      return res.json({
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
  
  // Check for potential prototype pollution attempts
  const hasPrototypePaths = Object.keys(userSettings).some(key => 
    key === '__proto__' || key === 'constructor' || key === 'prototype'
  );
  
  if (hasPrototypePaths) {
    console.log('Potential prototype pollution attempt detected');
    
    // Record the exploitation if user is authenticated
    if (req.user && req.user.recordVulnerability) {
      req.user.recordVulnerability('prototype_pollution_attempt', {
        payload: JSON.stringify(userSettings)
      });
    }
  }
  
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
  
  // Check if the user might have successfully exploited prototype pollution
  if (isAdmin && req.user.role !== 'admin') {
    console.log('Potential successful prototype pollution detected - non-admin user appears as admin');
    
    // Record the exploitation if user is authenticated
    if (req.user && req.user.recordVulnerability) {
      req.user.recordVulnerability('prototype_pollution_success', {
        username: req.user.username,
        role: req.user.role
      });
    }
  }
  
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
// ... existing code ...

// Function to update leaderboard - Make sure it can handle the new vulnerability chain
function updateLeaderboard(systemId, username, vulnType, vulnDetails = {}) {
  // Ensure the exploitation_tracking table exists
  db.run(`CREATE TABLE IF NOT EXISTS exploitation_tracking (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    system_id TEXT NOT NULL,
    username TEXT,
    exploit_type TEXT NOT NULL,
    exploit_details TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // Define modern app chain stages to track progress
  const modernAppChainStages = [
    'discovered_vulnerable_dependency',
    'client_side_pollution_success',
    'graphql_access',
    'graphql_direct_user_query',
    'graphql_pollution_access_success',
    'graphql_mass_data_query',
    'graphql_batch_attack',
    'graphql_transaction_exfiltration',
    'token_extraction_success',
    'mass_compromise_success'
  ];
  
  // Insert the exploitation record
  const exploitDetails = JSON.stringify(vulnDetails);
  
  db.run(
    `INSERT INTO exploitation_tracking (system_id, username, exploit_type, exploit_details) 
     VALUES (?, ?, ?, ?)`,
    [systemId, username, vulnType, exploitDetails],
    function(err) {
      if (err) {
        console.error('Error updating exploitation tracking:', err);
        return;
      }
      
      // Notify console about the exploitation
      console.log(`[EXPLOIT] System: ${systemId}, User: ${username}, Type: ${vulnType}`);
      
      // Check if this is part of the modern app chain
      if (modernAppChainStages.includes(vulnType)) {
        // Update the user's achievement in the modern app chain
        console.log(`User ${username} completed step in Modern Web App Attack Chain: ${vulnType}`);
        
        // Check if they've completed the entire chain
        if (vulnType === 'mass_compromise_success') {
          console.log(`🏆 User ${username} has COMPLETED the entire Modern Web App Attack Chain!`);
        }
      }
    }
  );
  
  // Get current leaderboard entry
  db.get('SELECT * FROM leaderboard WHERE system_id = ?', [systemId], (err, row) => {
    if (err) {
      console.error('Error getting leaderboard entry:', err.message);
      return false;
    }
    
    if (!row) {
      // Create new entry if it doesn't exist
      const now = new Date().toISOString();
      const initialCompleted = {};
      initialCompleted[vulnType] = {
        discovered: now,
        details: vulnDetails
      };
      
      db.run(
        'INSERT INTO leaderboard (system_id, username, score, completed_vulns, last_updated, first_seen) VALUES (?, ?, 1, ?, ?, ?)',
        [systemId, username || 'Anonymous', JSON.stringify(initialCompleted), now, now],
        (err) => {
          if (err) {
            console.error('Error creating leaderboard entry:', err.message);
          }
        }
      );
    } else {
      // Update existing entry
      const now = new Date().toISOString();
      let completedVulns = {};
      try {
        completedVulns = JSON.parse(row.completed_vulns);
      } catch (e) {
        console.error('Error parsing completed vulnerabilities:', e);
        completedVulns = {};
      }
      
      // Only update if this vulnerability hasn't been recorded yet
      if (!completedVulns[vulnType]) {
        completedVulns[vulnType] = {
          discovered: now,
          details: vulnDetails
        };
        
        // Calculate new score - more points for advanced vulns
        let pointValue = 1; // Default
        if (vulnType.includes('sql') || vulnType.includes('sqli')) pointValue = 2;
        if (vulnType.includes('xss')) pointValue = 2;
        if (vulnType.includes('csrf')) pointValue = 1;
        if (vulnType.includes('idor')) pointValue = 3;
        if (vulnType.includes('command')) pointValue = 5;
        if (vulnType.includes('upload')) pointValue = 4;
        if (vulnType.includes('prototype_pollution')) pointValue = 3;
        if (vulnType.includes('jwt')) pointValue = 4;
        if (vulnType.includes('ssrf')) pointValue = 4;
        if (vulnType.includes('race')) pointValue = 3;
        
        // Add success bonus
        if (vulnType.includes('success')) pointValue *= 2;
        
        const newScore = row.score + pointValue;
        
        // Use provided username or keep existing one
        const updatedUsername = username || row.username || 'Anonymous';
        
        // Update the entry
        db.run(
          'UPDATE leaderboard SET score = ?, username = ?, completed_vulns = ?, last_updated = ? WHERE system_id = ?',
          [newScore, updatedUsername, JSON.stringify(completedVulns), now, systemId],
          (err) => {
            if (err) {
              console.error('Error updating leaderboard:', err.message);
            }
          }
        );
      }
    }
  });
  
  return true;
}

// Add a leaderboard endpoint
app.get('/api/leaderboard', (req, res) => {
  // Get the top 10 scores
  db.all(`
    SELECT username, score, completed_vulns, last_updated 
    FROM leaderboard 
    ORDER BY score DESC, last_updated ASC
    LIMIT 10
  `, (err, rows) => {
    if (err) {
      console.error('Error fetching leaderboard:', err.message);
      return res.status(500).json({ error: 'Failed to fetch leaderboard' });
    }
    
    // Get current user's position if authenticated
    let userPosition = null;
    
    if (req.systemId) {
      db.get(`
        SELECT COUNT(*) as position
        FROM leaderboard
        WHERE score > (SELECT score FROM leaderboard WHERE system_id = ?)
      `, [req.systemId], (err, result) => {
        if (err) {
          console.error('Error getting user position:', err.message);
        } else {
          userPosition = result.position + 1; // Add 1 because positions start at 1
          
          // Get user's own entry
          db.get('SELECT * FROM leaderboard WHERE system_id = ?', [req.systemId], (err, userEntry) => {
            if (err || !userEntry) {
              return res.status(200).json({
                leaderboard: rows,
                userPosition: userPosition,
                userScore: null,
                totalPlayers: rows.length
              });
            }
            
            // Calculate total number of players
            db.get('SELECT COUNT(*) as count FROM leaderboard', (err, countResult) => {
              const totalPlayers = err ? rows.length : countResult.count;
              
              return res.status(200).json({
                leaderboard: rows,
                userPosition: userPosition,
                userScore: {
                  username: userEntry.username,
                  score: userEntry.score,
                  completedVulns: JSON.parse(userEntry.completed_vulns || '{}'),
                  lastUpdated: userEntry.last_updated
                },
                totalPlayers: totalPlayers
              });
            });
          });
        }
      });
    } else {
      // No system ID yet
      return res.status(200).json({
        leaderboard: rows,
        userPosition: null,
        userScore: null,
        totalPlayers: rows.length
      });
    }
  });
});

// Add an endpoint to update username on the leaderboard
app.post('/api/leaderboard/username', verifyToken, (req, res) => {
  const { username } = req.body;
  const systemId = req.headers['x-system-id'] || req.systemId || generateSystemId(req);
  
  if (!username) {
    return res.status(400).json({ error: 'Username required' });
  }
  
  if (!systemId) {
    return res.status(400).json({ error: 'System ID not found' });
  }
  
  // Sanitize username
  const sanitizedUsername = username.replace(/[<>]/g, '').substring(0, 30);
  
  // Update username in leaderboard
  db.run(
    'UPDATE leaderboard SET username = ? WHERE system_id = ?',
    [sanitizedUsername, systemId],
    function(err) {
      if (err) {
        console.error('Error updating leaderboard username:', err.message);
        return res.status(500).json({ error: 'Failed to update username' });
      }
      
      // Check if any rows were affected
      if (this.changes === 0) {
        // Create a new entry if it doesn't exist
        const now = new Date().toISOString();
        db.run(
          'INSERT INTO leaderboard (system_id, username, score, completed_vulns, last_updated, first_seen) VALUES (?, ?, 0, ?, ?, ?)',
          [systemId, sanitizedUsername, '{}', now, now],
          (insertErr) => {
            if (insertErr) {
              console.error('Error creating leaderboard entry:', insertErr.message);
              return res.status(500).json({ error: 'Failed to create leaderboard entry' });
            }
            
            return res.status(200).json({
              success: true,
              message: 'Username set successfully',
              username: sanitizedUsername
            });
          }
        );
      } else {
      return res.status(200).json({
        success: true,
        message: 'Username updated successfully',
        username: sanitizedUsername
      });
      }
    }
  );
});

// Add global error handler to prevent crashing during security scanning
app.use(errorHandler);

// Start the server
app.listen(PORT, () => {
  console.log(`DarkVault app running on port ${PORT}`);
  console.log(`WARNING: This application contains intentional security vulnerabilities!`);
  console.log(`It is intended for educational purposes only.`);
  console.log(`Error logs will be written to logs/error.log`);
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Add a leaderboard page
app.get('/leaderboard', (req, res) => {
  const html = `
  <!DOCTYPE html>
  <html>
  <head>
    <title>DarkVault Hacker Leaderboard</title>
    <style>
      body {
        font-family: 'Courier New', monospace;
        background-color: #121212;
        color: #00ff00;
        margin: 0;
        padding: 20px;
      }
      .container {
        max-width: 800px;
        margin: 0 auto;
      }
      h1 {
        text-align: center;
        margin-bottom: 30px;
        color: #00ff00;
      }
      table {
        width: 100%;
        border-collapse: collapse;
        margin-bottom: 20px;
      }
      th, td {
        padding: 12px;
        text-align: left;
        border-bottom: 1px solid #333;
      }
      th {
        background-color: #1a1a1a;
        color: #00ff00;
      }
      tr:hover {
        background-color: #1a1a1a;
      }
      .position {
        text-align: center;
        font-weight: bold;
      }
      .username {
        color: #00ff00;
        font-weight: bold;
      }
      .score {
        text-align: right;
        color: #00ff00;
        font-weight: bold;
      }
      .date {
        color: #888;
        font-size: 0.8em;
      }
      .user-stats {
        background-color: #1a1a1a;
        padding: 15px;
        border-radius: 5px;
        margin-bottom: 20px;
      }
      #set-username-form {
        margin-top: 20px;
        display: flex;
        gap: 10px;
      }
      #username-input {
        flex-grow: 1;
        padding: 8px;
        background-color: #333;
        border: 1px solid #444;
        color: #fff;
      }
      button {
        background-color: #00ff00;
        color: #000;
        border: none;
        padding: 8px 15px;
        cursor: pointer;
        font-weight: bold;
      }
      button:hover {
        background-color: #00cc00;
      }
      .hidden {
        display: none;
      }
      .vuln-list {
        margin-top: 10px;
        font-size: 0.9em;
      }
      .vuln-item {
        margin-bottom: 5px;
        display: flex;
        justify-content: space-between;
      }
      .vuln-name {
        color: #00cc00;
      }
      .vuln-date {
        color: #888;
        font-size: 0.8em;
      }
    </style>
  </head>
  <body>
    <div class="container">
      <h1>🏆 DarkVault Hacker Leaderboard 🏆</h1>
      
      <div id="user-stats" class="user-stats hidden">
        <h2>Your Stats</h2>
        <p>Current Position: <span id="user-position">-</span> / <span id="total-players">-</span></p>
        <p>Score: <span id="user-score">-</span></p>
        <div id="set-username-form">
          <input type="text" id="username-input" placeholder="Set your username">
          <button id="set-username-btn">Update</button>
        </div>
        <h3>Completed Vulnerabilities:</h3>
        <div id="vuln-list" class="vuln-list"></div>
      </div>
      
      <h2>Top Hackers</h2>
      <table id="leaderboard-table">
        <thead>
          <tr>
            <th>Position</th>
            <th>Username</th>
            <th>Score</th>
            <th>Last Activity</th>
          </tr>
        </thead>
        <tbody id="leaderboard-body">
          <tr>
            <td colspan="4" style="text-align: center">Loading leaderboard data...</td>
          </tr>
        </tbody>
      </table>
      
      <p style="text-align: center">
        <a href="/" style="color: #00ff00;">Back to DarkVault</a>
      </p>
    </div>
    
    <script>
      // Function to format dates
      function formatDate(dateString) {
        const date = new Date(dateString);
        return date.toLocaleString();
      }
      
      // Function to load leaderboard data
      async function loadLeaderboard() {
        try {
          const response = await fetch('/api/leaderboard');
          const data = await response.json();
          
          // Update leaderboard table
          const tableBody = document.getElementById('leaderboard-body');
          tableBody.innerHTML = '';
          
          if (data.leaderboard.length === 0) {
            const row = document.createElement('tr');
            row.innerHTML = '<td colspan="4" style="text-align: center">No data available yet</td>';
            tableBody.appendChild(row);
          } else {
            data.leaderboard.forEach((entry, index) => {
              const row = document.createElement('tr');
              row.innerHTML = \`
                <td class="position">\${index + 1}</td>
                <td class="username">\${entry.username || 'Anonymous'}</td>
                <td class="score">\${entry.score}</td>
                <td class="date">\${formatDate(entry.last_updated)}</td>
              \`;
              tableBody.appendChild(row);
            });
          }
          
          // Update user stats if available
          const userStatsDiv = document.getElementById('user-stats');
          if (data.userScore) {
            userStatsDiv.classList.remove('hidden');
            document.getElementById('user-position').textContent = data.userPosition;
            document.getElementById('total-players').textContent = data.totalPlayers;
            document.getElementById('user-score').textContent = data.userScore.score;
            document.getElementById('username-input').value = data.userScore.username || '';
            
            // Update completed vulnerabilities
            const vulnList = document.getElementById('vuln-list');
            vulnList.innerHTML = '';
            
            const completedVulns = data.userScore.completedVulns;
            if (Object.keys(completedVulns).length === 0) {
              vulnList.innerHTML = '<p>No vulnerabilities exploited yet</p>';
            } else {
              // Sort vulnerabilities by discovery date
              const vulnEntries = Object.entries(completedVulns);
              vulnEntries.sort((a, b) => new Date(b[1].discovered) - new Date(a[1].discovered));
              
              vulnEntries.forEach(([vulnType, vulnData]) => {
                const vulnItem = document.createElement('div');
                vulnItem.className = 'vuln-item';
                vulnItem.innerHTML = \`
                  <span class="vuln-name">\${formatVulnName(vulnType)}</span>
                  <span class="vuln-date">\${formatDate(vulnData.discovered)}</span>
                \`;
                vulnList.appendChild(vulnItem);
              });
            }
          }
        } catch (error) {
          console.error('Error loading leaderboard:', error);
        }
      }
      
      // Format vulnerability name for display
      function formatVulnName(vulnType) {
        // Convert snake_case to Title Case with spaces
        const formatted = vulnType
          .split('_')
          .map(word => word.charAt(0).toUpperCase() + word.slice(1))
          .join(' ');
          
        // Add special formatting for different vulnerability types
        if (vulnType.includes('sqli')) return '💉 ' + formatted;
        if (vulnType.includes('xss')) return '🔥 ' + formatted;
        if (vulnType.includes('csrf')) return '🔄 ' + formatted;
        if (vulnType.includes('idor')) return '🔓 ' + formatted;
        if (vulnType.includes('command')) return '⚡ ' + formatted;
        if (vulnType.includes('upload')) return '📁 ' + formatted;
        if (vulnType.includes('prototype')) return '🧬 ' + formatted;
        if (vulnType.includes('jwt')) return '🔑 ' + formatted;
        if (vulnType.includes('ssrf')) return '🌐 ' + formatted;
        if (vulnType.includes('race')) return '🏎️ ' + formatted;
        
        return '🐞 ' + formatted;
      }
      
      // Set up username update
      document.getElementById('set-username-btn').addEventListener('click', async () => {
        const username = document.getElementById('username-input').value.trim();
        if (!username) return;
        
        try {
          // Get system ID from cookie
          const getCookie = (name) => {
            const value = "; " + document.cookie;
            const parts = value.split("; " + name + "=");
            if (parts.length === 2) return parts.pop().split(';').shift();
            return null;
          };
          
          const systemId = getCookie('system_id');
          
          const response = await fetch('/api/leaderboard/username', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'Authorization': localStorage.getItem('token') || '',
              'X-System-ID': systemId || ''
            },
            body: JSON.stringify({ username })
          });
          
          if (response.ok) {
            loadLeaderboard();
            alert('Username updated successfully!');
          } else {
            const errorData = await response.json();
            alert('Failed to update username: ' + (errorData.error || 'Unknown error'));
          }
        } catch (error) {
          console.error('Error updating username:', error);
          alert('Failed to update username. Please try again.');
        }
      });
      
      // Load leaderboard on page load
      document.addEventListener('DOMContentLoaded', loadLeaderboard);
      
      // Refresh leaderboard every 30 seconds
      setInterval(loadLeaderboard, 30000);
    </script>
  </body>
  </html>
  `;
  
  res.setHeader('Content-Type', 'text/html');
  return res.status(200).send(html);
}); 

// Add check-exploit-progress endpoint 
app.get('/api/check-exploit-progress', (req, res) => {
  const chain = req.query.chain;
  const systemId = req.headers['x-system-id'] || generateSystemId(req);
  
  // If no system ID, return empty progress
  if (!systemId) {
    return res.json({
      success: true,
      stages: []
    });
  }
  
  // Define the stages for each chain in order of progression
  const chainStages = {
    'jwt-chain': ['jwt_info_access', 'jwt_decode_success', 'jwt_algorithm_confusion', 'jwt_admin_forge'],
    'sql-injection': ['sqli_detection', 'sqli_extraction', 'sqli_admin_access'],
    'modern-web-app': [
      'discovered_vulnerable_dependency',
      'client_side_pollution_success',
      'graphql_access',
      'graphql_direct_user_query',
      'graphql_pollution_access_success',
      'graphql_mass_data_query',
      'graphql_batch_attack',
      'graphql_transaction_exfiltration',
      'token_extraction_success',
      'mass_compromise_success'
    ]
  };
  
  // Chain descriptions to help users understand each chain
  const chainDescriptions = {
    'jwt-chain': 'JWT token manipulation to gain admin access',
    'sql-injection': 'SQL injection to extract sensitive data and escalate privileges',
    'modern-web-app': 'Modern web app vulnerabilities including GraphQL, prototype pollution, and horizontal privilege escalation'
  };
  
  // If chain doesn't exist, return empty progress
  if (!chainStages[chain]) {
    return res.json({
      success: false,
      message: 'Invalid chain specified',
      stages: []
    });
  }
  
  // Query the database for completed stages and their timestamps
  db.all(
    'SELECT DISTINCT exploit_type, MIN(timestamp) as first_detection FROM exploitation_tracking WHERE system_id = ? GROUP BY exploit_type ORDER BY first_detection',
    [systemId],
    (err, rows) => {
      if (err) {
        return res.status(500).json({
          success: false,
          message: 'Error checking progress',
          stages: []
        });
      }
      
      // Extract exploit types
      const completedExploits = rows.map(row => row.exploit_type);
      
      // Filter for the requested chain
      const completedStages = completedExploits.filter(exploit => 
        chainStages[chain].includes(exploit)
      );
      
      // Calculate completion percentage
      const totalStages = chainStages[chain].length;
      const completedCount = completedStages.length;
      const percentage = Math.round((completedCount / totalStages) * 100);
      
      // Get most recent stage details (with timestamp)
      let lastStage = null;
      let lastStageTime = null;
      
      if (completedStages.length > 0) {
        const lastStageType = completedStages[completedStages.length - 1];
        const matchingRow = rows.find(row => row.exploit_type === lastStageType);
        if (matchingRow) {
          lastStage = lastStageType;
          lastStageTime = matchingRow.first_detection;
        }
      }
      
      res.json({
        success: true,
        chain: chain,
        description: chainDescriptions[chain] || '',
        stages: completedStages,
        progress: {
          completed: completedCount,
          total: totalStages,
          percentage: percentage
        },
        last_stage: lastStage,
        last_stage_time: lastStageTime,
        next_stage: getNextStage(chainStages[chain], completedStages)
      });
    }
  );
});

// Helper function to determine next stage
function getNextStage(allStages, completedStages) {
  for (const stage of allStages) {
    if (!completedStages.includes(stage)) {
      return stage;
    }
  }
  return null; // All stages completed
}

// Update the check-exploit-progress endpoint
app.get('/api/check-exploit-progress', (req, res) => {
  const chain = req.query.chain;
  const systemId = req.headers['x-system-id'] || generateSystemId(req);
  
  // If no system ID, return empty progress
  if (!systemId) {
    return res.json({
      success: true,
      stages: []
    });
  }
  
  // Define the stages for each chain in order of progression
  const chainStages = {
    'jwt-chain': ['jwt_info_access', 'jwt_decode_success', 'jwt_algorithm_confusion', 'jwt_admin_forge'],
    'sql-injection': ['sqli_detection', 'sqli_extraction', 'sqli_admin_access'],
    'modern-web-app': [
      'discovered_vulnerable_dependency',
      'client_side_pollution_success',
      'graphql_access',
      'graphql_direct_user_query',
      'graphql_pollution_access_success',
      'graphql_mass_data_query',
      'graphql_batch_attack',
      'graphql_transaction_exfiltration',
      'token_extraction_success',
      'mass_compromise_success'
    ]
  };
  
  // Chain descriptions to help users understand each chain
  const chainDescriptions = {
    'jwt-chain': 'JWT token manipulation to gain admin access',
    'sql-injection': 'SQL injection to extract sensitive data and escalate privileges',
    'modern-web-app': 'Modern web app vulnerabilities including GraphQL, prototype pollution, and horizontal privilege escalation'
  };
  
  // If chain doesn't exist, return empty progress
  if (!chainStages[chain]) {
    return res.json({
      success: false,
      message: 'Invalid chain specified',
      stages: []
    });
  }
  
  // Query the database for completed stages and their timestamps
  db.all(
    'SELECT DISTINCT exploit_type, MIN(timestamp) as first_detection FROM exploitation_tracking WHERE system_id = ? GROUP BY exploit_type ORDER BY first_detection',
    [systemId],
    (err, rows) => {
      if (err) {
        return res.status(500).json({
          success: false,
          message: 'Error checking progress',
          stages: []
        });
      }
      
      // Extract exploit types
      const completedExploits = rows.map(row => row.exploit_type);
      
      // Filter for the requested chain
      const completedStages = completedExploits.filter(exploit => 
        chainStages[chain].includes(exploit)
      );
      
      // Calculate completion percentage
      const totalStages = chainStages[chain].length;
      const completedCount = completedStages.length;
      const percentage = Math.round((completedCount / totalStages) * 100);
      
      // Get most recent stage details (with timestamp)
      let lastStage = null;
      let lastStageTime = null;
      
      if (completedStages.length > 0) {
        const lastStageType = completedStages[completedStages.length - 1];
        const matchingRow = rows.find(row => row.exploit_type === lastStageType);
        if (matchingRow) {
          lastStage = lastStageType;
          lastStageTime = matchingRow.first_detection;
        }
      }
      
      res.json({
        success: true,
        chain: chain,
        description: chainDescriptions[chain] || '',
        stages: completedStages,
        progress: {
          completed: completedCount,
          total: totalStages,
          percentage: percentage
        },
        last_stage: lastStage,
        last_stage_time: lastStageTime,
        next_stage: getNextStage(chainStages[chain], completedStages)
      });
    }
  );
});

// Helper function to determine next stage
function getNextStage(allStages, completedStages) {
  for (const stage of allStages) {
    if (!completedStages.includes(stage)) {
      return stage;
    }
  }
  return null; // All stages completed
}

// Add this to the profile update endpoint
app.post('/api/users/update-profile', verifyToken, (req, res) => {
  const { bio, website, location } = req.body;
  const userId = req.user.id;
  const systemId = req.headers['x-system-id'] || generateSystemId(req);
  
  // DANGEROUS: Check for potential SQL injection patterns
  const sqlInjectionPatterns = [
    "';",
    "';--",
    "' OR ",
    "' UNION ",
    "' SELECT ",
    "' UPDATE ",
    "' INSERT ",
    "' DELETE "
  ];
  
  // Check for SQL injection patterns in user input
  let sqlInjectionDetected = false;
  let detectedPattern = '';
  
  [bio, website, location].forEach(field => {
    if (field) {
      sqlInjectionPatterns.forEach(pattern => {
        if (field.includes(pattern)) {
          sqlInjectionDetected = true;
          detectedPattern = pattern;
        }
      });
    }
  });
  
  // If SQL injection is detected, track it but still process the request (vulnerable by design)
  if (sqlInjectionDetected) {
    console.log(`Potential SQL injection detected in profile update for user ${req.user.username}`);
    updateLeaderboard(systemId, req.user.username, 'sqli_detection', {
      field: location ? 'location' : (bio ? 'bio' : 'website'),
      pattern: detectedPattern
    });
    
    // Check for UPDATE/INSERT statements (potential privilege escalation)
    if (location && location.toLowerCase().includes("update users set role") || location.toLowerCase().includes("admin")) {
      updateLeaderboard(systemId, req.user.username, 'sqli_privilege_attempt', {
        payload: location
      });
    }
  }
  
  // VULNERABLE BY DESIGN: Second-order SQL injection happens here
  // Store the user-provided inputs without proper sanitization
  db.run(
    `INSERT INTO profile_updates (user_id, bio, website, location, date) 
     VALUES (?, ?, ?, ?, datetime('now'))`,
    [userId, bio, website, location],
    function(err) {
      if (err) {
        console.error('Error updating profile:', err);
        return res.status(500).json({ error: 'Database error' });
      }
      
      if (sqlInjectionDetected) {
        updateLeaderboard(systemId, req.user.username, 'sqli_profile_update', {
          updateId: this.lastID
        });
      }
      
      return res.json({
        success: true,
        message: 'Profile updated successfully'
      });
    }
  );
});

// Add tracking to the admin profile updates viewing endpoint
app.get('/api/admin/profile-updates', verifyToken, (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  
  const systemId = req.headers['x-system-id'] || generateSystemId(req);
  
  // Admin endpoint to view profile updates - executes second-order SQL injection
  // VULNERABLE BY DESIGN
  db.all(`SELECT pu.id, pu.user_id, u.username, pu.bio, pu.website, pu.location, pu.date 
          FROM profile_updates pu 
          JOIN users u ON pu.user_id = u.id 
          ORDER BY pu.date DESC`, (err, rows) => {
    if (err) {
      console.error('Error fetching profile updates:', err);
      return res.status(500).json({ error: 'Database error' });
    }
    
    // Track access to the endpoint
    updateLeaderboard(systemId, req.user.username, 'admin_profile_view');
    
    // Process each profile update and check for SQL injection
    rows.forEach(row => {
      // This query executes any SQL injection payloads in the profile_updates table
      db.get(`SELECT '${row.location}' as test_field`, (injErr, injResult) => {
        // If there's an error, it might be due to SQL injection
        if (injErr) {
          console.error(`SQL error when processing user ${row.username}'s location: ${injErr.message}`);
          
          // Try to extract user ID from the location field (common in SQL injection attempts)
          if (row.location && row.location.includes("UPDATE users SET")) {
            updateLeaderboard(systemId, row.username, 'sqli_admin_execution', {
              updateId: row.id,
              error: injErr.message
            });
            
            // Check if the user's role has actually changed
            db.get('SELECT role FROM users WHERE id = ?', [row.user_id], (roleErr, roleResult) => {
              if (!roleErr && roleResult && roleResult.role === 'admin') {
                // The SQL injection has successfully escalated privileges
                updateLeaderboard(systemId, row.username, 'sqli_privilege_escalation');
                console.log(`⚠️ User ${row.username} has escalated to admin via SQL injection!`);
              }
            });
          }
        }
      });
    });
    
    return res.json({ success: true, updates: rows });
  });
});

// Add an endpoint to track DOM-based XSS attempts and successes
app.post('/api/track-xss', (req, res) => {
  const { type, payload, location, details } = req.body;
  const systemId = req.headers['x-system-id'] || generateSystemId(req);
  const username = req.headers['x-user'] || 'anonymous';
  
  // Validate input
  if (!type || !payload) {
    return res.status(400).json({ error: 'Missing required fields' });
  }
  
  // Map front-end event type to leaderboard event
  let eventType = 'xss_attempt';
  if (type === 'detection') {
    eventType = 'xss_detection';
  } else if (type === 'attempt') {
    eventType = 'xss_attempt';
  } else if (type === 'execution') {
    eventType = 'xss_execution';
  } else if (type === 'cookie_theft') {
    eventType = 'xss_cookie_theft';
  }
  
  // Record the event
  updateLeaderboard(systemId, username, eventType, {
    payload,
    location: location || 'unknown',
    details: details || {}
  });
  
  // Return success to avoid interfering with the XSS
  res.status(200).json({ success: true });
});

// Add documentation endpoint - vulnerable to DOM-based XSS
app.get('/api/documentation', (req, res) => {
  // Define API documentation with a warning that will be ignored
  const html = `
<!DOCTYPE html>
<html>
<head>
  <title>DarkVault API Documentation</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.0/dist/css/bootstrap.min.css" rel="stylesheet">
  <style>
    body { padding: 20px; }
    pre { background-color: #f0f0f0; padding: 10px; border-radius: 4px; }
    .warning { background-color: #fff3cd; padding: 15px; border-radius: 4px; margin-bottom: 20px; }
  </style>
</head>
<body>
  <div class="container">
    <h1>DarkVault API Documentation</h1>
    
    <div class="warning">
      <strong>Warning:</strong> This page contains a DOM-based XSS vulnerability for educational purposes.
    </div>
    
    <div id="api-intro">
      <p>Welcome to the DarkVault API documentation. This page describes the endpoints available in the application.</p>
    </div>
    
    <h2>Endpoints</h2>
    <div id="endpoints">
      <h3>Authentication</h3>
      <ul>
        <li><code>POST /api/login</code> - Authenticate user and get JWT token</li>
        <li><code>POST /api/register</code> - Create a new user account</li>
      </ul>
      
      <h3>Users</h3>
      <ul>
        <li><code>GET /api/users/:id</code> - Get user information</li>
        <li><code>POST /api/users/update-profile</code> - Update user profile</li>
      </ul>
      
      <h3>Transactions</h3>
      <ul>
        <li><code>POST /api/transfer</code> - Transfer money between accounts</li>
        <li><code>GET /api/transactions</code> - Get transaction history</li>
      </ul>
      
      <h3>Admin</h3>
      <ul>
        <li><code>GET /api/admin/profile-updates</code> - View profile updates (admin only)</li>
        <li><code>GET /api/admin/export-users</code> - Export user data (admin only)</li>
        <li><code>POST /api/admin/report</code> - Generate system report (admin only)</li>
      </ul>
    </div>
    
    <h2>Section Navigation</h2>
    <div class="mb-3">
      <p>Jump to section: <input type="text" id="section-input" class="form-control" placeholder="Enter section name"></p>
      <button id="go-to-section" class="btn btn-primary">Go</button>
      <div id="section-target"></div>
    </div>
    
    <hr>
    
    <h2>Documentation Details</h2>
    <div id="content-target">
      <!-- Documentation content will be loaded here -->
    </div>
    
    <!-- DOM-Based XSS Vulnerability -->
    <script>
      // VULNERABLE BY DESIGN: This makes the page vulnerable to DOM-based XSS
      document.addEventListener('DOMContentLoaded', function() {
        // Track XSS detection with a simple telemetry function
        function trackXssEvent(type, payload, location) {
          try {
            fetch('/api/track-xss', {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json',
                'x-user': localStorage.getItem('username') || 'anonymous',
                'x-system-id': localStorage.getItem('system_id') || ''
              },
              body: JSON.stringify({
                type: type,
                payload: payload,
                location: location
              })
            }).catch(() => {}); // Suppress errors to avoid interfering with XSS
          } catch (e) {
            // Ignore errors
          }
        }
        
        // Check URL hash for section to display
        if (window.location.hash) {
          const hash = window.location.hash.substring(1);
          
          // Check for potential XSS payloads
          if (hash.includes('<') && (hash.includes('script') || hash.includes('img') || hash.includes('on'))) {
            trackXssEvent('detection', hash, 'url_hash');
          }
          
          // VULNERABLE: Directly insert hash value into innerHTML
          document.getElementById('section-target').innerHTML = '<div class="p-3 mb-3 bg-light rounded">' + 
                                                               'Selected section: ' + hash + '</div>';
                                                               
          // Attempt to detect if an XSS payload executed
          setTimeout(() => {
            const scripts = document.querySelectorAll('script:not([src])');
            for (const script of scripts) {
              if (script.innerText.includes('fetch') && script.innerText.includes('cookie')) {
                trackXssEvent('execution', hash, 'script_tag');
              }
            }
          }, 500);
        }
        
        // Add click handler for navigation
        document.getElementById('go-to-section').addEventListener('click', function() {
          const section = document.getElementById('section-input').value;
          
          // Check for potential XSS payloads
          if (section.includes('<') && (section.includes('script') || section.includes('img') || section.includes('on'))) {
            trackXssEvent('attempt', section, 'section_input');
          }
          
          // VULNERABLE: Directly insert user input into innerHTML
          document.getElementById('section-target').innerHTML = '<div class="p-3 mb-3 bg-light rounded">' + 
                                                               'Selected section: ' + section + '</div>';
                                                               
          // Update URL hash
          window.location.hash = section;
        });
      });
    </script>
  </div>
</body>
</html>
  `;
  
  res.status(200).send(html);
});

// Add a quick-transfer endpoint that's vulnerable to race conditions
app.post('/api/quick-transfer', verifyToken, (req, res) => {
  const { to, amount } = req.body;
  const fromId = req.user.id;
  const systemId = req.headers['x-system-id'] || generateSystemId(req);
  
  // Validate input
  if (!to || !amount) {
    return res.status(400).json({ error: 'Missing required fields' });
  }
  
  if (isNaN(amount) || parseFloat(amount) <= 0) {
    return res.status(400).json({ error: 'Invalid amount' });
  }
  
  // VULNERABLE BY DESIGN: Track the timestamp of recent transfers for race condition detection
  const now = Date.now();
  // Set up global object for tracking rapid transfers if it doesn't exist
  if (!global.recentTransfers) {
    global.recentTransfers = {};
  }
  
  // Add this transfer to the user's recent transfers
  if (!global.recentTransfers[fromId]) {
    global.recentTransfers[fromId] = [];
  }
  
  // Add the current timestamp to the user's recent transfers
  global.recentTransfers[fromId].push({
    timestamp: now,
    amount: parseFloat(amount),
    to: to
  });
  
  // Check for potential race condition attempts (multiple transfers in a short window)
  const recentWindow = 2000; // 2 seconds window
  const recentCount = global.recentTransfers[fromId].filter(t => 
    now - t.timestamp < recentWindow
  ).length;
  
  if (recentCount >= 3) {
    console.log(`Potential race condition attack detected: ${recentCount} transfers in ${recentWindow}ms window`);
    updateLeaderboard(systemId, req.user.username, 'race_condition_attempt', {
      count: recentCount,
      window: recentWindow,
      recent_transfers: global.recentTransfers[fromId].slice(-5) // Last 5 transfers
    });
  }
  
  // VULNERABLE BY DESIGN: Race condition - We first check balance, then later update it
  // This creates a window where multiple transfers can be initiated before the balance is updated
  db.get('SELECT balance FROM users WHERE id = ?', [fromId], (err, row) => {
    if (err) {
      console.error('Database error in quick-transfer:', err);
      return res.status(500).json({ error: 'Database error' });
    }
    
    if (!row) {
      return res.status(404).json({ error: 'Sender account not found' });
    }
    
    const balance = row.balance;
    const transferAmount = parseFloat(amount);
    
    if (balance < transferAmount) {
      // Check if there's been a successful race condition exploit
      const overdraftCheck = global.recentTransfers[fromId]
        .filter(t => now - t.timestamp < 5000) // Look at last 5 seconds
        .reduce((sum, t) => sum + t.amount, 0);
      
      if (overdraftCheck > balance) {
        console.log(`⚠️ Race condition exploitation detected: User ${req.user.username} attempting to transfer $${overdraftCheck} with balance of $${balance}`);
        updateLeaderboard(systemId, req.user.username, 'race_condition_success', {
          attempted_transfers: overdraftCheck,
          actual_balance: balance,
          excess_amount: overdraftCheck - balance
        });
      }
      
      // Allow the transfer to proceed even with insufficient funds (vulnerable by design)
      console.log(`⚠️ ALLOWING insufficient funds transfer from ${fromId} for $${transferAmount} (balance: $${balance})`);
      
      // But make it look like we're enforcing the check
      if (Math.random() > 0.7) { // Only sometimes enforce the check to make the vulnerability exploitable but not too easy
        return res.status(400).json({ error: 'Insufficient funds' });
      }
    }
    
    // VULNERABLE BY DESIGN: Add artificial delay to make race condition easier to exploit
    setTimeout(() => {
      // Process the transfer
      const newBalance = balance - transferAmount;
      
      // Insert transaction record
      db.run(
        'INSERT INTO transactions (sender_id, receiver_id, amount, date, note) VALUES (?, ?, ?, datetime("now"), ?)',
        [fromId, to, transferAmount, 'Quick transfer'],
        function(err) {
          if (err) {
            console.error('Error inserting transaction:', err);
            return res.status(500).json({ error: 'Transaction failed' });
          }
          
          // Update sender's balance
          db.run(
            'UPDATE users SET balance = ? WHERE id = ?',
            [newBalance, fromId],
            function(err) {
              if (err) {
                console.error('Error updating sender balance:', err);
                return res.status(500).json({ error: 'Balance update failed' });
              }
              
              // Update receiver's balance
              db.run(
                'UPDATE users SET balance = balance + ? WHERE id = ?',
                [transferAmount, to],
                function(err) {
                  if (err) {
                    console.error('Error updating receiver balance:', err);
                    // Don't return an error here to simulate partial update success (another vulnerability)
                  }
                  
                  // Success response
                  return res.json({
                    success: true,
                    message: 'Transfer completed successfully',
                    transaction_id: this.lastID,
                    new_balance: newBalance
                  });
                }
              );
            }
          );
        }
      );
    }, 500); // 500ms delay to make race conditions easier to exploit
  });
});

// Add proxy endpoint with SSRF vulnerability
app.get('/api/proxy', verifyToken, (req, res) => {
  const url = req.query.url;
  const systemId = req.headers['x-system-id'] || generateSystemId(req);
  
  if (!url) {
    return res.status(400).json({ error: 'URL parameter is required' });
  }
  
  // DANGEROUS: Check for potential SSRF attempts
  const ssrfRiskPatterns = [
    'localhost',
    '127.0.0.1',
    '0.0.0.0',
    'internal',
    'admin',
    'file://',
    '10.',
    '172.16',
    '192.168',
    '.sock'
  ];
  
  // Check for SSRF indicators
  let ssrfAttemptDetected = false;
  let detectedPattern = '';
  
  ssrfRiskPatterns.forEach(pattern => {
    if (url.toLowerCase().includes(pattern)) {
      ssrfAttemptDetected = true;
      detectedPattern = pattern;
    }
  });
  
  // Categorize the SSRF attempt
  let ssrfType = 'ssrf_attempt';
  if (url.startsWith('file://')) {
    ssrfType = 'ssrf_file_access';
  } else if (url.includes('localhost') || url.includes('127.0.0.1')) {
    if (url.includes(':3001') || url.includes('admin')) {
      ssrfType = 'ssrf_internal_admin';
    } else {
      ssrfType = 'ssrf_internal_access';
    }
  } else if (url.match(/^https?:\/\/10\.|^https?:\/\/172\.|^https?:\/\/192\./)) {
    ssrfType = 'ssrf_private_network';
  }
  
  if (ssrfAttemptDetected) {
    console.log(`SSRF attempt detected: ${url}`);
    updateLeaderboard(systemId, req.user.username, ssrfType, {
      url: url,
      pattern: detectedPattern
    });
  }
  
  // VULNERABLE BY DESIGN: No URL validation, allowing SSRF
  axios.get(url, { 
    validateStatus: () => true, // Accept any status code
    timeout: 5000 // 5 second timeout
  })
  .then(response => {
    // Track successful SSRF request
    if (ssrfAttemptDetected && response.status === 200) {
      console.log(`Successful SSRF to ${url}`);
      updateLeaderboard(systemId, req.user.username, 'ssrf_success', {
        url: url,
        status: response.status,
        data_length: JSON.stringify(response.data).length
      });
      
      // If sensitive data appears to have been accessed, track it specifically
      const responseStr = JSON.stringify(response.data).toLowerCase();
      if (responseStr.includes('jwt') || responseStr.includes('secret') || 
          responseStr.includes('password') || responseStr.includes('api')) {
        console.log('⚠️ SSRF exposed sensitive information!');
        updateLeaderboard(systemId, req.user.username, 'ssrf_sensitive_data', {
          url: url,
          data_preview: JSON.stringify(response.data).substring(0, 100) + '...'
        });
      }
    }
    
    // Return the proxied response
    return res.status(response.status).json({
      status: response.status,
      headers: response.headers,
      data: response.data
    });
  })
  .catch(error => {
    console.error(`Proxy error for ${url}:`, error.message);
    return res.status(500).json({
      error: 'Proxy request failed',
      message: error.message
    });
  });
});

// Add comprehensive vulnerability chains leaderboard endpoint
app.get('/api/vulnerability-chains', (req, res) => {
  const chain = req.query.chain;
  const systemId = req.headers['x-system-id'] || generateSystemId(req);
  
  // If no system ID, return empty progress
  if (!systemId) {
    return res.json({
      success: true,
      stages: []
    });
  }
  
  // Define the stages for each chain in order of progression
  const chainStages = {
    'jwt-chain': [
      'jwt_info_access',
      'jwt_decode_success',
      'jwt_algorithm_confusion',
      'jwt_weak_key_success',
      'jwt_admin_forge'
    ],
    'sqli-chain': [
      'sqli_detection',
      'sqli_profile_update',
      'admin_profile_view',
      'sqli_admin_execution',
      'sqli_privilege_escalation'
    ],
    'cookie-sqli': [
      'cookie_sqli_attempt',
      'cookie_sqli_success',
      'cookie_sqli_data_leak'
    ],
    'xss-chain': [
      'xss_detection',
      'xss_attempt',
      'xss_execution',
      'xss_cookie_theft'
    ],
    'race-condition': [
      'race_condition_attempt',
      'race_condition_success'
    ],
    'prototype-pollution': [
      'prototype_pollution_attempt',
      'prototype_pollution_success'
    ],
    'ssrf-chain': [
      'ssrf_attempt',
      'ssrf_internal_access',
      'ssrf_internal_admin',
      'ssrf_file_access',
      'ssrf_success',
      'ssrf_sensitive_data'
    ],
    'csrf-chain': [
      'csrf_detection',
      'csrf_email_change',
      'csrf_account_takeover'
    ],
    'modern-web-app': [
      'discovered_vulnerable_dependency',
      'client_side_pollution_success',
      'graphql_access',
      'graphql_direct_user_query',
      'graphql_pollution_access_success',
      'graphql_mass_data_query',
      'graphql_batch_attack',
      'graphql_transaction_exfiltration',
      'token_extraction_success',
      'mass_compromise_success'
    ]
  };
  
  // Chain descriptions to help users understand each chain
  const chainDescriptions = {
    'jwt-chain': 'JWT token manipulation to gain admin access through altered authentication tokens',
    'sqli-chain': 'Second-order SQL Injection to achieve privilege escalation when an admin views your profile',
    'cookie-sqli': 'Cookie-based SQL Injection to extract sensitive data from the database',
    'xss-chain': 'DOM-based XSS to steal cookies and achieve session hijacking',
    'race-condition': 'Race condition exploitation in money transfers to bypass balance checks',
    'prototype-pollution': 'Prototype pollution to manipulate JavaScript objects and bypass security checks',
    'ssrf-chain': 'Server-side request forgery to access internal services and sensitive data',
    'csrf-chain': 'Cross-site request forgery to perform actions as another user without their knowledge',
    'modern-web-app': 'Modern web app vulnerabilities: GraphQL, prototype pollution, and horizontal privilege escalation'
  };
  
  // If chain doesn't exist, return all available chains
  if (!chain || !chainStages[chain]) {
    return res.json({
      success: true,
      message: 'Available vulnerability chains',
      chains: Object.keys(chainStages).map(chainKey => ({
        id: chainKey,
        name: chainKey.replace(/-/g, ' ').replace(/\b\w/g, l => l.toUpperCase()),
        description: chainDescriptions[chainKey] || '',
        stages: chainStages[chainKey].length
      }))
    });
  }
  
  // Query the database for completed stages and their timestamps
  db.all(
    'SELECT DISTINCT exploit_type, MIN(timestamp) as first_detection FROM exploitation_tracking WHERE system_id = ? GROUP BY exploit_type ORDER BY first_detection',
    [systemId],
    (err, rows) => {
      if (err) {
        return res.status(500).json({
          success: false,
          message: 'Error checking progress',
          stages: []
        });
      }
      
      // Extract exploit types
      const completedExploits = rows.map(row => row.exploit_type);
      
      // Filter for the requested chain
      const completedStages = completedExploits.filter(exploit => 
        chainStages[chain].includes(exploit)
      );
      
      // Calculate completion percentage
      const totalStages = chainStages[chain].length;
      const completedCount = completedStages.length;
      const percentage = Math.round((completedCount / totalStages) * 100);
      
      // Get most recent stage details (with timestamp)
      let lastStage = null;
      let lastStageTime = null;
      
      if (completedStages.length > 0) {
        const lastStageType = completedStages[completedStages.length - 1];
        const matchingRow = rows.find(row => row.exploit_type === lastStageType);
        if (matchingRow) {
          lastStage = lastStageType;
          lastStageTime = matchingRow.first_detection;
        }
      }
      
      // Find the next stage to complete
      const nextStage = chainStages[chain].find(stage => !completedStages.includes(stage));
      
      // Generate hint based on chain and progress
      let hint = '';
      
      if (nextStage) {
        // Chain-specific hints
        if (chain === 'jwt-chain') {
          if (nextStage === 'jwt_info_access') hint = 'Try accessing the /api/get-jwt-info endpoint to begin.';
          else if (nextStage === 'jwt_decode_success') hint = 'Decode your JWT token to understand its structure.';
          else if (nextStage === 'jwt_algorithm_confusion') hint = 'Try manipulating the "alg" field in the JWT header.';
          else hint = 'Look for weak JWT secrets or try the "none" algorithm.';
        } else if (chain === 'sqli-chain') {
          if (nextStage === 'sqli_detection') hint = 'Try injecting SQL in your profile information.';
          else if (nextStage === 'sqli_admin_execution') hint = 'Wait for an admin to view profile updates.';
          else hint = 'Use SQL to modify your role to admin.';
        } else if (chain === 'cookie-sqli') {
          hint = 'Try setting a malicious theme cookie with SQL injection.';
        } else if (chain === 'xss-chain') {
          hint = 'Check the /api/documentation page for DOM-based XSS opportunities.';
        } else if (chain === 'race-condition') {
          hint = 'Send multiple transfer requests simultaneously to bypass balance checks.';
        } else if (chain === 'ssrf-chain') {
          if (nextStage === 'ssrf_attempt') hint = 'Use the /api/proxy endpoint to make internal requests.';
          else if (nextStage === 'ssrf_internal_admin') hint = 'Try accessing the internal admin service on port 3001.';
          else hint = 'Look for ways to access local files or other internal resources.';
        } else if (chain === 'csrf-chain') {
          hint = 'Create a form on another site that submits to /api/update-email without CSRF protection.';
        }
      } else {
        hint = 'Congratulations! You have completed all stages of this vulnerability chain.';
      }
      
      res.json({
        success: true,
        chain: {
          id: chain,
          name: chain.replace(/-/g, ' ').replace(/\b\w/g, l => l.toUpperCase()),
          description: chainDescriptions[chain] || ''
        },
        stages: completedStages,
        all_stages: chainStages[chain],
        progress: {
          completed: completedCount,
          total: totalStages,
          percentage: percentage
        },
        last_stage: lastStage,
        last_stage_time: lastStageTime,
        next_stage: nextStage,
        hint: hint
      });
    }
  );
});

// Global error handler to prevent app crashes during security scanning
app.use((err, req, res, next) => {
  console.error('Global error handler caught: ', err.message);
  logError('global_error_handler', err, { 
    path: req.path,
    method: req.method,
    query: req.query,
    headers: req.headers
  });
  
  // Don't expose error details in production
  if (process.env.NODE_ENV === 'production') {
    return res.status(500).json({ error: 'Internal server error' });
  } else {
    // In dev/test mode, return error details to assist testing
    return res.status(500).json({ 
      error: 'Internal server error',
      message: err.message,
      stack: err.stack
    });
  }
});