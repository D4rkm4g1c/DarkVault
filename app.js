const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const md5 = require('md5');
const fs = require('fs');
const axios = require('axios');
const jwt = require('jsonwebtoken');
const xml2js = require('xml2js');
const ejs = require('ejs');
const serialize = require('node-serialize');
const xmlparser = require('express-xml-bodyparser');

// Initialize express app
const app = express();
const PORT = 3000;

// Set up view engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Middleware
app.use(express.static(path.join(__dirname, 'public')));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(cookieParser());
app.use(session({
  secret: 'darkvault-secret-key',
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false }
}));
app.use(xmlparser());

// Initialize database
const db = new sqlite3.Database('./darkvault.db');

// Create tables if they don't exist
db.serialize(() => {
  // Users table
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    password TEXT,
    email TEXT,
    isAdmin INTEGER DEFAULT 0
  )`);

  // Messages table (for XSS)
  db.run(`CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    message TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // Files table (for file upload vulnerabilities)
  db.run(`CREATE TABLE IF NOT EXISTS files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT,
    path TEXT,
    uploaded_by INTEGER
  )`);

  // Products table (for blind SQLi)
  db.run(`CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    description TEXT,
    price REAL,
    category TEXT
  )`);

  // Logs table (for blind XSS)
  db.run(`CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    action TEXT,
    ip_address TEXT,
    user_agent TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // User preferences table (for second-order SQL injection)
  db.run(`CREATE TABLE IF NOT EXISTS user_preferences (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    theme TEXT DEFAULT 'dark',
    display_name TEXT,
    avatar TEXT,
    bio TEXT,
    favorite_category TEXT
  )`);

  // User preferences filters table (for blind 2nd-order SQL injection)
  db.run(`CREATE TABLE IF NOT EXISTS user_filters (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    filter_name TEXT,
    filter_query TEXT
  )`);

  // Check if admin user exists, if not create one
  db.get("SELECT * FROM users WHERE username = 'admin'", (err, row) => {
    if (!row) {
      db.run("INSERT INTO users (username, password, email, isAdmin) VALUES (?, ?, ?, ?)", 
        ['admin', md5('SecretPassword123!'), 'admin@darkvault.com', 1]);
    }
  });

  // Add some sample products if none exist
  db.get("SELECT COUNT(*) as count FROM products", (err, row) => {
    if (row && row.count === 0) {
      const products = [
        ['Laptop', 'High-performance laptop with SSD', 999.99, 'Electronics'],
        ['Smartphone', 'Latest model with advanced camera', 799.99, 'Electronics'],
        ['Headphones', 'Noise-cancelling wireless headphones', 199.99, 'Audio'],
        ['Monitor', '4K Ultra HD monitor', 349.99, 'Electronics'],
        ['Keyboard', 'Mechanical gaming keyboard', 129.99, 'Accessories'],
        ['Mouse', 'Ergonomic wireless mouse', 49.99, 'Accessories'],
        ['Tablet', '10-inch tablet with stylus', 599.99, 'Electronics'],
        ['Speaker', 'Bluetooth waterproof speaker', 89.99, 'Audio'],
        ['USB Drive', '128GB high-speed USB drive', 29.99, 'Storage'],
        ['External HDD', '2TB portable hard drive', 79.99, 'Storage']
      ];
      
      products.forEach(product => {
        db.run(
          "INSERT INTO products (name, description, price, category) VALUES (?, ?, ?, ?)",
          product
        );
      });
    }
  });
});

// Somewhere after the initialization section and before the routes
// Add JWT secret (intentionally weak)
const JWT_SECRET = "darkvault-secret-key";

// Import routes
const indexRouter = require('./routes/index');
const adminRouter = require('./routes/admin');
const apiRouter = require('./routes/api');

// Routes
app.get('/', (req, res) => {
  res.render('index', { user: req.session.user });
});

// Login route - SQL Injection vulnerability
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  
  // Vulnerable SQL query (no prepared statement)
  const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${md5(password)}'`;
  
  db.get(query, (err, user) => {
    if (err) {
      return res.status(500).send('Database error');
    }
    
    if (!user) {
      return res.status(401).render('index', { error: 'Invalid credentials' });
    }
    
    // Set user in session
    req.session.user = user;
    
    // Redirect based on user type
    if (user.isAdmin) {
      res.redirect('/admin');
    } else {
      res.redirect('/dashboard');
    }
  });
});

// Registration route - stores passwords using weak hashing (md5)
app.post('/register', (req, res) => {
  const { username, password, email } = req.body;
  
  // Check if username exists
  db.get("SELECT * FROM users WHERE username = ?", [username], (err, user) => {
    if (user) {
      return res.status(400).render('index', { error: 'Username already exists' });
    }
    
    // Vulnerable password storage (md5)
    const hashedPassword = md5(password);
    
    db.run("INSERT INTO users (username, password, email) VALUES (?, ?, ?)", 
      [username, hashedPassword, email], function(err) {
        if (err) {
          return res.status(500).send('Error registering user');
        }
        
        // Auto-login after registration
        req.session.user = {
          id: this.lastID,
          username,
          email,
          isAdmin: 0
        };
        
        res.redirect('/dashboard');
      });
  });
});

// Dashboard route
app.get('/dashboard', (req, res) => {
  if (!req.session.user) {
    return res.redirect('/');
  }
  
  // Get messages for the dashboard - XSS vulnerability
  db.all("SELECT * FROM messages ORDER BY created_at DESC", (err, messages) => {
    if (err) {
      messages = [];
    }
    
    res.render('dashboard', { user: req.session.user, messages: messages });
  });
});

// Post message route - XSS vulnerability (no sanitization)
app.post('/message', (req, res) => {
  if (!req.session.user) {
    return res.redirect('/');
  }
  
  const { message } = req.body;
  
  db.run("INSERT INTO messages (user_id, message) VALUES (?, ?)", 
    [req.session.user.id, message], (err) => {
      if (err) {
        return res.status(500).send('Error posting message');
      }
      
      res.redirect('/dashboard');
    });
});

// File upload route - path traversal & arbitrary file upload vulnerability
app.post('/upload', (req, res) => {
  if (!req.session.user) {
    return res.redirect('/');
  }
  
  const { filename, fileContent } = req.body;
  
  // Vulnerable file path handling (path traversal)
  const filePath = path.join(__dirname, 'uploads', filename);
  
  // Ensure uploads directory exists
  if (!fs.existsSync(path.join(__dirname, 'uploads'))) {
    fs.mkdirSync(path.join(__dirname, 'uploads'));
  }
  
  // Write file without checking content type or extension
  fs.writeFile(filePath, fileContent, (err) => {
    if (err) {
      return res.status(500).send('Error uploading file');
    }
    
    db.run("INSERT INTO files (filename, path, uploaded_by) VALUES (?, ?, ?)",
      [filename, filePath, req.session.user.id], (err) => {
        if (err) {
          return res.status(500).send('Error recording file upload');
        }
        
        res.redirect('/dashboard');
      });
  });
});

// User information route - IDOR vulnerability
app.get('/user/:id', (req, res) => {
  if (!req.session.user) {
    return res.redirect('/');
  }
  
  // No authorization check - any user can access any profile
  db.get("SELECT id, username, email FROM users WHERE id = ?", [req.params.id], (err, user) => {
    if (err || !user) {
      return res.status(404).send('User not found');
    }
    
    res.render('profile', { currentUser: req.session.user, profileUser: user });
  });
});

// Admin panel route - broken access control
app.get('/admin', (req, res) => {
  // Poor authorization check - can be bypassed
  if (!req.session.user) {
    return res.redirect('/');
  }
  
  // Missing authorization check on server-side
  db.all("SELECT * FROM users", (err, users) => {
    if (err) {
      users = [];
    }
    
    res.render('admin', { user: req.session.user, users: users });
  });
});

// Command execution route - OS command injection
app.post('/ping', (req, res) => {
  if (!req.session.user) {
    return res.redirect('/');
  }
  
  const { host } = req.body;
  
  // Vulnerable command execution
  const exec = require('child_process').exec;
  exec(`ping -c 4 ${host}`, (err, stdout, stderr) => {
    res.render('ping', { user: req.session.user, output: stdout });
  });
});

// Products search route - Blind SQL Injection vulnerability
app.get('/products', (req, res) => {
  if (!req.session.user) {
    return res.redirect('/');
  }
  
  let query = "SELECT * FROM products";
  let hasResults = false;
  
  // Render the products page
  res.render('products', { 
    user: req.session.user, 
    hasResults: hasResults,
    searchPerformed: false
  });
});

// Products search with blind SQL injection
app.post('/products/search', (req, res) => {
  if (!req.session.user) {
    return res.redirect('/');
  }
  
  const { category, minPrice, maxPrice } = req.body;
  let hasResults = false;
  
  // Vulnerable parameter handling - no prepared statements or validation
  // Blind SQL injection vulnerability
  let query = `SELECT COUNT(*) as count FROM products WHERE 1=1`;
  
  if (category) {
    // Vulnerable to blind SQLi
    query += ` AND category = '${category}'`;
  }
  
  if (minPrice) {
    query += ` AND price >= ${minPrice}`;
  }
  
  if (maxPrice) {
    query += ` AND price <= ${maxPrice}`;
  }
  
  db.get(query, (err, row) => {
    // Only return if results exist, not the actual data (blind SQLi scenario)
    hasResults = (row && row.count > 0);
    
    if (err) {
      // Don't show SQL errors to the user (makes SQLi blind/harder)
      console.error(err);
      hasResults = false;
    }
    
    res.render('products', { 
      user: req.session.user, 
      hasResults: hasResults,
      searchPerformed: true,
      searchParams: { category, minPrice, maxPrice }
    });
  });
});

// Contact form with blind XSS vulnerability
app.get('/contact', (req, res) => {
  if (!req.session.user) {
    return res.redirect('/');
  }
  
  res.render('contact', { user: req.session.user, messageSent: false });
});

app.post('/contact', (req, res) => {
  if (!req.session.user) {
    return res.redirect('/');
  }
  
  const { subject, message } = req.body;
  
  // Store the message with user IP and user agent for admin review (vulnerable to blind XSS)
  const userIp = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
  const userAgent = req.headers['user-agent'];
  
  // Store log entry (vulnerable to blind XSS as admin will view these later)
  db.run(
    "INSERT INTO logs (user_id, action, ip_address, user_agent) VALUES (?, ?, ?, ?)",
    [req.session.user.id, `Contact form submission: ${subject}`, userIp, userAgent]
  );
  
  // Store the message for admin to review later (complete message content isn't displayed to the user)
  db.run(
    "INSERT INTO messages (user_id, message) VALUES (?, ?)",
    [req.session.user.id, `CONTACT: ${subject} - ${message}`],
    (err) => {
      if (err) {
        return res.status(500).send('Error submitting form');
      }
      
      res.render('contact', { user: req.session.user, messageSent: true });
    }
  );
});

// Admin logs route - Where blind XSS would be triggered when admin views logs
app.get('/admin/logs', (req, res) => {
  if (!req.session.user) {
    return res.redirect('/');
  }
  
  // Missing proper authorization - just like our admin route
  // This is where stored blind XSS payloads would execute when viewed by an admin
  db.all("SELECT logs.*, users.username FROM logs JOIN users ON logs.user_id = users.id ORDER BY logs.created_at DESC", (err, logs) => {
    if (err) {
      logs = [];
    }
    
    res.render('admin_logs', { user: req.session.user, logs: logs });
  });
});

// User settings route
app.get('/settings', (req, res) => {
  if (!req.session.user) {
    return res.redirect('/');
  }
  
  // Get user preferences
  db.get("SELECT * FROM user_preferences WHERE user_id = ?", [req.session.user.id], (err, preferences) => {
    // Get saved filters
    db.all("SELECT * FROM user_filters WHERE user_id = ?", [req.session.user.id], (err, filters) => {
      res.render('settings', { 
        user: req.session.user, 
        preferences: preferences || {}, 
        filters: filters || [],
        message: null
      });
    });
  });
});

// Save user preferences
app.post('/settings/save', (req, res) => {
  if (!req.session.user) {
    return res.redirect('/');
  }
  
  const { display_name, bio, avatar, theme, favorite_category } = req.body;
  
  // Check if user preferences exist
  db.get("SELECT * FROM user_preferences WHERE user_id = ?", [req.session.user.id], (err, preferences) => {
    if (preferences) {
      // Update existing preferences
      db.run(
        "UPDATE user_preferences SET display_name = ?, bio = ?, avatar = ?, theme = ?, favorite_category = ? WHERE user_id = ?",
        [display_name, bio, avatar, theme, favorite_category, req.session.user.id],
        (err) => {
          if (err) {
            return res.status(500).send('Error updating preferences');
          }
          
          res.render('settings', { 
            user: req.session.user, 
            preferences: { ...preferences, display_name, bio, avatar, theme, favorite_category },
            filters: [],
            message: 'Preferences updated successfully'
          });
        }
      );
    } else {
      // Insert new preferences
      db.run(
        "INSERT INTO user_preferences (user_id, display_name, bio, avatar, theme, favorite_category) VALUES (?, ?, ?, ?, ?, ?)",
        [req.session.user.id, display_name, bio, avatar, theme, favorite_category],
        (err) => {
          if (err) {
            return res.status(500).send('Error saving preferences');
          }
          
          res.render('settings', { 
            user: req.session.user, 
            preferences: { display_name, bio, avatar, theme, favorite_category },
            filters: [],
            message: 'Preferences saved successfully'
          });
        }
      );
    }
  });
});

// Save product filter (vulnerable to 2nd order SQL Injection)
app.post('/settings/filter', (req, res) => {
  if (!req.session.user) {
    return res.redirect('/');
  }
  
  const { filter_name, category, min_price, max_price } = req.body;
  
  // Store the filter criteria without sanitization
  // This is intentionally vulnerable, allowing filter_name or category to contain
  // SQL Injection payloads that will be executed later
  let filter_query = JSON.stringify({ category, min_price, max_price });
  
  db.run(
    "INSERT INTO user_filters (user_id, filter_name, filter_query) VALUES (?, ?, ?)",
    [req.session.user.id, filter_name, filter_query],
    function(err) {
      if (err) {
        return res.status(500).send('Error saving filter');
      }
      
      // Redirect to settings page
      db.get("SELECT * FROM user_preferences WHERE user_id = ?", [req.session.user.id], (err, preferences) => {
        db.all("SELECT * FROM user_filters WHERE user_id = ?", [req.session.user.id], (err, filters) => {
          res.render('settings', { 
            user: req.session.user, 
            preferences: preferences || {}, 
            filters: filters || [],
            message: 'Filter saved successfully'
          });
        });
      });
    }
  );
});

// Apply filter route (2nd order SQL Injection vulnerability)
app.get('/products/filter/:id', (req, res) => {
  if (!req.session.user) {
    return res.redirect('/');
  }
  
  const filterId = req.params.id;
  
  // Get the stored filter
  db.get("SELECT * FROM user_filters WHERE id = ? AND user_id = ?", [filterId, req.session.user.id], (err, filter) => {
    if (err || !filter) {
      return res.redirect('/products');
    }
    
    // Parse the stored filter
    const filterData = JSON.parse(filter.filter_query);
    
    // This is where the 2nd order SQL injection occurs
    // The category from the stored filter is directly inserted into the SQL query
    // If a malicious payload was stored in the filter_query, it will be executed here
    let query = `SELECT COUNT(*) as count FROM products WHERE 1=1`;
    
    if (filterData.category) {
      // Vulnerable to 2nd order SQLi
      query += ` AND category = '${filterData.category}'`;
    }
    
    if (filterData.min_price) {
      query += ` AND price >= ${filterData.min_price}`;
    }
    
    if (filterData.max_price) {
      query += ` AND price <= ${filterData.max_price}`;
    }
    
    // Execute the query with the potentially malicious input
    db.get(query, (err, row) => {
      // Only return if results exist, not the actual data (blind SQLi scenario)
      const hasResults = (row && row.count > 0);
      
      if (err) {
        console.error(err);
        return res.redirect('/products');
      }
      
      res.render('products', { 
        user: req.session.user, 
        hasResults: hasResults,
        searchPerformed: true,
        searchParams: { 
          category: filterData.category, 
          minPrice: filterData.min_price, 
          maxPrice: filterData.max_price,
          filterName: filter.filter_name
        }
      });
    });
  });
});

// Logout route
app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

// SSRF vulnerability - Website preview functionality
app.get('/preview', (req, res) => {
  if (!req.session.user) {
    return res.redirect('/');
  }
  
  res.render('preview', { user: req.session.user, preview: null, error: null });
});

app.post('/preview', async (req, res) => {
  if (!req.session.user) {
    return res.redirect('/');
  }
  
  const { url } = req.body;
  let preview = null;
  let error = null;
  
  // SSRF vulnerability: No validation of URL
  // Attacker can use this to scan internal network or access internal services
  try {
    const response = await axios.get(url);
    preview = {
      url: url,
      status: response.status,
      content: response.data.substring(0, 1500) + (response.data.length > 1500 ? '...' : ''),
      contentType: response.headers['content-type']
    };
    
    // Log the preview request
    db.run(
      "INSERT INTO logs (user_id, action, ip_address, user_agent) VALUES (?, ?, ?, ?)",
      [req.session.user.id, `URL preview requested: ${url}`, req.ip, req.headers['user-agent']]
    );
  } catch (err) {
    error = `Error fetching URL: ${err.message}`;
  }
  
  res.render('preview', { user: req.session.user, preview, error });
});

// XML External Entity (XXE) Injection vulnerability
app.get('/import', (req, res) => {
  if (!req.session.user) {
    return res.redirect('/');
  }
  
  res.render('import', { user: req.session.user, result: null, error: null });
});

app.post('/import', (req, res) => {
  if (!req.session.user) {
    return res.redirect('/');
  }
  
  const { xml_data } = req.body;
  let result = null;
  let error = null;
  
  // XXE vulnerability: Unsafe XML parsing
  const parser = new xml2js.Parser({
    // Explicitly allowing DTD which makes it vulnerable to XXE
    explicitCharkey: true,
    explicitArray: false,
    xmlns: true
  });
  
  try {
    // Vulnerable XML parsing - allows XXE attacks
    parser.parseString(xml_data, (err, data) => {
      if (err) {
        error = `XML parsing error: ${err.message}`;
      } else {
        // Process imported products
        result = data;
        
        try {
          if (data.products && data.products.product) {
            const products = Array.isArray(data.products.product) 
              ? data.products.product 
              : [data.products.product];
            
            products.forEach(product => {
              db.run(
                "INSERT INTO products (name, description, price, category) VALUES (?, ?, ?, ?)",
                [
                  product.name && product.name._ ? product.name._ : product.name,
                  product.description && product.description._ ? product.description._ : product.description,
                  product.price && product.price._ ? parseFloat(product.price._) : parseFloat(product.price || 0),
                  product.category && product.category._ ? product.category._ : product.category
                ]
              );
            });
            
            // Log the import
            db.run(
              "INSERT INTO logs (user_id, action, ip_address, user_agent) VALUES (?, ?, ?, ?)",
              [req.session.user.id, `Imported ${products.length} products from XML`, req.ip, req.headers['user-agent']]
            );
          }
        } catch (importErr) {
          error = `Error importing products: ${importErr.message}`;
        }
      }
    });
  } catch (parseErr) {
    error = `Error processing XML: ${parseErr.message}`;
  }
  
  res.render('import', { user: req.session.user, result, error });
});

// JWT Authentication vulnerability
app.get('/api/auth', (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  
  // Create JWT token with weak signature and without proper claims
  const payload = {
    id: req.session.user.id,
    username: req.session.user.username,
    isAdmin: req.session.user.isAdmin
  };
  
  // Vulnerable JWT: weak secret, no expiration, no audience or issuer
  const token = jwt.sign(payload, JWT_SECRET);
  
  res.json({ token });
});

app.get('/api/profile', (req, res) => {
  const token = req.headers.authorization ? req.headers.authorization.replace('Bearer ', '') : null;
  
  if (!token) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  
  try {
    // Vulnerable JWT verification: no signature algorithm check
    const decoded = jwt.verify(token, JWT_SECRET);
    
    // Get user data
    db.get("SELECT id, username, email, isAdmin FROM users WHERE id = ?", [decoded.id], (err, user) => {
      if (err || !user) {
        return res.status(404).json({ error: 'User not found' });
      }
      
      res.json({ user });
    });
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
});

// Server-Side Template Injection vulnerability
app.get('/email-template', (req, res) => {
  if (!req.session.user) {
    return res.redirect('/');
  }
  
  res.render('email_template', { 
    user: req.session.user, 
    preview: null, 
    error: null, 
    template: "Welcome, <%= username %>!\n\nThank you for joining DarkVault."
  });
});

app.post('/email-template', (req, res) => {
  if (!req.session.user) {
    return res.redirect('/');
  }
  
  const { template } = req.body;
  let preview = null;
  let error = null;
  
  try {
    // SSTI vulnerability: Directly evaluating user-provided template
    // This allows code execution through template syntax
    const compiled = ejs.compile(template);
    preview = compiled({
      username: req.session.user.username,
      email: req.session.user.email
    });
  } catch (err) {
    error = `Template error: ${err.message}`;
  }
  
  res.render('email_template', { user: req.session.user, preview, error, template });
});

// Insecure Deserialization vulnerability
app.get('/export-data', (req, res) => {
  if (!req.session.user) {
    return res.redirect('/');
  }
  
  // Get user data for export
  db.get("SELECT * FROM user_preferences WHERE user_id = ?", [req.session.user.id], (err, preferences) => {
    if (err) {
      return res.status(500).send('Error exporting data');
    }
    
    // Create data object
    const data = {
      user: {
        id: req.session.user.id,
        username: req.session.user.username,
        email: req.session.user.email
      },
      preferences: preferences || {
        theme: 'dark',
        display_name: req.session.user.username
      }
    };
    
    // Serialize data
    const serialized = serialize.serialize(data);
    
    // Base64 encode for transport
    const exportData = Buffer.from(serialized).toString('base64');
    
    res.render('export', { user: req.session.user, exportData });
  });
});

app.post('/import-data', (req, res) => {
  if (!req.session.user) {
    return res.redirect('/');
  }
  
  const { data } = req.body;
  let error = null;
  let importedData = null;
  
  try {
    // Decode from base64
    const decoded = Buffer.from(data, 'base64').toString();
    
    // Insecure deserialization vulnerability: directly deserializing user input
    // This can lead to remote code execution if exploited
    importedData = serialize.unserialize(decoded);
    
    // Log the import
    db.run(
      "INSERT INTO logs (user_id, action, ip_address, user_agent) VALUES (?, ?, ?, ?)",
      [req.session.user.id, 'Imported user data', req.ip, req.headers['user-agent']]
    );
  } catch (err) {
    error = `Error importing data: ${err.message}`;
  }
  
  res.render('import_data', { user: req.session.user, error, importedData });
});

// Local File Inclusion vulnerability
app.get('/docs/:filename', (req, res) => {
  const { filename } = req.params;
  
  // LFI vulnerability: No proper validation of file path
  // Attacker can use path traversal to access any file on the server
  const filePath = path.join(__dirname, 'docs', filename);
  
  fs.readFile(filePath, 'utf8', (err, content) => {
    if (err) {
      return res.status(404).send('Document not found');
    }
    
    res.render('document', { user: req.session.user || null, filename, content });
  });
});

// Vulnerable cookie handling - missing security attributes
app.get('/remember-settings', (req, res) => {
  const { theme, layout } = req.query;
  
  // Setting cookies without security attributes (missing httpOnly, secure, SameSite)
  res.cookie('userTheme', theme, { maxAge: 31536000000 }); // 1 year
  res.cookie('userLayout', layout, { maxAge: 31536000000 });
  
  // Also sets user preferences in localStorage via JavaScript
  res.send(`
    <script>
      // Vulnerable localStorage usage - storing sensitive data
      localStorage.setItem('userPreferences', JSON.stringify({
        theme: '${theme}',
        layout: '${layout}',
        userId: '${req.session.userId || 'guest'}',
        lastLogin: '${new Date().toISOString()}'
      }));
      document.write('Settings saved! <a href="/">Go back</a>');
    </script>
  `);
});

// Example of insecure use of a third-party library (lodash.merge)
// Vulnerable to prototype pollution
app.post('/merge-config', (req, res) => {
  const { userConfig } = req.body;
  if (!userConfig) {
    return res.status(400).send('No config provided');
  }
  
  // System default config
  const defaultConfig = {
    theme: 'light',
    notifications: true,
    language: 'en',
    timeout: 3600
  };
  
  // Using vulnerable version of lodash.merge
  // Susceptible to prototype pollution
  try {
    const lodashMerge = require('lodash.merge');
    
    // Vulnerable to prototype pollution if userConfig contains __proto__ properties
    const newConfig = lodashMerge({}, defaultConfig, userConfig);
    
    // Store the config
    req.session.userConfig = newConfig;
    
    res.json({ success: true, config: newConfig });
  } catch (err) {
    console.error('Merge error:', err);
    res.status(500).json({ error: 'Failed to merge configs', details: err.message });
  }
});

// Set up routes
app.use('/', indexRouter);
app.use('/admin', adminRouter);
app.use('/api', apiRouter);

// Start server
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
}); 