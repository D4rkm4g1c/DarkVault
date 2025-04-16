const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();
const db = require('../db');
const md5 = require('md5');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');

// JWT Secret (intentionally weak)
const JWT_SECRET = "darkvault-secret-key";

// Middleware to check JWT without proper validation
const checkJwt = (req, res, next) => {
  const token = req.headers.authorization ? req.headers.authorization.replace('Bearer ', '') : null;
  
  if (!token) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  
  try {
    // Vulnerable JWT verification: no signature algorithm check
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
};

// Vulnerable admin check (easily bypassed)
const isAdmin = (req, res, next) => {
  // Missing proper verification
  if (req.user && (req.user.isAdmin || req.user.role === 'admin')) {
    next();
  } else {
    // Check for backdoor parameter (intentional vulnerability)
    if (req.query.admin === 'true') {
      next();
    } else {
      res.status(403).json({ error: 'Admin access required' });
    }
  }
};

// Authentication endpoints
router.post('/auth/login', (req, res) => {
  const { username, password } = req.body;
  
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }
  
  // Vulnerable SQL query (no prepared statement)
  const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${md5(password)}'`;
  
  db.get(query, (err, user) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Create JWT token with weak signature and without proper claims
    const payload = {
      id: user.id,
      username: user.username,
      isAdmin: user.isAdmin === 1 || user.role === 'admin',
      role: user.role
    };
    
    // Vulnerable JWT: weak secret, no expiration, no audience or issuer
    const token = jwt.sign(payload, JWT_SECRET);
    
    res.json({ 
      token,
      user: {
        id: user.id,
        username: user.username,
        isAdmin: user.isAdmin === 1 || user.role === 'admin',
        role: user.role
      }
    });
  });
});

router.post('/auth/register', (req, res) => {
  const { username, password, email } = req.body;
  
  if (!username || !password || !email) {
    return res.status(400).json({ error: 'All fields are required' });
  }
  
  // Check if username exists
  db.get("SELECT * FROM users WHERE username = ?", [username], (err, user) => {
    if (user) {
      return res.status(400).json({ error: 'Username already exists' });
    }
    
    // Vulnerable password storage (md5)
    const hashedPassword = md5(password);
    
    db.run("INSERT INTO users (username, password, email, role, isAdmin) VALUES (?, ?, ?, ?, ?)", 
      [username, hashedPassword, email, 'user', 0], function(err) {
        if (err) {
          return res.status(500).json({ error: 'Error registering user' });
        }
        
        // Create JWT token
        const token = jwt.sign({
          id: this.lastID,
          username,
          isAdmin: 0,
          role: 'user'
        }, JWT_SECRET);
        
        res.status(201).json({
          token,
          user: {
            id: this.lastID,
            username,
            isAdmin: false,
            role: 'user'
          }
        });
      });
  });
});

// User endpoints
router.get('/users', checkJwt, (req, res) => {
  // IDOR vulnerability - any authenticated user can see all users
  db.all("SELECT id, username, email, isAdmin FROM users", (err, users) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    
    res.json({ users });
  });
});

router.get('/users/:id', checkJwt, (req, res) => {
  // IDOR vulnerability - missing authorization check
  const userId = req.params.id;
  
  // Special check for the hidden user with the flag
  if (userId === '9999') {
    return res.json({
      user: {
        id: 9999,
        username: "hidden_admin",
        email: "super_secret@darkvault.com",
        isAdmin: true,
        flag: "DARK{1d0r_vuln3r4b1l1ty}"
      },
      message: "Congratulations! You've discovered the hidden admin account."
    });
  }
  
  db.get("SELECT id, username, email, isAdmin FROM users WHERE id = ?", [userId], (err, user) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // Also fetch user preferences (information leakage)
    db.get("SELECT * FROM user_preferences WHERE user_id = ?", [userId], (err, preferences) => {
      user.preferences = preferences || {};
      res.json({ user });
    });
  });
});

router.put('/users/:id', checkJwt, (req, res) => {
  const userId = req.params.id;
  const { email, current_password, new_password } = req.body;
  
  // Missing proper authorization check - should verify req.user.id === userId
  
  db.get("SELECT * FROM users WHERE id = ?", [userId], (err, user) => {
    if (err || !user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // If changing password, verify current password
    if (new_password) {
      if (!current_password || md5(current_password) !== user.password) {
        return res.status(403).json({ error: 'Current password is incorrect' });
      }
      
      // Update with new password
      db.run("UPDATE users SET password = ?, email = ? WHERE id = ?", 
        [md5(new_password), email || user.email, userId], (err) => {
          if (err) {
            return res.status(500).json({ error: 'Error updating user' });
          }
          
          res.json({ message: 'User updated successfully' });
        });
    } else if (email) {
      // Just update email
      db.run("UPDATE users SET email = ? WHERE id = ?", [email, userId], (err) => {
        if (err) {
          return res.status(500).json({ error: 'Error updating user' });
        }
        
        res.json({ message: 'User updated successfully' });
      });
    } else {
      res.status(400).json({ error: 'No changes provided' });
    }
  });
});

router.delete('/users/:id', checkJwt, isAdmin, (req, res) => {
  const userId = req.params.id;
  
  db.run("DELETE FROM users WHERE id = ?", [userId], (err) => {
    if (err) {
      return res.status(500).json({ error: 'Error deleting user' });
    }
    
    res.json({ message: 'User deleted successfully' });
  });
});

// Product endpoints
router.get('/products', (req, res) => {
  // No authentication required (information disclosure)
  const { category, minPrice, maxPrice, sort } = req.query;
  
  // Vulnerable to SQL injection via query parameters
  let query = "SELECT * FROM products WHERE 1=1";
  let params = [];
  
  if (category) {
    // SQL injection vulnerability in category parameter
    query += ` AND category = '${category}'`;
  }
  
  if (minPrice) {
    query += " AND price >= ?";
    params.push(minPrice);
  }
  
  if (maxPrice) {
    query += " AND price <= ?";
    params.push(maxPrice);
  }
  
  // Vulnerable to SQL injection in sort parameter
  if (sort) {
    query += ` ORDER BY ${sort}`;
  } else {
    query += " ORDER BY id";
  }
  
  db.all(query, params, (err, products) => {
    if (err) {
      // Information leakage via detailed error message
      return res.status(500).json({ error: 'Database error', details: err.message });
    }
    
    res.json({ products });
  });
});

router.get('/products/:id', (req, res) => {
  const productId = req.params.id;
  
  // Vulnerable to SQL injection if productId is not sanitized
  db.get(`SELECT * FROM products WHERE id = ${productId}`, (err, product) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    
    if (!product) {
      return res.status(404).json({ error: 'Product not found' });
    }
    
    res.json({ product });
  });
});

router.post('/products', checkJwt, isAdmin, (req, res) => {
  const { name, description, price, category } = req.body;
  
  if (!name || !description || !price || !category) {
    return res.status(400).json({ error: 'All fields are required' });
  }
  
  // Missing input validation for price (should be a number)
  
  db.run(
    "INSERT INTO products (name, description, price, category) VALUES (?, ?, ?, ?)",
    [name, description, price, category],
    function(err) {
      if (err) {
        return res.status(500).json({ error: 'Error creating product' });
      }
      
      res.status(201).json({ 
        id: this.lastID,
        name,
        description,
        price,
        category
      });
    }
  );
});

router.put('/products/:id', checkJwt, isAdmin, (req, res) => {
  const productId = req.params.id;
  const { name, description, price, category } = req.body;
  
  // Missing validation for required fields
  
  db.get("SELECT * FROM products WHERE id = ?", [productId], (err, product) => {
    if (err || !product) {
      return res.status(404).json({ error: 'Product not found' });
    }
    
    // Update with new values or keep existing ones
    const updatedName = name || product.name;
    const updatedDescription = description || product.description;
    const updatedPrice = price || product.price;
    const updatedCategory = category || product.category;
    
    db.run(
      "UPDATE products SET name = ?, description = ?, price = ?, category = ? WHERE id = ?",
      [updatedName, updatedDescription, updatedPrice, updatedCategory, productId],
      (err) => {
        if (err) {
          return res.status(500).json({ error: 'Error updating product' });
        }
        
        res.json({
          id: productId,
          name: updatedName,
          description: updatedDescription,
          price: updatedPrice,
          category: updatedCategory
        });
      }
    );
  });
});

router.delete('/products/:id', checkJwt, isAdmin, (req, res) => {
  const productId = req.params.id;
  
  db.run("DELETE FROM products WHERE id = ?", [productId], (err) => {
    if (err) {
      return res.status(500).json({ error: 'Error deleting product' });
    }
    
    res.json({ message: 'Product deleted successfully' });
  });
});

// Settings endpoints
router.get('/settings', checkJwt, (req, res) => {
  db.get("SELECT * FROM user_preferences WHERE user_id = ?", [req.user.id], (err, preferences) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    
    res.json({ 
      preferences: preferences || {
        theme: 'dark',
        display_name: req.user.username
      }
    });
  });
});

router.put('/settings', checkJwt, (req, res) => {
  const { display_name, bio, avatar, theme, favorite_category } = req.body;
  
  // Missing input validation
  
  // Check if preferences exist
  db.get("SELECT * FROM user_preferences WHERE user_id = ?", [req.user.id], (err, preferences) => {
    if (preferences) {
      // Update existing preferences
      db.run(
        "UPDATE user_preferences SET display_name = ?, bio = ?, avatar = ?, theme = ?, favorite_category = ? WHERE user_id = ?",
        [display_name, bio, avatar, theme, favorite_category, req.user.id],
        (err) => {
          if (err) {
            return res.status(500).json({ error: 'Error updating preferences' });
          }
          
          res.json({ 
            preferences: { display_name, bio, avatar, theme, favorite_category }
          });
        }
      );
    } else {
      // Insert new preferences
      db.run(
        "INSERT INTO user_preferences (user_id, display_name, bio, avatar, theme, favorite_category) VALUES (?, ?, ?, ?, ?, ?)",
        [req.user.id, display_name, bio, avatar, theme, favorite_category],
        (err) => {
          if (err) {
            return res.status(500).json({ error: 'Error saving preferences' });
          }
          
          res.json({ 
            preferences: { display_name, bio, avatar, theme, favorite_category }
          });
        }
      );
    }
  });
});

// File upload vulnerability - enhanced for attack chaining
router.post('/upload', checkJwt, (req, res) => {
  const { filename, fileContent, fileType, cmdRef } = req.body;
  
  if (!filename || !fileContent) {
    return res.status(400).json({ error: 'Filename and content are required' });
  }
  
  // Basic file upload protection
  const blockedExtensions = ['.php', '.jsp', '.asp', '.cgi', '.exe', '.sh', '.pl'];
  const hasBlockedExtension = blockedExtensions.some(ext => 
    filename.toLowerCase().endsWith(ext)
  );
  
  if (hasBlockedExtension) {
    return res.status(403).json({ 
      error: 'Dangerous file type detected',
      message: 'Basic upload bypasses are blocked. Try more advanced techniques.'
    });
  }
  
  // Ensure uploads directory exists
  if (!fs.existsSync(path.join(__dirname, '..', 'uploads'))) {
    fs.mkdirSync(path.join(__dirname, '..', 'uploads'));
  }
  
  // Check for command injection to file upload attack chain
  if (cmdRef && cmdRef.includes('cmd_injection_ref')) {
    console.log('COMMAND INJECTION TO FILE UPLOAD CHAIN DETECTED');
    
    return res.json({
      success: true,
      message: "File uploaded with command injection privileges",
      flag: "DARK{ch41n3d_cmd_1nj3ct_f1l3_upl04d}",
      note: "Congratulations! You successfully chained command injection and file upload vulnerabilities."
    });
  }
  
  // Check for advanced file upload bypass techniques
  const filenameLower = filename.toLowerCase();
  const advancedBypassDetected = 
    // Double extension
    (filenameLower.includes('.jpg.php') || filenameLower.includes('.png.php')) ||
    // Null byte injection
    filenameLower.includes('%00') ||
    // Case sensitivity bypass
    (filenameLower.includes('.pHp') || filenameLower.includes('.phpJpg')) ||
    // Unusual extensions that might be processed by the server
    (filenameLower.endsWith('.phtml') || filenameLower.endsWith('.php5') || 
    filenameLower.endsWith('.shtml') || filenameLower.endsWith('.phar')) ||
    // Special character bypass
    (filenameLower.includes('.php.') || filenameLower.includes('.php_')) ||
    // MIME type confusion
    (fileType && fileType.includes('image/') && fileContent.includes('<?php'));
  
  const filePath = path.join(__dirname, '..', 'uploads', filename);
  
  fs.writeFile(filePath, fileContent, (err) => {
    if (err) {
      return res.status(500).json({ error: 'Error uploading file' });
    }
    
    let response = {
      message: 'File uploaded successfully',
      filePath
    };
    
    // If they used an advanced bypass technique
    if (advancedBypassDetected) {
      response.flag = "DARK{adv4nc3d_f1l3_upl04d_byp4ss}";
      response.note = "You've successfully bypassed basic file upload protections!";
    }
    
    db.run("INSERT INTO files (filename, path, uploaded_by) VALUES (?, ?, ?)",
      [filename, filePath, req.user.id], (err) => {
        if (err) {
          return res.status(500).json({ error: 'Error recording file upload' });
        }
        
        res.status(201).json(response);
      });
  });
});

// Export data - insecure deserialization vulnerability
router.get('/export', checkJwt, (req, res) => {
  // Get user data for export
  db.get("SELECT * FROM user_preferences WHERE user_id = ?", [req.user.id], (err, preferences) => {
    if (err) {
      return res.status(500).json({ error: 'Error exporting data' });
    }
    
    // Create data object
    const data = {
      user: {
        id: req.user.id,
        username: req.user.username,
        email: req.user.email
      },
      preferences: preferences || {
        theme: 'dark',
        display_name: req.user.username
      }
    };
    
    // Serialize and base64 encode (vulnerable to deserialization attacks)
    const serialize = require('node-serialize');
    const serialized = serialize.serialize(data);
    const exportData = Buffer.from(serialized).toString('base64');
    
    res.json({ data: exportData });
  });
});

// Admin endpoints
router.get('/admin/logs', checkJwt, isAdmin, (req, res) => {
  // Should check if user is admin (relies on isAdmin middleware which has a bypass)
  db.all("SELECT logs.*, users.username FROM logs JOIN users ON logs.user_id = users.id ORDER BY logs.created_at DESC", (err, logs) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    
    res.json({ logs });
  });
});

router.get('/admin/users', checkJwt, isAdmin, (req, res) => {
  // Get all users with sensitive details (poor data protection)
  db.all("SELECT * FROM users", (err, users) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    
    res.json({ users });
  });
});

// Vulnerable config endpoint - information disclosure
router.get('/config', checkJwt, (req, res) => {
  // Reveals sensitive system configuration
  const config = {
    dbPath: './darkvault.db',
    uploadPath: path.join(__dirname, '..', 'uploads'),
    jwt: {
      secret: JWT_SECRET,
      algorithm: 'HS256'
    },
    environment: process.env.NODE_ENV || 'development',
    version: '1.0.0'
  };
  
  res.json({ config });
});

// NoSQL injection simulation endpoint
router.post('/search/advanced', checkJwt, (req, res) => {
  const { query } = req.body;
  
  if (!query) {
    return res.status(400).json({ error: 'Query is required' });
  }
  
  // This would be vulnerable to NoSQL injection if using MongoDB
  // Simulated response for demonstration
  try {
    // Intentionally insecure eval to simulate NoSQL injection
    // DO NOT use eval in real applications
    const searchTerm = eval('`' + query + '`');
    
    // Simulate a search result
    const results = [
      { id: 1, name: 'Result 1', description: 'Description for result 1' },
      { id: 2, name: 'Result 2', description: 'Description for result 2' }
    ];
    
    res.json({ results });
  } catch (err) {
    // Information leakage via detailed error
    res.status(500).json({ error: 'Search error', details: err.message });
  }
});

// GraphQL mock endpoint with broken object level authorization
router.post('/graphql', checkJwt, (req, res) => {
  const { query } = req.body;
  
  // No rate limiting implemented intentionally
  
  // Example GraphQL query processing
  if (query.includes('__schema')) {
    // Allow introspection (security issue)
    return res.json({
      data: {
        __schema: {
          types: [
            { 
              name: 'User',
              fields: [
                { name: 'id', type: 'ID' },
                { name: 'username', type: 'String' },
                { name: 'email', type: 'String' },
                { name: 'password', type: 'String' }, // Exposing sensitive field
                { name: 'creditCardNumber', type: 'String' }, // Exposing sensitive field
                { name: 'apiKey', type: 'String' } // Exposing sensitive field
              ]
            },
            {
              name: 'PrivateData',
              fields: [
                { name: 'id', type: 'ID' },
                { name: 'userId', type: 'ID' },
                { name: 'secretKey', type: 'String' },
                { name: 'backupCodes', type: 'String' }
              ]
            }
          ]
        }
      }
    });
  }
  
  // BROKEN OBJECT LEVEL AUTHORIZATION
  // Note: No check if the requesting user owns the data
  if (query.includes('getUserData')) {
    const userId = query.match(/getUserData\(\s*id:\s*"?(\d+)"?\s*\)/)?.[1];
    
    if (userId) {
      // Missing verification if current user can access this user's data
      db.get("SELECT * FROM users WHERE id = ?", [userId], (err, userData) => {
        if (err || !userData) {
          return res.json({ 
            errors: [{ message: 'User not found' }]
          });
        }
        
        // Fetch sensitive data without proper authorization check
        db.all("SELECT * FROM user_preferences WHERE user_id = ?", [userId], (err, prefs) => {
          db.all("SELECT * FROM account_details WHERE user_id = ?", [userId], (err, accountDetails) => {
            // Return all data including sensitive information
            res.json({
              data: {
                user: {
                  ...userData,
                  preferences: prefs || [],
                  accountDetails: accountDetails || []
                }
              }
            });
          });
        });
      });
      return;
    }
  }
  
  // Default response
  res.json({
    errors: [{ message: 'Invalid GraphQL query' }]
  });
});

// Endpoint demonstrating improper rate limiting
router.get('/no-rate-limit', (req, res) => {
  // This endpoint should have rate limiting but doesn't
  res.json({
    message: 'This endpoint has no rate limiting protection',
    hint: 'Try sending many requests quickly to simulate a DoS attack',
    flag: req.headers['x-request-count'] && parseInt(req.headers['x-request-count']) > 50 ? 
      'DARK{r4t3_l1m1t_byp4ss3d}' : 'Keep trying, send more requests with X-Request-Count header'
  });
});

// Vulnerable to race conditions - counter increment
let requestCounter = 0;
router.post('/increment', checkJwt, (req, res) => {
  // Race condition vulnerability - counter can be incremented incorrectly
  // Missing proper synchronization
  const currentValue = requestCounter;
  
  // Simulate a delay to make race condition more likely
  setTimeout(() => {
    requestCounter = currentValue + 1;
    res.json({ counter: requestCounter });
  }, Math.random() * 100);
});

// NoSQL Injection Vulnerability demonstration
// This route simulates a MongoDB-style database query that's vulnerable to NoSQL injection
router.post('/search-users', (req, res) => {
  const { username, email } = req.body;
  
  // In a real app, this would use a MongoDB or similar NoSQL database
  // For demonstration, we'll simulate how a NoSQL query could be vulnerable
  
  console.log('NoSQL query parameters:', JSON.stringify(req.body));
  
  // Simulate a NoSQL query that's vulnerable to injection
  // Real exploit would be something like: {"username":{"$ne":null}}
  let query = "SIMULATED_NOSQL_QUERY: ";
  
  if (username) {
    query += `username: "${username}", `;
  }
  
  if (email) {
    query += `email: "${email}"`;
  }
  
  // Simulate query execution and return mock results
  // In a real vulnerable app, this would execute the injected query
  
  // If username contains NoSQL injection like {"$ne":null}, log it for demonstration
  if (username && (username.includes('$') || username.includes('{'))) {
    console.log('POTENTIAL NOSQL INJECTION DETECTED:', username);
    
    // Return all users as if the injection worked plus a flag
    return res.json({
      message: 'Query executed',
      query: query,
      flag: "DARK{n0sql_1nj3ct10n_m4st3r}",
      results: [
        { id: 1, username: 'admin', email: 'admin@darkvault.com', role: 'admin' },
        { id: 2, username: 'user1', email: 'user1@example.com', role: 'user' },
        { id: 3, username: 'user2', email: 'user2@example.com', role: 'user' }
      ]
    });
  }
  
  // Normal case - return filtered results
  res.json({
    message: 'Query executed',
    query: query,
    results: username === 'admin' ? 
      [{ id: 1, username: 'admin', email: 'admin@darkvault.com', role: 'admin' }] : 
      []
  });
});

// Weak Encryption Implementation
// Demonstrates poor cryptographic practices
router.post('/encrypt-data', (req, res) => {
  const { data, key } = req.body;
  
  if (!data || !key) {
    return res.status(400).json({ error: 'Missing data or key parameter' });
  }
  
  // Vulnerable: Using a weak custom encryption algorithm
  function weakEncrypt(text, encryptionKey) {
    let result = '';
    // Simple XOR "encryption" - extremely weak
    for (let i = 0; i < text.length; i++) {
      result += String.fromCharCode(text.charCodeAt(i) ^ encryptionKey.charCodeAt(i % encryptionKey.length));
    }
    // Convert to hex for display
    return Buffer.from(result).toString('hex');
  }
  
  // Vulnerable: Using a predictable, weak IV
  const weakIV = "0123456789";
  
  // Vulnerable: No key stretching, weak key validation
  if (key.length < 8) {
    // Still proceeds with weak key
    console.log('Warning: Encryption key is too short but proceeding anyway');
  }
  
  const encryptedData = weakEncrypt(data, key + weakIV);
  
  // Check if user is trying to break the encryption
  if (key === 'test' && data.includes('secret')) {
    // If they're testing the encryption with a specific pattern, give them the flag
    return res.json({
      success: true,
      encryptedData: encryptedData,
      message: "Encryption successful but insecure!",
      flag: "DARK{w34k_crypt0_3xpl01t3d}"
    });
  }
  
  // Information disclosure: returning too much data about the encryption process
  res.json({
    success: true,
    originalDataLength: data.length,
    encryptedData: encryptedData,
    keyUsed: key, // Extremely bad practice - exposing the key
    algorithm: "custom-xor", // Disclosing algorithm details
    iv: weakIV, // Exposing the IV
    message: "Data encrypted successfully. Note: This encryption is for demonstration only and is NOT secure!"
  });
});

// XSS Vulnerability in message board
router.post('/messages', (req, res) => {
  const { title, content, author } = req.body;
  
  if (!title || !content) {
    return res.status(400).json({ error: 'Title and content are required' });
  }
  
  // Basic XSS filtering - blocks obvious attempts
  const lowerContent = content.toLowerCase();
  const blockedPatterns = [
    '<script>', '</script>',
    'javascript:', 
    'onerror=', 'onload=', 'onclick=',
    'alert(', 'prompt(', 'confirm(',
    'document.cookie'
  ];
  
  // Check for basic XSS patterns
  const hasBlockedPattern = blockedPatterns.some(pattern => 
    lowerContent.includes(pattern.toLowerCase())
  );
  
  if (hasBlockedPattern) {
    return res.status(403).json({ 
      error: 'Potential XSS attack detected and blocked.',
      message: 'Basic XSS attempts are blocked. Try more advanced techniques.'
    });
  }
  
  // Still vulnerable to more sophisticated XSS
  // Store the message (simulated)
  const messageId = Date.now();
  
  // Check for advanced XSS attempts (for flag purposes)
  // These are patterns that would bypass our basic filter
  const advancedXssPatterns = [
    'eval(', 'settimeout(', 'setinterval(',
    '<img src=x', '<svg', '<iframe',
    'expression(', 'url(', 
    'background:', 'data:',
    'on\\w+=', // Regex-like check for event handlers with encoding
    '&#', '\\u', '%3c', '%3e' // Encoded characters
  ];
  
  const hasAdvancedPattern = advancedXssPatterns.some(pattern => {
    const regex = new RegExp(pattern, 'i');
    return regex.test(content);
  });
  
  if (hasAdvancedPattern) {
    console.log('ADVANCED XSS ATTEMPT DETECTED:', content);
    
    // Award flag for successful advanced XSS
    return res.json({
      id: messageId,
      title,
      content,
      author: author || 'Anonymous',
      timestamp: new Date().toISOString(),
      message: "Message posted successfully",
      flag: "DARK{adv4nc3d_xss_3xpl01t3r}"
    });
  }
  
  res.json({
    id: messageId,
    title,
    content,
    author: author || 'Anonymous',
    timestamp: new Date().toISOString(),
    message: "Message posted successfully"
  });
});

// File reading endpoint - vulnerable to path traversal
router.get('/file', (req, res) => {
  const filename = req.query.name;
  
  if (!filename) {
    return res.status(400).json({ error: 'Filename is required' });
  }
  
  // Basic path traversal protection
  const blockedPatterns = [
    '../', '..\\', '/..',
    'etc/passwd', 'etc/shadow',
    '/root', '/home',
    'flag.txt', '/etc/darkflag'
  ];
  
  // Check for basic path traversal attempts
  const hasBlockedPattern = blockedPatterns.some(pattern => 
    filename.toLowerCase().includes(pattern.toLowerCase())
  );
  
  if (hasBlockedPattern) {
    return res.status(403).json({ 
      error: 'Path traversal attempt detected.',
      message: 'Basic path traversal attempts are blocked. Try more advanced techniques.'
    });
  }
  
  // Still vulnerable to more sophisticated path traversal
  try {
    const filePath = path.join(__dirname, '../assets/', filename);
    
    // Check for advanced path traversal (encoding bypasses)
    if (filename.includes('%2e') || 
        filename.includes('%2f') || 
        filename.includes('\\u') || 
        filename.includes('..%2f') || 
        filename.includes('.././') || 
        filename.includes('....//') || 
        filename.includes('0x')) {
      
      console.log('ADVANCED PATH TRAVERSAL DETECTED:', filename);
      
      // Return the flag for advanced path traversal with a hint for the attack chain
      return res.json({
        content: "Congratulations! You've bypassed basic path traversal protections: DARK{adv4nc3d_p4th_tr4v3rs4l_m4st3r}",
        filename: filename,
        hint: "Try to find a file called 'config.secret' that contains JWT secrets for the admin dashboard."
      });
    }
    
    const data = fs.readFileSync(filePath, 'utf8');
    res.json({ content: data, filename: filename });
  } catch (err) {
    // Information leakage in error message
    res.status(500).json({ 
      error: 'Error reading file', 
      details: err.message, 
      path: path.join(__dirname, '../assets/', filename) 
    });
  }
});

// SQL Injection vulnerability in login route
router.post('/login', (req, res) => {
  const { username, password } = req.body;
  
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }
  
  // VULNERABLE: SQL Injection vulnerability
  // Direct string concatenation in SQL query without parameterization
  const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
  
  db.get(query, (err, user) => {
    if (err) {
      // VULNERABLE: Detailed error exposure
      return res.status(500).json({ error: 'Database error', details: err.message });
    }
    
    if (user) {
      // Check if this was a successful SQL injection
      if (username.includes("'") || username.includes("--")) {
        // User performed SQL injection - add flag to the response
        user.flag = "DARK{sql_m4st3r}";
        user.message = "Congratulations! You've successfully performed SQL injection!";
      }
      
      const token = generateToken(user);
      res.json({ success: true, user, token });
    } else {
      res.status(401).json({ error: 'Invalid username or password' });
    }
  });
});

// Command injection vulnerability in ping endpoint
router.post('/ping', (req, res) => {
  const { host } = req.body;
  
  if (!host) {
    return res.status(400).json({ error: 'Host is required' });
  }
  
  // Basic command injection protection
  const blockedPatterns = [
    ';', '&&', '||', '`', 
    'cat ', '/bin/sh', '/bin/bash',
    '| cat', '>/tmp', 
    'flag.txt', 'passwd'
  ];
  
  // Check for basic command injection attempts
  const hasBlockedPattern = blockedPatterns.some(pattern => 
    host.toLowerCase().includes(pattern.toLowerCase())
  );
  
  if (hasBlockedPattern) {
    return res.status(403).json({ 
      error: 'Potentially dangerous command detected.',
      message: 'Basic command injection attempts are blocked. Try more advanced techniques.'
    });
  }
  
  // Create a special flag file that can be found through command injection
  fs.writeFileSync('/tmp/cmd_flag.txt', 'DARK{c0mm4nd_1nj3ct10n_pr0}');
  
  console.log(`Executing ping command for host: ${host}`);
  
  // Still vulnerable to more sophisticated command injection
  exec(`ping -c 4 ${host}`, (error, stdout, stderr) => {
    if (error) {
      return res.status(500).json({ error: 'Execution error', details: error.message });
    }
    
    if (stderr) {
      return res.status(500).json({ error: 'stderr', details: stderr });
    }
    
    // Check for advanced command injection (bypassing filters)
    if ((host.includes('$') && (host.includes('(') || host.includes('{'))) || 
        (host.includes('\\') && host.includes('x')) || 
        host.includes('$(') || 
        host.includes('${') || 
        host.includes('%0A') || 
        host.includes('0x') || 
        host.includes('\\n')) {
      
      console.log('ADVANCED COMMAND INJECTION DETECTED:', host);
      
      // Give a reference token to use for the file upload attack chain
      return res.json({
        output: stdout,
        message: "Command executed successfully. You've bypassed the basic protections!",
        flag: "DARK{adv4nc3d_c0mm4nd_1nj3ct10n_pr0}",
        cmdRef: "cmd_injection_ref_" + Date.now(),
        note: "Use this cmdRef in the /upload endpoint to chain vulnerabilities."
      });
    }
    
    res.json({ output: stdout });
  });
});

// JWT Manipulation Vulnerability - enhanced with attack chain
router.get('/admin/dashboard', (req, res) => {
  // Extract token from Authorization header
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: 'Authentication token is required' });
  }
  
  try {
    // Basic JWT protection - check for none algorithm
    try {
      const decoded = jwt.decode(token, { complete: true });
      if (decoded && decoded.header && decoded.header.alg === 'none') {
        return res.status(401).json({ 
          error: 'Invalid token algorithm',
          message: 'Basic JWT attacks are blocked. Try more advanced techniques.'
        });
      }
    } catch (e) {
      // Continue processing even if decode fails
    }
    
    // Still vulnerable to more sophisticated JWT attacks
    const decoded = jwt.verify(token, 'darkvault-secret-key');
    
    // Check if this token was obtained through the attack chain
    // This simulates a scenario where the JWT secret was found through path traversal
    if (decoded.obtainedViaPathTraversal === true) {
      return res.json({
        message: "Congratulations! You've completed the attack chain!",
        user: decoded,
        flag: "DARK{ch41n3d_vulns_jwt_p4th_tr4v3rs4l}",
        note: "You successfully chained path traversal and JWT manipulation attacks."
      });
    }
    
    // Standard admin access
    if (decoded.isAdmin) {
      return res.json({
        message: "Welcome to the admin dashboard!",
        user: decoded,
        flag: "DARK{jwt_4dm1n_3sc4l4t10n}"
      });
    } else {
      return res.status(403).json({ error: 'Admin privileges required' });
    }
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token', details: err.message });
  }
});

// Add a hidden endpoint that reveals the JWT secret through path traversal
router.get('/secret-file', (req, res) => {
  res.json({
    content: "JWT_SECRET=darkvault-secret-key\nThis file is meant to be accessed via path traversal.",
    filename: "config.secret"
  });
});

// Race condition vulnerability
router.post('/update-balance', (req, res) => {
  const { userId, amount } = req.body;
  
  if (!userId || !amount) {
    return res.status(400).json({ error: 'User ID and amount are required' });
  }
  
  // VULNERABLE: Race condition example
  // Simulating a database read-then-write operation without proper locking
  
  // Create a counter for tracking the number of successful exploits
  if (!global.raceExploitCounter) {
    global.raceExploitCounter = 0;
  }
  
  // Step 1: Read current balance (vulnerable to race condition)
  console.log(`[${new Date().toISOString()}] Reading balance for user ${userId}`);
  
  // Simulate database read delay
  setTimeout(() => {
    // Mock current balance
    const currentBalance = 1000; 
    console.log(`[${new Date().toISOString()}] Current balance: ${currentBalance}`);
    
    // Step 2: Calculate new balance
    const newBalance = currentBalance + parseInt(amount);
    
    // Step 3: Update balance after delay (vulnerable window for race condition)
    setTimeout(() => {
      console.log(`[${new Date().toISOString()}] Updating balance to: ${newBalance}`);
      
      // Increment the exploit counter for this request
      global.raceExploitCounter++;
      
      // If user has triggered the race condition multiple times, provide the flag
      let flagData = {};
      if (global.raceExploitCounter >= 3) {
        flagData = {
          raceExploit: true,
          flag: "DARK{r4c3_c0nd1t10n_3xpl01t3d}",
          message: "Congratulations! You've successfully exploited the race condition vulnerability!"
        };
        // Reset counter
        global.raceExploitCounter = 0;
      }
      
      // Return the updated balance (in a real app, this would be after DB write)
      res.json({ 
        userId, 
        oldBalance: currentBalance,
        newBalance,
        message: 'Balance updated successfully',
        exploitCounter: global.raceExploitCounter,
        ...flagData
      });
    }, 500); // Intentional delay to make race condition more likely
  }, 500);
});

// CSRF Vulnerability demo - enhanced for attack chaining with XSS
router.post('/update-email', (req, res) => {
  const { userId, newEmail, xssRef } = req.body;
  
  if (!userId || !newEmail) {
    return res.status(400).json({ error: 'User ID and new email are required' });
  }
  
  // Basic CSRF protection - check referer
  const referer = req.headers.referer;
  if (referer && !referer.includes('darkvault')) {
    return res.status(403).json({ 
      error: 'Invalid referer',
      message: 'Basic CSRF attempts are blocked. Try more advanced techniques.'
    });
  }
  
  // Check for XSS to CSRF attack chain
  if (xssRef && xssRef.includes('xss_attack_ref')) {
    return res.json({
      success: true,
      message: "Email updated successfully",
      flag: "DARK{ch41n3d_xss_csrf_4tt4ck}",
      note: "Congratulations! You successfully chained XSS and CSRF vulnerabilities."
    });
  }
  
  // Check for regular CSRF testing pattern
  if (newEmail.includes('csrf') || newEmail.includes('attacker')) {
    return res.json({
      success: true,
      message: "Email updated successfully",
      flag: "DARK{csrf_pr0t3ct10n_byp4ss3d}",
      note: "This endpoint is vulnerable to CSRF because it doesn't validate any tokens"
    });
  }
  
  res.json({
    success: true,
    message: "Email updated successfully",
    note: "This endpoint is vulnerable to CSRF because it doesn't validate any tokens"
  });
});

// Helper endpoint to verify XSS payload effectiveness for attack chain
router.post('/report-xss', (req, res) => {
  const { payload, stolenCookie } = req.body;
  
  console.log('XSS REPORT RECEIVED:', { payload, stolenCookie });
  
  res.json({
    success: true,
    message: "XSS report received",
    xssRef: "xss_attack_ref_" + Date.now(),
    note: "Use this xssRef in the update-email endpoint to complete the attack chain"
  });
});

// Prototype Pollution vulnerability
router.post('/merge-config', (req, res) => {
  const { userConfig } = req.body;
  
  if (!userConfig || typeof userConfig !== 'object') {
    return res.status(400).json({ error: 'Valid user configuration object is required' });
  }
  
  // Default config
  const defaultConfig = {
    theme: 'dark',
    notifications: true,
    language: 'en'
  };
  
  // VULNERABLE: Unsafe merging of objects can lead to prototype pollution
  // In a real app, this would use something like lodash.merge which can be vulnerable
  function unsafeMerge(target, source) {
    for (const key in source) {
      if (typeof source[key] === 'object' && source[key] !== null) {
        if (!target[key]) target[key] = {};
        unsafeMerge(target[key], source[key]);
      } else {
        target[key] = source[key];
      }
    }
    return target;
  }
  
  // Check if this is a prototype pollution attempt
  if (JSON.stringify(userConfig).includes('__proto__') || 
      JSON.stringify(userConfig).includes('constructor') || 
      JSON.stringify(userConfig).includes('prototype')) {
    console.log('PROTOTYPE POLLUTION ATTEMPT DETECTED:', JSON.stringify(userConfig));
    
    // Create merged config (would be vulnerable in a real app)
    const mergedConfig = unsafeMerge({}, defaultConfig);
    unsafeMerge(mergedConfig, userConfig);
    
    return res.json({
      config: mergedConfig,
      message: "Configuration merged successfully",
      flag: "DARK{pr0t0typ3_p0llut10n_m4st3r}",
      note: "You've successfully demonstrated a prototype pollution attack vector!"
    });
  }
  
  // Create merged config (would be vulnerable in a real app)
  const mergedConfig = unsafeMerge({}, defaultConfig);
  unsafeMerge(mergedConfig, userConfig);
  
  res.json({
    config: mergedConfig,
    message: "Configuration merged successfully"
  });
});

// XXE Vulnerability in XML import
router.post('/import-xml', (req, res) => {
  const { xml } = req.body;
  
  if (!xml) {
    return res.status(400).json({ error: 'XML data is required' });
  }
  
  // VULNERABLE: Unsafe XML parsing susceptible to XXE
  try {
    const parser = require('xml2js').Parser({
      explicitArray: false,
      // Missing: disableDTD: true or other XXE protections
    });
    
    parser.parseString(xml, (err, result) => {
      if (err) {
        return res.status(400).json({ error: 'Invalid XML', details: err.message });
      }
      
      // Check if this is an XXE attack attempt
      if (xml.includes('<!ENTITY') && xml.includes('SYSTEM')) {
        console.log('XXE ATTACK DETECTED:', xml);
        
        return res.json({
          result,
          message: "XML processed successfully",
          note: "You've successfully exploited an XXE vulnerability",
          flag: "DARK{xxe_data_extr4ct0r}"
        });
      }
      
      res.json({
        result,
        message: "XML processed successfully"
      });
    });
  } catch (err) {
    res.status(500).json({ error: 'XML processing error', details: err.message });
  }
});

// SSTI Vulnerability in email templates
router.post('/render-template', (req, res) => {
  const { template, data } = req.body;
  
  if (!template) {
    return res.status(400).json({ error: 'Template is required' });
  }
  
  // VULNERABLE: Server-side template injection
  try {
    // Simulate template rendering with eval (extremely dangerous!)
    const ejs = require('ejs');
    const renderedTemplate = ejs.render(template, data || {});
    
    // Check if this is an SSTI attack that accessed environment variables
    if (template.includes('process.env')) {
      console.log('SSTI ATTACK DETECTED:', template);
      
      return res.json({
        rendered: renderedTemplate,
        message: "Template rendered successfully",
        flag: "DARK{t3mpl4t3_1nj3ct10n}"
      });
    }
    
    res.json({
      rendered: renderedTemplate,
      message: "Template rendered successfully"
    });
  } catch (err) {
    // Information leakage in error
    res.status(500).json({ error: 'Template rendering error', details: err.message });
  }
});

module.exports = router; 