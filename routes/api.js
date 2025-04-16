const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();
const md5 = require('md5');
const db = new sqlite3.Database('./darkvault.db');
const fs = require('fs');
const path = require('path');

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
  if (req.user && req.user.isAdmin) {
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
      isAdmin: user.isAdmin
    };
    
    // Vulnerable JWT: weak secret, no expiration, no audience or issuer
    const token = jwt.sign(payload, JWT_SECRET);
    
    res.json({ 
      token,
      user: {
        id: user.id,
        username: user.username,
        isAdmin: user.isAdmin ? true : false
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
    
    db.run("INSERT INTO users (username, password, email) VALUES (?, ?, ?)", 
      [username, hashedPassword, email], function(err) {
        if (err) {
          return res.status(500).json({ error: 'Error registering user' });
        }
        
        // Create JWT token
        const token = jwt.sign({
          id: this.lastID,
          username,
          isAdmin: 0
        }, JWT_SECRET);
        
        res.status(201).json({
          token,
          user: {
            id: this.lastID,
            username,
            isAdmin: false
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

// File upload vulnerability
router.post('/upload', checkJwt, (req, res) => {
  const { filename, fileContent } = req.body;
  
  // No validation of file extension or content type
  // Vulnerable to path traversal attacks
  const filePath = path.join(__dirname, '..', 'uploads', filename);
  
  // Ensure uploads directory exists
  if (!fs.existsSync(path.join(__dirname, '..', 'uploads'))) {
    fs.mkdirSync(path.join(__dirname, '..', 'uploads'));
  }
  
  fs.writeFile(filePath, fileContent, (err) => {
    if (err) {
      return res.status(500).json({ error: 'Error uploading file' });
    }
    
    db.run("INSERT INTO files (filename, path, uploaded_by) VALUES (?, ?, ?)",
      [filename, filePath, req.user.id], (err) => {
        if (err) {
          return res.status(500).json({ error: 'Error recording file upload' });
        }
        
        res.status(201).json({ 
          message: 'File uploaded successfully',
          filePath
        });
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

// GraphQL-like vulnerable endpoint
router.post('/graphql', (req, res) => {
  const { query } = req.body;
  
  if (!query) {
    return res.status(400).json({ error: 'Query is required' });
  }
  
  try {
    // Vulnerable implementation - directly evaluates user input
    // This simulates GraphQL introspection and injection vulnerabilities
    let result = {};
    
    // Simulate GraphQL processing with vulnerable eval
    if (query.includes('IntrospectionQuery')) {
      // Information disclosure through introspection
      result = {
        __schema: {
          types: [
            { name: 'User', fields: [
              { name: 'id', type: 'ID' },
              { name: 'username', type: 'String' },
              { name: 'email', type: 'String' },
              { name: 'password', type: 'String' }, // Sensitive field exposed
              { name: 'isAdmin', type: 'Boolean' }
            ]},
            { name: 'Product', fields: [
              { name: 'id', type: 'ID' },
              { name: 'name', type: 'String' },
              { name: 'description', type: 'String' },
              { name: 'price', type: 'Float' },
              { name: 'category', type: 'String' }
            ]}
          ]
        }
      };
    } else if (query.includes('allUsers')) {
      // No authentication check for sensitive data
      db.all("SELECT * FROM users", (err, users) => {
        if (err) {
          return res.status(500).json({ error: 'Database error', details: err.message });
        }
        result = { allUsers: users };
        res.json({ data: result });
      });
      return; // Return early as we're handling the response in the callback
    } else if (query.includes('user(')) {
      // Extract ID using regex - vulnerable to injection
      const idMatch = query.match(/user\(id:\s*["']?([^"'\s\)]+)["']?\)/);
      const id = idMatch ? idMatch[1] : null;
      
      if (id) {
        // Vulnerable to injection as we're not using parameterized queries
        db.get(`SELECT * FROM users WHERE id = ${id}`, (err, user) => {
          if (err) {
            return res.status(500).json({ error: 'Database error', details: err.message });
          }
          result = { user: user || null };
          res.json({ data: result });
        });
        return; // Return early
      }
    } else if (query.includes('product(')) {
      // Extract ID using regex - vulnerable to injection
      const idMatch = query.match(/product\(id:\s*["']?([^"'\s\)]+)["']?\)/);
      const id = idMatch ? idMatch[1] : null;
      
      if (id) {
        // Vulnerable to injection
        db.get(`SELECT * FROM products WHERE id = ${id}`, (err, product) => {
          if (err) {
            return res.status(500).json({ error: 'Database error', details: err.message });
          }
          result = { product: product || null };
          res.json({ data: result });
        });
        return; // Return early
      }
    }
    
    // Default response
    res.json({ data: result });
    
  } catch (err) {
    // Verbose error messages - information disclosure
    res.status(500).json({ 
      error: 'GraphQL error', 
      details: err.message,
      stack: err.stack // Leaking stack trace - security vulnerability
    });
  }
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
    
    // Return all users as if the injection worked
    return res.json({
      message: 'Query executed',
      query: query,
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

// Path Traversal Vulnerability in File Operations API
// This route is vulnerable to path traversal attacks
router.get('/file', (req, res) => {
  const filename = req.query.name;
  
  if (!filename) {
    return res.status(400).json({ error: 'Filename is required' });
  }
  
  // VULNERABLE: No sanitization of user input
  // Attacker can use "../" to traverse directories
  const filePath = path.join(__dirname, '../assets/', filename);
  
  console.log(`Attempting to access file: ${filePath}`);
  
  // Attempt to read the file
  fs.readFile(filePath, 'utf8', (err, data) => {
    if (err) {
      return res.status(404).json({ 
        error: 'File not found or cannot be read',
        details: err.message 
      });
    }
    
    // Send file contents directly to the user
    res.type('text/plain').send(data);
  });
});

// Race Condition Vulnerability - Account Balance Update
router.post('/update-balance', (req, res) => {
  const { userId, amount } = req.body;
  
  if (!userId || !amount) {
    return res.status(400).json({ error: 'User ID and amount are required' });
  }
  
  // VULNERABLE: Race condition example
  // Simulating a database read-then-write operation without proper locking
  
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
      
      // Return the updated balance (in a real app, this would be after DB write)
      res.json({ 
        userId, 
        oldBalance: currentBalance,
        newBalance,
        message: 'Balance updated successfully' 
      });
    }, 500); // Intentional delay to make race condition more likely
  }, 500);
});

module.exports = router; 