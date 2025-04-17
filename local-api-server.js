const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const md5 = require('md5');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const { exec } = require('child_process');

// Import the database module
const db = require('./db');

// Initialize Express app
const app = express();
const port = process.env.API_PORT || 3001;

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = path.join(__dirname, 'uploads');
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir);
    }
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + '-' + file.originalname);
  }
});

const upload = multer({ storage });

// JWT Secret (intentionally weak for the vulnerable app)
const JWT_SECRET = "darkvault-secret-key";

// Middleware to check JWT
const checkJwt = (req, res, next) => {
  const token = req.headers.authorization ? req.headers.authorization.replace('Bearer ', '') : null;
  
  if (!token) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  
  try {
    // Vulnerable JWT verification (no algorithm check)
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
};

// Admin check middleware
const isAdmin = (req, res, next) => {
  if (req.user && (req.user.isAdmin || req.user.role === 'admin')) {
    next();
  } else if (req.user && req.user.role === 'manager') {
    const managerAllowedPaths = ['/users', '/products', '/messages', '/todos'];
    const requestPath = req.path.split('/')[1];
    
    if (managerAllowedPaths.includes(requestPath)) {
      next();
    } else {
      res.status(403).json({ error: 'Manager does not have access to this resource' });
    }
  } else {
    // Backdoor parameter (intentional vulnerability)
    if (req.query.admin === 'true') {
      next();
    } else {
      res.status(403).json({ error: 'Admin access required' });
    }
  }
};

// Authentication endpoints
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }
  
  // Vulnerable SQL query
  const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${md5(password)}'`;
  
  db.get(query, (err, user) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Create JWT token
    const payload = {
      id: user.id,
      username: user.username,
      role: user.role,
      isAdmin: user.isAdmin === 1 || user.role === 'admin',
    };
    
    const token = jwt.sign(payload, JWT_SECRET);
    
    res.json({ 
      token,
      user: {
        id: user.id,
        username: user.username,
        role: user.role,
        isAdmin: user.isAdmin === 1 || user.role === 'admin',
      }
    });
  });
});

app.post('/api/auth/register', (req, res) => {
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
          role: 'user',
          isAdmin: 0,
        }, JWT_SECRET);
        
        res.status(201).json({
          token,
          user: {
            id: this.lastID,
            username,
            role: 'user',
            isAdmin: false,
          }
        });
      });
  });
});

// User endpoints
app.get('/api/users', checkJwt, (req, res) => {
  // IDOR vulnerability - any authenticated user can see all users
  db.all("SELECT id, username, email, isAdmin FROM users", (err, users) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    
    res.json({ users });
  });
});

app.get('/api/users/:id', checkJwt, (req, res) => {
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
    
    // Also fetch user preferences
    db.get("SELECT * FROM user_preferences WHERE user_id = ?", [userId], (err, preferences) => {
      user.preferences = preferences || {};
      res.json({ user });
    });
  });
});

app.put('/api/users/:id', checkJwt, (req, res) => {
  const userId = req.params.id;
  const { email, current_password, new_password } = req.body;
  
  // IDOR vulnerability - no proper authorization check
  if (parseInt(userId) !== req.user.id && !req.user.isAdmin) {
    // This check can be bypassed with JWT manipulation
    return res.status(403).json({ error: 'Not authorized to update this user' });
  }
  
  if (new_password && !current_password) {
    return res.status(400).json({ error: 'Current password is required to set new password' });
  }
  
  db.get("SELECT * FROM users WHERE id = ?", [userId], (err, user) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // Update logic
    if (new_password) {
      if (md5(current_password) !== user.password) {
        return res.status(400).json({ error: 'Current password is incorrect' });
      }
      
      db.run("UPDATE users SET password = ?, email = ? WHERE id = ?", 
        [md5(new_password), email || user.email, userId], (err) => {
          if (err) {
            return res.status(500).json({ error: 'Error updating user' });
          }
          
          res.json({ message: 'User updated successfully' });
        });
    } else if (email) {
      db.run("UPDATE users SET email = ? WHERE id = ?", [email, userId], (err) => {
        if (err) {
          return res.status(500).json({ error: 'Error updating user' });
        }
        
        res.json({ message: 'User updated successfully' });
      });
    } else {
      res.status(400).json({ error: 'No fields to update' });
    }
  });
});

// Todos endpoints
app.get('/api/todos', checkJwt, (req, res) => {
  // IDOR vulnerability - no proper filtering
  const userId = req.query.user_id || req.user.id;
  
  // This allows any authenticated user to see others' todos by manipulating user_id parameter
  db.all("SELECT * FROM todos WHERE user_id = ?", [userId], (err, todos) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    
    res.json({ todos });
  });
});

app.post('/api/todos', checkJwt, (req, res) => {
  const { title } = req.body;
  const userId = req.user.id;
  
  if (!title) {
    return res.status(400).json({ error: 'Title is required' });
  }
  
  db.run("INSERT INTO todos (user_id, title, completed) VALUES (?, ?, ?)", 
    [userId, title, 0], function(err) {
      if (err) {
        return res.status(500).json({ error: 'Error creating todo' });
      }
      
      res.status(201).json({
        todo: {
          id: this.lastID,
          user_id: userId,
          title,
          completed: 0
        }
      });
    });
});

app.put('/api/todos/:id', checkJwt, (req, res) => {
  const todoId = req.params.id;
  const { title, completed } = req.body;
  
  // Fetch the todo first to verify ownership (but with IDOR vulnerability)
  db.get("SELECT * FROM todos WHERE id = ?", [todoId], (err, todo) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    
    if (!todo) {
      return res.status(404).json({ error: 'Todo not found' });
    }
    
    if (todo.user_id !== req.user.id && !req.user.isAdmin) {
      return res.status(403).json({ error: 'Not authorized to update this todo' });
    }
    
    // Update the todo
    const updates = [];
    const params = [];
    
    if (title !== undefined) {
      updates.push("title = ?");
      params.push(title);
    }
    
    if (completed !== undefined) {
      updates.push("completed = ?");
      params.push(completed ? 1 : 0);
    }
    
    if (updates.length === 0) {
      return res.status(400).json({ error: 'No fields to update' });
    }
    
    params.push(todoId);
    
    db.run(`UPDATE todos SET ${updates.join(", ")} WHERE id = ?`, params, (err) => {
      if (err) {
        return res.status(500).json({ error: 'Error updating todo' });
      }
      
      res.json({ message: 'Todo updated successfully' });
    });
  });
});

app.delete('/api/todos/:id', checkJwt, (req, res) => {
  const todoId = req.params.id;
  
  // Fetch the todo first to verify ownership (but with IDOR vulnerability)
  db.get("SELECT * FROM todos WHERE id = ?", [todoId], (err, todo) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    
    if (!todo) {
      return res.status(404).json({ error: 'Todo not found' });
    }
    
    if (todo.user_id !== req.user.id && !req.user.isAdmin) {
      return res.status(403).json({ error: 'Not authorized to delete this todo' });
    }
    
    db.run("DELETE FROM todos WHERE id = ?", [todoId], (err) => {
      if (err) {
        return res.status(500).json({ error: 'Error deleting todo' });
      }
      
      res.json({ message: 'Todo deleted successfully' });
    });
  });
});

// Products endpoints
app.get('/api/products', (req, res) => {
  // SQLi vulnerability in category parameter
  const category = req.query.category;
  let query = "SELECT * FROM products";
  
  if (category) {
    // Unsafe string concatenation
    query += ` WHERE category = '${category}'`;
  }
  
  db.all(query, (err, products) => {
    if (err) {
      return res.status(500).json({ error: 'Database error', details: err.message });
    }
    
    res.json({ products });
  });
});

app.get('/api/products/:id', (req, res) => {
  const productId = req.params.id;
  
  db.get("SELECT * FROM products WHERE id = ?", [productId], (err, product) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    
    if (!product) {
      return res.status(404).json({ error: 'Product not found' });
    }
    
    res.json({ product });
  });
});

app.post('/api/products', checkJwt, isAdmin, (req, res) => {
  const { name, description, price, category } = req.body;
  
  if (!name || !price || !category) {
    return res.status(400).json({ error: 'Name, price, and category are required' });
  }
  
  db.run("INSERT INTO products (name, description, price, category) VALUES (?, ?, ?, ?)", 
    [name, description, price, category], function(err) {
      if (err) {
        return res.status(500).json({ error: 'Error creating product' });
      }
      
      res.status(201).json({
        product: {
          id: this.lastID,
          name,
          description,
          price,
          category
        }
      });
    });
});

// Messages endpoints
app.get('/api/messages', checkJwt, (req, res) => {
  const userId = req.user.id;
  
  db.all("SELECT * FROM messages WHERE user_id = ?", [userId], (err, messages) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    
    res.json({ messages });
  });
});

app.post('/api/messages', checkJwt, (req, res) => {
  const { title, content } = req.body;
  const userId = req.user.id;
  
  if (!content) {
    return res.status(400).json({ error: 'Message content is required' });
  }
  
  db.run("INSERT INTO messages (user_id, title, content, author) VALUES (?, ?, ?, ?)", 
    [userId, title || 'Untitled', content, req.user.username], function(err) {
      if (err) {
        return res.status(500).json({ error: 'Error creating message' });
      }
      
      res.status(201).json({
        message: {
          id: this.lastID,
          user_id: userId,
          title: title || 'Untitled',
          content,
          author: req.user.username
        }
      });
    });
});

// File upload endpoint
app.post('/api/upload', checkJwt, upload.single('file'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded' });
  }
  
  const file = req.file;
  const userId = req.user.id;
  
  db.run("INSERT INTO files (filename, path, uploaded_by) VALUES (?, ?, ?)", 
    [file.originalname, file.path, userId], function(err) {
      if (err) {
        return res.status(500).json({ error: 'Error saving file info' });
      }
      
      res.json({
        file: {
          id: this.lastID,
          filename: file.originalname,
          path: file.path,
          uploaded_by: userId
        }
      });
    });
});

// User preferences endpoint
app.post('/api/user/preferences', checkJwt, (req, res) => {
  const { display_name, bio, theme, favorite_category } = req.body;
  const userId = req.user.id;
  
  // Check if preferences exist
  db.get("SELECT * FROM user_preferences WHERE user_id = ?", [userId], (err, preferences) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    
    if (preferences) {
      // Update existing preferences
      db.run("UPDATE user_preferences SET display_name = ?, bio = ?, theme = ?, favorite_category = ? WHERE user_id = ?", 
        [display_name, bio, theme, favorite_category, userId], (err) => {
          if (err) {
            return res.status(500).json({ error: 'Error updating preferences' });
          }
          
          res.json({ message: 'Preferences updated successfully' });
        });
    } else {
      // Create new preferences
      db.run("INSERT INTO user_preferences (user_id, display_name, bio, theme, favorite_category) VALUES (?, ?, ?, ?, ?)", 
        [userId, display_name, bio, theme, favorite_category], (err) => {
          if (err) {
            return res.status(500).json({ error: 'Error creating preferences' });
          }
          
          res.json({ message: 'Preferences created successfully' });
        });
    }
  });
});

// System command injection vulnerability endpoint
app.get('/api/system/ping', checkJwt, isAdmin, (req, res) => {
  const host = req.query.host;
  
  if (!host) {
    return res.status(400).json({ error: 'Host parameter is required' });
  }
  
  // Command injection vulnerability
  exec(`ping -c 4 ${host}`, (error, stdout, stderr) => {
    if (error) {
      return res.status(500).json({ error: 'Ping failed', details: stderr });
    }
    
    res.json({ result: stdout });
  });
});

// XXE vulnerability endpoint
app.post('/api/parse-xml', (req, res) => {
  const xml = req.body.xml;
  
  if (!xml) {
    return res.status(400).json({ error: 'XML data is required' });
  }
  
  // Vulnerable XML parsing with XXE
  const xml2js = require('xml2js');
  const parser = new xml2js.Parser({
    explicitArray: false,
    // Vulnerable configuration
    explicitCharkey: true
  });
  
  parser.parseString(xml, (err, result) => {
    if (err) {
      return res.status(400).json({ error: 'Invalid XML', details: err.message });
    }
    
    res.json({ result });
  });
});

// Insecure deserialization endpoint
app.post('/api/deserialize', checkJwt, (req, res) => {
  const data = req.body.data;
  
  if (!data) {
    return res.status(400).json({ error: 'Data is required' });
  }
  
  try {
    // Vulnerable deserialization
    const serialize = require('node-serialize');
    const obj = serialize.unserialize(data);
    
    res.json({ result: obj });
  } catch (err) {
    res.status(400).json({ error: 'Deserialization failed', details: err.message });
  }
});

// Start the server
app.listen(port, () => {
  console.log(`DarkVault Local API Server running on http://localhost:${port}`);
  console.log('WARNING: This application contains deliberate vulnerabilities. Do not use in production.');
});

module.exports = app; 