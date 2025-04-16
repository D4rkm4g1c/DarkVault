const express = require('express');
const router = express.Router();
const sqlite3 = require('sqlite3').verbose();
const db = require('../db');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcrypt');
const { exec } = require('child_process');

// Authentication middleware
function isAuthenticated(req, res, next) {
  if (req.session && req.session.userId) {
    return next();
  }
  res.redirect('/login');
}

// Admin check middleware
function isAdmin(req, res, next) {
  if (req.session && req.session.user && (req.session.user.isAdmin || req.session.user.role === 'admin')) {
    return next();
  }
  
  // Manager has enhanced privileges on certain paths
  if (req.session && req.session.user && req.session.user.role === 'manager') {
    // Define paths that managers can access
    const managerPaths = [
      '/dashboard', 
      '/users', 
      '/products',
      '/messages'
    ];
    
    // Get the base path from the original URL
    const basePath = '/' + req.originalUrl.split('/')[1];
    
    if (managerPaths.includes(basePath)) {
      return next();
    }
  }
  
  // If we reach here, the user doesn't have sufficient permissions
  req.flash('error', 'You do not have permission to access this page');
  res.redirect('/login');
}

// Home page
router.get('/', (req, res) => {
  if (req.session.user) {
    db.getTodosByUserId(req.session.user.id, (err, todos) => {
      if (err) {
        console.error('Error fetching todos:', err);
        req.flash('error', 'Failed to load todos');
        return res.render('index', { 
          title: 'Home - DarkVault',
          user: req.session.user,
          todos: []
        });
      }
      res.render('index', { 
        title: 'Home - DarkVault',
        user: req.session.user,
        todos: todos
      });
    });
  } else {
    res.render('index', { 
      title: 'Welcome to DarkVault',
      user: null 
    });
  }
});

// Login page
router.get('/login', (req, res) => {
  if (req.session.user) {
    return res.redirect('/');
  }
  res.render('login', { 
    title: 'Login - DarkVault',
    error: req.flash('error')
  });
});

// Login form submission
router.post('/login', (req, res) => {
  const { username, password } = req.body;
  
  if (!username || !password) {
    req.flash('error', 'Username and password are required');
    return res.redirect('/login');
  }
  
  // VULNERABLE: This uses the SQL injection vulnerable function
  db.findUserByCredentials(username, password, (err, user) => {
    if (err) {
      console.error('Login error:', err);
      req.flash('error', 'An error occurred during login');
      return res.redirect('/login');
    }
    
    if (!user) {
      req.flash('error', 'Invalid username or password');
      return res.redirect('/login');
    }
    
    // Set user session
    req.session.user = user;
    res.redirect('/');
  });
});

// Registration page
router.get('/register', (req, res) => {
  if (req.session.user) {
    return res.redirect('/');
  }
  res.render('register', { 
    title: 'Register - DarkVault',
    error: req.flash('error')
  });
});

// Registration form submission
router.post('/register', (req, res) => {
  const { username, password, email } = req.body;
  
  if (!username || !password || !email) {
    req.flash('error', 'All fields are required');
    return res.redirect('/register');
  }
  
  db.findUserByUsername(username, (err, existingUser) => {
    if (err) {
      console.error('Registration error:', err);
      req.flash('error', 'An error occurred during registration');
      return res.redirect('/register');
    }
    
    if (existingUser) {
      req.flash('error', 'Username already exists');
      return res.redirect('/register');
    }
    
    // VULNERABLE: No password hashing
    db.createUser(username, password, email, function(err) {
      if (err) {
        console.error('Error creating user:', err);
        req.flash('error', 'Failed to create user');
        return res.redirect('/register');
      }
      
      req.flash('success', 'Registration successful. Please log in.');
      res.redirect('/login');
    });
  });
});

// Logout
router.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error('Logout error:', err);
    }
    res.redirect('/login');
  });
});

// Dashboard page
router.get('/dashboard', (req, res) => {
  // Check if user is logged in
  if (!req.session.user) {
    return res.redirect('/login?returnTo=/dashboard');
  }
  
  res.render('dashboard', {
    title: 'Dashboard',
    user: req.session.user
  });
});

// User profile page - vulnerable to IDOR
router.get('/user/:id', (req, res) => {
  // Check if user is logged in
  if (!req.session.user) {
    req.flash('error', 'You must be logged in to view user profiles');
    return res.redirect('/login');
  }
  
  const userId = req.params.id;
  
  // VULNERABLE: No authorization check if user should be allowed to view this profile
  // This is an intentional IDOR vulnerability for training purposes
  
  // First get the user data
  db.get("SELECT id, username, email, role, isAdmin FROM users WHERE id = ?", [userId], (err, user) => {
    if (err) {
      console.error('Error fetching user:', err);
      req.flash('error', 'Failed to load user');
      return res.redirect('/users');
    }
    
    if (!user) {
      req.flash('error', 'User not found');
      return res.redirect('/users');
    }

    // Then get user preferences
    db.get("SELECT * FROM user_preferences WHERE user_id = ?", [userId], (err, preferences) => {
      // Get user's messages
      db.all('SELECT * FROM messages WHERE user_id = ? ORDER BY created_at DESC LIMIT 5', [userId], (err, messages) => {
        // Format the profile data to match the expected format in the template
        const profile = {
          id: user.id,
          username: user.username,
          email: user.email,
          isAdmin: user.isAdmin === 1 || user.role === 'admin',
          preferences: preferences || {},
          // Easter egg: Access to "hidden" admin
          flag: userId === '9999' ? 'DARK{1d0r_vuln3r4b1l1ty}' : null
        };
        
        res.render('profile', { 
          title: `${user.username}'s Profile - DarkVault`,
          user: req.session.user,
          profile: profile,
          messages: messages || []
        });
      });
    });
  });
});

// Search route - vulnerable to XSS
router.get('/search', (req, res) => {
  const { q } = req.query;
  
  // Simulated search results
  let results = [];
  
  if (q) {
    // VULNERABLE: Reflects user input without sanitization
    results = [
      { title: `Results for: ${q}`, content: 'Sample content 1' },
      { title: 'Another result', content: 'Sample content 2' }
    ];
  }
  
  res.render('search', {
    title: 'Search Results - DarkVault',
    user: req.session.user,
    query: q,
    results: results
  });
});

// Message board
router.get('/messages', (req, res) => {
  if (!req.session.user) {
    req.flash('error', 'You must be logged in to view messages');
    return res.redirect('/login');
  }
  
  db.getAllMessages((err, messages) => {
    if (err) {
      console.error('Error fetching messages:', err);
      req.flash('error', 'Failed to load messages');
      return res.render('messages', { 
        title: 'Message Board - DarkVault',
        user: req.session.user,
        messages: []
      });
    }
    
    res.render('messages', { 
      title: 'Message Board - DarkVault',
      user: req.session.user,
      messages: messages
    });
  });
});

// Post message route - vulnerable to CSRF (no CSRF token)
router.post('/messages', (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  
  const { message } = req.body;
  
  if (!message) {
    return res.status(400).json({ error: 'Message content is required' });
  }
  
  // VULNERABLE: No input sanitization for XSS
  db.createMessage(req.session.user.id, message, (err) => {
    if (err) {
      console.error('Error creating message:', err);
      return res.status(500).json({ error: 'Failed to create message' });
    }
    
    res.redirect('/messages');
  });
});

// Command execution page (admin only)
router.get('/command', (req, res) => {
  if (!req.session.user || (!req.session.user.isAdmin && req.session.user.role !== 'admin')) {
    return res.status(403).send('Forbidden');
  }
  
  res.render('command', {
    title: 'Command Console',
    user: req.session.user,
    output: req.flash('output')
  });
});

// Execute command route - vulnerable to command injection
router.post('/command', (req, res) => {
  if (!req.session.user || (!req.session.user.isAdmin && req.session.user.role !== 'admin')) {
    return res.status(403).send('Forbidden');
  }
  
  const { command } = req.body;
  
  if (!command) {
    req.flash('error', 'Command cannot be empty');
    return res.redirect('/command');
  }
  
  // Vulnerable to command injection
  exec(command, (error, stdout, stderr) => {
    req.flash('output', stdout || stderr || 'Command executed with no output');
    res.redirect('/command');
  });
});

// Admin panel
router.get('/admin', (req, res) => {
  if (!req.session.user || (!req.session.user.isAdmin && req.session.user.role !== 'admin')) {
    return res.redirect('/login');
  }
  
  // Load system settings
  const defaultSettings = {
    debug_mode: '0',
    error_logging: 'standard',
    user_registration: 'enabled',
    default_role: 'user'
  };
  
  // In a real app, these would be loaded from the database
  const settings = defaultSettings;
  
  db.all("SELECT * FROM users", (err, users) => {
    if (err) {
      console.error(err);
      return res.status(500).send('Database error');
    }
    
    res.render('admin', {
      title: 'Admin Panel - DarkVault',
      user: req.session.user,
      users: users,
      settings: settings
    });
  });
});

// Admin logs
router.get('/admin/logs', (req, res) => {
  if (!req.session.user || (!req.session.user.isAdmin && req.session.user.role !== 'admin')) {
    return res.redirect('/login');
  }
  
  db.all("SELECT l.*, u.username FROM logs l LEFT JOIN users u ON l.user_id = u.id ORDER BY l.created_at DESC", (err, logs) => {
    if (err) {
      console.error(err);
      return res.status(500).send('Database error');
    }
    
    res.render('admin_logs', {
      title: 'System Logs - DarkVault',
      user: req.session.user,
      logs: logs
    });
  });
});

// Admin settings
router.post('/admin/settings', (req, res) => {
  if (!req.session.user || (!req.session.user.isAdmin && req.session.user.role !== 'admin')) {
    return res.redirect('/login');
  }
  
  const { debug_mode, error_logging, user_registration, default_role } = req.body;
  
  // In a real app, we would save these settings to a database
  console.log('Admin settings updated:', { debug_mode, error_logging, user_registration, default_role });
  
  req.flash('success_msg', 'Settings updated successfully');
  res.redirect('/admin');
});

// Add user (admin)
router.post('/admin/users/add', (req, res) => {
  if (!req.session.user || (!req.session.user.isAdmin && req.session.user.role !== 'admin')) {
    return res.redirect('/login');
  }
  
  const { username, password, email, role } = req.body;
  const isAdmin = role === 'admin' ? 1 : 0;
  
  if (!username || !password || !email) {
    req.flash('error_msg', 'All fields are required');
    return res.redirect('/admin');
  }
  
  db.findUserByUsername(username, (err, existingUser) => {
    if (err) {
      console.error('Error checking username:', err);
      req.flash('error_msg', 'Database error');
      return res.redirect('/admin');
    }
    
    if (existingUser) {
      req.flash('error_msg', 'Username already exists');
      return res.redirect('/admin');
    }
    
    db.run("INSERT INTO users (username, password, email, role, isAdmin) VALUES (?, ?, ?, ?, ?)", 
      [username, password, email, role, isAdmin], (err) => {
        if (err) {
          console.error('Error creating user:', err);
          req.flash('error_msg', 'Failed to create user');
          return res.redirect('/admin');
        }
        
        req.flash('success_msg', 'User created successfully');
        res.redirect('/admin');
      });
  });
});

// Edit user (admin)
router.post('/admin/users/edit', (req, res) => {
  if (!req.session.user || (!req.session.user.isAdmin && req.session.user.role !== 'admin')) {
    return res.redirect('/login');
  }
  
  const { user_id, username, email, role, isAdmin, password } = req.body;
  
  if (!user_id || !username || !email) {
    req.flash('error_msg', 'Required fields are missing');
    return res.redirect('/admin');
  }
  
  // If password is provided, update it too; otherwise, keep the existing password
  if (password && password.trim() !== '') {
    db.run("UPDATE users SET username = ?, email = ?, role = ?, isAdmin = ?, password = ? WHERE id = ?", 
      [username, email, role, isAdmin, password, user_id], (err) => {
        if (err) {
          console.error('Error updating user:', err);
          req.flash('error_msg', 'Failed to update user');
          return res.redirect('/admin');
        }
        
        req.flash('success_msg', 'User updated successfully');
        res.redirect('/admin');
      });
  } else {
    db.run("UPDATE users SET username = ?, email = ?, role = ?, isAdmin = ? WHERE id = ?", 
      [username, email, role, isAdmin, user_id], (err) => {
        if (err) {
          console.error('Error updating user:', err);
          req.flash('error_msg', 'Failed to update user');
          return res.redirect('/admin');
        }
        
        req.flash('success_msg', 'User updated successfully');
        res.redirect('/admin');
      });
  }
});

// Delete user (admin)
router.get('/admin/users/delete/:id', (req, res) => {
  if (!req.session.user || (!req.session.user.isAdmin && req.session.user.role !== 'admin')) {
    return res.redirect('/login');
  }
  
  const userId = req.params.id;
  
  // Don't allow deleting yourself
  if (req.session.user.id == userId) {
    req.flash('error_msg', 'You cannot delete your own account');
    return res.redirect('/admin');
  }
  
  db.run("DELETE FROM users WHERE id = ?", [userId], (err) => {
    if (err) {
      console.error('Error deleting user:', err);
      req.flash('error_msg', 'Failed to delete user');
      return res.redirect('/admin');
    }
    
    req.flash('success_msg', 'User deleted successfully');
    res.redirect('/admin');
  });
});

// API Documentation
router.get('/api/docs', (req, res) => {
  res.render('api_docs', {
    title: 'API Documentation - DarkVault',
    user: req.session.user || null
  });
});

// Users list page
router.get('/users', (req, res) => {
  // Check if user is logged in
  if (!req.session.user) {
    req.flash('error', 'You must be logged in to view users');
    return res.redirect('/login');
  }
  
  // UI-level permission check (still vulnerable to direct URL access)
  // VULNERABLE: Missing server-side authorization - user can still access by entering URL directly
  // This creates an intentional IDOR vulnerability for demonstration purposes
  
  db.getAllUsers((err, users) => {
    if (err) {
      console.error('Error fetching users:', err);
      req.flash('error', 'Failed to load users');
      return res.render('users', { 
        title: 'Users Directory - DarkVault',
        user: req.session.user,
        users: []
      });
    }
    
    res.render('users', { 
      title: 'Users Directory - DarkVault',
      user: req.session.user,
      users: users
    });
  });
});

// Files page
router.get('/files', (req, res) => {
  // Check if user is logged in
  if (!req.session.user) {
    req.flash('error', 'You must be logged in to view files');
    return res.redirect('/login');
  }
  
  db.all("SELECT * FROM files", (err, files) => {
    if (err) {
      console.error('Error fetching files:', err);
      req.flash('error', 'Failed to load files');
      return res.render('files', { 
        title: 'File Manager - DarkVault',
        user: req.session.user,
        files: []
      });
    }
    
    res.render('files', { 
      title: 'File Manager - DarkVault',
      user: req.session.user,
      files: files
    });
  });
});

// Site Map & Component Topology
router.get('/site-map', (req, res) => {
  res.render('site-map', {
    title: 'Site Component Topology - DarkVault',
    user: req.session.user || null
  });
});

// Code Review Examples
router.get('/code-review', (req, res) => {
  res.render('code-review', {
    title: 'Code Review Examples - DarkVault',
    user: req.session.user || null
  });
});

// Flag tracking dashboard
router.get('/flags', (req, res) => {
  res.render('flags', {
    title: 'Flag Tracking - DarkVault',
    user: req.session.user || null,
    flags: [
      { name: 'SQL Injection', id: 'sql_m4st3r', completed: false },
      { name: 'Path Traversal', id: 'p4th_tr4v3rs4l_m4st3r', completed: false },
      { name: 'Command Injection', id: 'c0mm4nd_1nj3ct10n_pr0', completed: false },
      { name: 'JWT Manipulation', id: 'jwt_4dm1n_3sc4l4t10n', completed: false },
      { name: 'GraphQL Introspection', id: 'gr4phql_1ntr0sp3ct10n', completed: false },
      { name: 'Race Condition', id: 'r4c3_c0nd1t10n_3xpl01t3d', completed: false },
      { name: 'XSS', id: 'xss_3xpl01t3r', completed: false },
      { name: 'IDOR', id: '1d0r_vuln3r4b1l1ty', completed: false },
      { name: 'XXE', id: 'xxe_data_extr4ct0r', completed: false },
      { name: 'SSTI', id: 't3mpl4t3_1nj3ct10n', completed: false },
      { name: 'NoSQL Injection', id: 'n0sql_1nj3ct10n_m4st3r', completed: false },
      { name: 'Weak Encryption', id: 'w34k_crypt0_3xpl01t3d', completed: false },
      { name: 'Insecure File Upload', id: 'f1l3_upl04d_byp4ss3d', completed: false },
      { name: 'CSRF', id: 'csrf_pr0t3ct10n_byp4ss3d', completed: false },
      { name: 'Prototype Pollution', id: 'pr0t0typ3_p0llut10n_m4st3r', completed: false }
    ]
  });
});

// Endpoint to check if a flag has been earned
router.post('/check-flag', (req, res) => {
  const { flag } = req.body;
  
  if (!flag) {
    return res.status(400).json({ error: 'No flag provided' });
  }
  
  // Validate flag format
  if (!flag.startsWith('DARK{') || !flag.endsWith('}')) {
    return res.status(400).json({ error: 'Invalid flag format' });
  }
  
  // Extract flag identifier
  const flagId = flag.substring(5, flag.length - 1);
  
  // Check against valid flags
  const validFlags = [
    'sql_m4st3r',
    'p4th_tr4v3rs4l_m4st3r',
    'c0mm4nd_1nj3ct10n_pr0',
    'jwt_4dm1n_3sc4l4t10n',
    'gr4phql_1ntr0sp3ct10n',
    'r4c3_c0nd1t10n_3xpl01t3d',
    'xss_3xpl01t3r',
    '1d0r_vuln3r4b1l1ty',
    'xxe_data_extr4ct0r',
    't3mpl4t3_1nj3ct10n',
    'n0sql_1nj3ct10n_m4st3r',
    'w34k_crypt0_3xpl01t3d',
    'f1l3_upl04d_byp4ss3d',
    'csrf_pr0t3ct10n_byp4ss3d',
    'pr0t0typ3_p0llut10n_m4st3r'
  ];
  
  if (validFlags.includes(flagId)) {
    // In a real app, we would update the user's progress in a database
    return res.json({ success: true, message: 'Flag validated successfully!' });
  } else {
    return res.json({ success: false, message: 'Invalid flag. Try again!' });
  }
});

// Add a todo
router.post('/todos', (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  
  const { title } = req.body;
  
  if (!title) {
    return res.status(400).json({ error: 'Todo title is required' });
  }
  
  db.createTodo(req.session.user.id, title, (err) => {
    if (err) {
      console.error('Error creating todo:', err);
      return res.status(500).json({ error: 'Failed to create todo' });
    }
    
    res.redirect('/');
  });
});

// VULNERABLE: IDOR in todo view
router.get('/todos/:id', (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  
  const todoId = req.params.id;
  
  // VULNERABLE: No authorization check if the todo belongs to the user
  db.getTodoById(todoId, (err, todo) => {
    if (err) {
      console.error('Error fetching todo:', err);
      return res.status(500).json({ error: 'Failed to fetch todo' });
    }
    
    if (!todo) {
      return res.status(404).json({ error: 'Todo not found' });
    }
    
    res.json(todo);
  });
});

// VULNERABLE: Command Injection in ping route
router.get('/ping', (req, res) => {
  if (!req.session.user) {
    req.flash('error', 'You must be logged in to use network tools');
    return res.redirect('/login');
  }
  
  const { host } = req.query;
  
  // Render the page without running a command if no host is provided
  if (!host) {
    return res.render('ping', {
      title: 'Network Ping - DarkVault',
      user: req.session.user,
      host: '',
      output: '',
      error: null
    });
  }
  
  // VULNERABLE: Command injection through unsanitized input
  // Note: This is deliberately vulnerable as part of the security training app
  exec(`ping -c 4 ${host}`, (error, stdout, stderr) => {
    res.render('ping', {
      title: 'Network Ping - DarkVault',
      user: req.session.user,
      host: host,
      output: stdout || stderr || 'No output received',
      error: error ? error.message : null
    });
  });
});

// Client-side page with DOM-based XSS vulnerability
router.get('/client-side', (req, res) => {
  res.render('client-side', {
    title: 'Client-Side App - DarkVault',
    user: req.session.user,
    defaultSearch: req.query.search || '',
    injectedData: req.query.data || '',
    message: req.query.message || '',
    template: req.query.template || '<div>${name} has role: ${role}</div>'
  });
});

// Settings page
router.get('/settings', (req, res) => {
  if (!req.session.user) {
    req.flash('error', 'You must be logged in to view settings');
    return res.redirect('/login');
  }
  
  // Get user preferences
  db.get("SELECT * FROM user_preferences WHERE user_id = ?", [req.session.user.id], (err, preferences) => {
    // Get saved filters (if any)
    db.all("SELECT * FROM product_filters WHERE user_id = ?", [req.session.user.id], (err, filters) => {
      res.render('settings', {
        title: 'User Settings - DarkVault',
        user: req.session.user,
        preferences: preferences || {},
        filters: filters || [],
        message: req.flash('success_msg')
      });
    });
  });
});

// Save settings
router.post('/settings/save', (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  
  const { display_name, avatar, bio, theme, favorite_category } = req.body;
  
  // Check if user already has preferences
  db.get("SELECT * FROM user_preferences WHERE user_id = ?", [req.session.user.id], (err, preferences) => {
    if (err) {
      console.error('Error checking preferences:', err);
      req.flash('error_msg', 'Database error');
      return res.redirect('/settings');
    }
    
    if (preferences) {
      // Update existing preferences
      db.run(
        "UPDATE user_preferences SET display_name = ?, bio = ?, avatar = ?, theme = ?, favorite_category = ? WHERE user_id = ?",
        [display_name, bio, avatar, theme, favorite_category, req.session.user.id],
        (err) => {
          if (err) {
            console.error('Error updating preferences:', err);
            req.flash('error_msg', 'Failed to update preferences');
          } else {
            req.flash('success_msg', 'Settings updated successfully');
          }
          res.redirect('/settings');
        }
      );
    } else {
      // Insert new preferences
      db.run(
        "INSERT INTO user_preferences (user_id, display_name, bio, avatar, theme, favorite_category) VALUES (?, ?, ?, ?, ?, ?)",
        [req.session.user.id, display_name, bio, avatar, theme, favorite_category],
        (err) => {
          if (err) {
            console.error('Error creating preferences:', err);
            req.flash('error_msg', 'Failed to save preferences');
          } else {
            req.flash('success_msg', 'Settings saved successfully');
          }
          res.redirect('/settings');
        }
      );
    }
  });
});

// Save product filter
router.post('/settings/filter', (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  
  const { filter_name, category, min_price, max_price } = req.body;
  
  if (!filter_name) {
    req.flash('error_msg', 'Filter name is required');
    return res.redirect('/settings');
  }
  
  // Create filter query object
  const filterQuery = {
    category: category || null,
    min_price: min_price || null,
    max_price: max_price || null
  };
  
  // Insert filter
  db.run(
    "INSERT INTO product_filters (user_id, filter_name, filter_query) VALUES (?, ?, ?)",
    [req.session.user.id, filter_name, JSON.stringify(filterQuery)],
    (err) => {
      if (err) {
        console.error('Error saving filter:', err);
        req.flash('error_msg', 'Failed to save filter');
      } else {
        req.flash('success_msg', 'Filter saved successfully');
      }
      res.redirect('/settings');
    }
  );
});

// Add template injection example with popular frameworks
router.post('/render-template', (req, res) => {
  const { template, data } = req.body;
  
  // VULNERABLE: Direct template rendering without proper sanitization
  try {
    // Simulate template rendering with eval (extremely dangerous)
    const compiledTemplate = new Function('data', `
      with(data) {
        return \`${template}\`;
      }
    `);
    
    // Execute template with user data
    const result = compiledTemplate(JSON.parse(data || '{}'));
    
    res.json({
      rendered: result,
      message: 'Template rendered successfully'
    });
  } catch (err) {
    res.status(500).json({
      error: 'Template rendering error',
      message: err.message,
      // Leaking stack trace - security vulnerability
      stack: err.stack
    });
  }
});

// Add a profile redirect route
router.get('/profile', (req, res) => {
  if (!req.session.user) {
    req.flash('error', 'You must be logged in to view your profile');
    return res.redirect('/login');
  }
  
  // Redirect to the user's profile page
  res.redirect(`/user/${req.session.user.id}`);
});

// Add a forgot-password redirect to fix broken link
router.get('/forgot-password', (req, res) => {
  res.redirect('/user/forgot-password');
});

// Version info page (information disclosure vulnerability)
router.get('/version-info', (req, res) => {
  // Deliberately leaking sensitive information
  const versionInfo = {
    application: 'DarkVault',
    version: '1.2.3',
    framework: 'Express.js 4.17.1',
    node: process.version,
    database: 'SQLite 3.36.0',
    modules: {
      bcrypt: '5.0.1',
      jwt: '8.5.1',
      'express-session': '1.17.2'
    },
    server: {
      os: process.platform,
      hostname: require('os').hostname(),
      users: require('os').userInfo().username,
      directories: {
        app: __dirname,
        node_modules: path.join(__dirname, '../node_modules'),
        upload_path: path.join(__dirname, '../uploads')
      }
    },
    environment: process.env.NODE_ENV || 'development',
    // API keys that shouldn't be exposed
    api_keys: {
      mailchimp: 'abc123-us10',
      stripe_test: 'sk_test_123456789',
      aws_secret: 'AKIAIOSFODNN7EXAMPLE'
    }
  };
  
  res.setHeader('X-Powered-By', 'Express 4.17.1');
  
  if (req.query.format === 'json') {
    res.json(versionInfo);
  } else {
    res.render('document', {
      title: 'Version Information - DarkVault',
      user: req.session.user,
      document: {
        title: 'System Version Information',
        content: JSON.stringify(versionInfo, null, 2)
      }
    });
  }
});

// Directory listing (information disclosure vulnerability)
router.get('/directory-listing', (req, res) => {
  const basePath = req.query.path || '.';
  const fullPath = path.resolve(basePath);
  
  // Vulnerable path traversal - no sanitization of path parameter
  fs.readdir(fullPath, { withFileTypes: true }, (err, dirents) => {
    if (err) {
      return res.status(500).render('error', {
        title: 'Error - DarkVault',
        errorCode: 500,
        message: `Error reading directory: ${err.message}`,
        user: req.session.user
      });
    }
    
    const fileList = dirents.map(dirent => {
      const entryPath = path.join(fullPath, dirent.name);
      let stats;
      try {
        stats = fs.statSync(entryPath);
      } catch (err) {
        stats = { size: 0, mtime: new Date() };
      }
      
      return {
        name: dirent.name,
        isDirectory: dirent.isDirectory(),
        size: stats.size,
        modified: stats.mtime,
        path: path.join(basePath, dirent.name)
      };
    });
    
    if (req.query.format === 'json') {
      res.json({
        current_path: fullPath,
        parent_path: path.dirname(fullPath),
        files: fileList
      });
    } else {
      res.render('files', {
        title: 'Directory Listing - DarkVault',
        user: req.session.user,
        current_path: fullPath,
        parent_path: path.dirname(fullPath),
        files: fileList
      });
    }
  });
});

// Handle robots.txt requests
router.get('/robots.txt', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/robots.txt'));
});

// Add a client-render route for DOM-based XSS vulnerabilities
router.get('/client-render', (req, res) => {
  res.render('client-render', {
    title: 'Client-Side Rendering Vulnerabilities',
    user: req.session.user || null,
    message: req.query.message || '',
    template: req.query.template || '<div>${name} has role: ${role}</div>',
    renderMode: req.query.renderMode || 'safe'
  });
});

module.exports = router; 