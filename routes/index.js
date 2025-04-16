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
          title: 'DarkVault - Home',
          user: req.session.user,
          todos: []
        });
      }
      res.render('index', { 
        title: 'DarkVault - Home',
        user: req.session.user,
        todos: todos
      });
    });
  } else {
    res.render('index', { 
      title: 'DarkVault - Home',
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
    title: 'DarkVault - Login',
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
    title: 'DarkVault - Register',
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
  const userId = req.params.id;
  
  // No authorization check for viewing profiles (IDOR vulnerability)
  db.get('SELECT id, username, email, profile_pic, bio FROM users WHERE id = ?', [userId], (err, user) => {
    if (err || !user) {
      req.flash('error', 'User not found');
      return res.redirect('/');
    }
    
    // Get user's messages
    db.all('SELECT * FROM messages WHERE user_id = ? ORDER BY created_at DESC', [userId], (err, messages) => {
      res.render('profile', {
        title: `${user.username}'s Profile`,
        profileUser: user,
        messages: messages || [],
        user: req.session.user
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
    title: 'DarkVault - Search',
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
        title: 'DarkVault - Messages',
        user: req.session.user,
        messages: []
      });
    }
    
    res.render('messages', { 
      title: 'DarkVault - Messages',
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
  
  db.all("SELECT * FROM users", (err, users) => {
    if (err) {
      console.error(err);
      return res.status(500).send('Database error');
    }
    
    res.render('admin', {
      title: 'Admin Panel - DarkVault',
      user: req.session.user,
      users: users
    });
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
    return res.status(401).json({ error: 'Authentication required' });
  }
  
  const { host } = req.query;
  
  if (!host) {
    return res.status(400).json({ error: 'Host parameter is required' });
  }
  
  // VULNERABLE: Command injection through unsanitized input
  exec(`ping -c 4 ${host}`, (error, stdout, stderr) => {
    res.render('ping', {
      user: req.session.user,
      host: host,
      output: stdout || stderr,
      error: error ? error.message : null
    });
  });
});

module.exports = router; 