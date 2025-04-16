const express = require('express');
const router = express.Router();
const sqlite3 = require('sqlite3').verbose();
const db = require('../db');
const md5 = require('md5');
const jwt = require('jsonwebtoken');

// JWT Secret (intentionally weak)
const JWT_SECRET = "darkvault-secret-key";

// Helper function to generate JWT token
function generateToken(user) {
  return jwt.sign({
    id: user.id,
    username: user.username,
    isAdmin: user.isAdmin === 1 || (user.role === 'admin' ? 1 : 0)
  }, JWT_SECRET);
}

// Login route
router.post('/login', (req, res) => {
  const { username, password } = req.body;
  
  if (!username || !password) {
    return res.status(400).render('login', {
      title: 'Login - DarkVault',
      error: 'Username and password are required'
    });
  }
  
  // VULNERABLE: Direct string concatenation in SQL query
  // This is vulnerable to SQL injection
  const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${md5(password)}'`;
  
  db.get(query, (err, user) => {
    if (err) {
      console.error(err);
      return res.status(500).render('login', {
        title: 'Login - DarkVault',
        error: 'Database error'
      });
    }
    
    if (!user) {
      return res.status(401).render('login', {
        title: 'Login - DarkVault',
        error: 'Invalid username or password'
      });
    }
    
    // Store user in session
    req.session.user = {
      id: user.id,
      username: user.username,
      email: user.email,
      isAdmin: user.isAdmin === 1 || user.role === 'admin'
    };
    
    // Check if this was a successful SQL injection
    if (username.includes("'") || username.includes("--")) {
      // User performed SQL injection - add flag
      req.session.user.flag = "DARK{sql_m4st3r}";
    }
    
    // Redirect to dashboard
    res.redirect('/dashboard');
  });
});

// Register route
router.post('/register', (req, res) => {
  const { username, password, email } = req.body;
  
  if (!username || !password || !email) {
    return res.status(400).render('register', {
      title: 'Register - DarkVault',
      error: 'All fields are required'
    });
  }
  
  // Check if username exists
  db.get("SELECT * FROM users WHERE username = ?", [username], (err, user) => {
    if (err) {
      console.error(err);
      return res.status(500).render('register', {
        title: 'Register - DarkVault',
        error: 'Database error'
      });
    }
    
    if (user) {
      return res.status(400).render('register', {
        title: 'Register - DarkVault',
        error: 'Username already exists'
      });
    }
    
    // Insert new user
    // VULNERABLE: Using weak password hashing (md5)
    const hashedPassword = md5(password);
    
    db.run(
      "INSERT INTO users (username, password, email, role, isAdmin) VALUES (?, ?, ?, ?, ?)",
      [username, hashedPassword, email, 'user', 0],
      function(err) {
        if (err) {
          console.error(err);
          return res.status(500).render('register', {
            title: 'Register - DarkVault',
            error: 'Error registering user'
          });
        }
        
        // Store user in session
        req.session.user = {
          id: this.lastID,
          username,
          email,
          isAdmin: false
        };
        
        // Redirect to dashboard
        res.redirect('/dashboard');
      }
    );
  });
});

// Profile route
router.get('/:id', (req, res) => {
  const userId = req.params.id;
  
  // VULNERABLE: Insecure Direct Object Reference (IDOR)
  // Missing authorization check - any user can access any profile
  
  // Special check for the hidden user with the flag
  if (userId === '9999') {
    return res.render('profile', {
      title: 'Hidden Profile - DarkVault',
      user: req.session.user || null,
      profile: {
        id: 9999,
        username: "hidden_admin",
        email: "super_secret@darkvault.com",
        isAdmin: true,
        flag: "DARK{1d0r_vuln3r4b1l1ty}"
      },
      message: "Congratulations! You've discovered the hidden admin account."
    });
  }
  
  db.get("SELECT id, username, email, role, isAdmin FROM users WHERE id = ?", [userId], (err, profile) => {
    if (err) {
      console.error(err);
      return res.status(500).render('error', {
        title: 'Error - DarkVault',
        errorCode: 500,
        message: 'Database error',
        user: req.session.user || null
      });
    }
    
    if (!profile) {
      return res.status(404).render('error', {
        title: '404 - User Not Found',
        errorCode: 404,
        message: 'The requested user profile was not found.',
        user: req.session.user || null
      });
    }
    
    // Also fetch user preferences (information leakage)
    db.get("SELECT * FROM user_preferences WHERE user_id = ?", [userId], (err, preferences) => {
      profile.preferences = preferences || {};
      
      res.render('profile', {
        title: `${profile.username}'s Profile - DarkVault`,
        user: req.session.user || null,
        profile: {
          id: profile.id,
          username: profile.username,
          email: profile.email,
          isAdmin: profile.isAdmin === 1 || profile.role === 'admin',
          preferences: profile.preferences
        }
      });
    });
  });
});

module.exports = router; 