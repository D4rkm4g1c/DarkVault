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

// Weak password recovery mechanism
router.get('/forgot-password', (req, res) => {
  res.render('forgot-password', {
    title: 'Forgot Password',
    user: req.session.user || null
  });
});

// Process forgot password requests
router.post('/forgot-password', (req, res) => {
  const { username, email } = req.body;
  
  if (!username || !email) {
    req.flash('error', 'Username and email are required');
    return res.redirect('/user/forgot-password');
  }
  
  // VULNERABLE: No rate limiting, allows enumeration attacks
  db.get("SELECT * FROM users WHERE username = ? AND email = ?", [username, email], (err, user) => {
    if (err) {
      req.flash('error', 'Database error occurred');
      return res.redirect('/user/forgot-password');
    }
    
    if (!user) {
      // VULNERABLE: Information disclosure via error message
      req.flash('error', 'No account found with that username and email combination');
      return res.redirect('/user/forgot-password');
    }
    
    // VULNERABLE: Weak token generation (predictable)
    const resetToken = Buffer.from(`${username}:${Date.now()}`).toString('base64');
    
    // VULNERABLE: Store token without proper expiration
    db.run("UPDATE users SET reset_token = ? WHERE id = ?", [resetToken, user.id], (err) => {
      if (err) {
        req.flash('error', 'Error updating reset token');
        return res.redirect('/user/forgot-password');
      }
      
      // VULNERABLE: Token leakage in URL
      const resetUrl = `http://localhost:3000/user/reset-password?token=${resetToken}&username=${username}`;
      
      req.flash('success', 'Password reset link generated: ' + resetUrl);
      res.redirect('/user/forgot-password');
    });
  });
});

// Reset password form
router.get('/reset-password', (req, res) => {
  const { token, username } = req.query;
  
  if (!token || !username) {
    req.flash('error', 'Invalid password reset link');
    return res.redirect('/user/forgot-password');
  }
  
  // VULNERABLE: No token validation before showing form
  res.render('reset-password', {
    title: 'Reset Password',
    user: req.session.user || null,
    token,
    username
  });
});

// Process password reset
router.post('/reset-password', (req, res) => {
  const { token, username, password, confirm_password } = req.body;
  
  if (!token || !username || !password || !confirm_password) {
    req.flash('error', 'All fields are required');
    return res.redirect(`/user/reset-password?token=${token}&username=${username}`);
  }
  
  if (password !== confirm_password) {
    req.flash('error', 'Passwords do not match');
    return res.redirect(`/user/reset-password?token=${token}&username=${username}`);
  }
  
  // VULNERABLE: No token expiration check
  db.get("SELECT * FROM users WHERE username = ? AND reset_token = ?", [username, token], (err, user) => {
    if (err) {
      req.flash('error', 'Database error occurred');
      return res.redirect(`/user/reset-password?token=${token}&username=${username}`);
    }
    
    if (!user) {
      req.flash('error', 'Invalid reset token');
      return res.redirect('/user/forgot-password');
    }
    
    // VULNERABLE: Weak password hashing
    const hashedPassword = require('md5')(password);
    
    // Update password
    db.run("UPDATE users SET password = ?, reset_token = NULL WHERE id = ?", [hashedPassword, user.id], (err) => {
      if (err) {
        req.flash('error', 'Error updating password');
        return res.redirect(`/user/reset-password?token=${token}&username=${username}`);
      }
      
      // Add token leakage in response headers
      res.setHeader('X-Auth-Token', user.password);
      
      req.flash('success', 'Password has been reset successfully');
      res.redirect('/login');
    });
  });
});

// Session fixation vulnerability demonstration
router.get('/session-fixation', (req, res) => {
  // VULNERABLE: Allowing session ID to be set via query parameter
  if (req.query.sessionId) {
    // Directly setting the session ID from a query parameter
    req.session.id = req.query.sessionId;
  }
  
  res.render('session-fixation', {
    title: 'Session Handling Demo',
    user: req.session.user || null,
    sessionId: req.session.id
  });
});

module.exports = router; 