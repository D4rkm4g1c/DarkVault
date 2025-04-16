# DarkVault
A deliberately vulnerable web application designed for security testing practice and exam preparation.

## About
DarkVault is a vulnerable web application created for practicing web application security testing and preparing for penetration testing exams. It contains a comprehensive set of vulnerabilities aligned with modern security examination requirements.

## Vulnerability Categories

### Web Application Components (LO2.4)
DarkVault uses a variety of components, each with its own vulnerabilities:
- Express.js framework
- EJS templating engine
- SQLite database
- JWT authentication
- XML processing 
- Node.js serialization utilities

### Enumeration & Reconnaissance (LO3.1-LO4.3)
- Exposed API endpoints without proper documentation at `/api/*`
- Information disclosure via verbose error messages
- User enumeration via different login error responses
- Exposed technical details in HTTP headers
- Hidden endpoints referenced in HTML comments

### Authentication & Authorization (LO4.4-LO4.5)
- SQL injection in login form: `' OR 1=1 --`
- Weak password hashing (MD5): Check the database to see unsalted MD5 hashes
- JWT token vulnerabilities: Try modifying the token payload using [jwt.io](https://jwt.io)
- Insecure JWT implementation at `/api/auth` - Try changing the `isAdmin` flag
- Missing access controls on admin panel: Direct access to `/admin` works without checks
- IDOR vulnerabilities in user profiles: Change ID in URL at `/user/1` to access other profiles

### Input Validation (LO4.6)
- XSS in message board: Post a message with `<script>alert('XSS')</script>`
- Command injection in ping tool: Enter `localhost; ls -la` as the host
- SQL injection in product search: Try `' OR 1=1--` in category field
- XXE in XML import: Upload XML with external entity defined
- Unrestricted file upload: Upload executable files without validation
- Path traversal: Use `../../../etc/passwd` in file access endpoints

### Information Disclosure (LO4.7)
- Path disclosure in error messages: Trigger errors to see file paths
- Source code exposure via LFI: Access `/docs/../app.js`
- User data leakage via IDOR: Access profiles of other users
- Configuration details exposure: Check `/api/config` endpoint

### Cross-Site Scripting (LO4.8)
- Stored XSS: Post persistent payloads to message board
- Reflected XSS: Use query parameters in search
- DOM-based XSS: HTML injection in client-side rendering
- Blind XSS: Submit XSS payload to contact form for admin to view

### Injection Attacks (LO4.9)
- SQL injection in various forms
- Command injection in the ping tool
- Server-Side Template Injection (SSTI): Try `<%= process.env %>` in email template
- XML External Entity (XXE) injection in import functionality
- NoSQL injection simulation: Try `{"$ne":null}` in username field at `/api/search-users`

### Session Handling (LO4.10)
- Insecure session configuration: Check cookie attributes
- Missing secure flag on cookies: Inspect cookies in browser
- Missing CSRF protection: No tokens for state-changing actions
- Session fixation vulnerability: Session IDs don't regenerate after login

### Encryption and Encoding (LO4.11)
- Weak password hashing: MD5 is used without salting
- Weak JWT secret: "darkvault-secret-key" is predictable
- Unencrypted sensitive data: Check `/api/export` endpoint
- Custom weak encryption: Try the `/api/encrypt-data` endpoint
- Base64 encoding misused as encryption: Check data export feature

### Source Code Review (LO4.12)
- Exposed source code via LFI vulnerability: Try accessing JavaScript files
- Hardcoded credentials: Look for secrets in exposed source code
- Debug code left in production: Check for console.log statements
- Hardcoded JWT_SECRET: See the token generation code

### Parameter Manipulation (LO4.13)
- Query parameter tampering: Try modifying values in `/api/file?name=example.txt`
- Cookie manipulation: Edit cookies for session hijacking
- HTTP header injection: Insert custom headers in requests
- Hidden field manipulation: Change hidden form fields

### Web API Attacks (LO4.15)
- GraphQL vulnerabilities: Try introspection queries at `/api/graphql`
- Missing rate limiting: Send numerous requests to API endpoints
- Broken object-level authorization: Access objects belonging to other users
- Path traversal in file API: Use `/api/file?name=../../../etc/passwd`

### Modern Database Security (LO5.16)
- SQL injection vulnerabilities across the application
- Excessive database privileges for application user
- Verbose database error messages: Trigger an error to see details

### Third-Party Libraries (LO5.17)
- Vulnerable xml2js implementation (XXE): Use in import functionality
- Insecure node-serialize package (RCE): Check `/api/export` and `/import-data`
- Prototype pollution via lodash.merge: Try the `/merge-config` endpoint with `{"__proto__":{}}` payload

### Race Conditions (LO5.18)
- Account balance updates: Exploit at `/api/update-balance` with concurrent requests
- Promo code usage: Try concurrent requests to `/api/apply-promo`
- TOCTOU vulnerabilities: Time-of-check to time-of-use issues in file operations

### Privilege Escalation (LO5.1-LO5.3)
- Vertical privilege escalation: Modify JWT to gain admin access
- Horizontal privilege escalation: Access other user accounts via IDOR
- Admin access through parameter manipulation: Use `/api/admin/users?admin=true`

## Setup and Installation

### Prerequisites
- Node.js (v12 or higher)
- npm

### Installation
1. Clone the repository:
```
git clone https://github.com/yourusername/darkvault.git
cd darkvault
```

2. Install dependencies:
```
npm install
```

3. Start the application:
```
npm start
```

4. Access the application at `http://localhost:3000`

## Default Credentials
- Admin: `admin / SecretPassword123!`
- Create your own user accounts through the registration page

## Example Attack Scenarios

### JWT Token Manipulation
1. Login to the application
2. Get JWT token from `/api/auth`
3. Decode the token using [jwt.io](https://jwt.io)
4. Change the `isAdmin` field to `true`
5. Replace the original token with the modified one in your requests

### Path Traversal Attack
1. Use the file reading endpoint: `/api/file?name=../../../etc/passwd`
2. This might expose sensitive system files due to directory traversal

### GraphQL Introspection Attack
1. Send a POST request to `/api/graphql` with body:
```json
{
  "query": "{ __schema { types { name fields { name type } } } }"
}
```
2. This exposes the entire API schema, including sensitive fields

### Race Condition Exploitation
1. Send multiple concurrent requests to `/api/update-balance` with:
```json
{
  "userId": 1,
  "amount": 100
}
```
2. The balance might increase more than expected due to race conditions

## CTF-Style Flags
DarkVault includes hidden flags that serve as proof of successful exploitation. Each vulnerability has an associated flag in the format `DARK{unique_identifier}` that can only be obtained by successfully exploiting that vulnerability.

### Flag System
- Each flag is uniquely tied to a specific vulnerability
- Flags are hidden in locations only accessible through successful exploitation
- A flag tracking dashboard is available at `/flags` to monitor your progress
- Collecting all flags demonstrates comprehensive understanding of web security concepts

### Example Flag Locations
1. **SQL Injection Flag**: Successfully exploit the login SQL injection to reveal `DARK{sql_m4st3r}`
2. **Path Traversal Flag**: Read the flag file at `/etc/darkflag` through path traversal
3. **XSS Flag**: Access cookies containing flag data through XSS payload
4. **Command Injection Flag**: Execute commands to read `/opt/flag.txt`
5. **IDOR Flag**: Access user ID 9999 to find a special flag
6. **JWT Manipulation Flag**: Successfully modify JWT token to receive admin flag

### Flag Implementation
Flags are implemented in the following ways:
- Hidden HTML comments in protected pages
- Special files only accessible through vulnerabilities
- Database records only revealed through successful injection attacks
- Environment variables exposed through SSTI
- Special user accounts with flag data
- Cookie values only accessible through client-side attacks
- Admin-only API endpoints with flag values
- Encrypted data requiring proper key extraction

For instructors: A complete list of flags and their locations is available in the `docs/flag_solutions.md` file.

## Warning
**IMPORTANT**: This application is deliberately vulnerable and should NOT be deployed on a production server or exposed to the internet. Use only in controlled environments for educational purposes.

## Exam Syllabus Coverage
For a complete mapping of DarkVault features to exam syllabus requirements, see `docs/exam_coverage.txt`.
