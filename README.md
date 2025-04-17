# DarkVault - Deliberately Vulnerable Banking Web Application

**WARNING: This application is intentionally vulnerable and should NEVER be deployed in a production environment or exposed to the internet. It is designed purely for educational purposes to demonstrate web application security vulnerabilities.**

## Overview

DarkVault is a deliberately vulnerable banking web application that demonstrates various web application security vulnerabilities, including:

- SQL Injection
- Cross-Site Scripting (XSS)
- Cross-Site Request Forgery (CSRF)
- Authentication and Authorization flaws
- Insecure Direct Object References (IDOR)
- Command Injection
- Unrestricted File Upload
- Insecure JWT implementation
- Race conditions
- Information disclosure
- and more...

## Installation

```bash
# Install dependencies
npm install

# Start the application
npm start
```

The application will run on http://localhost:3000

## Default Credentials

- Admin: username `admin`, password `admin123`
- User: username `alice`, password `password123`
- User: username `bob`, password `bobpassword`

## Vulnerabilities Included

### Authentication & Authorization

- Plaintext password storage
- Weak session management
- Missing password policies
- JWT token with debug mode bypass
- Insecure token storage in localStorage
- Admin role identification in JWT token

### Injection Vulnerabilities

- SQL Injection in login, register, and search functions
- Command Injection in admin report feature
- XSS in URL parameters, user search, transaction notes
- XSS in admin message system

### Broken Access Control

- Horizontal privilege escalation (IDOR) on user profiles
- Vertical privilege escalation via parameter manipulation
- Missing function level access control
- Authentication bypass via debug parameter

### Sensitive Data Exposure

- Plaintext passwords in database
- Verbose error messages
- Information leakage in API responses
- Insecure JWT token

### CSRF Vulnerabilities

- No CSRF tokens on forms
- Vulnerable transfer function
- No validation of origin/referer
- Insecure cookie settings

### Insecure File Upload

- No validation of file extensions
- No content-type checking
- Path traversal vulnerability
- No size limitations

### Business Logic Flaws

- No balance validation on transfers (unlimited money)
- Race conditions in transfer endpoint
- Ability to transfer negative amounts
- No transaction validation

### Web API Vulnerabilities

- Insecure CORS configuration
- Missing/improper HTTP security headers
- Excessive data exposure in API responses
- Broken function level authorization

### Modern Database & Third-Party vulnerabilities 

- Vulnerable versions of dependencies
- Missing query parameterization
- No database connection pooling
- Vulnerable JWT implementation

## Suggested Exercises

1. Login as a regular user and escalate privileges to admin
2. Steal sensitive information from other users
3. Perform SQL injection to bypass login
4. Inject JavaScript via the search function
5. Upload a malicious file to achieve code execution
6. Manipulate the client-side balance
7. Perform CSRF attacks on the transfer money function
8. Execute command injection via the admin report feature
9. Exploit race conditions to transfer more money than available
10. Use the debug parameter to bypass authentication

## Legal Disclaimer

This application is designed for educational and ethical testing purposes only. The authors of this application are not responsible for any misuse or damage caused by using this application for malicious purposes. Always practice ethical hacking and obtain proper authorization before testing vulnerabilities on any system. 