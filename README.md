# DarkVault

A deliberately vulnerable banking application for security training and education.

> **⚠️ WARNING: This application contains intentional security vulnerabilities. Never deploy in production environments or expose to the internet.**

## About DarkVault

DarkVault simulates a banking application with numerous security flaws designed for practicing penetration testing techniques, understanding common web vulnerabilities, and training in secure coding practices.

## Quick Start

```bash
# Install dependencies
npm install

# Start the application
npm start
```

Application will be available at: http://localhost:3000

A separate internal admin service runs on port 3001 (intentionally vulnerable to SSRF attacks).

## Default Access Credentials

| Account Type | Username | Password      |
|--------------|----------|---------------|
| Admin        | admin    | admin123      |
| User         | alice    | password123   |
| User         | bob      | bobpassword   |

## Technical Architecture

- Backend: Node.js with Express
- Database: SQLite
- Frontend: Plain JavaScript
- Authentication: JWT-based
- Supplementary: Internal admin service (SSRF target)

## Utility Scripts

- `race-condition-demo.js`: Demonstrates race condition exploitation
- `reset-users.sh`: Resets user accounts to their default state

## Security Vulnerabilities

### Authentication & Session Management
- Plaintext credential storage
- Weak JWT implementation with exposed secrets
- Debug mode authentication bypass
- Client-side token storage in localStorage
- Insufficient password policies

### Injection Vulnerabilities
- SQL Injection (login, registration, search)
- Command Injection (admin reports)
- Cross-Site Scripting (URL parameters, search, transaction notes)
- Prototype pollution

### Access Control
- Insecure Direct Object References (IDOR)
- Missing function-level authorization
- Privilege escalation via parameter tampering
- Exposed internal endpoints

### Data Protection
- Unencrypted sensitive information
- Detailed error messages revealing implementation details
- Exposed API keys and secrets
- Information leakage in API responses

### Request Forgery
- CSRF vulnerabilities in transaction functions
- Missing origin/referer validation
- Insecure cookie configuration
- SSRF vulnerabilities exposing internal services

### File Operations
- Insecure file upload implementation
- Path traversal vulnerabilities
- Insufficient file validation

### Business Logic Flaws
- Missing balance validation in transfers
- Race conditions in financial transactions
- Transaction manipulation (negative amounts)
- Inadequate validation controls

### API Security
- Misconfigured CORS settings
- Missing security headers
- Excessive data exposure
- Vulnerable dependencies

## Training Exercises

1. Privilege escalation from regular user to admin
2. Extract another user's sensitive information
3. Bypass authentication with SQL injection
4. Execute stored XSS via search functionality
5. Achieve code execution via file upload
6. Manipulate account balance through client-side attacks
7. Perform CSRF attacks against transaction endpoints
8. Execute OS commands via admin reporting feature
9. Exploit race conditions to drain accounts
10. Bypass security using debug parameters
11. Access internal services via SSRF
12. Manipulate objects through prototype pollution

## Legal Notice

This application is provided for educational and ethical testing purposes only. The authors assume no liability for misuse or damage resulting from this software. Always practice ethical security testing and obtain proper authorization before testing vulnerabilities on any system. 