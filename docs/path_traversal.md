# Path Traversal Vulnerability in DarkVault

## Overview
Path traversal (also known as directory traversal) is a vulnerability that allows attackers to access files and directories outside of the intended directory structure. This vulnerability exists when an application does not properly validate user input that specifies paths to files or directories.

## Implementation in DarkVault
In DarkVault, there is a deliberate path traversal vulnerability in the `/api/file` endpoint. This endpoint allows users to retrieve files from the server, but does not properly sanitize the filename parameter.

### Vulnerable Code
The vulnerability is implemented in `routes/api.js`:

```javascript
// GET /api/file?name=example.txt
// VULNERABLE: Path traversal in file operations
router.get('/file', (req, res) => {
  const filename = req.query.name;
  
  if (!filename) {
    return res.status(400).json({ error: 'Filename is required' });
  }
  
  // VULNERABLE: No validation of filename parameter
  // Attacker can use ../ to traverse directories
  const filePath = path.join(__dirname, '../assets/', filename);
  
  fs.readFile(filePath, 'utf8', (err, data) => {
    if (err) {
      return res.status(404).json({ error: 'File not found or cannot be read' });
    }
    
    res.json({ filename, content: data });
  });
});
```

## Exploitation
To exploit this vulnerability:

1. Normally, access a legitimate file: `/api/file?name=public_file.txt`
2. To exploit the vulnerability, use path traversal sequences: `/api/file?name=../config.json`
3. This allows access to files outside the intended directory.

## Impact
This vulnerability can allow attackers to:
- Access sensitive configuration files like `config.json`
- Read application source code
- Access files from other parts of the system
- Potentially read system files if the application has the necessary permissions

## Mitigation
To fix this vulnerability:
1. Validate user input for filenames
2. Implement a whitelist of allowed files
3. Use path normalization to resolve and check paths
4. Deny access to paths containing directory traversal sequences (`../`)
5. Use a file access library that prevents path traversal by design

## Example Fix
```javascript
// Secure version
router.get('/file', (req, res) => {
  const filename = req.query.name;
  
  if (!filename) {
    return res.status(400).json({ error: 'Filename is required' });
  }
  
  // Validate filename - prevent path traversal
  if (filename.includes('../') || filename.includes('..\\') || 
      !filename.match(/^[a-zA-Z0-9_\-\.]+$/)) {
    return res.status(403).json({ error: 'Invalid filename' });
  }
  
  const filePath = path.join(__dirname, '../assets/', filename);
  
  // Ensure the path is within the assets directory
  const normalizedPath = path.normalize(filePath);
  const assetsDir = path.normalize(path.join(__dirname, '../assets/'));
  
  if (!normalizedPath.startsWith(assetsDir)) {
    return res.status(403).json({ error: 'Access denied' });
  }
  
  fs.readFile(filePath, 'utf8', (err, data) => {
    if (err) {
      return res.status(404).json({ error: 'File not found or cannot be read' });
    }
    
    res.json({ filename, content: data });
  });
});
```

## Related Vulnerabilities
- Local File Inclusion (LFI)
- Remote File Inclusion (RFI)
- Arbitrary File Reading
- Source Code Disclosure

## OWASP References
- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [OWASP File System](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Path_Traversal) 