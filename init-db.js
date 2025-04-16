/**
 * Database Initialization Script
 * 
 * This script ensures that all default users exist in the database.
 * It can be run separately to reset users or before starting the application.
 */

const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');
const md5 = require('md5');

console.log('🔧 Running database initialization script...');

// Create database directory if it doesn't exist
const dbDir = path.join(__dirname, 'data');
if (!fs.existsSync(dbDir)) {
  fs.mkdirSync(dbDir, { recursive: true });
  console.log('✅ Created database directory:', dbDir);
}

// Initialize database connection
const dbPath = path.join(dbDir, 'darkvault.db');
console.log('📂 Database path:', dbPath);
const db = new sqlite3.Database(dbPath);

// Initialize tables
db.serialize(() => {
  console.log('🔄 Creating tables if they don\'t exist...');
  
  // Users table
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    email TEXT,
    role TEXT DEFAULT 'user',
    isAdmin INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )`);

  console.log('👤 Setting up default users...');

  // First, delete existing users with these usernames to avoid conflicts
  const usernamesToReset = ['admin', 'user1', 'manager', 'test'];
  
  db.run(`DELETE FROM users WHERE username IN ('${usernamesToReset.join("','")}')`, (err) => {
    if (err) {
      console.error('❌ Error deleting existing users:', err);
    } else {
      console.log('🗑️ Cleaned up existing default users');
      
      // Now create all default users
      const users = [
        {
          username: 'admin',
          password: md5('SecretPassword123!'),
          email: 'admin@darkvault.local',
          role: 'admin',
          isAdmin: 1
        },
        {
          username: 'user1',
          password: md5('Password123'),
          email: 'user1@darkvault.local',
          role: 'user',
          isAdmin: 0
        },
        {
          username: 'manager',
          password: md5('ManageIt!2023'),
          email: 'manager@darkvault.local',
          role: 'manager',
          isAdmin: 0
        },
        {
          username: 'test',
          password: md5('test123'),
          email: 'test@darkvault.local',
          role: 'user',
          isAdmin: 0
        }
      ];

      // Insert each user
      users.forEach(user => {
        db.run(
          "INSERT INTO users (username, password, email, role, isAdmin) VALUES (?, ?, ?, ?, ?)",
          [user.username, user.password, user.email, user.role, user.isAdmin],
          function(err) {
            if (err) {
              console.error(`❌ Error creating ${user.username}:`, err);
            } else {
              console.log(`✅ Created user ${user.username} with password ${user.username === 'admin' ? 'SecretPassword123!' : user.username === 'user1' ? 'Password123' : user.username === 'manager' ? 'ManageIt!2023' : 'test123'}`);
            }
          }
        );
      });
    }
  });
});

// Create files needed for path traversal vulnerabilities
console.log('📁 Setting up files for vulnerabilities...');

// Create assets directory for path traversal vulnerability if it doesn't exist
const assetsDir = path.join(__dirname, 'assets');
if (!fs.existsSync(assetsDir)) {
  fs.mkdirSync(assetsDir, { recursive: true });
  console.log('✅ Created assets directory:', assetsDir);
}

// Create sample files in the assets directory (normal access)
fs.writeFileSync(path.join(assetsDir, 'sample.txt'), 'This is a sample file in the assets directory.\n');
fs.writeFileSync(path.join(assetsDir, 'README.txt'), 'This directory contains files for the path traversal vulnerability.\n');

// Create flag.txt at project root
fs.writeFileSync(path.join(__dirname, 'flag.txt'), 'DARK{r00t_fl4g_f0und_v14_p4th_tr4v3rs4l}');

// Create opt directory for XXE vulnerability
const optDir = path.join(__dirname, 'opt');
if (!fs.existsSync(optDir)) {
  fs.mkdirSync(optDir, { recursive: true });
  console.log('✅ Created mock /opt directory:', optDir);
}

// Create XXE flag file in opt directory
fs.writeFileSync(path.join(optDir, 'xxe_flag.txt'), 'DARK{xxe_data_extr4ct0r}');
console.log('✅ Created XXE flag file in mock /opt directory');

// Create or overwrite config.json at project root (for various vulnerabilities)
const configJson = {
  "database": {
    "username": "darkvault_admin",
    "password": "supersecretpassword123",
    "host": "localhost",
    "port": 5432,
    "name": "darkvault_db"
  },
  "api": {
    "secret_key": "8b45e4bd7c5df4857fb2641b8f5c2c952f80429c",
    "token_expiry": "24h"
  },
  "smtp": {
    "host": "smtp.darkvault.local",
    "port": 587,
    "user": "notifications@darkvault.local",
    "password": "smtp-password-do-not-share"
  },
  "admin": {
    "default_password": "admin123"
  }
};

fs.writeFileSync(path.join(__dirname, 'config.json'), JSON.stringify(configJson, null, 2));
console.log('✅ Created config.json with sensitive information');

// Create config.secret at project root (for the JWT secret)
fs.writeFileSync(path.join(__dirname, 'config.secret'), 'JWT_SECRET=darkvault-secret-key\nThis file contains sensitive configuration data that should not be accessible via the web application.');

// Create etc directory to simulate system files
const etcDir = path.join(__dirname, 'etc');
if (!fs.existsSync(etcDir)) {
  fs.mkdirSync(etcDir, { recursive: true });
  console.log('✅ Created mock /etc directory:', etcDir);
}

// Create darkflag in etc (for the path traversal flag)
fs.writeFileSync(path.join(etcDir, 'darkflag'), 'DARK{p4th_tr4v3rs4l_m4st3r}');

// Create mock passwd file for path traversal demo
fs.writeFileSync(path.join(etcDir, 'passwd'), `
root:x:0:0:root:/root:/bin/bash
admin:x:1000:1000:DarkVault Admin:/home/admin:/bin/bash
user1:x:1001:1001:Regular User:/home/user1:/bin/bash
manager:x:1002:1002:Manager User:/home/manager:/bin/bash
test:x:1003:1003:Test User:/home/test:/bin/bash
`);

// Create docs directory with sensitive files
const docsDir = path.join(__dirname, 'docs');
if (!fs.existsSync(docsDir)) {
  fs.mkdirSync(docsDir, { recursive: true });
  console.log('✅ Created docs directory:', docsDir);
}

// Create sensitive files in docs
fs.writeFileSync(path.join(docsDir, 'sensitive.txt'), 'This file contains sensitive information that should be protected.\nSECRET_API_KEY=abcd1234\nPASSWORD=supersecretpassword');

// Create directory for temporary files (needed for command injection and file upload vulnerabilities)
const tmpDir = path.join(__dirname, 'tmp');
if (!fs.existsSync(tmpDir)) {
  fs.mkdirSync(tmpDir, { recursive: true });
  console.log('✅ Created tmp directory for command injection results:', tmpDir);
}

// Create file for command injection vulnerability
fs.writeFileSync(path.join(tmpDir, 'cmd_flag.txt'), 'DARK{c0mm4nd_1nj3ct10n_pr0}');

// Create uploads directory for file upload vulnerability
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
  console.log('✅ Created uploads directory for file upload vulnerability:', uploadsDir);
}

// Create file for XXE vulnerability
const xxeFile = `<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE note [
<!ELEMENT note (to,from,heading,body)>
<!ELEMENT to (#PCDATA)>
<!ELEMENT from (#PCDATA)>
<!ELEMENT heading (#PCDATA)>
<!ELEMENT body (#PCDATA)>
]>
<note>
<to>User</to>
<from>Admin</from>
<heading>Security Note</heading>
<body>This is a sample XML file for XXE testing</body>
</note>`;
fs.writeFileSync(path.join(docsDir, 'sample.xml'), xxeFile);

// Create .env file for SSTI vulnerability
fs.writeFileSync(path.join(__dirname, '.env'), `
# Environment Variables
APP_SECRET=env_file_secret_key_12345
API_TOKEN=c29tZXJhbmRvbXRva2VuCg==
DEBUG=true
NODE_ENV=development
APP_PORT=3000
FLAG_SSTI=DARK{t3mpl4t3_1nj3ct10n}
`);

console.log('✅ Created all files needed for vulnerabilities');

// Alert about one-time setup
console.log('\n⚠️  For command injection to work fully, please run this command once:');
console.log('   echo "DARK{c0mm4nd_1nj3ct10n_pr0}" > /tmp/cmd_flag.txt');
console.log('   (This creates a file that can be accessed during command injection tests)\n');

// Close the database connection after a delay to ensure all operations complete
setTimeout(() => {
  db.close((err) => {
    if (err) {
      console.error('❌ Error closing database:', err);
    } else {
      console.log('✅ Database initialization complete and connection closed');
    }
  });
}, 2000); 