# DarkVault Installation Guide

This guide provides detailed instructions for setting up and running the DarkVault deliberately vulnerable web application.

## Prerequisites

- Node.js (v12 or higher) - [Download from nodejs.org](https://nodejs.org/)
- npm (included with Node.js)
- Git

## Installation Steps

### 1. Clone the Repository

```bash
git clone https://github.com/D4rkm4g1c/DarkVault.git
cd DarkVault
```

### 2. Install Dependencies

```bash
npm install
```

This will install all required dependencies:
- Express.js (web framework)
- SQLite3 (database)
- EJS (templating engine)
- JWT (for authentication)
- And other dependencies

### 3. Set Up the Database

The application uses SQLite, which doesn't require a separate installation.
The database file `darkvault.db` will be created automatically when you first run the application.

### 4. Configure Environment (Optional)

By default, the application runs in development mode with all vulnerabilities enabled.
If you need to customize settings, you can create a `.env` file in the project root:

```
PORT=3000
NODE_ENV=development
JWT_SECRET=darkvault-secret-key
```

## Running the Application

### Standard Mode

```bash
npm start
```

### Development Mode (with auto-reload)

```bash
npm run dev
```

If you don't have nodemon installed globally, you can install it with:

```bash
npm install -g nodemon
```

### Access the Application

Open your browser and navigate to:
```
http://localhost:3000
```

## Default Credentials

- **Admin Account**:
  - Username: `admin`
  - Password: `SecretPassword123!`

- You can also create your own user accounts through the registration page.

## Flag Tracking Dashboard

Access the flag tracking dashboard at:
```
http://localhost:3000/flags
```

## Troubleshooting

### Port Already in Use

If port 3000 is already in use, you can modify the port in the `.env` file or start the application with:

```bash
PORT=3001 npm start
```

### Database Errors

If you encounter database errors, try removing the database file and letting the application recreate it:

```bash
rm darkvault.db
npm start
```

### Node Version Issues

If you encounter compatibility issues, ensure you're using Node.js v12 or higher:

```bash
node -v
```

## Warning

**IMPORTANT**: This application is deliberately vulnerable and should NOT be deployed on a production server or exposed to the internet. Use only in controlled environments for educational purposes.

Run this application in an isolated environment, such as a virtual machine or container, to prevent potential security risks to your system. 