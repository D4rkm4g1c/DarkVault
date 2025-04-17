const express = require('express');
const path = require('path');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const sqlite3 = require('sqlite3').verbose();
const fs = require('fs');
const helmet = require('helmet');
const morgan = require('morgan');
const cors = require('cors');
const xmlParser = require('express-xml-bodyparser');
const flash = require('connect-flash');
const db = require('./db');

// Initialize Express app
const app = express();
const port = process.env.PORT || 3000;

// API Server configuration
const apiServerUrl = process.env.API_SERVER_URL || 'http://localhost:3001';
app.locals.apiServerUrl = apiServerUrl;

// Set up view engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Middlewares
app.use(cors());
app.use(morgan('dev'));
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(xmlParser());
app.use(cookieParser());

// Session configuration - insecure settings
app.use(session({
  secret: 'darkvault-secret-key',
  resave: false,
  saveUninitialized: true,
  cookie: { secure: process.env.NODE_ENV === 'production' }
}));

// Flash messages
app.use(flash());

// Create assets directory for path traversal vulnerability if it doesn't exist
const assetsDir = path.join(__dirname, 'assets');
if (!fs.existsSync(assetsDir)){
  fs.mkdirSync(assetsDir);
  fs.writeFileSync(path.join(assetsDir, 'sample.txt'), 'This is a sample file in the assets directory.\n');
  fs.writeFileSync(path.join(assetsDir, 'README.txt'), 'This directory contains files for the path traversal vulnerability.\n');
}

// Create uploads directory if it doesn't exist
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)){
  fs.mkdirSync(uploadsDir);
}

// Global variables middleware
app.use((req, res, next) => {
  // Make flash messages consistently available to templates
  res.locals.success_msg = req.flash('success') || req.flash('success_msg') || [];
  res.locals.error_msg = req.flash('error') || req.flash('error_msg') || [];
  res.locals.user = req.session.user || null;
  res.locals.apiServerUrl = apiServerUrl;
  next();
});

// Routes
const indexRouter = require('./routes/index');
const apiRouter = require('./routes/api');
const userRouter = require('./routes/user');

app.use('/', indexRouter);
app.use('/api', apiRouter);
app.use('/user', userRouter);

// Error handling middleware
app.use((req, res, next) => {
  res.status(404).render('error', {
    title: '404 - Page Not Found',
    errorCode: 404,
    message: 'The page you requested was not found.',
    user: req.session.user || null
  });
});

app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).render('error', {
    title: '500 - Server Error',
    errorCode: 500,
    message: 'Something went wrong on the server.',
    error: process.env.NODE_ENV === 'development' ? err : {},
    user: req.session.user || null
  });
});

// Start server
app.listen(port, () => {
  console.log(`DarkVault server running on http://localhost:${port}`);
  console.log(`API Server URL: ${apiServerUrl}`);
  console.log('WARNING: This application contains deliberate vulnerabilities. Do not use in production.');
});

module.exports = app; 