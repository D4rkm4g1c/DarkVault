/**
 * Error handler middleware for DarkVault
 * Helps prevent application crashes during security testing like Burp Suite scans
 */

const fs = require('fs');

// Ensure logs directory exists
if (!fs.existsSync('logs')) {
  fs.mkdirSync('logs');
}

// Error logging function
function logError(location, error, data = {}) {
  const timestamp = new Date().toISOString();
  const logEntry = `${timestamp} - ${location} - ${error.message}\nData: ${JSON.stringify(data)}\nStack: ${error.stack}\n\n`;
  
  fs.appendFile('logs/error.log', logEntry, (err) => {
    if (err) console.error('Failed to write to log file:', err);
  });
  
  console.error(`${timestamp} - ${location} - ${error.message}`);
}

// Global error handler middleware
function errorHandler(err, req, res, next) {
  console.error('Global error handler caught: ', err.message);
  logError('global_error_handler', err, { 
    path: req.path,
    method: req.method,
    query: req.query,
    headers: req.headers
  });
  
  // Don't expose error details in production
  if (process.env.NODE_ENV === 'production') {
    return res.status(500).json({ error: 'Internal server error' });
  } else {
    // In dev/test mode, return error details to assist testing
    return res.status(500).json({ 
      error: 'Internal server error',
      message: err.message,
      stack: err.stack
    });
  }
}

// Request body validation middleware
function validateRequestBody(req, res, next) {
  // Many security scanners will send malformed data
  // This middleware helps prevent crashes for common patterns
  try {
    // For JSON requests, ensure they're parseable
    const contentType = req.headers['content-type'] || '';
    if (contentType.includes('application/json') && req.body) {
      // Body already parsed by bodyParser, just check it exists
      if (typeof req.body !== 'object') {
        console.warn('Invalid JSON body received');
        req.body = {}; // Set empty object to prevent crashes
      }
    }
    
    next();
  } catch (error) {
    console.error('Request validation error:', error.message);
    next(); // Continue, but log the error
  }
}

// Function to handle very large payloads
function handleLargePayloads(err, req, res, next) {
  if (err && err.type === 'entity.too.large') {
    return res.status(413).json({
      error: 'Payload too large',
      message: 'The request payload is too large'
    });
  }
  next(err);
}

/**
 * Utility to safely execute SQL queries that could be vulnerable to injection
 * Important: This doesn't prevent the vulnerability, but prevents the app from crashing
 * during security scanning
 */
function safeSqliteQuery(db, queryType, query, params, callback) {
  try {
    // Execute the query with error handling
    db[queryType](query, params, (err, result) => {
      if (err) {
        console.error('SQL Error:', err.message);
        console.error('Query:', query);
        console.error('Params:', params);
        
        // Log to file
        logError('sql_error', err, { query, params });
        
        // Instead of crashing, return empty result
        if (queryType === 'get') {
          callback(null, null);
        } else if (queryType === 'all') {
          callback(null, []);
        } else {
          callback(null);
        }
      } else {
        callback(null, result);
      }
    });
  } catch (error) {
    console.error('Critical SQL execution error:', error.message);
    logError('sql_critical_error', error, { query, params });
    
    // Return safe defaults
    if (queryType === 'get') {
      callback(null, null);
    } else if (queryType === 'all') {
      callback(null, []);
    } else {
      callback(null);
    }
  }
}

module.exports = {
  errorHandler,
  validateRequestBody,
  handleLargePayloads,
  logError,
  safeSqliteQuery
}; 