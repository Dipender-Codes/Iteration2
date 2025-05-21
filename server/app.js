// server/app.js
const express = require('express');
const path = require('path');
const cors = require('cors');
const db = require('./models/db');
require('dotenv').config();


// Import routes
const serviceRoutes = require('./routes/services');
const bookingRoutes = require('./routes/booking');

const app = express();

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve static files from the client directory
app.use(express.static(path.join(__dirname, '../client')));

// Routes
app.use(serviceRoutes);
app.use(bookingRoutes);

// Fallback route - serve the main HTML file for any unmatched routes
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../client/index.html'));
});

// Test database connection on startup
db.testConnection()
  .then(success => {
    if (!success) {
      console.warn('Warning: Database connection test failed. Check your database configuration.');
    }
  });

module.exports = app;