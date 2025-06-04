const express = require('express');
const router = express.Router();
const db = require('../models/db');

// ✅ Input sanitization to prevent SQL injection or abuse
const xss = require('xss-clean'); // Must be registered in app.js globally
const rateLimit = require('express-rate-limit'); // Also should be registered in app.js

// Optional route-specific rate limiting (defense-in-depth)
const servicesLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 50,
  message: 'Too many requests to /api/services. Please try again later.',
});

router.get('/api/services', servicesLimiter, async (req, res) => {
  try {
    // Query database for all services - updated to match schema
    const query = `
      SELECT
        service_id as id,
        name,
        category,
        description,
        duration_minutes as duration,
        is_active
      FROM
        services
      WHERE
        is_active = TRUE
      ORDER BY
        category, name
    `;

    const services = await db.query(query);

    return res.status(200).json(services);
  } catch (error) {
    console.error('Error fetching services:', error);
    return res.status(500).json({
      error: true,
      message: 'Failed to fetch dental services'
    });
  }
});

module.exports = router;
