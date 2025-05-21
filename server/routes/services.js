// 2. Update services.js route to match schema
const express = require('express');
const router = express.Router();
const db = require('../models/db');

/**
 * GET /api/services
 * Returns all dental services organized by category
 */
router.get('/api/services', async (req, res) => {
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