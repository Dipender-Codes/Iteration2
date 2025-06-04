const ServicesModel = require('../models/services.model');

class ServicesController {
  // Input validation helper
  static validateServiceId(serviceId) {
    // Check if serviceId exists and is not empty
    if (!serviceId || typeof serviceId !== 'string') {
      return false;
    }
    
    // Check for basic SQL injection patterns
    const sqlInjectionPatterns = /['"`;\\--]|(\bunion\b)|(\bselect\b)|(\binsert\b)|(\bupdate\b)|(\bdelete\b)|(\bdrop\b)/i;
    if (sqlInjectionPatterns.test(serviceId)) {
      return false;
    }
    
    // Check for reasonable length (adjust based on your ID format)
    if (serviceId.length > 50) {
      return false;
    }
    
    // Check for valid characters (alphanumeric, hyphens, underscores)
    const validIdPattern = /^[a-zA-Z0-9_-]+$/;
    if (!validIdPattern.test(serviceId)) {
      return false;
    }
    
    return true;
  }

  // Sanitize error messages to prevent information disclosure
  static sanitizeError(error, isDevelopment = false) {
    if (isDevelopment) {
      return error.message;
    }
    
    // In production, return generic error messages
    const sensitivePatterns = /password|token|key|secret|database|connection|query/i;
    if (sensitivePatterns.test(error.message)) {
      return 'Internal server error';
    }
    
    return error.message;
  }

  // Rate limiting check (implement with your rate limiting middleware)
  static checkRateLimit(req, res, next) {
    // This should be implemented with middleware like express-rate-limit
    // Placeholder for rate limiting logic
    next();
  }

  // Get all active services
  static async getAllServices(req, res) {
    try {
      // Add rate limiting
      // You should implement proper rate limiting middleware
      
      const services = await ServicesModel.getAllServices();
      
      // Sanitize output - remove sensitive fields if any
      const sanitizedServices = services.map(service => {
        const { internalNotes, createdBy, ...publicService } = service;
        return publicService;
      });
      
      res.json(sanitizedServices);
    } catch (error) {
      console.error('Error fetching services:', error);
      
      // Don't expose internal error details in production
      const isDevelopment = process.env.NODE_ENV === 'development';
      const sanitizedError = this.sanitizeError(error, isDevelopment);
      
      res.status(500).json({ 
        message: 'Unable to fetch services',
        ...(isDevelopment && { error: sanitizedError })
      });
    }
  }

  // Get a specific service by ID
  static async getServiceById(req, res) {
    try {
      const serviceId = req.params.serviceId;
      
      // Input validation
      if (!this.validateServiceId(serviceId)) {
        return res.status(400).json({ 
          message: 'Invalid service ID format' 
        });
      }
      
      const service = await ServicesModel.getServiceById(serviceId);
      
      if (!service) {
        return res.status(404).json({ message: 'Service not found' });
      }
      
      // Sanitize output - remove sensitive fields
      const { internalNotes, createdBy, ...publicService } = service;
      
      res.json(publicService);
    } catch (error) {
      console.error('Error fetching service:', error);
      
      // Don't expose internal error details in production
      const isDevelopment = process.env.NODE_ENV === 'development';
      const sanitizedError = this.sanitizeError(error, isDevelopment);
      
      res.status(500).json({ 
        message: 'Unable to fetch service',
        ...(isDevelopment && { error: sanitizedError })
      });
    }
  }
}

module.exports = ServicesController;