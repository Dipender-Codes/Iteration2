// booking.controller.secured.js
// Enhanced security version of your booking controller

const BookingModel = require('../models/db');
const ServicesModel = require('../models/db');
const { body, validationResult } = require('express-validator');
const xss = require('xss');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const { formatTimeString } = require('../utils/date.utils');
const { sendBookingConfirmation } = require('../utils/email.utils');

// Security middleware - Rate limiting for booking endpoints
const bookingRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Limit each IP to 5 booking requests per windowMs
  message: {
    error: 'Too many booking attempts from this IP, please try again after 15 minutes.'
  },
  standardHeaders: true,
  legacyHeaders: false,
  // Skip rate limiting for trusted IPs (optional)
  skip: (req) => {
    const trustedIPs = process.env.TRUSTED_IPS ? process.env.TRUSTED_IPS.split(',') : [];
    return trustedIPs.includes(req.ip);
  }
});

// Rate limiting for time slot queries
const timeSlotRateLimit = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 30, // Allow 30 time slot requests per minute per IP
  message: {
    error: 'Too many time slot requests, please slow down.'
  }
});

// Enhanced validation middleware with security focus
const validateAppointment = [
  // Sanitize and validate service ID
  body('service')
    .trim()
    .escape() // HTML escape
    .isLength({ min: 1, max: 50 })
    .matches(/^[a-zA-Z0-9_-]+$/)
    .withMessage('Invalid service ID format'),
    
  // Strict date validation
  body('date')
    .trim()
    .isDate({ format: 'YYYY-MM-DD', strictMode: true })
    .custom((value) => {
      const selectedDate = new Date(value);
      const today = new Date();
      const maxDate = new Date();
      maxDate.setFullYear(today.getFullYear() + 1); // 1 year max advance booking
      
      if (selectedDate < today.setHours(0,0,0,0)) {
        throw new Error('Cannot book appointments in the past');
      }
      if (selectedDate > maxDate) {
        throw new Error('Cannot book appointments more than 1 year in advance');
      }
      return true;
    }),
    
  // Enhanced time validation
  body('time')
    .trim()
    .matches(/^([01]\d|2[0-3]):([0-5]\d)(:([0-5]\d))?$/)
    .custom((value) => {
      const [hours, minutes] = value.split(':');
      const timeNum = parseInt(hours) * 100 + parseInt(minutes);
      
      // Business hours validation (8 AM to 6 PM)
      if (timeNum < 800 || timeNum >= 1800) {
        throw new Error('Appointments only available between 8:00 AM and 6:00 PM');
      }
      return true;
    })
    .withMessage('Invalid time format or outside business hours'),
    
  // Enhanced name validation with XSS protection
  body('name')
    .trim()
    .escape()
    .isLength({ min: 2, max: 100 })
    .matches(/^[a-zA-Z\s'-]+$/)
    .withMessage('Name must contain only letters, spaces, hyphens, and apostrophes'),
    
  // Strict email validation
  body('email')
    .trim()
    .isEmail({ 
      allow_display_name: false,
      require_display_name: false,
      allow_utf8_local_part: false,
      require_tld: true
    })
    .isLength({ max: 254 }) // RFC 5321 limit
    .normalizeEmail({
      gmail_lowercase: true,
      gmail_remove_dots: false,
      outlookdotcom_lowercase: true,
      yahoo_lowercase: true
    })
    .custom((value) => {
      // Block disposable email domains
      const disposableDomains = [
        '10minutemail.com', 'tempmail.org', 'guerrillamail.com',
        'mailinator.com', 'yopmail.com', 'temp-mail.org'
      ];
      const domain = value.split('@')[1];
      if (disposableDomains.includes(domain.toLowerCase())) {
        throw new Error('Disposable email addresses are not allowed');
      }
      return true;
    }),
    
  // Enhanced phone validation
  body('phone')
    .trim()
    .custom(value => {
      // Remove all non-digits
      const cleanPhone = value.replace(/\D/g, '');
      
      // Australian phone number patterns
      const mobileRegex = /^04\d{8}$/;
      const landlineRegex = /^0[2378]\d{8}$/;
      
      if (!mobileRegex.test(cleanPhone) && !landlineRegex.test(cleanPhone)) {
        throw new Error('Must be a valid Australian phone number');
      }
      
      // Additional validation - no repeated digits (basic spam detection)
      if (/^(\d)\1{9}$/.test(cleanPhone)) {
        throw new Error('Invalid phone number pattern');
      }
      
      return true;
    }),
    
  // Secure notes handling
  body('notes')
    .optional()
    .trim()
    .isLength({ max: 500 })
    .custom((value) => {
      if (value) {
        // Check for potential script injection attempts
        const suspiciousPatterns = [
          /<script/i, /javascript:/i, /vbscript:/i, /onload=/i, 
          /onerror=/i, /onclick=/i, /eval\(/i, /expression\(/i
        ];
        
        if (suspiciousPatterns.some(pattern => pattern.test(value))) {
          throw new Error('Notes contain potentially harmful content');
        }
      }
      return true;
    })
    .withMessage('Notes cannot exceed 500 characters or contain scripts')
];

// Input sanitization helper
function sanitizeInput(input) {
  if (typeof input !== 'string') return input;
  
  return xss(input, {
    whiteList: {}, // No HTML tags allowed
    stripIgnoreTag: true,
    stripIgnoreTagBody: ['script', 'style']
  });
}

// Security logging helper
function logSecurityEvent(type, details, req) {
  const securityLog = {
    timestamp: new Date().toISOString(),
    type,
    ip: req.ip || req.connection.remoteAddress,
    userAgent: req.get('User-Agent'),
    details,
    headers: {
      'x-forwarded-for': req.get('x-forwarded-for'),
      'x-real-ip': req.get('x-real-ip')
    }
  };
  
  console.warn('🚨 SECURITY EVENT:', JSON.stringify(securityLog, null, 2));
  
  // In production, you should log this to a security monitoring service
  // Example: await securityLogger.alert(securityLog);
}

class BookingController {
  /**
   * SECURED: Enhanced appointment creation with comprehensive security measures
   */
  static async createAppointment(req, res) {
    try {
      // Security headers check
      const suspiciousHeaders = ['x-forwarded-host', 'x-original-url', 'x-rewrite-url'];
      const hasSuspiciousHeaders = suspiciousHeaders.some(header => req.get(header));
      
      if (hasSuspiciousHeaders) {
        logSecurityEvent('SUSPICIOUS_HEADERS', { headers: req.headers }, req);
        return res.status(400).json({ message: 'Invalid request headers' });
      }

      // Content-Type validation
      if (!req.is('application/json')) {
        logSecurityEvent('INVALID_CONTENT_TYPE', { contentType: req.get('content-type') }, req);
        return res.status(400).json({ message: 'Content-Type must be application/json' });
      }

      // Request size validation (already handled by body-parser limits, but double-check)
      const requestSize = JSON.stringify(req.body).length;
      if (requestSize > 5000) { // 5KB limit
        logSecurityEvent('OVERSIZED_REQUEST', { size: requestSize }, req);
        return res.status(413).json({ message: 'Request payload too large' });
      }

      console.log('📩 Secure request processing initiated for IP:', req.ip);
      
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        logSecurityEvent('VALIDATION_FAILED', { errors: errors.array() }, req);
        return res.status(400).json({
          message: 'Validation failed',
          errors: errors.array().map(err => ({
            field: err.path,
            message: err.msg
          }))
        });
      }

      const { service, date, time, name, email, phone, notes } = req.body;

      // Additional security: Check for injection patterns in all fields
      const allFields = { service, date, time, name, email, phone, notes };
      for (const [field, value] of Object.entries(allFields)) {
        if (value && typeof value === 'string') {
          // SQL injection patterns
          const sqlPatterns = [
            /(\b(union|select|insert|update|delete|drop|create|alter|exec|execute)\b)/i,
            /(--|\/\*|\*\/|;|\||&)/,
            /(\bor\b|\band\b).*[=<>]/i
          ];
          
          if (sqlPatterns.some(pattern => pattern.test(value))) {
            logSecurityEvent('SQL_INJECTION_ATTEMPT', { field, value: value.substring(0, 100) }, req);
            return res.status(400).json({ message: 'Invalid input detected' });
          }
        }
      }

      console.log('✅ Security validation passed');
      console.log('📅 Processing booking for:', sanitizeInput(name));

      // Deep sanitization of all inputs
      const sanitizedNotes = notes ? sanitizeInput(notes) : null;
      const sanitizedName = sanitizeInput(name);
      const sanitizedService = sanitizeInput(service);
      
      // Enhanced time formatting with validation
      let formattedTime = time;
      if (time && !time.includes(':')) {
        formattedTime = formatTimeString(time);
      } else if (time && time.split(':').length === 2) {
        formattedTime = `${time}:00`;
      }
      
      // Validate final time format
      if (!/^([01]\d|2[0-3]):([0-5]\d):([0-5]\d)$/.test(formattedTime)) {
        logSecurityEvent('INVALID_TIME_FORMAT', { originalTime: time, formattedTime }, req);
        return res.status(400).json({ message: 'Invalid time format' });
      }
      
      const formattedPhone = phone.replace(/\D/g, ''); // Remove all non-digits

      // Service validation with rate limiting check
      const serviceDetails = await ServicesModel.getServiceById(sanitizedService);
      if (!serviceDetails) {
        logSecurityEvent('INVALID_SERVICE_ACCESS', { serviceId: sanitizedService }, req);
        return res.status(400).json({ message: 'Invalid service selected' });
      }

      // Duplicate booking prevention (within last 5 minutes)
      const recentBookingCheck = await BookingModel.checkRecentBooking(
        email.toLowerCase(), 
        date, 
        5 // minutes
      );
      
      if (recentBookingCheck) {
        logSecurityEvent('DUPLICATE_BOOKING_ATTEMPT', { email, date, time }, req);
        return res.status(429).json({ 
          message: 'Duplicate booking detected. Please wait 5 minutes before booking again.' 
        });
      }

      console.log('✅ Service and duplicate checks passed');

      // Structure booking data with sanitized inputs
      const bookingData = {
        fullName: sanitizedName,
        name: sanitizedName,
        email: email.toLowerCase(),
        phone: formattedPhone,
        serviceId: sanitizedService,
        appointmentDate: date,
        date: date,
        startTime: formattedTime,
        time: formattedTime,
        additionalNotes: sanitizedNotes,
        // Security metadata
        ipAddress: req.ip,
        userAgent: req.get('User-Agent')?.substring(0, 255), // Limit length
        createdAt: new Date().toISOString()
      };

      // Create booking with enhanced error handling
      const appointmentId = await BookingModel.createAppointment(bookingData);
      console.log('✅ Secure appointment created with ID:', appointmentId);

      // Log successful booking for monitoring
      console.log('📊 BOOKING SUCCESS:', {
        appointmentId,
        date,
        time: formattedTime,
        service: serviceDetails.name,
        ip: req.ip
      });

      // Email sending with security considerations
      let emailSent = false;
      let emailError = null;

      try {
        const emailData = this.prepareSecureEmailData(bookingData, serviceDetails);

        if (!emailData) {
          throw new Error('Failed to prepare secure email data');
        }

        // Email rate limiting check
        const emailRateCheck = await this.checkEmailRateLimit(email);
        if (!emailRateCheck.allowed) {
          console.warn('⚠️ Email rate limit exceeded for:', email);
          // Don't fail the booking, just skip email
          throw new Error('Email rate limit exceeded');
        }

        console.log('📧 Sending secure confirmation email');
        
        const emailSendPromise = sendBookingConfirmation(emailData);
        const timeoutPromise = new Promise((_, reject) => 
          setTimeout(() => reject(new Error('Email timeout')), 15000)
        );
        
        const emailResult = await Promise.race([emailSendPromise, timeoutPromise]);
        
        console.log('✅ Secure email sent successfully');
        emailSent = true;
        
      } catch (err) {
        emailError = err;
        console.error('❌ Secure email sending failed:', err.message);
        
        // Log email failures for monitoring
        logSecurityEvent('EMAIL_SEND_FAILURE', { 
          error: err.message,
          appointmentId 
        }, req);
      }

      // Secure response (limited information exposure)
      res.status(201).json({
        success: true,
        message: 'Appointment booked successfully',
        appointmentId: appointmentId.toString(), // Ensure string format
        appointmentDate: date,
        appointmentTime: formattedTime,
        serviceName: serviceDetails.name,
        emailConfirmationSent: emailSent,
        // Don't expose detailed error messages in production
        ...(process.env.NODE_ENV !== 'production' && emailError && {
          emailError: emailError.message
        })
      });

    } catch (dbError) {
      console.error('❌ Secure booking error:', dbError);
      
      // Log database errors for monitoring
      logSecurityEvent('DATABASE_ERROR', { 
        error: dbError.message,
        stack: dbError.stack?.substring(0, 500)
      }, req);

      // Handle specific database errors securely
      if (dbError.message?.includes('time slot is already booked')) {
        return res.status(409).json({ 
          success: false,
          message: 'Selected time slot is no longer available' 
        });
      }

      if (dbError.message?.includes('date is not available')) {
        return res.status(400).json({ 
          success: false,
          message: 'Selected date is not available for booking' 
        });
      }

      // Generic error response (don't expose internal details)
      res.status(500).json({
        success: false,
        message: 'Unable to process booking request',
        error: process.env.NODE_ENV === 'production' 
          ? 'Internal server error' 
          : dbError.message?.substring(0, 100) // Limit error message length
      });
    }
  }

  /**
   * SECURED: Enhanced time slot retrieval with input validation and rate limiting
   */
  static async getAvailableTimeSlots(req, res) {
    try {
      // Apply rate limiting
      timeSlotRateLimit(req, res, async () => {
        const { date, serviceId } = req.query;

        // Enhanced input validation
        if (!date || !serviceId) {
          return res.status(400).json({ 
            success: false,
            message: 'Date and serviceId are required' 
          });
        }

        // Sanitize inputs
        const sanitizedDate = sanitizeInput(date);
        const sanitizedServiceId = sanitizeInput(serviceId);

        // Strict date format validation
        if (!sanitizedDate.match(/^\d{4}-\d{2}-\d{2}$/)) {
          logSecurityEvent('INVALID_DATE_FORMAT', { date: sanitizedDate }, req);
          return res.status(400).json({ 
            success: false,
            message: 'Invalid date format. Use YYYY-MM-DD.' 
          });
        }

        // Date range validation
        const requestedDate = new Date(sanitizedDate);
        const today = new Date();
        const maxDate = new Date();
        maxDate.setFullYear(today.getFullYear() + 1);

        if (requestedDate < today.setHours(0,0,0,0)) {
          return res.status(400).json({ 
            success: false,
            message: 'Cannot request time slots for past dates' 
          });
        }

        if (requestedDate > maxDate) {
          return res.status(400).json({ 
            success: false,
            message: 'Cannot request time slots more than 1 year in advance' 
          });
        }

        // Service ID validation
        if (!sanitizedServiceId.match(/^[a-zA-Z0-9_-]+$/)) {
          logSecurityEvent('INVALID_SERVICE_ID_FORMAT', { serviceId: sanitizedServiceId }, req);
          return res.status(400).json({ 
            success: false,
            message: 'Invalid service ID format' 
          });
        }

        // Verify service exists
        const serviceDetails = await ServicesModel.getServiceById(sanitizedServiceId);
        if (!serviceDetails) {
          logSecurityEvent('INVALID_SERVICE_REQUEST', { serviceId: sanitizedServiceId }, req);
          return res.status(400).json({ 
            success: false,
            message: 'Invalid service selected' 
          });
        }

        // Get available time slots
        const availableSlots = await BookingModel.getAvailableTimeSlots(
          sanitizedDate, 
          sanitizedServiceId
        );

        // Security: Limit the number of returned slots to prevent data exposure
        const limitedSlots = availableSlots.slice(0, 50); // Max 50 slots

        res.json({
          success: true,
          availableSlots: limitedSlots,
          serviceDuration: serviceDetails.duration_minutes,
          requestedDate: sanitizedDate,
          totalSlots: availableSlots.length,
          returned: limitedSlots.length
        });
      });

    } catch (error) {
      console.error('❌ Secure time slots error:', error);
      
      logSecurityEvent('TIMESLOT_FETCH_ERROR', { 
        error: error.message 
      }, req);

      res.status(500).json({
        success: false,
        message: 'Unable to fetch available time slots',
        error: process.env.NODE_ENV === 'production' 
          ? 'Server error' 
          : error.message?.substring(0, 100)
      });
    }
  }

  /**
   * SECURED: Prepare email data with additional security validation
   */
  static prepareSecureEmailData(bookingData, serviceDetails) {
    if (!bookingData || !serviceDetails) {
      console.error('❌ Missing booking data or service details for secure email');
      return null;
    }

    // Additional validation for email data
    const emailData = {
      fullName: sanitizeInput(bookingData.fullName || bookingData.name || 'Patient'),
      email: bookingData.email ? bookingData.email.toLowerCase().trim() : '',
      appointmentDate: bookingData.appointmentDate || bookingData.date,
      startTime: bookingData.startTime || bookingData.time,
      serviceName: sanitizeInput(serviceDetails.name || 'Dental Service')
    };

    // Enhanced validation
    const missingFields = [];
    if (!emailData.email || emailData.email === '') missingFields.push('email');
    if (!emailData.appointmentDate) missingFields.push('appointmentDate');
    if (!emailData.startTime) missingFields.push('startTime');
    if (!emailData.fullName) missingFields.push('fullName');
    if (!emailData.serviceName) missingFields.push('serviceName');

    if (missingFields.length > 0) {
      console.error('❌ Missing required fields for secure email:', missingFields.join(', '));
      return null;
    }

    // Email format validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(emailData.email)) {
      console.error('❌ Invalid email format for secure email:', emailData.email);
      return null;
    }

    // Date and time format validation
    if (!/^\d{4}-\d{2}-\d{2}$/.test(emailData.appointmentDate)) {
      console.error('❌ Invalid date format for secure email:', emailData.appointmentDate);
      return null;
    }

    if (!/^([01]\d|2[0-3]):([0-5]\d):([0-5]\d)$/.test(emailData.startTime)) {
      if (/^([01]\d|2[0-3]):([0-5]\d)$/.test(emailData.startTime)) {
        emailData.startTime = `${emailData.startTime}:00`;
      } else {
        console.error('❌ Invalid time format for secure email:', emailData.startTime);
        return null;
      }
    }

    console.log('✅ Secure email data prepared successfully');
    return emailData;
  }

  /**
   * Email rate limiting helper
   */
  static async checkEmailRateLimit(email) {
    // Implement email-specific rate limiting
    // This would typically use Redis or in-memory cache
    
    // For now, return allowed - implement based on your caching solution
    return { allowed: true, remaining: 5 };
  }
}

// Export with rate limiting middleware
module.exports = {
  BookingController,
  validateAppointment,
  bookingRateLimit,
  timeSlotRateLimit
};