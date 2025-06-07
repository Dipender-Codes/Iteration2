const mysql = require('mysql2/promise');
require('dotenv').config();

// Security configuration
const SECURITY_CONFIG = {
  MAX_QUERY_LENGTH: 10000,
  MAX_PARAM_LENGTH: 1000,
  ALLOWED_OPERATIONS: ['SELECT', 'INSERT', 'UPDATE', 'DELETE'],
  RATE_LIMIT: {
    maxQueries: 100,
    windowMs: 60000 // 1 minute
  }
};

// Rate limiting storage (in production, use Redis)
const rateLimitStore = new Map();

// Create a connection pool with security configurations
const pool = mysql.createPool({
  host: process.env.DB_HOST || 'srv611.hstgr.io',
  user: process.env.DB_USER || 'u963206240_thoroughdental',
  password: process.env.DB_PASSWORD || 'Dipender@2622',
  database: process.env.DB_NAME || 'u963206240_dental_booking',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  acquireTimeout: 60000,
  timeout: 60000,
  multipleStatements: false, // Prevent SQL injection via multiple statements
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Database utility functions
const db = {
  // Security validation functions
  validateQuery(sql) {
    if (!sql || typeof sql !== 'string') {
      throw new Error('Invalid query: SQL must be a non-empty string');
    }
    
    if (sql.length > SECURITY_CONFIG.MAX_QUERY_LENGTH) {
      throw new Error('Query too long: Potential DoS attack');
    }
    
    // Check for dangerous SQL patterns
    const dangerousPatterns = [
      /;\s*(drop|truncate|delete|alter|create|exec|execute|sp_|xp_)/i,
      /union.*select/i,
      /\/\*.*\*\//i, // Block comments
      /--.*$/i, // Line comments
      /\bor\b.*['"]\s*['"]/i, // OR-based injection
      /\band\b.*['"]\s*['"]/i, // AND-based injection
      /\bxor\b/i,
      /benchmark\s*\(/i,
      /sleep\s*\(/i,
      /waitfor\s+delay/i,
      /load_file\s*\(/i,
      /outfile\s*['"]/i,
      /dumpfile\s*['"]/i
    ];
    
    for (const pattern of dangerousPatterns) {
      if (pattern.test(sql)) {
        throw new Error('Potentially malicious SQL detected');
      }
    }
    
    return true;
  },

  validateParams(params) {
    if (!Array.isArray(params)) {
      throw new Error('Parameters must be an array');
    }
    
    for (const param of params) {
      if (param !== null && param !== undefined) {
        const paramStr = String(param);
        if (paramStr.length > SECURITY_CONFIG.MAX_PARAM_LENGTH) {
          throw new Error('Parameter too long: Potential buffer overflow attack');
        }
        
        // Check for suspicious patterns in parameters
        const suspiciousPatterns = [
          /script\s*>/i,
          /<\s*iframe/i,
          /javascript:/i,
          /vbscript:/i,
          /on\w+\s*=/i
        ];
        
        for (const pattern of suspiciousPatterns) {
          if (pattern.test(paramStr)) {
            throw new Error('Potentially malicious parameter detected');
          }
        }
      }
    }
    
    return true;
  },

  // Rate limiting check
  checkRateLimit(identifier = 'default') {
    const now = Date.now();
    const windowStart = now - SECURITY_CONFIG.RATE_LIMIT.windowMs;
    
    if (!rateLimitStore.has(identifier)) {
      rateLimitStore.set(identifier, []);
    }
    
    const requests = rateLimitStore.get(identifier);
    
    // Remove old requests outside the window
    const validRequests = requests.filter(timestamp => timestamp > windowStart);
    
    if (validRequests.length >= SECURITY_CONFIG.RATE_LIMIT.maxQueries) {
      throw new Error('Rate limit exceeded');
    }
    
    validRequests.push(now);
    rateLimitStore.set(identifier, validRequests);
    
    return true;
  },

  // Sanitize input data
  sanitizeInput(input) {
    if (typeof input === 'string') {
      return input
        .trim()
        .replace(/[\x00-\x1F\x7F-\x9F]/g, '') // Remove control characters
        .substring(0, SECURITY_CONFIG.MAX_PARAM_LENGTH);
    }
    return input;
  },

  // Test the database connection
  async testConnection() {
    try {
      const connection = await pool.getConnection();
      console.log('Database connection established successfully');
      connection.release();
      return true;
    } catch (error) {
      console.error('Database connection failed:', error.message);
      return false;
    }
  },

  // Execute a query with parameters (secured)
  async query(sql, params = [], identifier = 'default') {
    try {
      // Rate limiting
      this.checkRateLimit(identifier);
      
      // Validate query and parameters
      this.validateQuery(sql);
      this.validateParams(params);
      
      // Sanitize parameters
      const sanitizedParams = params.map(param => this.sanitizeInput(param));
      
      const [results] = await pool.execute(sql, sanitizedParams);
      return results;
    } catch (error) {
      // Log security incidents
      if (error.message.includes('malicious') || error.message.includes('Rate limit')) {
        console.error('SECURITY ALERT:', {
          message: error.message,
          sql: sql.substring(0, 100) + '...', // Log only first 100 chars
          timestamp: new Date().toISOString(),
          identifier
        });
      } else {
        console.error('Database query error:', error.message);
      }
      throw error;
    }
  },

  // === Booking Functions (Secured) ===

  /**
   * Create a new appointment with enhanced security
   */
  async createAppointment(bookingData) {
    try {
      // Input validation and sanitization
      const requiredFields = ['fullName', 'email', 'phone', 'serviceId', 'appointmentDate', 'startTime'];
      for (const field of requiredFields) {
        if (!bookingData[field]) {
          throw new Error(`Missing required field: ${field}`);
        }
      }

      // Validate email format
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(bookingData.email)) {
        throw new Error('Invalid email format');
      }

      // Validate phone format (basic)
      const phoneRegex = /^[\d\s\-\+\(\)]{10,15}$/;
      if (!phoneRegex.test(bookingData.phone)) {
        throw new Error('Invalid phone format');
      }

      // Validate date format (YYYY-MM-DD)
      const dateRegex = /^\d{4}-\d{2}-\d{2}$/;
      if (!dateRegex.test(bookingData.appointmentDate)) {
        throw new Error('Invalid date format');
      }

      // Validate time format (HH:MM:SS)
      const timeRegex = /^\d{2}:\d{2}:\d{2}$/;
      if (!timeRegex.test(bookingData.startTime)) {
        throw new Error('Invalid time format');
      }

      // Validate service ID (alphanumeric only)
      const serviceIdRegex = /^[a-zA-Z0-9_-]+$/;
      if (!serviceIdRegex.test(bookingData.serviceId)) {
        throw new Error('Invalid service ID format');
      }

      // Sanitize text inputs
      const sanitizedData = {
        fullName: this.sanitizeInput(bookingData.fullName),
        email: this.sanitizeInput(bookingData.email),
        phone: this.sanitizeInput(bookingData.phone),
        serviceId: this.sanitizeInput(bookingData.serviceId),
        appointmentDate: bookingData.appointmentDate,
        startTime: bookingData.startTime,
        additionalNotes: this.sanitizeInput(bookingData.additionalNotes || '')
      };

      // Get service duration
      const serviceQuery = `
        SELECT duration_minutes 
        FROM services 
        WHERE service_id = ? AND is_active = TRUE
      `;
      const [service] = await this.query(serviceQuery, [sanitizedData.serviceId], 'service-lookup');
      
      if (!service) {
        throw new Error('Invalid or inactive service');
      }
      
      const serviceDuration = service.duration_minutes;
      
      // Calculate end time based on start time and duration
      const startTime = sanitizedData.startTime;
      const [hours, minutes, seconds] = startTime.split(':').map(Number);
      
      // Convert to minutes for easier calculation
      const startMinutes = hours * 60 + minutes;
      const endMinutes = startMinutes + serviceDuration;
      
      // Convert back to time format
      const endHours = Math.floor(endMinutes / 60);
      const endMins = endMinutes % 60;
      const endTime = `${endHours.toString().padStart(2, '0')}:${endMins.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
      
      // Check availability
      const availabilityQuery = `
        SELECT 1 FROM appointments 
        WHERE 
          appointment_date = ? 
          AND status != 'cancelled'
          AND (
            (start_time <= ? AND end_time > ?) OR 
            (start_time < ? AND end_time >= ?) OR
            (start_time >= ? AND end_time <= ?)
          )
      `;
      
      const availabilityParams = [
        sanitizedData.appointmentDate,
        endTime, sanitizedData.startTime,
        endTime, sanitizedData.startTime,
        sanitizedData.startTime, endTime
      ];
      
      const existingAppointments = await this.query(availabilityQuery, availabilityParams, 'availability-check');
      
      if (existingAppointments.length > 0) {
        throw new Error('Selected time slot is already booked');
      }
      
      // Check if the date is blocked
      const blockedQuery = `
        SELECT 1 FROM blocked_dates 
        WHERE blocked_date = ?
      `;
      const blockedResult = await this.query(blockedQuery, [sanitizedData.appointmentDate], 'blocked-check');
      
      if (blockedResult.length > 0) {
        throw new Error('Selected date is not available for booking');
      }
      
      // Insert the appointment
      const insertQuery = `
        INSERT INTO appointments (
          full_name, 
          email, 
          phone, 
          service_id, 
          appointment_date, 
          start_time, 
          end_time, 
          additional_notes,
          status,
          created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'confirmed', NOW())
      `;
      
      const params = [
        sanitizedData.fullName,
        sanitizedData.email,
        sanitizedData.phone,
        sanitizedData.serviceId,
        sanitizedData.appointmentDate,
        sanitizedData.startTime,
        endTime,
        sanitizedData.additionalNotes
      ];
      
      const result = await this.query(insertQuery, params, 'appointment-insert');
      
      return result.insertId;
    } catch (error) {
      console.error('Error creating appointment:', error.message);
      throw error;
    }
  },
  
  /**
   * Get available time slots with security validation
   */
  async getAvailableTimeSlots(date, serviceId) {
    try {
      // Input validation
      const dateRegex = /^\d{4}-\d{2}-\d{2}$/;
      if (!dateRegex.test(date)) {
        throw new Error('Invalid date format');
      }

      const serviceIdRegex = /^[a-zA-Z0-9_-]+$/;
      if (!serviceIdRegex.test(serviceId)) {
        throw new Error('Invalid service ID format');
      }

      // Sanitize inputs
      const sanitizedDate = this.sanitizeInput(date);
      const sanitizedServiceId = this.sanitizeInput(serviceId);

      // Check if the date is blocked
      const blockedQuery = `
        SELECT 1 FROM blocked_dates WHERE blocked_date = ?
      `;
      const blockedResult = await this.query(blockedQuery, [sanitizedDate], 'blocked-date-check');
      
      if (blockedResult.length > 0) {
        return [];
      }
      
      // Get the day of week
      const parsedDate = new Date(sanitizedDate);
      const dayNames = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
      const dayOfWeek = dayNames[parsedDate.getDay()];
      
      // Check if the clinic is open on this day
      const businessHoursQuery = `
        SELECT is_open, open_time, close_time 
        FROM business_hours 
        WHERE day_of_week = ?
      `;
      const [businessHours] = await this.query(businessHoursQuery, [dayOfWeek], 'business-hours-check');
      
      if (!businessHours || !businessHours.is_open) {
        return [];
      }
      
      // Get the service duration
      const serviceQuery = `
        SELECT duration_minutes FROM services WHERE service_id = ? AND is_active = TRUE
      `;
      const [service] = await this.query(serviceQuery, [sanitizedServiceId], 'service-duration-check');
      
      if (!service) {
        throw new Error('Service not found or inactive');
      }
      
      const serviceDuration = service.duration_minutes;
      
      // Get existing appointments for the date
      const appointmentsQuery = `
        SELECT start_time, end_time 
        FROM appointments 
        WHERE appointment_date = ? AND status != 'cancelled'
      `;
      const bookedSlots = await this.query(appointmentsQuery, [sanitizedDate], 'appointments-check');
      
      // Generate available time slots (rest of the logic remains the same)
      const availableSlots = [];
      
      // Parse business hours
      const openTime = businessHours.open_time.split(':');
      const closeTime = businessHours.close_time.split(':');
      
      const openMinutes = parseInt(openTime[0]) * 60 + parseInt(openTime[1]);
      const closeMinutes = parseInt(closeTime[0]) * 60 + parseInt(closeTime[1]);
      
      // Generate slots at 30-minute intervals
      for (let minutes = openMinutes; minutes < closeMinutes; minutes += 30) {
        const hour = Math.floor(minutes / 60);
        const minute = minutes % 60;
        
        const timeSlot = `${hour.toString().padStart(2, '0')}:${minute.toString().padStart(2, '0')}:00`;
        
        // Calculate end time for this slot
        const endMinutes = minutes + serviceDuration;
        const endHour = Math.floor(endMinutes / 60);
        const endMinute = endMinutes % 60;
        
        const endTimeSlot = `${endHour.toString().padStart(2, '0')}:${endMinute.toString().padStart(2, '0')}:00`;
        
        // Skip if this would go beyond closing time
        if (endMinutes > closeMinutes) {
          continue;
        }
        
        // Check if this time slot overlaps with any booked appointment
        let isOverlapping = false;
        
        for (const booking of bookedSlots) {
          const bookingStart = booking.start_time;
          const bookingEnd = booking.end_time;
          
          // Check if the proposed slot overlaps with an existing booking
          if ((timeSlot < bookingEnd) && (endTimeSlot > bookingStart)) {
            isOverlapping = true;
            break;
          }
        }
        
        // Calculate buffer time if needed
        const bufferMinutes = serviceDuration % 30 === 0 ? 0 : 30 - (serviceDuration % 30);
        
        // Check if there's enough buffer after this appointment ends
        let hasProperBuffer = true;
        
        if (bufferMinutes > 0 && !isOverlapping) {
          const bufferEndMinutes = endMinutes + bufferMinutes;
          const bufferEndHour = Math.floor(bufferEndMinutes / 60);
          const bufferEndMinute = bufferEndMinutes % 60;
          const bufferEndTimeSlot = `${bufferEndHour.toString().padStart(2, '0')}:${bufferEndMinute.toString().padStart(2, '0')}:00`;
          
          for (const booking of bookedSlots) {
            const bookingStart = booking.start_time;
            if (bufferEndTimeSlot > bookingStart && endTimeSlot <= bookingStart) {
              hasProperBuffer = false;
              break;
            }
          }
        }
        
        if (!isOverlapping && hasProperBuffer) {
          availableSlots.push(timeSlot);
        }
      }
      
      return availableSlots;
    } catch (error) {
      console.error('Error getting available time slots:', error.message);
      throw error;
    }
  },

  // Enhanced date formatting with validation
  formatDateForDb(date) {
    if (!date) return null;
    
    if (date instanceof Date) {
      const formatted = date.toISOString().split('T')[0];
      if (!/^\d{4}-\d{2}-\d{2}$/.test(formatted)) {
        throw new Error('Invalid date format after conversion');
      }
      return formatted;
    }
    
    // If it's already in YYYY-MM-DD format, validate and return
    if (/^\d{4}-\d{2}-\d{2}$/.test(date)) {
      const parsedDate = new Date(date);
      if (isNaN(parsedDate.getTime())) {
        throw new Error('Invalid date value');
      }
      return date;
    }
    
    // Try to parse the date and format it
    try {
      const parsedDate = new Date(date);
      if (isNaN(parsedDate.getTime())) {
        throw new Error('Invalid date value');
      }
      const formatted = parsedDate.toISOString().split('T')[0];
      if (!/^\d{4}-\d{2}-\d{2}$/.test(formatted)) {
        throw new Error('Invalid date format after parsing');
      }
      return formatted;
    } catch (error) {
      console.error('Error formatting date:', error.message);
      throw new Error('Unable to format date');
    }
  }
};

module.exports = db;
