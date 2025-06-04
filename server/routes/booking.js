// Enhanced secure booking.js route with fixed service ID validation
const express = require('express');
const router = express.Router();
const db = require('../models/db');
const { parseLocalDate } = require('../utils/date.utils');
const rateLimit = require('express-rate-limit');
const validator = require('validator');
const crypto = require('crypto');

// Additional rate limiting for booking endpoints
const bookingLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // Limit each IP to 10 booking attempts per 15 minutes
  message: {
    error: 'Too many booking attempts from this IP. Please try again later.'
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// More restrictive rate limiting for slot checking
const slotCheckLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 30, // Allow frequent slot checking but with limits
  message: {
    error: 'Too many slot check requests. Please slow down.'
  }
});

// Input validation middleware
const validateInput = (req, res, next) => {
  const { body, query } = req;
  
  // Sanitize and validate all inputs
  for (const key in body) {
    if (typeof body[key] === 'string') {
      // Remove potential XSS attempts
      body[key] = validator.escape(body[key].trim());
      
      // Check for suspicious patterns
      if (containsSuspiciousPattern(body[key])) {
        console.warn(`Suspicious input detected from IP ${req.ip}: ${key} = ${body[key]}`);
        return res.status(400).json({
          error: true,
          message: 'Invalid input detected'
        });
      }
    }
  }
  
  for (const key in query) {
    if (typeof query[key] === 'string') {
      query[key] = validator.escape(query[key].trim());
      
      if (containsSuspiciousPattern(query[key])) {
        console.warn(`Suspicious query detected from IP ${req.ip}: ${key} = ${query[key]}`);
        return res.status(400).json({
          error: true,
          message: 'Invalid query parameter'
        });
      }
    }
  }
  
  next();
};

// Function to detect suspicious patterns
const containsSuspiciousPattern = (input) => {
  const suspiciousPatterns = [
    /(<script|<\/script|javascript:|vbscript:|onload=|onerror=)/i,
    /(union\s+select|select\s+\*|drop\s+table|insert\s+into|delete\s+from)/i,
    /(exec\s*\(|system\s*\(|eval\s*\(|setTimeout\s*\()/i,
    /(\.\.\/)|(\.\.\\)/g, // Path traversal
    /(proc\/|etc\/|bin\/|usr\/)/i, // System paths
    /(%00|%2e%2e|%252e)/i, // Encoded attacks
  ];
  
  return suspiciousPatterns.some(pattern => pattern.test(input));
};

// Enhanced SQL injection protection
const sanitizeForSQL = (value) => {
  if (typeof value !== 'string') return value;
  
  // Remove SQL comments and dangerous characters
  return value
    .replace(/--.*$/gm, '') // Remove SQL comments
    .replace(/\/\*.*?\*\//g, '') // Remove multi-line comments
    .replace(/[;\\]/g, ''); // Remove dangerous characters
};

// Input validation for dates
const validateDate = (dateString) => {
  if (!dateString || typeof dateString !== 'string') return false;
  
  // Check format
  if (!dateString.match(/^\d{4}-\d{2}-\d{2}$/)) return false;
  
  // Check if it's a valid date
  const date = new Date(dateString + 'T00:00:00');
  if (isNaN(date.getTime())) return false;
  
  // Check reasonable date range (not too far in past or future)
  const now = new Date();
  const minDate = new Date(now.getFullYear() - 1, 0, 1);
  const maxDate = new Date(now.getFullYear() + 2, 11, 31);
  
  return date >= minDate && date <= maxDate;
};

// Input validation for time
const validateTime = (timeString) => {
  if (!timeString || typeof timeString !== 'string') return false;
  
  // Check format HH:MM:SS
  const timePattern = /^([01]?[0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]$/;
  return timePattern.test(timeString);
};

// FIXED: Input validation for service ID - now handles alphanumeric IDs
const validateServiceId = (serviceId) => {
  if (!serviceId || typeof serviceId !== 'string') return false;
  
  // Allow alphanumeric service IDs like "CONS001", "SERVICE123", etc.
  // Must be 3-20 characters, can contain letters, numbers, and underscores
  const serviceIdPattern = /^[A-Za-z0-9_]{3,20}$/;
  return serviceIdPattern.test(serviceId);
};

// Request logging for security monitoring
const logSecurityEvent = (req, eventType, details = '') => {
  const timestamp = new Date().toISOString();
  const ip = req.ip || req.connection.remoteAddress;
  const userAgent = req.get('User-Agent') || 'Unknown';
  
  console.log(`[SECURITY] ${timestamp} - ${eventType} - IP: ${ip} - UserAgent: ${userAgent} - Details: ${details}`);
};

/**
 * GET /api/booking/available-slots
 * Returns available time slots for a given date and service
 */
router.get('/api/booking/available-slots', slotCheckLimiter, validateInput, async (req, res) => {
  try {
    const { date, serviceId } = req.query;
    
    // Enhanced validation
    if (!date || !serviceId) {
      logSecurityEvent(req, 'INVALID_SLOT_REQUEST', 'Missing required parameters');
      return res.status(400).json({ 
        error: true, 
        message: 'Date and service ID are required' 
      });
    }
    
    // Validate date format and range
    if (!validateDate(date)) {
      logSecurityEvent(req, 'INVALID_DATE_FORMAT', `Date: ${date}`);
      return res.status(400).json({
        error: true,
        message: 'Invalid date format or range'
      });
    }
    
    // Validate service ID
    if (!validateServiceId(serviceId)) {
      logSecurityEvent(req, 'INVALID_SERVICE_ID', `ServiceId: ${serviceId}`);
      return res.status(400).json({
        error: true,
        message: 'Invalid service ID'
      });
    }
    
    // Sanitize inputs
    const sanitizedDate = sanitizeForSQL(date);
    const sanitizedServiceId = sanitizeForSQL(serviceId); // Keep as string, don't parse as int
    
    // IMPORTANT: Use the date string directly without Date object conversion
    const formattedDate = sanitizedDate;
    
    // Log for debugging
    console.log('Using formatted date for available slots query:', formattedDate);
    console.log('Using service ID:', sanitizedServiceId);
    
    // Use parameterized queries to prevent SQL injection
    const blockedQuery = `
      SELECT 1 FROM blocked_dates WHERE blocked_date = ? LIMIT 1
    `;
    const blockedResult = await db.query(blockedQuery, [formattedDate]);
    
    if (blockedResult.length > 0) {
      return res.status(200).json({ 
        availableSlots: [],
        message: 'This date is not available for booking'
      });
    }
    
    // Get the day of week safely using parseLocalDate from utils
    const parsedDate = parseLocalDate(sanitizedDate);
    const dayNames = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
    const dayOfWeek = dayNames[parsedDate.getDay()];
    
    // Check if the office is open on this day with parameterized query
    const businessHoursQuery = `
      SELECT is_open, open_time, close_time 
      FROM business_hours 
      WHERE day_of_week = ? LIMIT 1
    `;
    
    const [businessHours] = await db.query(businessHoursQuery, [dayOfWeek]);
    
    if (!businessHours || !businessHours.is_open) {
      return res.status(200).json({ 
        availableSlots: [],
        message: 'The office is closed on this day'
      });
    }
    
    // Get service duration with parameterized query - use string comparison for service_id
    const serviceQuery = `
      SELECT duration_minutes FROM services WHERE service_id = ? AND is_active = TRUE LIMIT 1
    `;
    const [service] = await db.query(serviceQuery, [sanitizedServiceId]);
    
    if (!service) {
      logSecurityEvent(req, 'INVALID_SERVICE_ACCESS', `ServiceId: ${sanitizedServiceId}`);
      return res.status(404).json({ 
        error: true, 
        message: 'Service not found or inactive' 
      });
    }
    
    const serviceDuration = parseInt(service.duration_minutes) || 30;
    
    // Validate service duration is reasonable
    if (serviceDuration < 15 || serviceDuration > 480) { // 15 minutes to 8 hours
      logSecurityEvent(req, 'SUSPICIOUS_SERVICE_DURATION', `Duration: ${serviceDuration}`);
      return res.status(400).json({
        error: true,
        message: 'Invalid service configuration'
      });
    }
    
    // Get existing appointments for the date with parameterized query
    const appointmentsQuery = `
      SELECT start_time, end_time 
      FROM appointments 
      WHERE appointment_date = ? AND status != 'cancelled'
      ORDER BY start_time
    `;
    const bookedSlots = await db.query(appointmentsQuery, [formattedDate]);
    
    // Generate available time slots based on business hours and booked slots
    const availableSlots = [];
    
    // Parse business hours to minutes for easier calculation
    const openTime = businessHours.open_time.split(':');
    const closeTime = businessHours.close_time.split(':');
    
    const openMinutes = parseInt(openTime[0]) * 60 + parseInt(openTime[1]);
    const closeMinutes = parseInt(closeTime[0]) * 60 + parseInt(closeTime[1]);
    
    // Validate business hours are reasonable
    if (openMinutes < 0 || openMinutes > 1440 || closeMinutes < 0 || closeMinutes > 1440 || openMinutes >= closeMinutes) {
      logSecurityEvent(req, 'INVALID_BUSINESS_HOURS', `Open: ${openMinutes}, Close: ${closeMinutes}`);
      return res.status(500).json({
        error: true,
        message: 'Invalid business hours configuration'
      });
    }
    
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
      
      if (!isOverlapping) {
        availableSlots.push(timeSlot);
      }
    }
    
    return res.status(200).json({ 
      availableSlots,
      requestedDate: formattedDate
    });
  } catch (error) {
    logSecurityEvent(req, 'SLOT_QUERY_ERROR', error.message);
    console.error('Error fetching available slots:', error);
    return res.status(500).json({ 
      error: true, 
      message: 'Failed to fetch available time slots' 
    });
  }
});

/**
 * GET /api/booking/available-dates
 * Returns which dates of a month are available for booking
 */
router.get('/api/booking/available-dates', slotCheckLimiter, validateInput, async (req, res) => {
  try {
    const { year, month, serviceId } = req.query;
    
    if (!year || !month || !serviceId) {
      logSecurityEvent(req, 'INVALID_DATES_REQUEST', 'Missing required parameters');
      return res.status(400).json({ 
        error: true, 
        message: 'Year, month, and service ID are required' 
      });
    }
    
    // Enhanced validation
    const yearNum = parseInt(year);
    const monthNum = parseInt(month);
    
    if (isNaN(yearNum) || isNaN(monthNum) || 
        yearNum < 2020 || yearNum > 2030 || 
        monthNum < 1 || monthNum > 12) {
      logSecurityEvent(req, 'INVALID_DATE_RANGE', `Year: ${year}, Month: ${month}`);
      return res.status(400).json({
        error: true,
        message: 'Invalid year or month range'
      });
    }
    
    if (!validateServiceId(serviceId)) {
      logSecurityEvent(req, 'INVALID_SERVICE_ID', `ServiceId: ${serviceId}`);
      return res.status(400).json({
        error: true,
        message: 'Invalid service ID'
      });
    }
    
    const sanitizedServiceId = sanitizeForSQL(serviceId); // Keep as string
    const adjustedMonth = monthNum - 1; // JavaScript months are 0-indexed
    
    // Get service duration with parameterized query
    const serviceQuery = `
      SELECT duration_minutes FROM services WHERE service_id = ? AND is_active = TRUE LIMIT 1
    `;
    const [service] = await db.query(serviceQuery, [sanitizedServiceId]);
    
    if (!service) {
      logSecurityEvent(req, 'INVALID_SERVICE_ACCESS', `ServiceId: ${sanitizedServiceId}`);
      return res.status(404).json({ 
        error: true, 
        message: 'Service not found or inactive' 
      });
    }
    
    const serviceDuration = parseInt(service.duration_minutes) || 30;
    
    // Validate service duration
    if (serviceDuration < 15 || serviceDuration > 480) {
      logSecurityEvent(req, 'SUSPICIOUS_SERVICE_DURATION', `Duration: ${serviceDuration}`);
      return res.status(400).json({
        error: true,
        message: 'Invalid service configuration'
      });
    }
    
    // Get all days in the requested month
    const daysInMonth = new Date(yearNum, adjustedMonth + 1, 0).getDate();
    const blockedDates = {};
    
    // Get blocked dates with parameterized query
    const blockedQuery = `
      SELECT DATE_FORMAT(blocked_date, '%Y-%m-%d') as date_str
      FROM blocked_dates 
      WHERE YEAR(blocked_date) = ? AND MONTH(blocked_date) = ?
    `;
    const blockedResult = await db.query(blockedQuery, [yearNum, monthNum]);
    
    blockedResult.forEach(row => {
      blockedDates[row.date_str] = true;
    });
    
    // Get business hours
    const businessHoursQuery = `
      SELECT day_of_week, is_open, open_time, close_time 
      FROM business_hours
    `;
    const businessHoursResult = await db.query(businessHoursQuery);
    
    const businessHoursByDay = {};
    businessHoursResult.forEach(row => {
      businessHoursByDay[row.day_of_week] = {
        isOpen: row.is_open,
        openTime: row.open_time,
        closeTime: row.close_time
      };
    });
    
    // Get appointments for the month with parameterized query
    const appointmentsQuery = `
      SELECT 
        DATE_FORMAT(appointment_date, '%Y-%m-%d') as date_str,
        start_time, 
        end_time
      FROM appointments 
      WHERE 
        YEAR(appointment_date) = ? 
        AND MONTH(appointment_date) = ?
        AND status != 'cancelled'
      ORDER BY appointment_date, start_time
    `;
    const appointmentsResult = await db.query(appointmentsQuery, [yearNum, monthNum]);
    
    // Group appointments by date
    const appointmentsByDate = {};
    appointmentsResult.forEach(appointment => {
      if (!appointmentsByDate[appointment.date_str]) {
        appointmentsByDate[appointment.date_str] = [];
      }
      appointmentsByDate[appointment.date_str].push({
        startTime: appointment.start_time,
        endTime: appointment.end_time
      });
    });
    
    // Initialize result
    const availableDates = [];
    
    // Check each day of the month
    for (let day = 1; day <= daysInMonth; day++) {
      const date = new Date(yearNum, adjustedMonth, day);
      const dateStr = `${yearNum}-${monthNum.toString().padStart(2, '0')}-${day.toString().padStart(2, '0')}`;
      const dayName = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'][date.getDay()];
      
      // Skip if in the past, blocked, or clinic is closed
      const today = new Date();
      today.setHours(0, 0, 0, 0);
      
      if (date < today || blockedDates[dateStr] || !businessHoursByDay[dayName] || !businessHoursByDay[dayName].isOpen) {
        continue;
      }
      
      // Calculate if this date has any available slots
      const businessHours = businessHoursByDay[dayName];
      if (!businessHours.openTime || !businessHours.closeTime) {
        continue;
      }
      
      // Parse business hours
      const openTime = businessHours.openTime.split(':');
      const closeTime = businessHours.closeTime.split(':');
      
      const openMinutes = parseInt(openTime[0]) * 60 + parseInt(openTime[1]);
      const closeMinutes = parseInt(closeTime[0]) * 60 + parseInt(closeTime[1]);
      
      // Validate business hours
      if (openMinutes < 0 || openMinutes > 1440 || closeMinutes < 0 || closeMinutes > 1440 || openMinutes >= closeMinutes) {
        continue;
      }
      
      const dayAppointments = appointmentsByDate[dateStr] || [];
      
      // Check if any slot is available
      let hasAvailableSlot = false;
      
      for (let minutes = openMinutes; minutes < closeMinutes; minutes += 30) {
        const hour = Math.floor(minutes / 60);
        const minute = minutes % 60;
        
        const timeSlot = `${hour.toString().padStart(2, '0')}:${minute.toString().padStart(2, '0')}:00`;
        
        const endMinutes = minutes + serviceDuration;
        const endHour = Math.floor(endMinutes / 60);
        const endMinute = endMinutes % 60;
        
        const endTimeSlot = `${endHour.toString().padStart(2, '0')}:${endMinute.toString().padStart(2, '0')}:00`;
        
        if (endMinutes > closeMinutes) {
          continue;
        }
        
        let isOverlapping = false;
        
        for (const booking of dayAppointments) {
          const bookingStart = booking.startTime;
          const bookingEnd = booking.endTime;
          
          if ((timeSlot < bookingEnd) && (endTimeSlot > bookingStart)) {
            isOverlapping = true;
            break;
          }
        }
        
        if (!isOverlapping) {
          hasAvailableSlot = true;
          break;
        }
      }
      
      if (hasAvailableSlot) {
        availableDates.push(day);
      }
    }
    
    return res.status(200).json({ availableDates });
  } catch (error) {
    logSecurityEvent(req, 'DATES_QUERY_ERROR', error.message);
    console.error('Error fetching available dates:', error);
    return res.status(500).json({ 
      error: true, 
      message: 'Failed to fetch available dates' 
    });
  }
});

/**
 * POST /api/booking/create
 * Creates a new appointment booking
 */
router.post('/api/booking/create', bookingLimiter, validateInput, async (req, res) => {
  try {
    const { service: serviceId, date, time, name, email, phone, notes } = req.body;
    
    // Enhanced validation
    if (!serviceId || !date || !time || !name || !email || !phone) {
      logSecurityEvent(req, 'INCOMPLETE_BOOKING_REQUEST', 'Missing required fields');
      return res.status(400).json({ 
        error: true, 
        message: 'Missing required booking information' 
      });
    }
    
    // Validate date
    if (!validateDate(date)) {
      logSecurityEvent(req, 'INVALID_BOOKING_DATE', `Date: ${date}`);
      return res.status(400).json({ 
        error: true, 
        message: 'Invalid date format or range' 
      });
    }
    
    // Validate time
    if (!validateTime(time)) {
      logSecurityEvent(req, 'INVALID_BOOKING_TIME', `Time: ${time}`);
      return res.status(400).json({
        error: true,
        message: 'Invalid time format'
      });
    }
    
    // Validate service ID
    if (!validateServiceId(serviceId)) {
      logSecurityEvent(req, 'INVALID_BOOKING_SERVICE', `ServiceId: ${serviceId}`);
      return res.status(400).json({
        error: true,
        message: 'Invalid service ID'
      });
    }
    
    // Enhanced email validation
    if (!validator.isEmail(email) || email.length > 254) {
      logSecurityEvent(req, 'INVALID_EMAIL', `Email: ${email}`);
      return res.status(400).json({
        error: true,
        message: 'Invalid email address'
      });
    }
    
    // Enhanced phone validation
    const cleanPhone = phone.replace(/[^\d+\-\s()]/g, '');
    if (cleanPhone.length < 10 || cleanPhone.length > 20) {
      logSecurityEvent(req, 'INVALID_PHONE', `Phone: ${phone}`);
      return res.status(400).json({
        error: true,
        message: 'Invalid phone number'
      });
    }
    
    // Enhanced name validation
    if (name.length < 2 || name.length > 100 || !/^[a-zA-Z\s\-'\.]+$/.test(name)) {
      logSecurityEvent(req, 'INVALID_NAME', `Name: ${name}`);
      return res.status(400).json({
        error: true,
        message: 'Invalid name format'
      });
    }
    
    // Validate notes length
    if (notes && notes.length > 500) {
      logSecurityEvent(req, 'EXCESSIVE_NOTES_LENGTH', `Length: ${notes.length}`);
      return res.status(400).json({
        error: true,
        message: 'Notes too long'
      });
    }
    
    // Sanitize inputs
    const formattedDate = sanitizeForSQL(date);
    const sanitizedTime = sanitizeForSQL(time);
    const sanitizedName = sanitizeForSQL(name);
    const sanitizedEmail = validator.normalizeEmail(email);
    const sanitizedPhone = sanitizeForSQL(cleanPhone);
    const sanitizedNotes = notes ? sanitizeForSQL(notes) : '';
    const sanitizedServiceId = sanitizeForSQL(serviceId); // Keep as string
    
    // Additional security check: Prevent booking too far in advance
    const bookingDate = new Date(formattedDate);
    const maxAdvanceBooking = new Date();
    maxAdvanceBooking.setMonth(maxAdvanceBooking.getMonth() + 6); // 6 months max
    
    if (bookingDate > maxAdvanceBooking) {
      logSecurityEvent(req, 'EXCESSIVE_ADVANCE_BOOKING', `Date: ${formattedDate}`);
      return res.status(400).json({
        error: true,
        message: 'Cannot book more than 6 months in advance'
      });
    }
    
    // Log booking attempt
    console.log('Booking attempt:', {
      date: formattedDate,
      time: sanitizedTime,
      service: sanitizedServiceId,
      ip: req.ip
    });
    
    // Call the stored procedure with sanitized inputs
    const query = `CALL insert_appointment(?, ?, ?, ?, ?, ?, ?)`;
    
    const result = await db.query(query, [
      sanitizedName,
      sanitizedEmail,
      sanitizedPhone,
      sanitizedServiceId, // Pass as string, not integer
      formattedDate,
      sanitizedTime,
      sanitizedNotes
    ]);
    
    // Log successful booking
    logSecurityEvent(req, 'SUCCESSFUL_BOOKING', `AppointmentId: ${result[0][0].appointment_id}`);
    
    return res.status(201).json({ 
      success: true, 
      message: 'Appointment booked successfully',
      appointmentId: result[0][0].appointment_id,
      bookedDate: formattedDate
    });
  } catch (error) {
    logSecurityEvent(req, 'BOOKING_ERROR', error.message);
    console.error('Error creating booking:', error);
    
    // Enhanced error handling with security considerations
    if (error.message && error.message.includes('Selected time slot is already booked')) {
      return res.status(409).json({ 
        error: true, 
        message: 'This time slot is no longer available' 
      });
    } else if (error.message && error.message.includes('Selected date is not available')) {
      return res.status(409).json({ 
        error: true, 
        message: 'This date is not available for booking' 
      });
    } else if (error.message && error.message.includes('Invalid or inactive service')) {
      return res.status(400).json({ 
        error: true, 
        message: 'The selected service is invalid or no longer available' 
      });
    } else if (error.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({
        error: true,
        message: 'A booking conflict occurred. Please try again.'
      });
    }
    
    return res.status(500).json({ 
      error: true, 
      message: 'Failed to book appointment' 
    });
  }
});

/**
 * GET /api/booking/csrf-token
 * Returns a CSRF token for form submission
 */
router.get('/api/booking/csrf-token', (req, res) => {
  // Generate a cryptographically secure CSRF token
  const csrfToken = crypto.randomBytes(32).toString('hex');
  
  // In a real application, you would store this token in session
  // and validate it on form submission
  res.json({ csrfToken });
});

module.exports = router;