// booking.controller.fixed.js
// This is a fixed version of your booking controller with corrections for email sending

const BookingModel = require('../models/db');
const ServicesModel = require('../models/db');
const { body, validationResult } = require('express-validator');
const xss = require('xss');
const { formatTimeString } = require('../utils/date.utils');
const { sendBookingConfirmation } = require('../utils/email.utils'); // Path verification needed

// Validation middleware for booking appointments
const validateAppointment = [
  body('service').trim().isAlphanumeric().withMessage('Invalid service ID'),
  body('date').isDate().withMessage('Invalid date format'),
  body('time').matches(/^([01]\d|2[0-3]):([0-5]\d):([0-5]\d)$/).withMessage('Invalid time format'),
  body('name').trim().isLength({ min: 2, max: 100 }).withMessage('Name must be between 2 and 100 characters'),
  body('email')
    .trim()
    .isEmail().withMessage('Invalid email address format')
    .normalizeEmail(),
  body('phone')
    .trim()
    .custom(value => {
      const cleanPhone = value.replace(/[\s()-]/g, '');
      const mobileRegex = /^04\d{8}$/;
      const landlineRegex = /^0[2378]\d{8}$/;

      if (!mobileRegex.test(cleanPhone) && !landlineRegex.test(cleanPhone)) {
        throw new Error('Must be a valid Australian phone number (10 digits)');
      }

      return true;
    }),
  body('notes').optional().trim().isLength({ max: 500 }).withMessage('Notes cannot exceed 500 characters')
];

class BookingController {
  /**
   * FIXED: Handles appointment creation with improved error handling
   * and clearer email preparation logic.
   */
  static async createAppointment(req, res) {
    try {
      // Log incoming request for debugging
      console.log('📩 Raw request body:', JSON.stringify(req.body, null, 2));
      
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          message: 'Validation failed',
          errors: errors.array()
        });
      }

      const { service, date, time, name, email, phone, notes } = req.body;

      console.log('📅 Booking request received:');
      console.log('- Date:', date);
      console.log('- Time:', time);
      console.log('- Service:', service);
      console.log('- Name:', name);
      console.log('- Email:', email);

      // Sanitize input
      const sanitizedNotes = notes ? xss(notes) : null;
      const sanitizedName = xss(name);
      
      // FIXED: Ensure time is consistently in HH:MM:SS format
      let formattedTime = time;
      if (time && !time.includes(':')) {
        formattedTime = formatTimeString(time);
      } else if (time && time.split(':').length === 2) {
        // Add seconds if only hours and minutes are provided
        formattedTime = `${time}:00`;
      }
      
      const formattedPhone = phone.replace(/[\s()\-]/g, '');

      // Confirm service exists
      const serviceDetails = await ServicesModel.getServiceById(service);
      if (!serviceDetails) {
        console.error('❌ Invalid service selected:', service);
        return res.status(400).json({ message: 'Invalid service selected' });
      }
      console.log('✅ Service confirmed:', serviceDetails.name);

      // FIXED: Structure booking data with consistent field names
      // Include both naming conventions for maximum compatibility
      const bookingData = {
        fullName: sanitizedName,
        name: sanitizedName,
        email: email.toLowerCase(),
        phone: formattedPhone,
        serviceId: service,
        appointmentDate: date,    // YYYY-MM-DD format
        date: date,
        startTime: formattedTime, // HH:MM:SS format
        time: formattedTime,
        additionalNotes: sanitizedNotes
      };

      // Create booking in database
      const appointmentId = await BookingModel.createAppointment(bookingData);
      console.log('✅ Appointment created with ID:', appointmentId);

      // Attempt to send confirmation email
      let emailSent = false;
      let emailError = null;

      try {
        console.log('\n📤 PREPARING EMAIL DATA');
        
        // FIXED: Prepare email data with improved error handling
        const emailData = this.prepareEmailData(bookingData, serviceDetails);

        if (!emailData) {
          throw new Error('Failed to prepare email data - missing required information');
        }

        // Double-check data format before sending
        console.log('\n📧 FINAL EMAIL DATA CHECK:');
        console.log('- fullName:', emailData.fullName);
        console.log('- email:', emailData.email);
        console.log('- appointmentDate:', emailData.appointmentDate);
        console.log('- startTime:', emailData.startTime);
        console.log('- serviceName:', emailData.serviceName);

        // FIXED: Send email with improved error handling and clearer logging
        console.log('\n📧 SENDING APPOINTMENT CONFIRMATION EMAIL');
        console.log('----------------------------------------');
        
        // Send the email with timeout handling
        const emailSendPromise = sendBookingConfirmation(emailData);
        
        // Create a timeout promise
        const timeoutPromise = new Promise((_, reject) => 
          setTimeout(() => reject(new Error('Email send timeout after 20 seconds')), 20000)
        );
        
        // Race between email sending and timeout
        const emailResult = await Promise.race([emailSendPromise, timeoutPromise]);
        
        console.log('✅ Confirmation email sent successfully!');
        console.log('Message ID:', emailResult.messageId);
        emailSent = true;
      } catch (err) {
        emailError = err;
        console.error('❌ EMAIL SENDING FAILED:');
        console.error('Error Code:', err.code || 'N/A');
        console.error('Error Message:', err.message);
        
        // Enhanced debugging for email errors
        if (err.code === 'EAUTH') {
          console.error('🔑 Authentication error - check EMAIL_USER and EMAIL_PASS env variables');
        } else if (err.code === 'ESOCKET') {
          console.error('🔌 Connection error - check EMAIL_HOST and EMAIL_PORT env variables');
        } else if (err.message?.includes('Missing fields')) {
          console.error('📄 Field error - check field names in prepareEmailData and email.utils.js');
          console.error('Required: fullName, email, appointmentDate, startTime, serviceName');
        }
      }

      // Log final email status
      if (emailSent) {
        console.log('📧 Email confirmation successfully sent to customer');
      } else {
        console.log('⚠️ Email confirmation could not be sent. The booking was created successfully.');
      }

      // Final response to client (includes email status)
      res.status(201).json({
        message: 'Appointment booked successfully',
        appointmentId,
        service: serviceDetails.name,
        appointmentDate: date,
        emailConfirmationSent: emailSent,
        emailError: emailSent ? null : (process.env.NODE_ENV === 'production' ? 'Email sending failed' : emailError?.message)
      });

    } catch (dbError) {
      console.error('❌ Database operation error:', dbError);

      if (dbError.message?.includes('time slot is already booked')) {
        return res.status(409).json({ message: 'Selected time slot is no longer available' });
      }

      if (dbError.message?.includes('date is not available')) {
        return res.status(400).json({ message: 'Selected date is not available for booking' });
      }

      res.status(500).json({
        message: 'Unable to book appointment',
        error: process.env.NODE_ENV === 'production' ? 'Server error' : dbError.message
      });
    }
  }

  /**
   * Retrieves available time slots for a specific service and date.
   */
  static async getAvailableTimeSlots(req, res) {
    try {
      const { date, serviceId } = req.query;

      console.log('Date received in getAvailableTimeSlots:', date);

      // Input validation
      if (!date || !date.match(/^\d{4}-\d{2}-\d{2}$/)) {
        return res.status(400).json({ message: 'Invalid date format. Use YYYY-MM-DD.' });
      }

      if (!serviceId || !serviceId.match(/^[a-zA-Z0-9-_]+$/)) {
        return res.status(400).json({ message: 'Invalid service ID format' });
      }

      const serviceDetails = await ServicesModel.getServiceById(serviceId);
      if (!serviceDetails) {
        return res.status(400).json({ message: 'Invalid service selected' });
      }

      const availableSlots = await BookingModel.getAvailableTimeSlots(date, serviceId);

      res.json({
        availableSlots,
        serviceDuration: serviceDetails.duration_minutes,
        requestedDate: date
      });
    } catch (error) {
      console.error('Error fetching time slots:', error);
      res.status(500).json({
        message: 'Unable to fetch available time slots',
        error: process.env.NODE_ENV === 'production' ? 'Server error' : error.message
      });
    }
  }

    /**
   * FIXED: Prepares the email content based on booking and service information.
   * Ensures field names exactly match what email.utils.js expects.
   */
    static prepareEmailData(bookingData, serviceDetails) {
      if (!bookingData || !serviceDetails) {
        console.error('❌ Missing booking data or service details for email', { 
          hasBookingData: !!bookingData, 
          hasServiceDetails: !!serviceDetails 
        });
        return null;
      }
  
      // Log raw data for debugging
      console.log('🔍 Raw booking data received:', JSON.stringify(bookingData, null, 2));
      console.log('🔍 Raw service details received:', JSON.stringify(serviceDetails, null, 2));
  
      // FIXED: Create email data with EXACT field names expected by sendBookingConfirmation
      // Make sure the field names match EXACTLY with what's in email.utils.js
      const emailData = {
        fullName: bookingData.fullName || bookingData.name || 'Patient',
        email: bookingData.email ? bookingData.email.toLowerCase() : '',
        appointmentDate: bookingData.appointmentDate || bookingData.date,
        startTime: bookingData.startTime || bookingData.time,
        serviceName: serviceDetails.name || 'Dental Service' 
      };
  
      // Validate required email fields - All must be present and non-empty
      const missingFields = [];
      if (!emailData.email || emailData.email === '') missingFields.push('email');
      if (!emailData.appointmentDate) missingFields.push('appointmentDate');
      if (!emailData.startTime) missingFields.push('startTime');
      if (!emailData.fullName) missingFields.push('fullName');
      if (!emailData.serviceName) missingFields.push('serviceName');
  
      if (missingFields.length > 0) {
        console.error('❌ Missing required fields for email:', missingFields.join(', '));
        console.error('Current email data:', emailData);
        return null;
      }
  
      // Format validation - ensure date is YYYY-MM-DD and time is HH:MM:SS
      if (!/^\d{4}-\d{2}-\d{2}$/.test(emailData.appointmentDate)) {
        console.error('❌ Invalid date format:', emailData.appointmentDate);
        return null;
      }
  
      if (!/^([01]\d|2[0-3]):([0-5]\d):([0-5]\d)$/.test(emailData.startTime)) {
        // Try to fix the time format if it's missing seconds
        if (/^([01]\d|2[0-3]):([0-5]\d)$/.test(emailData.startTime)) {
          emailData.startTime = `${emailData.startTime}:00`;
        } else {
          console.error('❌ Invalid time format and couldn\'t fix:', emailData.startTime);
          return null;
        }
      }
  
      console.log('📧 Email data prepared successfully:', JSON.stringify(emailData, null, 2));
      return emailData;
    }
}
module.exports = {
  BookingController,
  validateAppointment
};