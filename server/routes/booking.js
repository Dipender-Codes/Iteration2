// Updated booking.js route to handle dates correctly without timezone issues
const express = require('express');
const router = express.Router();
const db = require('../models/db');
const { parseLocalDate } = require('../utils/date.utils');

/**
 * GET /api/booking/available-slots
 * Returns available time slots for a given date and service
 */
router.get('/api/booking/available-slots', async (req, res) => {
  try {
    const { date, serviceId } = req.query;
    
    if (!date || !serviceId) {
      return res.status(400).json({ 
        error: true, 
        message: 'Date and service ID are required' 
      });
    }
    
    // Validate date format (YYYY-MM-DD)
    if (!date.match(/^\d{4}-\d{2}-\d{2}$/)) {
      return res.status(400).json({
        error: true,
        message: 'Invalid date format. Use YYYY-MM-DD.'
      });
    }
    
    // IMPORTANT: Use the date string directly without Date object conversion
    // This avoids timezone issues
    const formattedDate = date;
    
    // Log for debugging
    console.log('Using formatted date for available slots query:', formattedDate);
    
    // Check if date is blocked
    const blockedQuery = `
      SELECT 1 FROM blocked_dates WHERE blocked_date = ?
    `;
    const blockedResult = await db.query(blockedQuery, [formattedDate]);
    
    if (blockedResult.length > 0) {
      return res.status(200).json({ 
        availableSlots: [],
        message: 'This date is not available for booking'
      });
    }
    
    // Get the day of week safely using parseLocalDate from utils
    const parsedDate = parseLocalDate(date);
    const dayNames = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
    const dayOfWeek = dayNames[parsedDate.getDay()];
    
    // Check if the office is open on this day
    const businessHoursQuery = `
      SELECT is_open, open_time, close_time 
      FROM business_hours 
      WHERE day_of_week = ?
    `;
    
    const [businessHours] = await db.query(businessHoursQuery, [dayOfWeek]);
    
    if (!businessHours || !businessHours.is_open) {
      return res.status(200).json({ 
        availableSlots: [],
        message: 'The office is closed on this day'
      });
    }
    
    // Get service duration
    const serviceQuery = `
      SELECT duration_minutes FROM services WHERE service_id = ? AND is_active = TRUE
    `;
    const [service] = await db.query(serviceQuery, [serviceId]);
    
    if (!service) {
      return res.status(404).json({ 
        error: true, 
        message: 'Service not found or inactive' 
      });
    }
    
    const serviceDuration = service.duration_minutes || 30; // Default to 30 minutes if not specified
    
    // Get existing appointments for the date
    const appointmentsQuery = `
      SELECT start_time, end_time 
      FROM appointments 
      WHERE appointment_date = ? AND status != 'cancelled'
    `;
    const bookedSlots = await db.query(appointmentsQuery, [formattedDate]);
    
    // Generate available time slots based on business hours and booked slots
    const availableSlots = [];
    
    // Parse business hours to minutes for easier calculation
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
      
      if (!isOverlapping) {
        availableSlots.push(timeSlot);
      }
    }
    
    return res.status(200).json({ 
      availableSlots,
      requestedDate: formattedDate // Return the requested date for debugging
    });
  } catch (error) {
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
router.get('/api/booking/available-dates', async (req, res) => {
  try {
    const { year, month, serviceId } = req.query;
    
    if (!year || !month || !serviceId) {
      return res.status(400).json({ 
        error: true, 
        message: 'Year, month, and service ID are required' 
      });
    }
    
    // Validate inputs
    const yearNum = parseInt(year);
    const monthNum = parseInt(month) - 1; // JavaScript months are 0-indexed
    
    if (isNaN(yearNum) || isNaN(monthNum) || monthNum < 0 || monthNum > 11) {
      return res.status(400).json({
        error: true,
        message: 'Invalid year or month'
      });
    }
    
    // Get service duration for availability calculation
    const serviceQuery = `
      SELECT duration_minutes FROM services WHERE service_id = ? AND is_active = TRUE
    `;
    const [service] = await db.query(serviceQuery, [serviceId]);
    
    if (!service) {
      return res.status(404).json({ 
        error: true, 
        message: 'Service not found or inactive' 
      });
    }
    
    const serviceDuration = service.duration_minutes || 30;
    
    // Get all days in the requested month
    const daysInMonth = new Date(yearNum, monthNum + 1, 0).getDate();
    const blockedDates = {};
    
    // Get all blocked dates for the month
    const blockedQuery = `
      SELECT DATE_FORMAT(blocked_date, '%Y-%m-%d') as date_str
      FROM blocked_dates 
      WHERE YEAR(blocked_date) = ? AND MONTH(blocked_date) = ?
    `;
    const blockedResult = await db.query(blockedQuery, [yearNum, monthNum + 1]);
    
    blockedResult.forEach(row => {
      blockedDates[row.date_str] = true;
    });
    
    // Get business hours for each day of week
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
    
    // Get all booked appointments for the month
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
    `;
    const appointmentsResult = await db.query(appointmentsQuery, [yearNum, monthNum + 1]);
    
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
    
    // Initialize result with all dates of the month
    const availableDates = [];
    
    // Check each day of the month
    for (let day = 1; day <= daysInMonth; day++) {
      const date = new Date(yearNum, monthNum, day);
      // Create YYYY-MM-DD string using local date components
      const dateStr = `${yearNum}-${(monthNum + 1).toString().padStart(2, '0')}-${day.toString().padStart(2, '0')}`;
      const dayName = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'][date.getDay()];
      
      // Skip if in the past, blocked, or clinic is closed
      const today = new Date();
      today.setHours(0, 0, 0, 0);
      
      if (date < today || blockedDates[dateStr] || !businessHoursByDay[dayName].isOpen) {
        continue;
      }
      
      // Calculate if this date has any available slots
      const businessHours = businessHoursByDay[dayName];
      if (!businessHours.openTime || !businessHours.closeTime) {
        continue;
      }
      
      // Parse business hours to minutes for easier calculation
      const openTime = businessHours.openTime.split(':');
      const closeTime = businessHours.closeTime.split(':');
      
      const openMinutes = parseInt(openTime[0]) * 60 + parseInt(openTime[1]);
      const closeMinutes = parseInt(closeTime[0]) * 60 + parseInt(closeTime[1]);
      
      // Get booked appointments for this date
      const dayAppointments = appointmentsByDate[dateStr] || [];
      
      // Check if any slot is available for this date
      let hasAvailableSlot = false;
      
      // Generate slots at 30-minute intervals and check if any is available
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
        
        for (const booking of dayAppointments) {
          const bookingStart = booking.startTime;
          const bookingEnd = booking.endTime;
          
          // Check if the proposed slot overlaps with an existing booking
          if ((timeSlot < bookingEnd) && (endTimeSlot > bookingStart)) {
            isOverlapping = true;
            break;
          }
        }
        
        if (!isOverlapping) {
          hasAvailableSlot = true;
          break; // We found at least one available slot
        }
      }
      
      if (hasAvailableSlot) {
        availableDates.push(day);
      }
    }
    
    return res.status(200).json({ availableDates });
  } catch (error) {
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
router.post('/api/booking/create', async (req, res) => {
  try {
    const { service: serviceId, date, time, name, email, phone, notes } = req.body;
    
    // Log received date for debugging
    console.log('Received date for booking:', date);
    
    // Validate required fields
    if (!serviceId || !date || !time || !name || !email || !phone) {
      return res.status(400).json({ 
        error: true, 
        message: 'Missing required booking information' 
      });
    }
    
    // Validate date format
    if (!date.match(/^\d{4}-\d{2}-\d{2}$/)) {
      return res.status(400).json({ 
        error: true, 
        message: 'Invalid date format. Use YYYY-MM-DD.' 
      });
    }
    
    // Use the date exactly as received, without any Date object creation
    const formattedDate = date;
    
    // Call the stored procedure to handle booking
    const query = `CALL insert_appointment(?, ?, ?, ?, ?, ?, ?)`;
    
    const result = await db.query(query, [
      name,          // p_full_name
      email,         // p_email
      phone,         // p_phone
      serviceId,     // p_service_id
      formattedDate, // p_appointment_date - use as is without conversion
      time,          // p_start_time
      notes || ''    // p_additional_notes
    ]);
    
    return res.status(201).json({ 
      success: true, 
      message: 'Appointment booked successfully',
      appointmentId: result[0][0].appointment_id,
      bookedDate: formattedDate // Return the booked date for confirmation
    });
  } catch (error) {
    console.error('Error creating booking:', error);
    
    // Check for specific error messages from the stored procedure
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
  // In a real application, you would generate a real CSRF token
  // For this example, we'll return a simple placeholder
  const csrfToken = Math.random().toString(36).substring(2, 15);
  res.json({ csrfToken });
});


module.exports = router;