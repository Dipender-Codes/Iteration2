const mysql = require('mysql2/promise');
require('dotenv').config();

// Create a connection pool
const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || 'dpandey13',
  database: process.env.DB_NAME || 'dental_clinic_booking',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// Database utility functions
const db = {
  // Test the database connection
  async testConnection() {
    try {
      const connection = await pool.getConnection();
      console.log('Database connection established successfully');
      connection.release();
      return true;
    } catch (error) {
      console.error('Database connection failed:', error);
      return false;
    }
  },

  // Execute a query with parameters
  async query(sql, params = []) {
    try {
      const [results] = await pool.execute(sql, params);
      return results;
    } catch (error) {
      console.error('Database query error:', error);
      throw error;
    }
  },

  
  // === Booking Functions (Incorporated from booking.model.js) ===

  /**
   * Create a new appointment with end time calculated based on service duration
   * @param {Object} bookingData - Contains appointment details
   * @returns {Promise<number>} - Returns the appointment ID
   */
  async createAppointment(bookingData) {
    try {
      // Get service duration
      const serviceQuery = `
        SELECT duration_minutes 
        FROM services 
        WHERE service_id = ? AND is_active = TRUE
      `;
      const [service] = await this.query(serviceQuery, [bookingData.serviceId]);
      
      if (!service) {
        throw new Error('Invalid or inactive service');
      }
      
      const serviceDuration = service.duration_minutes;
      
      // Calculate end time based on start time and duration
      const startTime = bookingData.startTime;
      const [hours, minutes, seconds] = startTime.split(':').map(Number);
      
      // Convert to minutes for easier calculation
      const startMinutes = hours * 60 + minutes;
      const endMinutes = startMinutes + serviceDuration;
      
      // Convert back to time format
      const endHours = Math.floor(endMinutes / 60);
      const endMins = endMinutes % 60;
      const endTime = `${endHours.toString().padStart(2, '0')}:${endMins.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
      
      // First, check if the time slot is available
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
        bookingData.appointmentDate,
        endTime, bookingData.startTime,
        endTime, bookingData.startTime,
        bookingData.startTime, endTime
      ];
      
      const existingAppointments = await this.query(availabilityQuery, availabilityParams);
      
      if (existingAppointments.length > 0) {
        throw new Error('Selected time slot is already booked');
      }
      
      // Check if the date is blocked
      const blockedQuery = `
        SELECT 1 FROM blocked_dates 
        WHERE blocked_date = ?
      `;
      const blockedResult = await this.query(blockedQuery, [bookingData.appointmentDate]);
      
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
        bookingData.fullName,
        bookingData.email,
        bookingData.phone,
        bookingData.serviceId,
        bookingData.appointmentDate,
        bookingData.startTime,
        endTime,
        bookingData.additionalNotes
      ];
      
      const result = await this.query(insertQuery, params);
      
      // Return the appointment ID
      return result.insertId;
    } catch (error) {
      console.error('Error creating appointment:', error);
      throw error;
    }
  },
  
  /**
   * Get available time slots based on service duration
   * @param {string} date - Date string in YYYY-MM-DD format
   * @param {string} serviceId - Service ID
   * @returns {Promise<Array>} - Available time slots
   */
  async getAvailableTimeSlots(date, serviceId) {
    try {
      // Check if the date is blocked
      const blockedQuery = `
        SELECT 1 FROM blocked_dates WHERE blocked_date = ?
      `;
      const blockedResult = await this.query(blockedQuery, [date]);
      
      if (blockedResult.length > 0) {
        return [];
      }
      
      // Get the day of week
      const parsedDate = new Date(date);
      const dayNames = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
      const dayOfWeek = dayNames[parsedDate.getDay()];
      
      // Check if the clinic is open on this day
      const businessHoursQuery = `
        SELECT is_open, open_time, close_time 
        FROM business_hours 
        WHERE day_of_week = ?
      `;
      const [businessHours] = await this.query(businessHoursQuery, [dayOfWeek]);
      
      if (!businessHours || !businessHours.is_open) {
        return [];
      }
      
      // Get the service duration
      const serviceQuery = `
        SELECT duration_minutes FROM services WHERE service_id = ? AND is_active = TRUE
      `;
      const [service] = await this.query(serviceQuery, [serviceId]);
      
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
      const bookedSlots = await this.query(appointmentsQuery, [date]);
      
      // Generate available time slots
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
        // If service duration is not a multiple of 30, add buffer time
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
      console.error('Error getting available time slots:', error);
      throw error;
    }
  },

  // Utility function for formatting dates (referenced in booking.model.js)
  formatDateForDb(date) {
    if (!date) return null;
    
    if (date instanceof Date) {
      return date.toISOString().split('T')[0];
    }
    
    // If it's already in YYYY-MM-DD format, return as is
    if (/^\d{4}-\d{2}-\d{2}$/.test(date)) {
      return date;
    }
    
    // Try to parse the date and format it
    try {
      const parsedDate = new Date(date);
      return parsedDate.toISOString().split('T')[0];
    } catch (error) {
      console.error('Error formatting date:', error);
      return null;
    }
  }

  
};

module.exports = db;