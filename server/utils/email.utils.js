// enhanced-email.utils.js
// It provides better logging, validation, and error handling

const nodemailer = require('nodemailer');
require('dotenv').config();

// Set to true for detailed logging, false for production use
const DEBUG_MODE = process.env.NODE_ENV !== 'production';

/**
 * Create and configure nodemailer transporter with detailed error checks
 * @returns {object} Nodemailer transporter
 */
function createTransporter() {
  const requiredVars = ['EMAIL_HOST', 'EMAIL_PORT', 'EMAIL_USER', 'EMAIL_PASS'];
  const missingVars = requiredVars.filter(name => !process.env[name]);

  if (missingVars.length) {
    console.error('❌ Missing required env variables:', missingVars.join(', '));
    throw new Error(`Missing email configuration: ${missingVars.join(', ')}`);
  }

  if (DEBUG_MODE) {
    console.log('\n📧 Email Config Loaded:');
    console.log(`- Host: ${process.env.EMAIL_HOST}`);
    console.log(`- Port: ${process.env.EMAIL_PORT}`);
    console.log(`- User: ${process.env.EMAIL_USER}`);
    console.log(`- Secure: ${process.env.EMAIL_SECURE === 'true'}`);
  }

  const transporterConfig = {
    host: process.env.EMAIL_HOST,
    port: parseInt(process.env.EMAIL_PORT) || 587,
    secure: process.env.EMAIL_SECURE === 'true',
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
    },
    // Settings for more reliable connections
    connectionTimeout: 10000, // 10 seconds
    greetingTimeout: 10000,   // 10 seconds
    socketTimeout: 15000      // 15 seconds
  };

  // Enable detailed logging in non-production environments
  if (DEBUG_MODE) {
    transporterConfig.logger = true;
    transporterConfig.debug = true;
  }

  return nodemailer.createTransport(transporterConfig);
}

/**
 * Format a YYYY-MM-DD date into readable format
 * @param {string} dateStr 
 * @returns {string}
 */
function formatDateForDisplay(dateStr) {
  try {
    if (!dateStr || typeof dateStr !== 'string') {
      console.warn('⚠️ Invalid date provided to formatDateForDisplay:', dateStr);
      return 'Invalid Date';
    }
    
    const [year, month, day] = dateStr.split('-').map(Number);
    const date = new Date(year, month - 1, day);

    if (isNaN(date)) {
      console.warn('⚠️ Date parsing failed in formatDateForDisplay:', dateStr);
      return 'Invalid Date';
    }

    return date.toLocaleDateString('en-US', {
      weekday: 'long',
      year: 'numeric',
      month: 'long',
      day: 'numeric',
    });
  } catch (error) {
    console.error('⚠️ Error formatting date:', dateStr, error);
    return 'Invalid Date';
  }
}

/**
 * Format time from 24-hour (HH:MM:SS) to 12-hour AM/PM format
 * @param {string} timeStr 
 * @returns {string}
 */
function formatTimeFor12Hour(timeStr) {
  try {
    if (!timeStr || typeof timeStr !== 'string') {
      console.warn('⚠️ Invalid time provided to formatTimeFor12Hour:', timeStr);
      return 'Invalid Time';
    }
    
    // Handle both HH:MM:SS and HH:MM formats
    const timeParts = timeStr.split(':');
    const hours = parseInt(timeParts[0], 10);
    const minutes = parseInt(timeParts[1], 10);
    
    if (isNaN(hours) || isNaN(minutes)) {
      console.warn('⚠️ Time parsing failed in formatTimeFor12Hour:', timeStr);
      return 'Invalid Time';
    }

    const period = hours >= 12 ? 'PM' : 'AM';
    const hour12 = hours % 12 || 12;
    return `${hour12}:${String(minutes).padStart(2, '0')} ${period}`;
  } catch (error) {
    console.error('⚠️ Error formatting time:', timeStr, error);
    return 'Invalid Time';
  }
}

/**
 * Verify transporter connection (useful for diagnostics)
 * @returns {Promise<boolean>} Connection status
 */
async function verifyConnection() {
  try {
    const transporter = createTransporter();
    await transporter.verify();
    console.log('✅ SMTP connection verified successfully');
    return true;
  } catch (error) {
    console.error('❌ SMTP connection verification failed:', error.message);
    throw error;
  }
}

/**
 * Send booking confirmation email with structured formatting and diagnostics
 * @param {object} bookingData - Includes email, fullName, appointmentDate, startTime, serviceName
 * @returns {Promise<object>} Email send response
 */
async function sendBookingConfirmation(bookingData) {
  if (!bookingData || typeof bookingData !== 'object') {
    throw new Error('❌ Booking data is missing or invalid');
  }

  if (DEBUG_MODE) {
    console.log('📧 Booking data received for email:', JSON.stringify(bookingData, null, 2));
  }

  const requiredFields = ['email', 'fullName', 'appointmentDate', 'startTime', 'serviceName'];
  const missingFields = requiredFields.filter(field => !bookingData[field]);

  if (missingFields.length) {
    const msg = `❌ Missing fields in booking data: ${missingFields.join(', ')}`;
    console.error(msg);
    throw new Error(msg);
  }

  try {
    // Validate email format
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(bookingData.email)) {
      throw new Error(`Invalid email address: ${bookingData.email}`);
    }

    // Format date and time with fallbacks
    const displayDate = formatDateForDisplay(bookingData.appointmentDate) || bookingData.appointmentDate;
    const displayTime = formatTimeFor12Hour(bookingData.startTime) || bookingData.startTime;

    // Create transporter
    const transporter = createTransporter();

    // Define mail content
    const mailOptions = {
      from: `"Dental Clinic" <${process.env.EMAIL_USER}>`,
      to: bookingData.email,
      subject: 'Your Appointment Confirmation',
      text: `
APPOINTMENT CONFIRMATION

Hello ${bookingData.fullName},

Your appointment is confirmed.

Service: ${bookingData.serviceName}
Date: ${displayDate}
Time: ${displayTime}

If you need to reschedule, contact us at least 24 hours in advance.

- Dental Clinic
(This is an automated message)
      `.trim(),
      html: `
        <div style="font-family: Arial; padding: 20px; max-width: 600px; border: 1px solid #ddd; border-radius: 6px;">
          <h2 style="color: #4a90e2;">Appointment Confirmation</h2>
          <p>Hello <strong>${bookingData.fullName}</strong>,</p>
          <p>Your appointment is confirmed. Please find the details below:</p>
          <div style="background-color: #f7f7f7; padding: 15px; border-radius: 5px;">
            <p><strong>Service:</strong> ${bookingData.serviceName}</p>
            <p><strong>Date:</strong> ${displayDate}</p>
            <p><strong>Time:</strong> ${displayTime}</p>
          </div>
          <p style="margin-top: 20px;">For changes, contact us 24 hours in advance.</p>
          <p>Thank you for choosing our dental clinic!</p>
          <p style="font-size: 12px; color: #888; border-top: 1px solid #eee; margin-top: 30px; padding-top: 10px;">This is an automated message. Please do not reply.</p>
        </div>
      `,
    };

    if (DEBUG_MODE) {
      console.log('✉️ Sending email to:', mailOptions.to);
    }

    // Try to send the email with retry mechanism
    let retries = 2;
    let lastError = null;
    
    while (retries >= 0) {
      try {
        const info = await transporter.sendMail(mailOptions);
        console.log('✅ Email sent successfully! Message ID:', info.messageId);
        return info;
      } catch (error) {
        lastError = error;
        if (retries > 0) {
          console.log(`⚠️ Email send attempt failed, retrying... (${retries} attempts left)`);
          retries--;
          // Wait 1 second before retrying
          await new Promise(resolve => setTimeout(resolve, 1000));
        } else {
          break;
        }
      }
    }
    
    // If we got here, all retries failed
    console.error('❌ Failed to send email after all retries:', lastError.message);
    
    // Provide meaningful error messages based on error code
    if (lastError.code === 'EAUTH') {
      console.error('🔑 Auth error: Check EMAIL_USER and EMAIL_PASS or App Password for Gmail');
    } else if (lastError.code === 'ESOCKET') {
      console.error('🔌 Socket error: Check EMAIL_HOST and EMAIL_PORT connectivity');
    } else if (lastError.code === 'ETIMEDOUT') {
      console.error('⏱️ Timeout: Network issue or firewall blocking');
    }

    throw lastError;
  } catch (error) {
    console.error('❌ Email sending process failed:', error.message);
    throw error;
  }
}

module.exports = {
  sendBookingConfirmation,
  createTransporter,
  formatDateForDisplay,
  formatTimeFor12Hour,
  verifyConnection,
};