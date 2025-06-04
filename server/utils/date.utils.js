/**
 * Convert time string from 12-hour format to 24-hour format
 * @param {string} timeStr - Time string in format "hh:mm" or "hh:mm AM/PM"
 * @param {string} [period] - Optional "AM" or "PM"
 * @returns {string} Time in 24-hour format "hh:mm:00"
 */
function formatTimeString(timeStr, period) {
  if (typeof timeStr !== 'string') return '00:00:00';

  // Check if period is already part of the time string
  if (!period && timeStr.includes(' ')) {
    const parts = timeStr.split(' ');
    timeStr = parts[0];
    period = parts[1];
  }

  let [hours, minutes] = timeStr.split(':').map(Number);

  if (isNaN(hours) || isNaN(minutes)) return '00:00:00';

  if (period === 'PM' && hours !== 12) {
    hours += 12;
  } else if (period === 'AM' && hours === 12) {
    hours = 0;
  }

  return `${hours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')}:00`;
}

/**
 * Convert time from 24-hour format to 12-hour format
 * @param {string} timeStr - Time string in 24-hour format "hh:mm:ss"
 * @returns {string} Time in 12-hour format "h:mm AM/PM"
 */
function formatTimeFor12Hour(timeStr) {
  if (typeof timeStr !== 'string' || !timeStr.includes(':')) return '';

  const [hours, minutes] = timeStr.split(':').map(Number);
  if (isNaN(hours) || isNaN(minutes)) return '';

  const period = hours >= 12 ? 'PM' : 'AM';
  const hour12 = hours % 12 || 12;

  return `${hour12}:${minutes.toString().padStart(2, '0')} ${period}`;
}

/**
 * Format date as "YYYY-MM-DD" in local timezone WITHOUT any timezone conversion
 * @param {Date} date - Date object
 * @returns {string} Formatted date
 */
function formatDateForDb(date) {
  if (!(date instanceof Date) || isNaN(date)) return '';

  const year = date.getFullYear();
  const month = (date.getMonth() + 1).toString().padStart(2, '0');
  const day = date.getDate().toString().padStart(2, '0');
  return `${year}-${month}-${day}`;
}

/**
 * Format date for display in user's locale format
 * This creates a date object keeping the same day/month/year without timezone interference
 * @param {string} dateStr - Date string in format "YYYY-MM-DD"
 * @returns {string} Formatted date for display
 */
function formatDateForDisplay(dateStr) {
  if (typeof dateStr !== 'string') return '';

  const [year, month, day] = dateStr.split('-').map(Number);
  if ([year, month, day].some(isNaN)) return '';

  const date = new Date(year, month - 1, day);
  const options = { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' };

  return date.toLocaleDateString('en-US', options);
}

/**
 * Parse ISO date string to Date object preserving the date in local timezone
 * @param {string} dateStr - Date string in format "YYYY-MM-DD"
 * @returns {Date} Date object
 */
function parseLocalDate(dateStr) {
  if (typeof dateStr !== 'string') return new Date(NaN);

  const [year, month, day] = dateStr.split('-').map(Number);
  if ([year, month, day].some(isNaN)) return new Date(NaN);

  return new Date(year, month - 1, day);
}

module.exports = {
  formatTimeString,
  formatTimeFor12Hour,
  formatDateForDb,
  formatDateForDisplay,
  parseLocalDate
};
