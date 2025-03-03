/**
 * Utility for Cloudflare Turnstile verification
 */
import logger from '../logging/logger.js';
import config from '../config/config.js';

// Cloudflare Turnstile verification endpoint
const TURNSTILE_VERIFY_URL = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';

/**
 * Verify a Turnstile token with Cloudflare's verification API
 * 
 * @param {string} token - The Turnstile token from the client
 * @param {string} remoteip - Optional remote IP address
 * @returns {Promise<Object>} - Verification result object with success flag and any error details
 */
export async function verifyTurnstileToken(token, remoteip = null) {
  if (!config.TURNSTILE_SECRET_KEY) {
    logger.error('Turnstile secret key is not configured');
    return { success: false, error: 'Turnstile verification not properly configured' };
  }

  try {
    // Prepare form data for the verification request
    const formData = new URLSearchParams();
    formData.append('secret', config.TURNSTILE_SECRET_KEY);
    formData.append('response', token);
    
    // Add IP address if provided
    if (remoteip) {
      formData.append('remoteip', remoteip);
    }

    // Send verification request to Cloudflare
    const response = await fetch(TURNSTILE_VERIFY_URL, {
      method: 'POST',
      body: formData,
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      }
    });

    // Parse and return the response
    const result = await response.json();
    
    if (!result.success) {
      logger.warn('Turnstile verification failed', {
        'error-codes': result['error-codes'],
        token: token.substring(0, 10) + '...' // Log only part of the token for debugging
      });
    } else {
      logger.debug('Turnstile verification successful', {
        hostname: result.hostname,
        challenge_ts: result.challenge_ts,
        action: result.action,
        cdata: result.cdata
      });
    }
    
    return result;
  } catch (error) {
    logger.error('Error during Turnstile verification', {
      error: error.message,
      stack: error.stack
    });
    
    return {
      success: false,
      'error-codes': ['internal-error'],
      error: 'Internal server error during verification'
    };
  }
}

/**
 * Helper function to get a friendly error message from Turnstile error codes
 * 
 * @param {Array} errorCodes - Array of error codes from Turnstile response
 * @returns {string} - Human-readable error message
 */
export function getTurnstileErrorMessage(errorCodes) {
  if (!errorCodes || !Array.isArray(errorCodes) || errorCodes.length === 0) {
    return 'Unknown verification error';
  }
  
  const primaryError = errorCodes[0];
  
  switch (primaryError) {
    case 'missing-input-secret':
      return 'The secret key is missing';
    case 'invalid-input-secret':
      return 'The secret key is invalid or malformed';
    case 'missing-input-response':
      return 'The response parameter was not passed';
    case 'invalid-input-response':
      return 'The response parameter is invalid or malformed';
    case 'bad-request':
      return 'The request was rejected because it was malformed';
    case 'timeout-or-duplicate':
      return 'The response is no longer valid: either is too old or has been used previously';
    case 'internal-error':
      return 'An internal error occurred while validating the response';
    default:
      return `Verification failed: ${primaryError}`;
  }
}
