/**
 * Utilities for safely parsing request data with size limits
 */
import logger from '../logging/logger.js';
import { createError, ErrorTypes } from '../logging/error-handler.js';

// Default size limits
const DEFAULT_LIMITS = {
  requestSize: 25 * 1024 * 1024,  // 25MB global maximum for any request
  pasteSize: 2 * 1024 * 1024,     // 2MB per paste content
  totalPasteSize: 20 * 1024 * 1024 // 20MB combined maximum
};

/**
 * Safely parse JSON from request with size validation
 * @param {Request} req - Hono request object
 * @param {Object} options - Configuration options
 * @returns {Promise<Object>} Parsed JSON or throws appropriate error
 */
export async function safeParseJSON(req, options = {}) {
  const limits = { ...DEFAULT_LIMITS, ...options };
  
  try {
    // Check content-length header first for early rejection
    const contentLength = parseInt(req.header('content-length') || '0');
    if (contentLength > limits.requestSize) {
      throw createError(
        'Request payload too large', 
        ErrorTypes.CONTENT_SIZE, 
        {
          currentSize: contentLength,
          maxSize: limits.requestSize
        }
      );
    }
    
    // If content-length is acceptable or not provided, try to parse JSON
    try {
      // First attempt to read the request body normally
      return await req.json();
    } catch (error) {
      // Special handling for "body already read" errors
      if (error.message && (
          error.message.includes('Body has already been read') || 
          error.message.includes('Body is unusable')
        )) {
        
        logger.warn('Request body already consumed, attempting fallback', {
          error: error.message,
          path: req.path
        });
        
        // Comprehensive check for cached body in various places
        let cachedBody = null;
        
        // Method 1: Check if we have access to the context directly
        if (req._c && typeof req._c.get === 'function') {
          cachedBody = req._c.get('cachedRequestBody');
          if (cachedBody) {
            logger.info('Found cached body in req._c', { bodySize: cachedBody.length });
          }
        }
        
        // Method 2: Check if the raw request has the context
        if (!cachedBody && req.raw && req.raw._c && typeof req.raw._c.get === 'function') {
          cachedBody = req.raw._c.get('cachedRequestBody');
          if (cachedBody) {
            logger.info('Found cached body in req.raw._c', { bodySize: cachedBody.length });
          }
        }
        
        // Method 3: Try to access the _request property if it exists
        if (!cachedBody && req._request && req._request._c && typeof req._request._c.get === 'function') {
          cachedBody = req._request._c.get('cachedRequestBody');
          if (cachedBody) {
            logger.info('Found cached body in req._request._c', { bodySize: cachedBody.length });
          }
        }
        
        // Method 4: Try to access other possible locations where the body might be cached
        if (!cachedBody && req.raw && req.raw.context && typeof req.raw.context.get === 'function') {
          cachedBody = req.raw.context.get('cachedRequestBody');
          if (cachedBody) {
            logger.info('Found cached body in req.raw.context', { bodySize: cachedBody.length });
          }
        }
        
        // If we found a cached body, try to parse it
        if (cachedBody) {
          try {
            return JSON.parse(cachedBody);
          } catch (parseError) {
            logger.error('Failed to parse cached JSON body', {
              error: parseError.message,
              bodySnippet: cachedBody.length > 50 ? cachedBody.substring(0, 50) + '...' : cachedBody
            });
            throw createError(
              'Invalid JSON in cached request body', 
              ErrorTypes.BAD_REQUEST, 
              { originalError: parseError }
            );
          }
        }
        
        // If we still don't have a body, log the failure with diagnostic info
        logger.error('Failed to read raw request body', {
          error: error.message,
          path: req.path,
          // Log info about what properties are available for debugging
          hasRaw: Boolean(req.raw),
          hasContext: Boolean(req._c || (req.raw?._c)),
          requestProperties: Object.keys(req),
          rawRequestProperties: req.raw ? Object.keys(req.raw) : []
        });
        
        throw createError(
          'Request body already consumed and recovery failed', 
          ErrorTypes.BAD_REQUEST, 
          { originalError: error }
        );
      }
      
      // For other types of errors, pass through
      throw error;
    }
  } catch (error) {
    // Check if it's a parse error from JSON.parse
    if (error instanceof SyntaxError) {
      throw createError(
        'Invalid JSON payload', 
        ErrorTypes.BAD_REQUEST, 
        { originalError: error }
      );
    }
    
    // If this is already our custom error, just pass it through
    if (error.errorType) {
      throw error;
    }
    
    // Otherwise, wrap in our custom error
    throw createError(
      'Error parsing request body: ' + error.message, 
      ErrorTypes.BAD_REQUEST, 
      { originalError: error }
    );
  }
}

/**
 * Validate paste content size across tabs
 * @param {Array} tabs - Array of paste tabs
 * @param {Object} options - Size limits
 * @returns {Object} Validation result with status and errors if applicable
 */
export function validatePasteSize(tabs, options = {}) {
  const limits = { ...DEFAULT_LIMITS, ...options };
  const result = {
    valid: true,
    totalSize: 0,
    errors: []
  };
  
  if (!Array.isArray(tabs)) {
    result.valid = false;
    result.errors.push({
      message: 'Tabs must be an array',
      code: 'INVALID_TABS_FORMAT'
    });
    return result;
  }
  
  // Check individual tab sizes and accumulate total
  for (let i = 0; i < tabs.length; i++) {
    const tab = tabs[i];
    const tabName = tab.name || `Tab ${i + 1}`;
    
    if (!tab.content) {
      continue;
    }
    
    if (typeof tab.content !== 'string') {
      result.valid = false;
      result.errors.push({
        message: `Content in tab "${tabName}" must be a string`,
        code: 'INVALID_CONTENT_TYPE',
        tab: i
      });
      continue;
    }
    
    const contentSize = Buffer.byteLength(tab.content, 'utf8');
    result.totalSize += contentSize;
    
    // Check individual size limit
    if (contentSize > limits.pasteSize) {
      result.valid = false;
      result.errors.push({
        message: `Content in tab "${tabName}" exceeds size limit`,
        code: 'TAB_SIZE_EXCEEDED',
        tab: i,
        size: contentSize,
        maxSize: limits.pasteSize,
        humanReadableSize: `${(contentSize / (1024 * 1024)).toFixed(2)}MB`,
        humanReadableMax: `${(limits.pasteSize / (1024 * 1024)).toFixed(1)}MB`
      });
    }
  }
  
  // Check total size across all tabs
  if (result.totalSize > limits.totalPasteSize) {
    result.valid = false;
    result.errors.push({
      message: 'Total content size across all tabs exceeds maximum allowed',
      code: 'TOTAL_SIZE_EXCEEDED',
      size: result.totalSize,
      maxSize: limits.totalPasteSize,
      humanReadableSize: `${(result.totalSize / (1024 * 1024)).toFixed(2)}MB`,
      humanReadableMax: `${(limits.totalPasteSize / (1024 * 1024)).toFixed(1)}MB`
    });
  }
  
  return result;
}

/**
 * Format error response for size validation failures
 * @param {Object} validationResult - Result from validatePasteSize
 * @returns {Object} Formatted error response
 */
export function formatSizeValidationError(validationResult) {
  // If validation failed, create a proper error
  if (!validationResult.valid && validationResult.errors.length > 0) {
    const primaryError = validationResult.errors[0];
    
    // Create a user-friendly error message
    const message = primaryError.message;
    
    // Create safe details that don't expose system information
    const safeDetails = {
      code: primaryError.code
    };
    
    // Add size information if available
    if (primaryError.humanReadableSize) {
      safeDetails.currentSize = primaryError.humanReadableSize;
    }
    
    if (primaryError.humanReadableMax) {
      safeDetails.maxSize = primaryError.humanReadableMax;
    }
    
    // If there are multiple errors, add them to the details
    if (validationResult.errors.length > 1) {
      safeDetails.additionalErrors = validationResult.errors.slice(1).map(err => ({
        message: err.message,
        code: err.code,
        tab: err.tab
      }));
    }
    
    // Return properly formatted error
    const error = createError(message, ErrorTypes.CONTENT_SIZE);
    error.safeDetails = safeDetails;
    return {
      error: message,
      ...safeDetails
    };
  }
  
  // Return empty object if validation passed
  return {};
}

/**
 * Helper function to retrieve cached request body from any available location in the context
 * @param {Object} c - Hono context or request object
 * @returns {string|null} - The cached request body or null if not found
 */
export function getCachedRequestBody(c) {
  // Try to get the cached body from all possible locations
  let cachedBody = null;
  
  // If we have a Hono context
  if (c && typeof c.get === 'function') {
    cachedBody = c.get('cachedRequestBody');
    if (cachedBody) return cachedBody;
  }
  
  // If we have a request with context
  if (c?.req && c.req._c && typeof c.req._c.get === 'function') {
    cachedBody = c.req._c.get('cachedRequestBody');
    if (cachedBody) return cachedBody;
  }
  
  // If we have a raw request with context
  if (c?.req && c.req.raw && c.req.raw._c && typeof c.req.raw._c.get === 'function') {
    cachedBody = c.req.raw._c.get('cachedRequestBody');
    if (cachedBody) return cachedBody;
  }
  
  // If we are passed a request directly
  if (c?._c && typeof c._c.get === 'function') {
    cachedBody = c._c.get('cachedRequestBody');
    if (cachedBody) return cachedBody;
  }
  
  // If we are passed a raw request
  if (c?.raw && c.raw._c && typeof c.raw._c.get === 'function') {
    cachedBody = c.raw._c.get('cachedRequestBody');
    if (cachedBody) return cachedBody;
  }
  
  // More fallbacks
  if (c?._request && c._request._c && typeof c._request._c.get === 'function') {
    cachedBody = c._request._c.get('cachedRequestBody');
    if (cachedBody) return cachedBody;
  }
  
  // Try originalRaw if available
  if (c?.req && c.req.originalRaw && c.req.originalRaw._c && typeof c.req.originalRaw._c.get === 'function') {
    cachedBody = c.req.originalRaw._c.get('cachedRequestBody');
    if (cachedBody) return cachedBody;
  }
  
  return null;
}

// Export constants for consistent use across the application
export const SIZE_LIMITS = DEFAULT_LIMITS; 