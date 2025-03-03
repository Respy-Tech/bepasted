/**
 * Centralized error handling utilities
 * Provides consistent error handling across the application
 */

import logger from './logger.js';
import config from '../config/config.js';

/**
 * Standard error types used across the application
 */
export const ErrorTypes = {
  VALIDATION: 'VALIDATION_ERROR',
  AUTHENTICATION: 'AUTHENTICATION_ERROR',
  AUTHORIZATION: 'AUTHORIZATION_ERROR',
  NOT_FOUND: 'NOT_FOUND',
  RATE_LIMIT: 'RATE_LIMIT',
  BAD_REQUEST: 'BAD_REQUEST',
  INTERNAL: 'INTERNAL_ERROR',
  CONTENT_SIZE: 'CONTENT_SIZE_ERROR',
};

/**
 * Error status code mapping
 */
const statusCodes = {
  [ErrorTypes.VALIDATION]: 400,
  [ErrorTypes.AUTHENTICATION]: 401,
  [ErrorTypes.AUTHORIZATION]: 403,
  [ErrorTypes.NOT_FOUND]: 404,
  [ErrorTypes.RATE_LIMIT]: 429,
  [ErrorTypes.BAD_REQUEST]: 400,
  [ErrorTypes.INTERNAL]: 500,
  [ErrorTypes.CONTENT_SIZE]: 413,
};

/**
 * Creates an application error with consistent structure
 * @param {string} message - User-facing error message
 * @param {string} type - Error type from ErrorTypes
 * @param {Object} details - Additional details (only logged, not sent to user in production)
 * @returns {Error} Structured error object
 */
export function createError(message, type = ErrorTypes.INTERNAL, details = {}) {
  const error = new Error(message);
  error.type = type;
  error.status = statusCodes[type] || 500;
  error.details = details;
  return error;
}

/**
 * Handles errors consistently across the application
 * @param {Error} error - The error object
 * @param {Object} c - Hono context
 * @param {boolean} isAPI - Whether this is an API endpoint (for response format)
 * @returns {Response} Formatted error response
 */
export function handleError(error, c, isAPI = true) {
  // Extract error details
  const status = error.status || statusCodes[error.type] || 500;
  const type = error.type || ErrorTypes.INTERNAL;
  
  // Determine environment for error detail level
  const isProd = config.NODE_ENV === 'production';
  
  // Create safe, user-facing error message
  let userMessage = error.message;
  
  // For 500 errors in production, use generic message
  if (status === 500 && isProd) {
    userMessage = 'An unexpected error occurred. Please try again later.';
  }
  
  // Log the error with appropriate level based on status code
  const logDetails = {
    errorType: type,
    status,
    path: c.req.path,
    method: c.req.method,
    ip: c.req.header('cf-connecting-ip') || c.req.header('x-real-ip'),
    details: error.details || {},
  };
  
  // Add stack trace for server errors but not for client errors
  if (status >= 500) {
    logDetails.stack = error.stack;
    logger.error(`Server error: ${error.message}`, logDetails);
  } else if (status === 429) {
    logger.warn(`Rate limit exceeded: ${error.message}`, logDetails);
  } else {
    logger.info(`Client error: ${error.message}`, logDetails);
  }
  
  // Create user-facing response
  if (isAPI) {
    // API response as JSON
    return c.json({
      error: userMessage,
      code: type,
      // Include non-sensitive details that are safe for users
      ...(error.safeDetails && { details: error.safeDetails }),
    }, status);
  } else {
    // For web routes, handle differently based on error type
    if (status === 404) {
      // Redirect to a custom 404 page
      return c.redirect('/not-found');
    } else if (status === 429) {
      // Redirect to rate limit error page
      return c.redirect('/rate-limit-error');
    } else if (status >= 500) {
      // Server errors show error page
      return c.html(`
        <!DOCTYPE html>
        <html lang="en">
        <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>Server Error - BePasted</title>
          <link rel="stylesheet" href="/css/styles.css">
        </head>
        <body>
          <div class="error-container">
            <h1>Something went wrong</h1>
            <p>We're experiencing some technical difficulties. Please try again later.</p>
            <a href="/" class="btn">Return to Homepage</a>
          </div>
        </body>
        </html>
      `, 500);
    } else {
      // Client errors show appropriate message
      return c.html(`
        <!DOCTYPE html>
        <html lang="en">
        <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>Error - BePasted</title>
          <link rel="stylesheet" href="/css/styles.css">
        </head>
        <body>
          <div class="error-container">
            <h1>Error</h1>
            <p>${userMessage}</p>
            <a href="/" class="btn">Return to Homepage</a>
          </div>
        </body>
        </html>
      `, status);
    }
  }
}

/**
 * Middleware to handle errors in async route handlers
 * @param {Function} handler - Async route handler
 * @param {boolean} isAPI - Whether this is an API endpoint
 * @returns {Function} Wrapped handler with error handling
 */
export function asyncErrorHandler(handler, isAPI = true) {
  return async (c, next) => {
    try {
      return await handler(c, next);
    } catch (error) {
      return handleError(error, c, isAPI);
    }
  };
}

/**
 * Error handling middleware
 * @param {Object} c - Hono context
 * @param {Function} next - Next middleware function
 */
export async function errorMiddleware(c, next) {
  try {
    await next();
  } catch (error) {
    // Determine if this is an API request based on path
    const isAPI = c.req.path.startsWith('/api/');
    return handleError(error, c, isAPI);
  }
}

/**
 * Special handling for MongoDB errors to prevent information disclosure
 * @param {Error} error - MongoDB error
 * @returns {Error} Sanitized error
 */
export function sanitizeMongoDBError(error) {
  // Original error for server logs
  const originalError = error;
  
  // Create a sanitized version for user response
  let sanitizedMessage = 'A database error occurred';
  let errorType = ErrorTypes.INTERNAL;
  let status = 500;
  
  // Handle common MongoDB errors with appropriate user messages
  if (error.name === 'ValidationError') {
    sanitizedMessage = 'The provided data is invalid';
    errorType = ErrorTypes.VALIDATION;
    status = 400;
    
    // Log detailed validation errors for debugging
    if (error.errors) {
      console.error('Validation Error Details:');
      Object.keys(error.errors).forEach(field => {
        console.error(`  - Field '${field}': ${error.errors[field].message}`);
        console.error(`    Kind: ${error.errors[field].kind}`);
        console.error(`    Path: ${error.errors[field].path}`);
        console.error(`    Value: ${JSON.stringify(error.errors[field].value)}`);
      });
    }
    
    // Create safe validation details without exposing schema internals
    const safeDetails = {};
    if (error.errors) {
      Object.keys(error.errors).forEach(field => {
        // Only include the field name and kind, not the full error
        safeDetails[field] = {
          message: `Invalid ${field}`,
          kind: error.errors[field].kind
        };
      });
    }
    
    // Create a new error with sanitized details
    const sanitizedError = createError(sanitizedMessage, errorType);
    sanitizedError.safeDetails = safeDetails;
    sanitizedError.details = { originalError }; // For logging only
    return sanitizedError;
  }
  
  if (error.code === 11000) {
    // Duplicate key error
    sanitizedMessage = 'This item already exists';
    errorType = ErrorTypes.VALIDATION;
    status = 400;
  }
  
  // Create standard sanitized error
  const sanitizedError = createError(sanitizedMessage, errorType);
  sanitizedError.details = { originalError }; // For logging only
  return sanitizedError;
} 