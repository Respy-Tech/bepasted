/**
 * Utilities for safely parsing request data with size limits
 */
import logger from "../logging/logger.js";
import { createError, ErrorTypes } from "../logging/error-handler.js";

// Default size limits
const DEFAULT_LIMITS = {
  requestSize: 25 * 1024 * 1024, // 25MB global maximum for any request
  pasteSize: 2 * 1024 * 1024, // 2MB per paste content
  totalPasteSize: 20 * 1024 * 1024, // 20MB combined maximum
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
    // Check content-length and try to parse JSON
    await validateContentLength(req, limits.requestSize);
    return await parseRequestJSON(req);
  } catch (error) {
    return handleParseError(error);
  }
}

/**
 * Validate content length against size limits
 * @param {Request} req - Request object
 * @param {number} maxSize - Maximum allowed size in bytes
 * @throws {Error} If content length exceeds maximum size
 */
async function validateContentLength(req, maxSize) {
  const contentLength = parseInt(req.header("content-length") || "0");
  if (contentLength > maxSize) {
    throw createError("Request payload too large", ErrorTypes.CONTENT_SIZE, {
      currentSize: contentLength,
      maxSize,
    });
  }
}

/**
 * Parse JSON from request
 * @param {Request} req - Request object
 * @returns {Promise<Object>} Parsed JSON
 * @throws {Error} If parsing fails
 */
async function parseRequestJSON(req) {
  try {
    return await req.json();
  } catch (error) {
    if (isBodyAlreadyReadError(error)) {
      return handleBodyAlreadyRead(req, error);
    }
    throw error;
  }
}

/**
 * Check if the error indicates body already read
 * @param {Error} error - Error to check
 * @returns {boolean} True if body already read error
 */
function isBodyAlreadyReadError(error) {
  return (
    error.message &&
    (error.message.includes("Body has already been read") ||
      error.message.includes("Body is unusable"))
  );
}

/**
 * Handle case when body was already read
 * @param {Request} req - Request object
 * @param {Error} originalError - Original error
 * @returns {Object} Parsed JSON
 * @throws {Error} If recovery fails
 */
async function handleBodyAlreadyRead(req, originalError) {
  logger.warn("Request body already consumed, attempting fallback", {
    error: originalError.message,
    path: req.path,
  });

  // Try to retrieve cached body
  const cachedBody = retrieveCachedBody(req);

  if (cachedBody) {
    try {
      return JSON.parse(cachedBody);
    } catch (parseError) {
      logger.error("Failed to parse cached JSON body", {
        error: parseError.message,
        bodySnippet:
          cachedBody.length > 50
            ? cachedBody.substring(0, 50) + "..."
            : cachedBody,
      });
      throw createError(
        "Invalid JSON in cached request body",
        ErrorTypes.BAD_REQUEST,
        { originalError: parseError }
      );
    }
  }

  // Log failure diagnostics
  logRequestDiagnostics(req, originalError);

  throw createError(
    "Request body already consumed and recovery failed",
    ErrorTypes.BAD_REQUEST,
    { originalError }
  );
}

/**
 * Retrieve cached body from request
 * @param {Request} req - Request object
 * @returns {string|null} Cached body if found
 */
function retrieveCachedBody(req) {
  const possibleLocations = [
    { obj: req, path: ["_c", "get"], label: "req._c" },
    { obj: req, path: ["raw", "_c", "get"], label: "req.raw._c" },
    { obj: req, path: ["_request", "_c", "get"], label: "req._request._c" },
    { obj: req, path: ["raw", "context", "get"], label: "req.raw.context" },
  ];

  for (const { obj, path, label } of possibleLocations) {
    const body = getCachedBodyFromPath(obj, path);
    if (body) {
      logger.info(`Found cached body in ${label}`, { bodySize: body.length });
      return body;
    }
  }

  return null;
}

/**
 * Log diagnostic information for request
 * @param {Request} req - Request object
 * @param {Error} error - Original error
 */
function logRequestDiagnostics(req, error) {
  logger.error("Failed to read raw request body", {
    error: error.message,
    path: req.path,
    hasRaw: Boolean(req.raw),
    hasContext: Boolean(req._c || req.raw?._c),
    requestProperties: Object.keys(req),
    rawRequestProperties: req.raw ? Object.keys(req.raw) : [],
  });
}

/**
 * Handle any parse errors
 * @param {Error} error - Error that occurred during parsing
 * @throws {Error} Appropriately wrapped error
 */
function handleParseError(error) {
  // Return custom error if it already exists
  if (error.errorType) {
    throw error;
  }

  // Handle syntax errors from JSON parsing
  if (error instanceof SyntaxError) {
    throw createError("Invalid JSON payload", ErrorTypes.BAD_REQUEST, {
      originalError: error,
    });
  }

  // Wrap other errors
  throw createError(
    "Error parsing request body: " + error.message,
    ErrorTypes.BAD_REQUEST,
    { originalError: error }
  );
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
    errors: [],
  };

  if (!Array.isArray(tabs)) {
    result.valid = false;
    result.errors.push({
      message: "Tabs must be an array",
      code: "INVALID_TABS_FORMAT",
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

    if (typeof tab.content !== "string") {
      result.valid = false;
      result.errors.push({
        message: `Content in tab "${tabName}" must be a string`,
        code: "INVALID_CONTENT_TYPE",
        tab: i,
      });
      continue;
    }

    const contentSize = Buffer.byteLength(tab.content, "utf8");
    result.totalSize += contentSize;

    // Check individual size limit
    if (contentSize > limits.pasteSize) {
      result.valid = false;
      result.errors.push({
        message: `Content in tab "${tabName}" exceeds size limit`,
        code: "TAB_SIZE_EXCEEDED",
        tab: i,
        size: contentSize,
        maxSize: limits.pasteSize,
        humanReadableSize: `${(contentSize / (1024 * 1024)).toFixed(2)}MB`,
        humanReadableMax: `${(limits.pasteSize / (1024 * 1024)).toFixed(1)}MB`,
      });
    }
  }

  // Check total size across all tabs
  if (result.totalSize > limits.totalPasteSize) {
    result.valid = false;
    result.errors.push({
      message: "Total content size across all tabs exceeds maximum allowed",
      code: "TOTAL_SIZE_EXCEEDED",
      size: result.totalSize,
      maxSize: limits.totalPasteSize,
      humanReadableSize: `${(result.totalSize / (1024 * 1024)).toFixed(2)}MB`,
      humanReadableMax: `${(limits.totalPasteSize / (1024 * 1024)).toFixed(
        1
      )}MB`,
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
      code: primaryError.code,
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
      safeDetails.additionalErrors = validationResult.errors
        .slice(1)
        .map((err) => ({
          message: err.message,
          code: err.code,
          tab: err.tab,
        }));
    }

    // Return properly formatted error
    const error = createError(message, ErrorTypes.CONTENT_SIZE);
    error.safeDetails = safeDetails;
    return {
      error: message,
      ...safeDetails,
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
  // Define possible paths to check for cached request body
  const paths = [
    // Direct context
    { obj: c, path: ["get"] },
    // Request with context
    { obj: c, path: ["req", "_c", "get"] },
    // Raw request with context
    { obj: c, path: ["req", "raw", "_c", "get"] },
    // Direct request
    { obj: c, path: ["_c", "get"] },
    // Raw request
    { obj: c, path: ["raw", "_c", "get"] },
    // Request property
    { obj: c, path: ["_request", "_c", "get"] },
    // Original raw request
    { obj: c, path: ["req", "originalRaw", "_c", "get"] },
  ];

  // Check each path
  for (const { obj, path } of paths) {
    const cachedBody = getCachedBodyFromPath(obj, path);
    if (cachedBody) return cachedBody;
  }

  return null;
}

/**
 * Helper to safely access cached body using a path of properties
 * @param {Object} obj - Starting object
 * @param {Array<string>} path - Array of property names to traverse
 * @returns {string|null} - Cached body if found
 */
function getCachedBodyFromPath(obj, path) {
  try {
    // Navigate to the target object
    let current = obj;
    const getMethod = path[path.length - 1];

    // Follow the path except for the last element (the 'get' method)
    for (let i = 0; i < path.length - 1; i++) {
      current = current?.[path[i]];
      if (!current) return null;
    }

    // Check if the get method exists and is a function
    if (typeof current[getMethod] === "function") {
      const body = current[getMethod]("cachedRequestBody");
      return body || null;
    }
  } catch (e) {
    // Silently fail and return null for any errors
  }
  return null;
}

// Export constants for consistent use across the application
export const SIZE_LIMITS = DEFAULT_LIMITS;
