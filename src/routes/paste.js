import { Hono } from 'hono';
import crypto from 'crypto';
import mongoose from 'mongoose';
import { Paste, ArchivedPaste } from '../models/paste.js';
import { createPasteLimiter, passwordAttemptLimiter } from '../utils/security/rate-limiter.js';
import { randomBytes } from 'crypto';
import { verifyTurnstileToken, getTurnstileErrorMessage } from '../utils/http/turnstile-verifier.js';
import { ReportedPaste } from '../models/reportedPastes.js';
import { ipValidator } from '../utils/security/ip-validator.js';
import logger from '../utils/logging/logger.js';
import contentScanner from '../utils/security/content-scanner.js';
import IPAnonymizer from '../utils/security/ip-anonymizer.js';
import { safeParseJSON, validatePasteSize, formatSizeValidationError, SIZE_LIMITS, getCachedRequestBody } from '../utils/http/request-parser.js';
import { createError, ErrorTypes, asyncErrorHandler, sanitizeMongoDBError } from '../utils/logging/error-handler.js';
import config from '../utils/config/config.js';
import { getDomain } from '../utils/config/domain.js';

// Create separate routers for API and views
const apiRouter = new Hono();
const viewRouter = new Hono();

// Size limit constants - use the values from the request parser utility
const MAX_REQUEST_SIZE = SIZE_LIMITS.requestSize;
const MAX_PASTE_SIZE = SIZE_LIMITS.pasteSize;
const MAX_TOTAL_CONTENT_SIZE = SIZE_LIMITS.totalPasteSize;

// Helper to generate unique ID
const generateId = () => {
    return crypto.randomBytes(4).toString('hex');
};

// Helper to escape HTML to prevent XSS attacks
const escapeHtml = (unsafe) => {
    if (typeof unsafe !== 'string') return '';
    return unsafe
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
};

// Helper to inject SimpleAnalytics script (only in production)
const injectSimpleAnalytics = (nonce) => {
    // Only inject SimpleAnalytics if not in development environment
    if (config.NODE_ENV !== 'development') {
        return `
    <!-- 100% privacy-first analytics -->
    <script data-collect-dnt="true" async src="https://sa.bepasted.com/latest.js" nonce="${nonce}"></script>
    <noscript><img src="https://sa.bepasted.com/noscript.gif?collect-dnt=true" alt="" referrerpolicy="no-referrer-when-downgrade"/></noscript>
    `;
    }
    return '';
};

// Request size limiting middleware that preserves the request body
apiRouter.use('/paste', async (c, next) => {
    // First check if the body has already been cached by the global middleware
    const cachedBody = c.get('cachedRequestBody');
    if (cachedBody) {
        // If we already have the body cached from the global middleware, no need to read it again
        logger.debug('Using body already cached by global middleware', {
            size: cachedBody.length,
            path: c.req.path
        });
        
        // Just validate size limit and continue
        if (cachedBody.length > MAX_REQUEST_SIZE) {
            logger.warn('Upload exceeds maximum size', {
                size: cachedBody.length,
                maxSize: MAX_REQUEST_SIZE,
                path: c.req.path
            });
            
            return c.json({
                error: 'Upload exceeds maximum size',
                maxSize: `${(MAX_REQUEST_SIZE / (1024 * 1024)).toFixed(1)}MB`
            }, 413);
        }
        
        // Continue processing since we don't need to read the body again
        return next();
    }
    
    // Only proceed to read the body if it hasn't been cached already
    // Only apply for content types that might contain large data
    const contentType = c.req.header('content-type') || '';
    if (!contentType.includes('application/json') && !contentType.includes('multipart/form-data')) {
        // Not a content type we're concerned about
        return next();
    }
    
    // Check content-length first for a quick rejection
    const contentLength = parseInt(c.req.header('content-length') || '0');
    if (contentLength > MAX_REQUEST_SIZE) {
        logger.warn('Upload exceeds maximum size based on Content-Length header', {
            size: contentLength,
            maxSize: MAX_REQUEST_SIZE,
            path: c.req.path
        });
        
        return c.json({
            error: 'Upload exceeds maximum size',
            maxSize: `${(MAX_REQUEST_SIZE / (1024 * 1024)).toFixed(1)}MB`
        }, 413);
    }
    
    // For streaming validation, we need to copy the body so it can be used again
    try {
        // We'll read the body once and store it for re-use ONLY if it hasn't been cached already
        logger.info('Route middleware caching request body for reuse', {
            path: c.req.path,
            size: contentLength
        });
        
        // Clone the request to get a fresh body stream for consumption
        const originalReq = c.req.raw;
        
        // We'll read the body once and store it for re-use
        const bodyText = await originalReq.text();
        
        // Validate size directly after reading (without parsing yet)
        if (bodyText.length > MAX_REQUEST_SIZE) {
            logger.warn('Upload exceeds maximum size', {
                size: bodyText.length,
                maxSize: MAX_REQUEST_SIZE,
                path: c.req.path
            });
            
            return c.json({
                error: 'Upload exceeds maximum size',
                maxSize: `${(MAX_REQUEST_SIZE / (1024 * 1024)).toFixed(1)}MB`
            }, 413);
        }
        
        // Store the body text in the context for later use
        c.set('cachedRequestBody', bodyText);
        
        // Continue the request processing
        return next();
    } catch (error) {
        logger.error('Error during request body handling', { 
            error: error.message,
            stack: error.stack 
        });
        
        throw createError(
            'Error processing request body', 
            ErrorTypes.BAD_REQUEST, 
            { originalError: error }
        );
    }
});

// API routes with improved error handling
apiRouter.post('/paste', asyncErrorHandler(async (c) => {
    // Check for rate limiting
    const rateLimitResult = await createPasteLimiter.rateLimit(c);
    
    // Enhanced logging for IP detection
    logger.info('Rate limit result', {
        rateLimitResult: {
            ip: rateLimitResult.ip,
            anonymizedIP: rateLimitResult.anonymizedIP,
            isLimited: rateLimitResult.isLimited,
            suspicious: rateLimitResult.suspicious
        }
    });
    
    // Validate IP values
    if (!rateLimitResult.anonymizedIP || rateLimitResult.anonymizedIP === 'unknown') {
        logger.warn('Missing anonymized IP in rate limiter result, using fallback value');
        // Ensure we have a value for anonymizedIP
        rateLimitResult.anonymizedIP = 'unknown-' + crypto.randomBytes(4).toString('hex');
    }
    
    if (rateLimitResult.isLimited) {
        throw createError(
            'Rate limit exceeded. Please try again later.',
            ErrorTypes.RATE_LIMIT,
            { timeLeft: rateLimitResult.timeLeft }
        );
    }

    // Parse request body, using the cached body if available
    let body;
    try {
        // Try different ways to access the cached body
        let cachedBody = c.get('cachedRequestBody');
        
        // If no cached body in context, look in the request
        if (!cachedBody && c.req._c && typeof c.req._c.get === 'function') {
            cachedBody = c.req._c.get('cachedRequestBody');
        }
        
        // If still no cached body, look in raw request
        if (!cachedBody && c.req.raw && c.req.raw._c && typeof c.req.raw._c.get === 'function') {
            cachedBody = c.req.raw._c.get('cachedRequestBody');
        }
        
        if (cachedBody) {
            // Parse the cached body text
            try {
                body = JSON.parse(cachedBody);
                
                // Size validation is already done by the middleware
                logger.debug('Successfully parsed cached request body', { 
                    bodySize: cachedBody.length,
                    path: c.req.path
                });
            } catch (parseError) {
                logger.error('Failed to parse cached JSON body', {
                    error: parseError.message,
                    path: c.req.path
                });
                
                throw createError(
                    'Invalid JSON payload in cached body', 
                    ErrorTypes.BAD_REQUEST,
                    { originalError: parseError }
                );
            }
        } else {
            // Fallback to reading the body directly (should not happen with our middleware)
            logger.warn('No cached body found, reading request directly', {
                path: c.req.path
            });
            body = await safeParseJSON(c.req);
        }
    } catch (error) {
        // For better diagnostics, log everything we can about the request
        logger.error('Error parsing request body', {
            error: error.message,
            path: c.req.path,
            method: c.req.method,
            contentType: c.req.header('content-type'),
            contentLength: c.req.header('content-length'),
            hasCachedBody: !!c.get('cachedRequestBody')
        });
        
        // Check if it's a JSON parsing error
        if (error instanceof SyntaxError) {
            throw createError(
                'Invalid JSON payload', 
                ErrorTypes.BAD_REQUEST, 
                { originalError: error }
            );
        }
        
        // Other errors pass through
        throw error;
    }
    
    // Log the full body for debugging expiry issues
    logger.info('Full request body received', {
        bodyKeys: Object.keys(body),
        expiryTime: body.expiryTime,
        expiryUnit: body.expiryUnit,
        deleteAfterTime: body.deleteAfterTime,
        expirySettings: body.expirySettings,
        // Log other potential expiry-related fields
        expires: body.expires,
        expiry: body.expiry,
        burnAfterViews: body.burnAfterViews
    });
    
    // Validate turnstile token
    const token = body.token;
    if (!token) {
        throw createError('Turnstile verification required', ErrorTypes.VALIDATION);
    }
    
    // Verify the token with Cloudflare's API
    const turnstileResult = await verifyTurnstileToken(token, rateLimitResult.ip);
    if (!turnstileResult.success) {
        logger.warn('Turnstile verification failed', { 
            error: turnstileResult['error-codes'],
            ip: rateLimitResult.anonymizedIP
        });
        
        throw createError(
            `Turnstile verification failed: ${getTurnstileErrorMessage(turnstileResult['error-codes'])}`,
            ErrorTypes.VALIDATION,
            { 
                errorCodes: turnstileResult['error-codes'],
                tokenLength: token ? token.length : 0
            }
        );
    }
    
    logger.info('Turnstile verification succeeded', {
        ip: rateLimitResult.anonymizedIP
    });

    // Validate required fields
    if (!body.tabs || !Array.isArray(body.tabs) || body.tabs.length === 0) {
        throw createError('At least one tab with content is required', ErrorTypes.VALIDATION);
    }

    // Validate tab count limit
    if (body.tabs.length > 10) {
        throw createError('Maximum of 10 tabs allowed', ErrorTypes.VALIDATION);
    }

    // Validate paste content size using our utility
    const sizeValidation = validatePasteSize(body.tabs);
    if (!sizeValidation.valid) {
        logger.info('Paste size validation failed', { 
            errors: sizeValidation.errors,
            totalSize: sizeValidation.totalSize,
            ip: rateLimitResult.anonymizedIP
        });
        
        // Get the formatted error from our utility
        const errorResponse = formatSizeValidationError(sizeValidation);
        return c.json(errorResponse, 400);
    }
    
    // Check if any tab has content
    let hasContent = false;
    for (const tab of body.tabs) {
        if (tab.content && tab.content.trim().length > 0) {
            hasContent = true;
            
            // Scan content for malicious code/patterns
            const scanResults = contentScanner.scanContent(tab.content);
            
            // Block high-risk content
            if (contentScanner.shouldBlockContent(scanResults)) {
                logger.warn('Blocking paste with malicious content', { 
                    ip: rateLimitResult.anonymizedIP,
                    threatLevel: scanResults.threatLevel
                });
                
                throw createError(
                    'This content has been blocked as it may contain malicious code or sensitive data.',
                    ErrorTypes.VALIDATION,
                    { details: contentScanner.getReadableReport(scanResults) }
                );
            }
            
            // For medium-risk content, add a warning but allow it
            if (!scanResults.safe) {
                logger.info('Potentially concerning content detected but not blocked', {
                    ip: rateLimitResult.anonymizedIP,
                    threatLevel: scanResults.threatLevel
                });
            }
        }
    }
    
    if (!hasContent) {
        throw createError('At least one tab must have content', ErrorTypes.VALIDATION);
    }
    
    // Generate unique ID
    let id = generateId();
    while (await Paste.findOne({ id })) {
        id = generateId();
    }
    
    // Debug log to see what expiry data is coming in
    logger.info('Expiry data received from client', {
        expiryTime: body.expiryTime,
        expiryUnit: body.expiryUnit,
        rawExpiryTime: typeof body.expiryTime,
        rawExpiryUnit: typeof body.expiryUnit,
        expiry: body.expiry ? {
            value: body.expiry.value,
            unit: body.expiry.unit,
            type: typeof body.expiry.value
        } : null
    });
    
    // Define expiry settings based on user input
    let expirySettings = null;
    
    // Check for both formats: expiryTime/expiryUnit at top level, or expiry object
    let expiryValue, expiryUnit;
    
    // Check for the nested expiry object first (seems to be what the client is using)
    if (body.expiry && typeof body.expiry === 'object' && body.expiry.value !== undefined && body.expiry.unit) {
        expiryValue = body.expiry.value;
        expiryUnit = body.expiry.unit;
        logger.info('Using nested expiry object format', {
            value: expiryValue,
            unit: expiryUnit,
            valueType: typeof expiryValue
        });
    } 
    // Fallback to legacy format of top-level expiryTime/expiryUnit
    else if (body.expiryTime && body.expiryUnit) {
        expiryValue = body.expiryTime;
        expiryUnit = body.expiryUnit;
        logger.info('Using top-level expiry fields format', {
            value: expiryValue,
            unit: expiryUnit
        });
    }
    
    // Only try to parse expiry settings if both expiryValue and expiryUnit are found
    if (expiryValue !== undefined && expiryUnit) {
        const expiryTime = parseInt(expiryValue);
        
        // Debug validation steps
        logger.info('Parsing expiry time', {
            rawValue: expiryValue,
            parsedValue: expiryTime,
            isValidNumber: !isNaN(expiryTime) && expiryTime > 0
        });
        
        // Validate the time is a number and greater than 0
        if (!isNaN(expiryTime) && expiryTime > 0) {
            // Validate the unit is one of the allowed values
            const validUnits = ['seconds', 'minutes', 'hours', 'days'];
            
            logger.info('Validating expiry unit', {
                providedUnit: expiryUnit,
                isValidUnit: validUnits.includes(expiryUnit)
            });
            
            if (validUnits.includes(expiryUnit)) {
                // Calculate total seconds for validation
                let totalSeconds = 0;
                switch (expiryUnit) {
                    case 'seconds':
                        totalSeconds = expiryTime;
                        break;
                    case 'minutes':
                        totalSeconds = expiryTime * 60;
                        break;
                    case 'hours':
                        totalSeconds = expiryTime * 60 * 60;
                        break;
                    case 'days':
                        totalSeconds = expiryTime * 24 * 60 * 60;
                        break;
                }
    
                // Validate against limits (min 5 seconds, max 30 days)
                let adjustedExpiryTime = expiryTime;
                if (totalSeconds < 5) {
                    logger.info('Expiry time too short, using minimum 5 seconds', { 
                        providedTime: expiryTime, 
                        unit: expiryUnit,
                        ip: rateLimitResult.anonymizedIP 
                    });
                    totalSeconds = 5;
                    // Also adjust the input value if we adjusted the time
                    if (expiryUnit === 'seconds') {
                        adjustedExpiryTime = 5;
                    }
                } else if (totalSeconds > 30 * 24 * 60 * 60) {
                    logger.info('Expiry time too long, using maximum 30 days', { 
                        providedTime: expiryTime, 
                        unit: expiryUnit,
                        ip: rateLimitResult.anonymizedIP 
                    });
                    totalSeconds = 30 * 24 * 60 * 60;
                    // Also adjust the input value if we adjusted the time
                    if (expiryUnit === 'days') {
                        adjustedExpiryTime = 30;
                    }
                }
    
                // Calculate expiry date based on validated time
                const now = new Date();
                const expiresAt = new Date(now.getTime() + totalSeconds * 1000);
                
                // Create complete expiry settings object
                expirySettings = {
                    value: adjustedExpiryTime,
                    unit: expiryUnit,
                    expiresAt: expiresAt
                };
                
                logger.info('Paste expiry settings configured', {
                    expiryTime: totalSeconds,
                    expirySettings: {
                        value: expirySettings.value,
                        unit: expirySettings.unit,
                        expiresAt: expirySettings.expiresAt instanceof Date ? 
                            expirySettings.expiresAt.toISOString() : null
                    }
                });
            } else {
                logger.warn('Invalid expiry unit provided, ignoring expiry settings', { 
                    unit: expiryUnit, 
                    ip: rateLimitResult.anonymizedIP 
                });
            }
        } else {
            logger.warn('Invalid expiry time provided, ignoring expiry settings', {
                time: expiryValue,
                parsedTime: expiryTime,
                ip: rateLimitResult.anonymizedIP
            });
        }
    } else {
        logger.info('No valid expiry settings to add to paste data', {
            hasExpirySettings: !!expirySettings,
            valueIsNumber: expirySettings ? typeof expirySettings.value === 'number' : false,
            unitIsString: expirySettings ? typeof expirySettings.unit === 'string' : false,
            expiresAtIsDate: expirySettings ? expirySettings.expiresAt instanceof Date : false,
            expirySettings: expirySettings || 'null'
        });
        // Ensure expiry is explicitly undefined to avoid empty object issues
        expirySettings = undefined;
    }
    
    try {
        // Create paste with detected and anonymized IP
        let pasteData = {
            id,
            tabs: Array.isArray(body.tabs) ? body.tabs : [{
                id: 1,
                name: body.tabName || 'Untitled',
                content: body.content || ''
            }],
            isPrivate: body.isPrivate || false,
            allowRaw: body.allowRaw || false,
            creatorIp: rateLimitResult.ip || '[unknown]',
            anonymizedCreatorIp: rateLimitResult.anonymizedIP || 'unknown',
            createdFromRegion: c.req.header('cf-ipcountry') || 'unknown',
            dataRetentionDate: new Date(Date.now() + (config.DATA_RETENTION_DAYS * 24 * 60 * 60 * 1000)) // Configurable retention period
        };
        
        // Debug log to verify that the IP values are properly set
        logger.info('IP values for paste creation', { 
            originalIp: rateLimitResult.ip || '[unknown]',
            anonymizedIp: rateLimitResult.anonymizedIP || 'unknown',
            finalAnonymizedIp: pasteData.anonymizedCreatorIp
        });
        
        // Only add password if private
        if (body.isPrivate && body.password) {
            pasteData.password = body.password;
        }
        
        // Only add expiry if it's set and all required fields are present
        if (expirySettings && 
            typeof expirySettings.value === 'number' && 
            typeof expirySettings.unit === 'string' && 
            expirySettings.expiresAt instanceof Date) {
            
            pasteData.expiry = expirySettings;
            logger.info('Adding expiry settings to paste data', {
                value: expirySettings.value,
                unit: expirySettings.unit,
                expiresAt: expirySettings.expiresAt.toISOString()
            });
        } else {
            // If expiry is not provided or invalid, don't include the field at all
            logger.info('No valid expiry settings to add to paste data', {
                hasExpirySettings: !!expirySettings,
                valueIsNumber: expirySettings ? typeof expirySettings.value === 'number' : false,
                unitIsString: expirySettings ? typeof expirySettings.unit === 'string' : false,
                expiresAtIsDate: expirySettings ? expirySettings.expiresAt instanceof Date : false,
                expirySettings: expirySettings || 'null'
            });
            // Ensure expiry is explicitly undefined to avoid empty object issues
            pasteData.expiry = undefined;
        }
        
        // Only add burn count if it's set
        if (body.burnAfterViews || body.burnCount) {
            pasteData.burnCount = body.burnAfterViews || body.burnCount;
            logger.info('Adding burn count to paste', { 
                burnCount: pasteData.burnCount,
                source: body.burnAfterViews ? 'burnAfterViews' : 'burnCount'
            });
        }
        
        // Final validation of essential fields before creating the Paste object
        if (!pasteData.anonymizedCreatorIp || pasteData.anonymizedCreatorIp === 'unknown') {
            logger.warn('anonymizedCreatorIp is missing or invalid, using fallback value');
            pasteData.anonymizedCreatorIp = 'unknown-' + crypto.randomBytes(4).toString('hex');
        }
        
        if (!pasteData.dataRetentionDate || !(pasteData.dataRetentionDate instanceof Date)) {
            logger.warn('dataRetentionDate is missing or invalid, setting default value');
            pasteData.dataRetentionDate = new Date(Date.now() + (config.DATA_RETENTION_DAYS * 24 * 60 * 60 * 1000));
        }
        
        // Create and validate the paste object before saving
        try {
            const paste = new Paste(pasteData);
            
            // Validate the paste manually before saving
            // This helps catch errors before hitting the database
            const validationError = paste.validateSync();
            if (validationError) {
                logger.error('Paste validation failed before save', {
                    error: validationError.message,
                    details: validationError.errors
                });
                
                // Use sanitizeMongoDBError for consistent error handling
                throw validationError;
            }
            
            // Add debug logging for paste object before saving
            logger.info('Paste object before save', { 
                pasteId: id,
                hasAnonymizedCreatorIp: !!paste.anonymizedCreatorIp,
                hasDataRetentionDate: paste.dataRetentionDate instanceof Date,
                anonymizedCreatorIp: paste.anonymizedCreatorIp,
                dataRetentionDate: paste.dataRetentionDate instanceof Date ? paste.dataRetentionDate.toISOString() : null,
                hasExpiry: !!paste.expiry,
                expiryDetails: paste.expiry ? {
                    hasValue: paste.expiry.value !== undefined && paste.expiry.value !== null,
                    value: paste.expiry.value,
                    hasUnit: paste.expiry.unit !== undefined && paste.expiry.unit !== null,
                    unit: paste.expiry.unit,
                    hasExpiresAt: paste.expiry.expiresAt instanceof Date,
                    expiresAt: paste.expiry.expiresAt instanceof Date ? paste.expiry.expiresAt.toISOString() : null
                } : null,
                hasBurnCount: !!paste.burnCount,
                burnCount: paste.burnCount
            });
            
            await paste.save();
            
            logger.info('New paste created', { 
                pasteId: id, 
                isPrivate: body.isPrivate,
                anonymizedCreatorIp: rateLimitResult.anonymizedIP,
                tabCount: body.tabs.length,
                totalSize: `${(sizeValidation.totalSize / 1024).toFixed(1)}KB`,
                hasExpiry: !!paste.expiry,
                hasBurnCount: !!body.burnAfterViews
            });
            
            return c.json({ id });
        } catch (error) {
            // Use the sanitizeMongoDBError function to prevent exposing schema details
            throw sanitizeMongoDBError(error);
        }
    } catch (error) {
        // This catch handles other errors not related to paste creation
        logger.error('Error in paste creation process', {
            error: error.message,
            stack: error.stack
        });
        throw error;
    }
}));

apiRouter.get('/api/paste/:id', async (c) => {
    try {
        const id = c.req.param('id');
        const paste = await Paste.findOne({ id });
        
        if (!paste) {
            return c.json({ error: 'Paste not found' }, 404);
        }
        
        // Check if paste is expired
        if (paste.checkExpiry()) {
            await archivePaste(paste);
            return c.json({ error: 'Paste has expired' }, 410);
        }
        
        // Handle private pastes
        if (paste.isPrivate) {
            const password = c.req.query('password');
            if (!password) {
                return c.json({ error: 'Password required', isPrivate: true }, 401);
            }
            
            // Verify password first
            const isValid = await paste.verifyPassword(password);
            if (isValid) {
                // Don't count view if it's the creator using improved IP detection
                const rateLimitResult = await createPasteLimiter.rateLimit(c);
                if (rateLimitResult.ip !== paste.creatorIp) {
                    paste.currentViews++;
                    await paste.save();
                }
                
                // Return paste data
                return c.json({
                    tabs: paste.tabs,
                    isPrivate: paste.isPrivate,
                    allowRaw: paste.allowRaw,
                    expiry: paste.expiry,
                    burnCount: paste.burnCount,
                    currentViews: paste.currentViews,
                    createdAt: paste.createdAt
                });
            }

            // Only check rate limit for failed attempts
            const rateLimitResult = await passwordAttemptLimiter.rateLimit(c, id);
            if (rateLimitResult.isLimited) {
                return c.json({
                    error: 'Too many password attempts',
                    timeLeft: rateLimitResult.timeLeft,
                    attemptsRemaining: 0
                }, 429);
            }
            
            // Password is invalid but not rate limited yet
            return c.json({
                error: 'Invalid password',
                attemptsRemaining: rateLimitResult.remainingAttempts
            }, 401);
        }
        
        // Don't count view if it's the creator using improved IP detection
        const rateLimitResult = await createPasteLimiter.rateLimit(c);
        if (rateLimitResult.ip !== paste.creatorIp) {
            paste.currentViews++;
            await paste.save();
        }
        
        // Return paste data
        return c.json({
            tabs: paste.tabs,
            isPrivate: paste.isPrivate,
            allowRaw: paste.allowRaw,
            expiry: paste.expiry,
            burnCount: paste.burnCount,
            currentViews: paste.currentViews,
            createdAt: paste.createdAt
        });
    } catch (error) {
        console.error('Error retrieving paste:', error);
        return c.json({ error: 'Failed to retrieve paste' }, 500);
    }
});

apiRouter.get('/api/paste/:id/raw', async (c) => {
    try {
        const id = c.req.param('id');
        const paste = await Paste.findOne({ id });
        
        if (!paste) {
            return c.text('Paste not found', 404);
        }
        
        // Check if paste is expired
        if (paste.checkExpiry()) {
            await archivePaste(paste);
            return c.text('Paste has expired', 410);
        }
        
        // Check if raw access is allowed
        if (!paste.allowRaw) {
            return c.text('Raw access not allowed for this paste', 403);
        }
        
        // Raw access not allowed for private pastes
        if (paste.isPrivate) {
            return c.text('Raw access not allowed for private pastes', 403);
        }
        
        // Raw access not allowed for multi-tab pastes
        if (paste.tabs.length > 1) {
            return c.text('Raw access not allowed for multi-tab pastes', 403);
        }
        
        // Don't count view if it's the creator using improved IP detection
        const rateLimitResult = await createPasteLimiter.rateLimit(c);
        if (rateLimitResult.ip !== paste.creatorIp) {
            paste.currentViews++;
            await paste.save();
        }
        
        // Return raw content
        return c.text(paste.tabs[0].content);
    } catch (error) {
        console.error('Error retrieving raw paste:', error);
        return c.text('Failed to retrieve paste', 500);
    }
});

apiRouter.post('/paste/:id/verify-password', async (c) => {
    try {
        const id = c.req.param('id');
        const paste = await Paste.findOne({ id });
        
        if (!paste) {
            return c.json({ error: 'Paste not found' }, 404);
        }
        
        if (!paste.isPrivate) {
            return c.json({ error: 'Paste is not private' }, 400);
        }
        
        // Check if paste is expired
        if (paste.checkExpiry()) {
            await archivePaste(paste);
            return c.json({ error: 'Paste has expired' }, 410);
        }

        const body = await c.req.json();
        if (!body || !body.password) {
            return c.json({ error: 'Password is required' }, 400);
        }

        // Verify password first
        const isValid = await paste.verifyPassword(body.password);

        // If password is correct, don't count this attempt towards rate limit
        if (isValid) {
            return c.json({ success: true });
        }

        // Only check rate limit for failed attempts
        const rateLimitResult = await passwordAttemptLimiter.rateLimit(c, id);
        
        // If rate limited, return time left
        if (rateLimitResult.isLimited) {
            return c.json({
                error: 'Too many password attempts',
                timeLeft: rateLimitResult.timeLeft,
                attemptsRemaining: 0
            }, 429);
        }
        
        // Password is invalid but not rate limited yet
        return c.json({
            error: 'Invalid password',
            attemptsRemaining: rateLimitResult.remainingAttempts
        }, 401);
    } catch (error) {
        // Generic error message without exposing details
        console.error('Error in password verification endpoint');
        return c.json({ error: 'Internal server error' }, 500);
    }
});

// View routes
viewRouter.get('/paste/:id', async (c) => {
    try {
        const id = c.req.param('id');
        
        // Generate a cryptographically secure nonce
        const nonce = randomBytes(16).toString('base64');
        
        // Set strict CSP headers
        c.header('Content-Security-Policy', `
            default-src 'none';
            script-src 'nonce-${nonce}' https://challenges.cloudflare.com https://cdnjs.cloudflare.com;
            style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com;
            img-src 'self' data: https://sa.bepasted.com;
            font-src 'self';
            connect-src 'self' https://sa.bepasted.com;
            base-uri 'none';
            form-action 'self';
            frame-ancestors 'none';
        `.replace(/\s+/g, ' ').trim());
        
        const paste = await Paste.findOne({ id });
        
        if (!paste) {
            const domain = getDomain();
            return c.html(`
                <!DOCTYPE html>
                <html lang="en">
                <head>
                    <meta charset="UTF-8">
                    <meta name="description" content="Paste not found on BePasted - A free, no-login text and code sharing service." />
                    <meta property="og:title" content="BePasted - Paste Not Found" />
                    <meta name="csrf-token" content="${c.get('csrfToken') || ''}" />
                    <meta property="og:description" content="Paste not found on BePasted - A free, no-login text and code sharing service." />
                    <meta property="og:type" content="website" />
                    <meta property="og:url" content="${domain}/paste/${escapeHtml(id)}" />
                    <meta property="og:image" content="${domain}/assets/banner.png" />
                    <meta property="og:image:width" content="1200" />
                    <meta property="og:image:height" content="630" />
                    <meta name="twitter:card" content="summary_large_image" />
                    <meta name="twitter:title" content="BePasted - Paste Not Found" />
                    <meta name="twitter:description" content="Paste not found on BePasted - A free, no-login text and code sharing service." />
                    <meta name="twitter:image" content="${domain}/assets/be-logo-64x64.webp" />
                    <meta name="twitter:url" content="${domain}/paste/${escapeHtml(id)}" />
                    <meta name="robots" content="noindex, follow" />
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <meta name="theme-color" content="#0f5132" />
                    <meta name="color-scheme" content="light dark" />
                    <link rel="icon" type="image/x-icon" href="/favicon.ico" />
                    <link rel="icon" type="image/png" sizes="32x32" href="/assets/be-logo-256x256.png" />
                    <link rel="icon" type="image/png" sizes="16x16" href="/assets/be-logo-6xs64.webp" />
                    <link rel="apple-touch-icon" sizes="180x180" href="/assets/be-logo-64x64.webp" />
                    <title>404 - Paste Not Found - BePasted</title>
                    <link rel="stylesheet" href="/css/style.css">
                    ${injectSimpleAnalytics(nonce)}
                </head>
                <body>
                    <header>
                        <h1 class="logo-container">
                            <a href="/">
                                <img src="/assets/banner.png" alt="BePasted" class="banner-image">
                            </a>
                            <div class="custom-divider"></div>
                        </h1>
                    </header>
                    
                    <main>
                        <div class="error-container">
                            <h2>404 - Paste Not Found</h2>
                            <p>The paste you are looking for does not exist or has been removed.</p>
                            <a href="/" class="home-button">Create New Paste</a>
                        </div>

                        <footer class="credits-container">
                            <div class="nav-container">
                                <a href="/" class="credits-button">← Back to Home</a>
                                <a href="/credits" class="credits-button">Credits</a>
                                <a href="/privacy-policy" class="credits-button">Privacy</a>
                                <a href="/tos" class="credits-button">Terms</a>
                            </div>

                            <div class="footer-content">
                                <p class="copyright-text">BePasted is a product of <a href="https://respy.tech" target="_blank" rel="noopener noreferrer" class="company-link">Respy.Tech</a>. &copy; 2025 <a href="https://respy.tech" target="_blank" rel="noopener noreferrer" class="company-link">Respy.Tech</a>. All rights reserved.</p>
                            </div>
                        </footer>
                    </main>
                </body>
                </html>
            `, 404);
        }
        
        // Check if paste is expired
        if (paste.checkExpiry()) {
            await archivePaste(paste);
            const domain = getDomain();
            return c.html(`
                <!DOCTYPE html>
                <html lang="en">
                <head>
                    <meta charset="UTF-8">
                    <meta name="description" content="This paste has expired on BePasted - A free, no-login text and code sharing service." />
                    <meta property="og:title" content="BePasted - Paste Has Expired" />
                    <meta name="csrf-token" content="${c.get('csrfToken') || ''}" />
                    <meta property="og:description" content="This paste has expired on BePasted - A free, no-login text and code sharing service." />
                    <meta property="og:type" content="website" />
                    <meta property="og:url" content="${domain}/paste/${escapeHtml(id)}" />
                    <meta property="og:image" content="${domain}/assets/banner.png" />
                    <meta property="og:image:width" content="1200" />
                    <meta property="og:image:height" content="630" />
                    <meta name="twitter:card" content="summary_large_image" />
                    <meta name="twitter:title" content="BePasted - Paste Has Expired" />
                    <meta name="twitter:description" content="This paste has expired on BePasted - A free, no-login text and code sharing service." />
                    <meta name="twitter:image" content="${domain}/assets/be-logo-64x64.webp" />
                    <meta name="twitter:url" content="${domain}/paste/${escapeHtml(id)}" />
                    <meta name="robots" content="noindex, follow" />
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <meta name="theme-color" content="#0f5132" />
                    <meta name="color-scheme" content="light dark" />
                    <link rel="icon" type="image/x-icon" href="/favicon.ico" />
                    <link rel="icon" type="image/png" sizes="32x32" href="/assets/be-logo-256x256.png" />
                    <link rel="icon" type="image/png" sizes="16x16" href="/assets/be-logo-6xs64.webp" />
                    <link rel="apple-touch-icon" sizes="180x180" href="/assets/be-logo-64x64.webp" />
                    <title>410 - Paste Has Expired - BePasted</title>
                    <link rel="stylesheet" href="/css/style.css">
                    ${injectSimpleAnalytics(nonce)}
                </head>
                <body>
                    <header>
                        <h1 class="logo-container">
                            <a href="/">
                                <img src="/assets/banner.png" alt="BePasted" class="banner-image">
                            </a>
                            <div class="custom-divider"></div>
                        </h1>
                    </header>
                    
                    <main>
                        <div class="error-container">
                            <h2>410 - Paste Has Expired</h2>
                            <p>This paste has expired ${paste.expiry?.expiresAt ? 'due to time limit' : 'due to view limit'}.</p>
                            <p>Expired pastes are archived and cannot be restored.</p>
                            <a href="/" class="home-button">Create New Paste</a>
                        </div>

                        <footer class="credits-container">
                            <div class="nav-container">
                                <a href="/" class="credits-button">← Back to Home</a>
                                <a href="/credits" class="credits-button">Credits</a>
                                <a href="/privacy-policy" class="credits-button">Privacy</a>
                                <a href="/tos" class="credits-button">Terms</a>
                            </div>

                            <div class="footer-content">
                                <p class="copyright-text">BePasted is a product of <a href="https://respy.tech" target="_blank" rel="noopener noreferrer" class="company-link">Respy.Tech</a>. &copy; 2025 <a href="https://respy.tech" target="_blank" rel="noopener noreferrer" class="company-link">Respy.Tech</a>. All rights reserved.</p>
                            </div>
                        </footer>
                    </main>
                </body>
                </html>
            `, 410);
        }
        
        // If paste is private, show password form
        if (paste.isPrivate) {
            const password = c.req.query('password');
            if (!password) {
                return c.html(`
                    <!DOCTYPE html>
                    <html lang="en">
                    <head>
                        <meta charset="UTF-8">
                        <meta name="viewport" content="width=device-width, initial-scale=1.0">
                        <title>Password Required - BePasted</title>
                        <meta name="csrf-token" content="${c.get('csrfToken') || ''}" />
                        <meta name="theme-color" content="#0f5132" />
                        <meta name="color-scheme" content="light dark" />
                        <link rel="stylesheet" href="/css/style.css">
                        ${injectSimpleAnalytics(nonce)}
                        <script nonce="${nonce}">
                            document.addEventListener('DOMContentLoaded', () => {
                                const form = document.getElementById('password-form');
                                const passwordInput = document.getElementById('password-input');
                                const errorText = document.getElementById('password-error');
                                const submitButton = document.querySelector('button[type="submit"]');

                                const pasteId = '${escapeHtml(id)}'; // Escape ID for additional security

                                form.addEventListener('submit', async (e) => {
                                    e.preventDefault();
                                    submitButton.disabled = true;
                                    errorText.textContent = ''; // Clear previous error

                                    try {
                                        const response = await fetch('/paste/' + pasteId + '/verify-password', {
                                            method: 'POST',
                                            headers: {
                                                'Content-Type': 'application/json',
                                                'Accept': 'application/json',
                                                'X-CSRF-Token': document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || ''
                                            },
                                            body: JSON.stringify({
                                                password: passwordInput.value
                                            })
                                        });

                                        const data = await response.json();

                                        if (response.status === 429) {
                                            // Rate limited
                                            errorText.textContent = \`Too many attempts. Please try again in \${Math.ceil(data.timeLeft / 1000)} seconds.\`;
                                            startCountdown(data.timeLeft);
                                        } else if (!response.ok) {
                                            if (data.error && data.attemptsRemaining !== undefined) {
                                                errorText.textContent = \`\${data.error}. \${data.attemptsRemaining} attempts remaining.\`;
                                            } else {
                                                errorText.textContent = data.error || 'Invalid password';
                                            }
                                        } else {
                                            // Success - redirect with password
                                            window.location.href = '/paste/' + pasteId + '?password=' + encodeURIComponent(passwordInput.value);
                                            return;
                                        }
                                    } catch (error) {
                                        // Remove detailed error logging
                                        errorText.textContent = 'An error occurred. Please try again.';
                                    }

                                    submitButton.disabled = false;
                                });

                                function startCountdown(timeLeft) {
                                    const updateTimer = () => {
                                        const secondsLeft = Math.ceil(timeLeft / 1000);
                                        errorText.textContent = \`Too many attempts. Please try again in \${secondsLeft} seconds.\`;
                                        timeLeft -= 1000;

                                        if (timeLeft > 0) {
                                            setTimeout(updateTimer, 1000);
                                        } else {
                                            errorText.textContent = '';
                                            submitButton.disabled = false;
                                        }
                                    };
                                    updateTimer();
                                }
                            });
                        </script>
                    </head>
                    <body>
                        <header>
                            <h1 class="logo-container">
                                <a href="/">
                                    <img src="/assets/banner.png" alt="BePasted" class="banner-image">
                                </a>
                                <div class="custom-divider"></div>
                            </h1>
                        </header>
                        
                        <main>
                            <div class="password-container">
                                <h2>Password Required</h2>
                                <p>This paste is password protected.</p>
                                <form id="password-form">
                                    <div class="password-input-container">
                                        <input type="password" id="password-input" placeholder="Enter password" required>
                                        <p id="password-error" class="error-text"></p>
                                    </div>
                                    <button type="submit" class="submit-button">Submit</button>
                                </form>
                            </div>
                        </main>
                        
                        <footer class="credits-container">
                        <div class="nav-container">
                            <a href="/" class="credits-button">← Back to Home</a>
                            <a href="/credits" class="credits-button">Credits</a>
                            <a href="/privacy-policy" class="credits-button">Privacy</a>
                            <a href="/tos" class="credits-button">Terms</a>
                        </div>
                        
                            <div class="footer-content">
                                <p class="copyright-text">BePasted is a product of <a href="https://respy.tech" target="_blank" rel="noopener noreferrer" class="company-link">Respy.Tech</a>. &copy; 2025 <a href="https://respy.tech" target="_blank" rel="noopener noreferrer" class="company-link">Respy.Tech</a>. All rights reserved.</p>
                            </div>
                        </footer>
                    </body>
                    </html>
                `);
            }
        }

        // Update view count if needed using improved IP detection
        const rateLimitResult = await createPasteLimiter.rateLimit(c);
        if (rateLimitResult.ip !== paste.creatorIp && paste.burnCount && !paste.isExpired) {
            paste.currentViews++;
            if (paste.currentViews >= paste.burnCount) {
                paste.isExpired = true;
            }
            await paste.save();
        }

        // Get domain for meta tags
        const domain = getDomain();
        
        // Serve the view page
        return c.html(`
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="description" content="View the paste ${escapeHtml(id)} on BePasted - A free, no-login text and code sharing service." />
                <meta property="og:title" content="BePasted - Paste ${escapeHtml(id)}" />
                <meta property="og:description" content="View the paste ${escapeHtml(id)} on BePasted - A free, no-login text and code sharing service." />
                <meta property="og:type" content="website" />
                <meta property="og:url" content="${domain}/paste/${escapeHtml(id)}" />
                <meta property="og:image" content="${domain}/assets/banner.png" />
                <meta property="og:image:width" content="1200" />
                <meta property="og:image:height" content="630" />
                <meta name="twitter:card" content="summary_large_image" />
                <meta name="twitter:title" content="BePasted - Paste ${escapeHtml(id)}" />
                <meta name="twitter:description" content="View the paste ${escapeHtml(id)} on BePasted - A free, no-login text and code sharing service." />
                <meta name="twitter:image" content="${domain}/assets/be-logo-64x64.webp" />
                <meta name="twitter:url" content="${domain}/paste/${escapeHtml(id)}" />
                <meta name="keywords" content="BePasted, code sharing, text sharing, paste service, code snippets, text snippets" />
                <meta name="robots" content="index, follow" />
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <meta name="theme-color" content="#0f5132" />
                <meta name="color-scheme" content="light dark" />
                <link rel="canonical" href="${domain}/paste/${escapeHtml(id)}">
                <link rel="icon" type="image/x-icon" href="/favicon.ico" />
                <link rel="icon" type="image/png" sizes="32x32" href="/assets/be-logo-256x256.png" />
                <link rel="icon" type="image/png" sizes="16x16" href="/assets/be-logo-6xs64.webp" />
                <link rel="apple-touch-icon" sizes="180x180" href="/assets/be-logo-64x64.webp" />
                <title>BePasted - Paste ${escapeHtml(id)}</title>
                <link rel="stylesheet" href="/css/style.css">
                ${injectSimpleAnalytics(nonce)}
                <script nonce="${nonce}" src="/js/paste-view.js" type="module"></script>
                <script nonce="${nonce}" src="/js/syntax-highlight.js"></script>
                <meta name="csrf-token" content="${c.get('csrfToken') || ''}" />
            </head>
            <body>
                <header>
                    <h1 class="logo-container">
                        <a href="/">
                            <img src="/assets/banner.png" alt="BePasted" class="banner-image">
                        </a>
                        <div class="custom-divider"></div>
                    </h1>
                </header>
                
                <main>
                    <div class="paste-info">
                        <div class="paste-header">
                            <h2>Paste #${escapeHtml(id)}</h2>
                            <div class="paste-metadata">
                                <div class="metadata-item">
                                    <span class="metadata-label">Expires:</span>
                                    <span class="metadata-value">${paste.expiry?.expiresAt ? 
                                        `in ${Math.ceil((paste.expiry.expiresAt - Date.now()) / 1000)} seconds` : 
                                        'Never'
                                    }</span>
                                </div>
                                ${paste.burnCount ? `
                                <div class="metadata-item">
                                    <span class="metadata-label">Views:</span>
                                    <span class="metadata-value">${paste.currentViews.toLocaleString()}/${paste.burnCount.toLocaleString()}</span>
                                </div>` : ''}
                            </div>
                            
                            <div class="paste-actions">
                                ${paste.allowRaw ? `
                                <a href="/paste/${escapeHtml(id)}/raw" class="raw-link">
                                    <svg width="16" height="16" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg">
                                        <path d="M8 0L14 4V12L8 16L2 12V4L8 0Z" stroke="currentColor" stroke-width="1.5"/>
                                        <path d="M8 8V16M8 8L2 4M8 8L14 4" stroke="currentColor" stroke-width="1.5"/>
                                    </svg>
                                    View Raw
                                </a>` : ''}
                                
                                <button id="copy-button" class="copy-button" title="Copy Current Tab Content">
                                    <svg width="16" height="16" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg">
                                        <path d="M13 5H7C5.89543 5 5 5.89543 5 7V13C5 14.1046 5.89543 15 7 15H13C14.1046 15 15 14.1046 15 13V7C15 5.89543 14.1046 5 13 5Z" stroke="currentColor" stroke-width="1.5"/>
                                        <path d="M3 11H2C0.895431 11 0 10.1046 0 9V3C0 1.89543 0.895431 1 2 1H8C9.10457 1 10 1.89543 10 3V4" stroke="currentColor" stroke-width="1.5"/>
                                    </svg>
                                    Copy
                                </button>
                                
                                <button id="report-button" class="report-button" title="Report This Paste">
                                    <svg width="16" height="16" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg">
                                        <path d="M8 1.5V3M8 13V14.5M14.5 8H13M3 8H1.5M12.3 12.3L11.3 11.3M12.3 3.7L11.3 4.7M3.7 3.7L4.7 4.7M3.7 12.3L4.7 11.3M8 5V8M8 11H8.01M14.5 8C14.5 11.5899 11.5899 14.5 8 14.5C4.41015 14.5 1.5 11.5899 1.5 8C1.5 4.41015 4.41015 1.5 8 1.5C11.5899 1.5 14.5 4.41015 14.5 8Z" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
                                    </svg>
                                    Report
                                </button>
                            </div>
                        </div>
                    </div>

                    <div id="tabs-container">
                        <div id="tabs">
                            ${paste.tabs.map((tab, index) => `
                                <button class="tab${index === 0 ? ' active' : ''}" data-tab="${index + 1}">
                                    <span class="tab-name">${escapeHtml(tab.name)}</span>
                                </button>
                            `).join('')}
                        </div>
                    </div>
                    
                    <div id="editor-container">
                        ${paste.tabs.map((tab, index) => `
                            <div class="editor-wrapper${index === 0 ? ' active' : ''}" data-tab="${index + 1}">
                                <div class="line-numbers">
                                    <div class="line-numbers-content"></div>
                                </div>
                                <pre class="paste-content">${escapeHtml(tab.content)}</pre>
                            </div>
                        `).join('')}
                    </div>

                    <footer class="credits-container">
                        <div class="nav-container">
                            <a href="/" class="credits-button">← Back to Home</a>
                            <a href="/credits" class="credits-button">Credits</a>
                            <a href="/privacy-policy" class="credits-button">Privacy</a>
                            <a href="/tos" class="credits-button">Terms</a>
                        </div>

                        <div class="footer-content">
                            <p class="copyright-text">BePasted is a product of <a href="https://respy.tech" target="_blank" rel="noopener noreferrer" class="company-link">Respy.Tech</a>. &copy; 2025 <a href="https://respy.tech" target="_blank" rel="noopener noreferrer" class="company-link">Respy.Tech</a>. All rights reserved.</p>
                        </div>
                    </footer>
                </main>
                
                <!-- Report Modal -->
                <div id="report-modal" class="modal">
                    <div class="modal-content">
                        <div class="modal-header">
                            <h3>Report Inappropriate Content</h3>
                            <button class="close-modal">&times;</button>
                        </div>
                        <div class="modal-body">
                            <p>Please provide details about why you're reporting this paste:</p>
                            <textarea id="report-reason" placeholder="Describe the issue with this paste (e.g., contains harmful content, violates terms of service, etc.)" rows="4"></textarea>
                        </div>
                        <div class="modal-footer">
                            <div id="report-status" class="hidden">
                                <div class="status-icon success hidden">
                                    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                                        <circle cx="12" cy="12" r="10" stroke="currentColor" stroke-width="2" fill="none"/>
                                        <path d="M8 12L11 15L16 9" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                                    </svg>
                                    <span>Thank you! Your report has been submitted.</span>
                                </div>
                                <div class="status-icon error hidden">
                                    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                                        <circle cx="12" cy="12" r="10" stroke="currentColor" stroke-width="2" fill="none"/>
                                        <path d="M12 8V12M12 16H12.01" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
                                    </svg>
                                    <span>Oops, something went wrong.</span>
                                </div>
                            </div>
                            <div class="loading-spinner hidden"></div>
                            <button id="submit-report">Submit Report</button>
                        </div>
                    </div>
                </div>

                <script nonce="${nonce}">
                    // Initialize report functionality
                    document.addEventListener('DOMContentLoaded', () => {
                        const reportButton = document.getElementById('report-button');
                        const reportModal = document.getElementById('report-modal');
                        const closeModalBtn = document.querySelector('.close-modal');
                        const submitReportBtn = document.getElementById('submit-report');
                        const reportReason = document.getElementById('report-reason');
                        const reportStatus = document.getElementById('report-status');
                        const loadingSpinner = document.querySelector('.loading-spinner');
                        const successStatus = document.querySelector('.status-icon.success');
                        const errorStatus = document.querySelector('.status-icon.error');
                        
                        // Show modal
                        reportButton.addEventListener('click', () => {
                            reportModal.classList.add('show');
                            reportReason.focus();
                        });
                        
                        // Close modal on X button or outside click
                        closeModalBtn.addEventListener('click', () => {
                            reportModal.classList.remove('show');
                        });
                        
                        window.addEventListener('click', (e) => {
                            if (e.target === reportModal) {
                                reportModal.classList.remove('show');
                            }
                        });
                        
                        // Submit report
                        submitReportBtn.addEventListener('click', async () => {
                            const reason = reportReason.value.trim();
                            if (!reason) {
                                reportReason.classList.add('error');
                                return;
                            }
                            
                            reportReason.classList.remove('error');
                            
                            // Show loading spinner
                            submitReportBtn.disabled = true;
                            loadingSpinner.classList.remove('hidden');
                            reportStatus.classList.add('hidden');
                            successStatus.classList.add('hidden');
                            errorStatus.classList.add('hidden');
                            
                            try {
                                const response = await fetch('/paste/${escapeHtml(id)}/report', {
                                    method: 'POST',
                                    headers: {
                                        'Content-Type': 'application/json',
                                        'X-CSRF-Token': document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || ''
                                    },
                                    body: JSON.stringify({ reason })
                                });
                                
                                const result = await response.json();
                                
                                // Hide loading spinner
                                loadingSpinner.classList.add('hidden');
                                reportStatus.classList.remove('hidden');
                                
                                if (response.ok && result.success) {
                                    // Show success message
                                    successStatus.classList.remove('hidden');
                                    
                                    // Clear input and close modal after delay
                                    setTimeout(() => {
                                        reportModal.classList.remove('show');
                                        reportReason.value = '';
                                        successStatus.classList.add('hidden');
                                        submitReportBtn.disabled = false;
                                    }, 2000);
                                } else {
                                    // Show error message
                                    errorStatus.querySelector('span').textContent = result.error || 'Oops, something went wrong.';
                                    errorStatus.classList.remove('hidden');
                                    submitReportBtn.disabled = false;
                                }
                            } catch (error) {
                                // Show error message
                                loadingSpinner.classList.add('hidden');
                                reportStatus.classList.remove('hidden');
                                errorStatus.classList.remove('hidden');
                                submitReportBtn.disabled = false;
                            }
                        });
                    });
                </script>
            </body>
            </html>
        `);
    } catch (error) {
        console.error('Error serving paste view:', error);
        return c.html('<h1>500 - Internal Server Error</h1>', 500);
    }
});

viewRouter.get('/paste/:id/raw', async (c) => {
    try {
        const id = c.req.param('id');
        const paste = await Paste.findOne({ id });
        
        if (!paste) {
            return c.text('Paste not found', 404);
        }
        
        // Check if paste is expired
        if (paste.checkExpiry()) {
            await archivePaste(paste);
            return c.text('Paste has expired', 410);
        }
        
        // Check if raw access is allowed
        if (!paste.allowRaw) {
            return c.text('Raw access not allowed for this paste', 403);
        }
        
        // Raw access not allowed for private pastes
        if (paste.isPrivate) {
            return c.text('Raw access not allowed for private pastes', 403);
        }
        
        // Raw access not allowed for multi-tab pastes
        if (paste.tabs.length > 1) {
            return c.text('Raw access not allowed for multi-tab pastes', 403);
        }
        
        // Don't count view if it's the creator using improved IP detection
        const rateLimitResult = await createPasteLimiter.rateLimit(c);
        if (rateLimitResult.ip !== paste.creatorIp) {
            paste.currentViews++;
            await paste.save();
        }
        
        // Set content type to plain text and return raw content
        c.header('Content-Type', 'text/plain; charset=utf-8');
        return c.text(paste.tabs[0].content);
    } catch (error) {
        console.error('Error retrieving raw paste:', error);
        return c.text('Failed to retrieve paste', 500);
    }
});

// Helper function to archive expired pastes
async function archivePaste(paste) {
    if (!paste.isExpired) return;

    try {
        // Create archive data object
        const archiveData = {
            originalId: paste.id,
            tabs: paste.tabs,
            isPrivate: paste.isPrivate,
            allowRaw: paste.allowRaw,
            burnCount: paste.burnCount,
            finalViews: paste.currentViews,
            createdAt: paste.createdAt,
            expiredAt: new Date(),
            expiryReason: paste.expiry?.expiresAt && Date.now() > paste.expiry.expiresAt ? 'time' : 'views'
        };

        // Only include expiry if it exists and has all required fields
        const expiry = paste.expiry;
        if (expiry && expiry.value && expiry.unit && expiry.expiresAt) {
            archiveData.expiry = {
                value: expiry.value,
                unit: expiry.unit,
                expiresAt: expiry.expiresAt
            };
        }

        const archive = new ArchivedPaste(archiveData);
        await archive.save();
        await paste.deleteOne();
    } catch (error) {
        console.error('Error archiving paste:', error);
        throw error;
    }
}

// Simple rate limiter for report endpoint
const reportLimiterMap = new Map(); // IP -> { timestamp, count }
const REPORT_LIMIT_WINDOW = 60 * 1000; // 1 minute window
const REPORT_LIMIT_MAX = 3; // 3 reports per minute

// Helper function to extract IP address from request
function getClientIP(c) {
    // Convert Hono's header getter to headers object
    const headers = {
        'cf-connecting-ip': c.req.header('cf-connecting-ip'),
        'x-real-ip': c.req.header('x-real-ip'),
        'x-client-ip': c.req.header('x-client-ip'),
        'x-forwarded-for': c.req.header('x-forwarded-for'),
        'x-session-token': c.req.header('x-session-token')
    };
    
    // Validate IP and get session info
    const ipInfo = ipValidator.extractIP(headers);
    return ipInfo.ip;
}

// Report paste endpoint with improved error handling
apiRouter.post('/paste/:id/report', asyncErrorHandler(async (c) => {
    // Rate limit check
    const ip = getClientIP(c);
    const now = Date.now();
    
    // Clean up old entries
    for (const [storedIp, data] of reportLimiterMap.entries()) {
        if (now - data.timestamp > REPORT_LIMIT_WINDOW) {
            reportLimiterMap.delete(storedIp);
        }
    }
    
    // Check if IP is rate limited
    const ipData = reportLimiterMap.get(ip) || { timestamp: now, count: 0 };
    
    // If window has passed, reset
    if (now - ipData.timestamp > REPORT_LIMIT_WINDOW) {
        ipData.timestamp = now;
        ipData.count = 0;
    }
    
    // Check if over limit
    if (ipData.count >= REPORT_LIMIT_MAX) {
        throw createError(
            'Too many reports from this IP, please try again later',
            ErrorTypes.RATE_LIMIT
        );
    }
    
    // Increment count
    ipData.count++;
    reportLimiterMap.set(ip, ipData);

    const id = c.req.param('id');
    const reporterIp = ip;

    // Get the request body data, prioritizing the cached body if available
    let reason;
    try {
        // Use the new helper function to get cached request body
        const cachedBody = getCachedRequestBody(c);
        
        if (cachedBody) {
            // Parse the cached JSON manually
            try {
                const bodyData = JSON.parse(cachedBody);
                reason = bodyData.reason;
                logger.info('Successfully retrieved cached request body for report', {
                    bodySize: cachedBody.length,
                    path: c.req.path
                });
            } catch (parseError) {
                logger.error('Failed to parse cached JSON body for report', {
                    error: parseError.message,
                    path: c.req.path
                });
                throw createError('Invalid JSON in request body', ErrorTypes.BAD_REQUEST);
            }
        } else {
            // If no cached body is found, try to use safeParseJSON as a last resort
            logger.warn('No cached body found for report endpoint, falling back to safeParseJSON', {
                path: c.req.path
            });
            const bodyData = await safeParseJSON(c.req);
            reason = bodyData.reason;
        }
    } catch (error) {
        logger.error('Error retrieving request body for report', {
            error: error.message,
            path: c.req.path,
            hasCachedBody: !!getCachedRequestBody(c)
        });
        throw createError('Failed to read request body', ErrorTypes.BAD_REQUEST);
    }

    // Validate report reason
    if (!reason || typeof reason !== 'string' || reason.trim().length === 0) {
        throw createError(
            'Please provide a valid reason for your report',
            ErrorTypes.VALIDATION
        );
    }

    // Find the paste
    const paste = await Paste.findOne({ id: id });
    if (!paste) {
        throw createError(
            'Paste not found',
            ErrorTypes.NOT_FOUND
        );
    }

    // Create a report with limited paste data for admin review
    try {
        await ReportedPaste.create({
            pasteId: id,
            reason: reason.trim(),
            reporterIp,
            pasteData: {
                pasteId: id,
                content: paste.tabs.map(tab => tab.content).join('\n\n--- Tab Separator ---\n\n'),
                isPrivate: paste.isPrivate,
                isExpired: paste.isExpired,
                creatorIp: paste.creatorIp,
                createdAt: paste.createdAt
            }
        });
    } catch (err) {
        // Check for duplicate key error (user already reported this paste)
        if (err.code === 11000) {
            throw createError(
                'You have already reported this paste',
                ErrorTypes.VALIDATION
            );
        }
        throw sanitizeMongoDBError(err);
    }

    return c.json({ success: true });
}));

export const pasteRoutes = {
    api: apiRouter,
    view: viewRouter
};
