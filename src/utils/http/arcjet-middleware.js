import arcjet, { shield } from "@arcjet/node";
import config from '../config/config.js';
import logger from '../logging/logger.js';

let mode;
if(config.NODE_ENV === 'development') {
  mode = 'DRY_RUN';
} else {
  mode = 'LIVE';
}

// Initialize Arcjet with configuration
const aj = arcjet({
  key: config.ARCJET_KEY,
  rules: [
    shield({
      mode,
      environment: config.ARCJET_ENV,
    }),
  ],
});

/**
 * Middleware function for Arcjet protection
 * @param {Object} c - Hono context
 * @param {Function} next - Next middleware function
 * @returns {Promise} - Promise that resolves to the next middleware or error response
 */
export async function arcjetProtect(c, next) {
  try {
    const decision = await aj.protect(c.env.incoming);

    if (decision.isDenied()) {
      logger.warn('Arcjet protection denied request', {
        path: c.req.path,
        ip: c.req.header('cf-connecting-ip') || c.req.header('x-real-ip'),
        reason: decision.reason || 'unknown'
      });
      return c.json({ error: "Forbidden. Protected by Arcjet." }, 403);
    }

    return next();
  } catch (error) {
    logger.error('Arcjet protection error', { error: error.message });
    return c.json({ error: "Security service error" }, 500);
  }
} 