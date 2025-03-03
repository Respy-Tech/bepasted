import { ipValidator } from './ip-validator.js';

class RateLimiter {
    constructor(windowMs, max) {
        this.windowMs = windowMs;
        this.max = max;
        this.hits = new Map();
        this.sessionHits = new Map();
        this.resourceHits = new Map(); // Track hits per resource (e.g., paste ID)
    }

    /**
     * Rate limits based on IP, session if available, and optionally a resource ID
     * @param {Object} c - Hono context
     * @param {string} resourceId - Optional resource ID to track separately (e.g., paste ID)
     * @returns {Object} Rate limit result
     */
    async rateLimit(c, resourceId = null) {
        const now = Date.now();
        
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
        const sessionToken = headers['x-session-token'];
        
        // If IP is suspicious, apply stricter rate limiting
        const effectiveMax = ipInfo.suspicious ? Math.floor(this.max / 2) : this.max;
        
        // Create unique keys for this request
        const ipKey = resourceId ? `${ipInfo.ip}:${resourceId}` : ipInfo.ip;
        const sessionKey = resourceId && sessionToken ? `${sessionToken}:${resourceId}` : sessionToken;
        
        // Get hits for IP, session, and resource
        const ipHits = this.hits.get(ipKey) || [];
        const sessionHits = sessionKey ? (this.sessionHits.get(sessionKey) || []) : [];
        const resourceHits = resourceId ? (this.resourceHits.get(resourceId) || []) : [];
        
        // Remove expired hits
        const validIpHits = ipHits.filter(hit => now - hit < this.windowMs);
        const validSessionHits = sessionHits.filter(hit => now - hit < this.windowMs);
        const validResourceHits = resourceHits.filter(hit => now - hit < this.windowMs);
        
        // Update hits
        this.hits.set(ipKey, validIpHits);
        if (sessionKey) this.sessionHits.set(sessionKey, validSessionHits);
        if (resourceId) this.resourceHits.set(resourceId, validResourceHits);
        
        // Check if either IP, session, or resource has exceeded max attempts
        const isIpLimited = validIpHits.length >= effectiveMax;
        const isSessionLimited = sessionToken && validSessionHits.length >= effectiveMax;
        const isResourceLimited = resourceId && validResourceHits.length >= (effectiveMax * 2); // Allow more attempts per resource
        
        const timeLeft = Math.min(
            validIpHits[0] || Infinity,
            validSessionHits[0] || Infinity,
            validResourceHits[0] || Infinity
        ) + this.windowMs - now;
        
        // Calculate remaining attempts (use the most restrictive limit)
        const remainingAttempts = Math.max(0, effectiveMax - Math.max(
            validIpHits.length,
            sessionToken ? validSessionHits.length : 0,
            resourceId ? Math.floor(validResourceHits.length / 2) : 0
        ));
        
        // If we have no remaining attempts, we are limited
        const isLimited = remainingAttempts === 0 || isIpLimited || isSessionLimited || isResourceLimited;
        
        // Only add new hit if we still have attempts remaining
        if (!isLimited) {
            validIpHits.push(now);
            if (sessionKey) validSessionHits.push(now);
            if (resourceId) validResourceHits.push(now);
            
            this.hits.set(ipKey, validIpHits);
            if (sessionKey) this.sessionHits.set(sessionKey, validSessionHits);
            if (resourceId) this.resourceHits.set(resourceId, validResourceHits);
        }
        
        return {
            isLimited,
            timeLeft: timeLeft > 0 ? timeLeft : 0,
            ip: ipInfo.ip,
            anonymizedIP: ipInfo.anonymizedIP,
            suspicious: ipInfo.suspicious,
            remainingAttempts
        };
    }

    /**
     * Get remaining attempts for an IP
     * @param {string} ip - IP address
     * @returns {number} Number of attempts remaining
     */
    getRemainingAttempts(ip) {
        const now = Date.now();
        const hits = this.hits.get(ip) || [];
        const validHits = hits.filter(hit => now - hit < this.windowMs);
        return Math.max(0, this.max - validHits.length);
    }

    // Clean up old entries periodically
    cleanup() {
        const now = Date.now();
        
        // Clean up IP hits
        for (const [ip, hits] of this.hits.entries()) {
            const validHits = hits.filter(hit => now - hit < this.windowMs);
            if (validHits.length === 0) {
                this.hits.delete(ip);
            } else {
                this.hits.set(ip, validHits);
            }
        }
        
        // Clean up session hits
        for (const [session, hits] of this.sessionHits.entries()) {
            const validHits = hits.filter(hit => now - hit < this.windowMs);
            if (validHits.length === 0) {
                this.sessionHits.delete(session);
            } else {
                this.sessionHits.set(session, validHits);
            }
        }
        
        // Clean up resource hits
        for (const [resource, hits] of this.resourceHits.entries()) {
            const validHits = hits.filter(hit => now - hit < this.windowMs);
            if (validHits.length === 0) {
                this.resourceHits.delete(resource);
            } else {
                this.resourceHits.set(resource, validHits);
            }
        }
    }
}

// Create instances for different rate limits
export const createPasteLimiter = new RateLimiter(60 * 1000, 10); // 10 requests per minute
export const passwordAttemptLimiter = new RateLimiter(60 * 1000, 6); // 6 attempts per minute (3 for suspicious IPs)

// Run cleanup every minute
setInterval(() => {
    createPasteLimiter.cleanup();
    passwordAttemptLimiter.cleanup();
}, 60 * 1000);
