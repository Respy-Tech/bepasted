import crypto from 'crypto';
import IPAnonymizer from '../security/ip-anonymizer.js';
import logger from '../logging/logger.js';

/**
 * Validates and extracts client IP with additional security measures
 * while respecting privacy through anonymization
 */
class IPValidator {
    constructor() {
        // Store validated IPs with their first seen timestamp
        this.validatedIPs = new Map();
        
        // Store session tokens mapped to anonymized IPs
        this.sessions = new Map();
        
        // Store suspicious activity counts
        this.suspiciousActivity = new Map();
        
        // Clean up old entries every hour
        setInterval(() => this.cleanup(), 60 * 60 * 1000);
        
        logger.info('IP Validator initialized with privacy protection');
    }

    /**
     * Validates IP address format
     */
    isValidIPFormat(ip) {
        // IPv4 validation
        const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
        if (ipv4Regex.test(ip)) {
            const parts = ip.split('.');
            return parts.every(part => {
                const num = parseInt(part, 10);
                return num >= 0 && num <= 255;
            });
        }
        
        // IPv6 validation
        const ipv6Regex = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
        return ipv6Regex.test(ip);
    }

    /**
     * Extracts client IP from request headers with validation
     */
    extractIP(headers) {
        // Priority order of headers
        const ipHeaders = [
            'cf-connecting-ip',      // Cloudflare
            'x-real-ip',            // Nginx
            'x-client-ip',          // Apache
            'x-forwarded-for'       // Standard proxy header
        ];

        let clientIP = null;
        let headerUsed = null;

        // Try to get IP from trusted headers
        for (const header of ipHeaders) {
            const value = headers[header];
            if (value) {
                // For x-forwarded-for, take the first IP in the list
                const ip = header === 'x-forwarded-for' 
                    ? value.split(',')[0].trim()
                    : value;
                
                if (this.isValidIPFormat(ip)) {
                    clientIP = ip;
                    headerUsed = header;
                    break;
                }
            }
        }

        if (!clientIP) {
            // If no valid IP found, mark as suspicious
            logger.warn('No valid IP found in request');
            return { ip: 'unknown', suspicious: true };
        }

        // Get anonymized version for storage and comparison
        const anonymizedIP = IPAnonymizer.anonymizeIP(clientIP);

        // Check for sudden IP changes with same session
        const sessionToken = headers['x-session-token'];
        if (sessionToken && this.sessions.has(sessionToken)) {
            const existingAnonymizedIP = this.sessions.get(sessionToken);
            if (existingAnonymizedIP !== anonymizedIP) {
                // Potential session hijacking attempt
                this.markSuspiciousActivity(anonymizedIP);
                logger.warn('Potential session hijacking detected');
                return { 
                    ip: clientIP, 
                    anonymizedIP,
                    suspicious: true 
                };
            }
        }

        // Track first seen timestamp using anonymized IP
        if (!this.validatedIPs.has(anonymizedIP)) {
            this.validatedIPs.set(anonymizedIP, Date.now());
        }

        return { 
            ip: clientIP, 
            anonymizedIP,
            suspicious: false,
            headerUsed,
            firstSeen: this.validatedIPs.get(anonymizedIP)
        };
    }

    /**
     * Generates a new session token
     */
    generateSessionToken(ip) {
        const token = crypto.randomBytes(32).toString('hex');
        const anonymizedIP = IPAnonymizer.anonymizeIP(ip);
        this.sessions.set(token, anonymizedIP);
        return token;
    }

    /**
     * Marks suspicious activity for an IP
     */
    markSuspiciousActivity(ip) {
        const anonymizedIP = typeof ip === 'string' ? IPAnonymizer.anonymizeIP(ip) : ip;
        const count = (this.suspiciousActivity.get(anonymizedIP) || 0) + 1;
        this.suspiciousActivity.set(anonymizedIP, count);
        
        if (count >= 3) {
            logger.warn('IP marked as suspicious after multiple suspicious activities', { anonymizedIP });
        }
    }

    /**
     * Checks if an IP has been marked as suspicious
     */
    isSuspicious(ip) {
        const anonymizedIP = IPAnonymizer.anonymizeIP(ip);
        return this.suspiciousActivity.get(anonymizedIP) >= 3; // Threshold for suspicious activity
    }

    /**
     * Cleanup old entries
     */
    cleanup() {
        const now = Date.now();
        
        // Clean up old validated IPs (older than 24 hours)
        for (const [ip, timestamp] of this.validatedIPs.entries()) {
            if (now - timestamp > 24 * 60 * 60 * 1000) {
                this.validatedIPs.delete(ip);
            }
        }
        
        // Clean up old sessions (older than 12 hours)
        for (const [token, ip] of this.sessions.entries()) {
            if (!this.validatedIPs.has(ip)) {
                this.sessions.delete(token);
            }
        }
        
        // Clean up old suspicious activity (older than 6 hours)
        this.suspiciousActivity.clear();
    }
}

export const ipValidator = new IPValidator(); 