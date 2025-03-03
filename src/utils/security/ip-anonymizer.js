import crypto from 'crypto';
import config from '../config/config.js';

/**
 * Utility for anonymizing IP addresses to protect user privacy
 * while still allowing for necessary functions like rate limiting.
 */
class IPAnonymizer {
  /**
   * Create a secure hash of an IP address
   * @param {string} ip - The IP address to anonymize
   * @param {boolean} partialAnonymization - Whether to retain part of the IP (for geo functionality)
   * @returns {string} The anonymized IP hash
   */
  static anonymizeIP(ip, partialAnonymization = false) {
    if (!ip || ip === 'unknown') return 'unknown';
    
    // For IPv4 addresses
    if (ip.includes('.')) {
      if (partialAnonymization) {
        // Partial anonymization: keep the first two octets for geolocation abilities
        // e.g., 192.168.1.1 becomes 192.168.0.0
        const parts = ip.split('.');
        const partialIP = `${parts[0]}.${parts[1]}.0.0`;
        return this.hashIP(partialIP);
      }
    } 
    // For IPv6 addresses
    else if (ip.includes(':')) {
      if (partialAnonymization) {
        // Keep only the first half of the IPv6 address
        const parts = ip.split(':');
        const partialIP = parts.slice(0, 4).join(':') + ':0000:0000:0000:0000';
        return this.hashIP(partialIP);
      }
    }
    
    // Full anonymization (default)
    return this.hashIP(ip);
  }
  
  /**
   * Create a hash of the IP using SHA-256
   * @private
   * @param {string} ip - The IP to hash
   * @returns {string} The hashed IP
   */
  static hashIP(ip) {
    // Use a consistent salt to ensure the same IP always hashes to the same value
    // but also adds security to prevent reverse lookup
    const salt = config.IP_HASH_SALT || 'BePasted-secure-salt';
    return crypto
      .createHash('sha256')
      .update(ip + salt)
      .digest('hex');
  }
}

export default IPAnonymizer; 