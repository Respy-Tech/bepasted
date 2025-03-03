/**
 * Get the domain based on the current environment
 * @returns {string} The appropriate domain for the current environment
 */
import config from './config.js';

export function getDomain() {
    return config.DOMAIN || (config.NODE_ENV === 'development' 
        ? 'http://localhost:3000' 
        : 'https://bepasted.com');
} 