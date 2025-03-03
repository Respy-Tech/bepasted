/**
 * @file config.js
 * @description Centralized configuration management for BePasted application.
 * Handles loading, validating, and providing access to environment variables.
 */

import dotenv from 'dotenv';
import { join } from 'path';
import { fileURLToPath } from 'url';
import { dirname } from 'path';
import fs from 'fs';

// Get directory info for finding .env file
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

/**
 * Loads environment variables from .env file
 * @returns {boolean} Whether the .env file was successfully loaded
 */
function loadEnvFile() {
  try {
    // Try to find .env file in different locations
    const envPaths = [
      join(process.cwd(), '.env'),
      join(dirname(dirname(__dirname)), '.env'),
      join(__dirname, '../../.env')
    ];

    for (const envPath of envPaths) {
      if (fs.existsSync(envPath)) {
        const result = dotenv.config({ path: envPath });
        if (result.error) {
          console.warn(`Warning: Error parsing .env file: ${result.error.message}`);
          return false;
        }
        return true;
      }
    }

    console.warn('Warning: No .env file found. Using existing environment variables.');
    return false;
  } catch (error) {
    console.warn(`Warning: Error loading .env file: ${error.message}`);
    return false;
  }
}

// Load environment variables
const envFileLoaded = loadEnvFile();

/**
 * Schema definition for environment variables
 * Includes type conversion, validation, and defaults
 */
const configSchema = {
  // Node environment
  NODE_ENV: {
    type: 'string',
    default: 'development',
    validate: (value) => ['development', 'production', 'test'].includes(value),
    errorMessage: 'NODE_ENV must be one of: development, production, test',
  },

  // Server configuration
  PORT: {
    type: 'number',
    default: 3000,
    validate: (value) => value > 0 && value < 65536,
    errorMessage: 'PORT must be a valid port number (1-65535)',
  },
  
  // Database configuration
  MONGODB_URI: {
    type: 'string',
    required: true,
    sensitive: true,
    errorMessage: 'MONGODB_URI is required',
  },
  MONGODB_POOL_SIZE: {
    type: 'number',
    default: 10,
    validate: (value) => value > 0 && value <= 100,
    errorMessage: 'MONGODB_POOL_SIZE must be between 1 and 100',
  },
  MONGODB_CONNECT_TIMEOUT_MS: {
    type: 'number',
    default: 30000,
    validate: (value) => value >= 1000 && value <= 120000,
    errorMessage: 'MONGODB_CONNECT_TIMEOUT_MS must be between 1000 and 120000',
  },
  
  // Cloudflare Turnstile configuration
  TURNSTILE_SECRET_KEY: {
    type: 'string',
    required: true,
    sensitive: true,
    errorMessage: 'TURNSTILE_SECRET_KEY is required',
  },
  TURNSTILE_SITE_KEY: {
    type: 'string',
    required: true,
    errorMessage: 'TURNSTILE_SITE_KEY is required',
  },
  
  // Arcjet configuration
  ARCJET_KEY: {
    type: 'string',
    required: true,
    sensitive: true,
    errorMessage: 'ARCJET_KEY is required',
  },
  ARCJET_ENV: {
    type: 'string',
    default: 'development',
    validate: (value) => ['development', 'production'].includes(value),
    errorMessage: 'ARCJET_ENV must be one of: development, production',
  },
  
  // Security settings
  IP_HASH_SALT: {
    type: 'string',
    required: true,
    sensitive: true,
    validate: (value) => value.length >= 32,
    errorMessage: 'IP_HASH_SALT must be at least 32 characters long',
  },
  CSRF_SECRET: {
    type: 'string',
    required: true,
    sensitive: true,
    validate: (value) => value.length >= 32,
    errorMessage: 'CSRF_SECRET must be at least 32 characters long',
  },
  DATA_RETENTION_DAYS: {
    type: 'number',
    default: 30,
    validate: (value) => value > 0 && value <= 365,
    errorMessage: 'DATA_RETENTION_DAYS must be between 1 and 365',
  },
  
  ARCHIVE_RETENTION_DAYS: {
    type: 'number',
    default: 90, // 3 months is the default
    validate: (value) => value > 0 && value <= 365 * 2, // Allow up to 2 years
    errorMessage: 'ARCHIVE_RETENTION_DAYS must be between 1 and 730',
  },
  
  // Logging configuration
  LOG_LEVEL: {
    type: 'string',
    default: 'INFO',
    validate: (value) => ['ERROR', 'WARN', 'INFO', 'DEBUG'].includes(value.toUpperCase()),
    transform: (value) => value.toUpperCase(),
    errorMessage: 'LOG_LEVEL must be one of: ERROR, WARN, INFO, DEBUG',
  },
  
  // CORS configuration
  ALLOWED_ORIGINS: {
    type: 'array',
    default: ['http://localhost:3000'],
    transform: (value) => (value ? value.split(',').map((origin) => origin.trim()) : []),
  },
  
  // Domain configuration
  DOMAIN: {
    type: 'string',
    default: 'http://localhost:3000',
    validate: (value) => /^https?:\/\//.test(value),
    errorMessage: 'DOMAIN must be a valid URL starting with http:// or https://',
  },
  
  // BetterStack configuration
  BETTERSTACK_ENABLED: {
    type: 'boolean',
    default: false,
    transform: (value) => value === 'true' || value === true,
  },
  BETTERSTACK_TOKEN: {
    type: 'string',
    required: false,
    sensitive: true,
    conditional: (config) => config.BETTERSTACK_ENABLED === true,
    errorMessage: 'BETTERSTACK_TOKEN is required when BETTERSTACK_ENABLED is true',
  },
  BETTERSTACK_ENDPOINT: {
    type: 'string',
    default: 'https://in.logs.betterstack.com',
    conditional: (config) => config.BETTERSTACK_ENABLED === true,
    validate: (value) => /^https?:\/\//.test(value),
    errorMessage: 'BETTERSTACK_ENDPOINT must be a valid URL starting with http:// or https://',
  },
  
  // Application version
  npm_package_version: {
    type: 'string',
    default: '2.0.1',
    required: false,
  },
};

/**
 * Processes and validates environment variables according to schema
 * @param {object} schema - Configuration schema
 * @returns {object} Processed configuration object
 */
function processConfig(schema) {
  const config = {};
  const errors = [];
  const warnings = [];
  const requiredInProd = [];

  // First pass: basic processing and type conversion
  Object.entries(schema).forEach(([key, definition]) => {
    let value = process.env[key];
    const isDefined = value !== undefined && value !== '';
    
    // Apply default if value is not defined
    if (!isDefined && definition.default !== undefined) {
      value = definition.default;
    }
    
    // Type conversion
    if (isDefined) {
      try {
        if (definition.type === 'number') {
          value = Number(value);
          if (isNaN(value)) {
            errors.push(`${key} must be a valid number`);
            return;
          }
        } else if (definition.type === 'boolean') {
          value = value === 'true' || value === true;
        } else if (definition.type === 'array' && definition.transform) {
          value = definition.transform(value);
        }
      } catch (error) {
        errors.push(`Error processing ${key}: ${error.message}`);
        return;
      }
    }
    
    // Apply custom transform if specified
    if (isDefined && definition.transform && definition.type !== 'array') {
      try {
        value = definition.transform(value);
      } catch (error) {
        errors.push(`Error transforming ${key}: ${error.message}`);
        return;
      }
    }
    
    // Store the value
    config[key] = value;
  });
  
  // Second pass: validation and requirements check
  Object.entries(schema).forEach(([key, definition]) => {
    const value = config[key];
    const isDefined = value !== undefined && value !== '';
    
    // Check required fields
    if (definition.required && !isDefined) {
      if (process.env.NODE_ENV === 'production') {
        errors.push(definition.errorMessage || `${key} is required`);
      } else {
        // In non-production, track as required only in production
        requiredInProd.push(key);
      }
    }
    
    // Check conditional requirements
    if (definition.conditional && definition.conditional(config) && !isDefined) {
      errors.push(definition.errorMessage || `${key} is required based on other settings`);
    }
    
    // Validate values
    if (isDefined && definition.validate && !definition.validate(value)) {
      errors.push(definition.errorMessage || `${key} failed validation`);
    }
  });
  
  // Add warnings for fields required in production but not in current environment
  if (process.env.NODE_ENV !== 'production' && requiredInProd.length > 0) {
    warnings.push(`The following variables will be required in production: ${requiredInProd.join(', ')}`);
  }
  
  return { config, errors, warnings };
}

// Process and validate configuration
const { config, errors, warnings } = processConfig(configSchema);

// Handle configuration errors
if (errors.length > 0) {
  console.error('\n❌ Configuration Error(s):');
  errors.forEach((error) => console.error(`- ${error}`));
  console.error('\nPlease fix these issues in your .env file before continuing.');
  
  // Exit in production, but allow continuing in development with warnings
  if (process.env.NODE_ENV === 'production') {
    process.exit(1);
  }
}

// Display warnings
if (warnings.length > 0) {
  console.warn('\n⚠️ Configuration Warning(s):');
  warnings.forEach((warning) => console.warn(`- ${warning}`));
  console.warn('');
}

// Log configuration status
if (!envFileLoaded) {
  console.warn('⚠️ Running without .env file. Using environment variables and defaults.');
} else if (process.env.NODE_ENV !== 'production') {
  console.info('✅ Configuration loaded from .env file');
}

// Create a frozen object to prevent modification after initialization
const appConfig = Object.freeze(config);

export default appConfig; 