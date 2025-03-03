/**
 * Privacy-focused logging utility that provides structured logging
 * without recording sensitive user information.
 * Integrated with BetterStack for centralized logging and metrics.
 */
import fetch from 'node-fetch';

// To avoid circular dependency issues, check if we're being imported by config.js
// and conditionally import config
let config;
try {
  const importingFile = new Error().stack.split('\n')[2]?.trim() || '';
  const isImportedByConfig = importingFile.includes('config.js');
  
  if (!isImportedByConfig) {
    // Safe to import config as we're not being imported by config.js
    const { default: configModule } = await import('./config/config.js');
    config = configModule;
  } else {
    // Being imported by config.js, use environment variables directly
    config = {
      NODE_ENV: process.env.NODE_ENV || 'development',
      LOG_LEVEL: process.env.LOG_LEVEL || 'INFO',
      BETTERSTACK_ENABLED: process.env.BETTERSTACK_ENABLED === 'true',
      BETTERSTACK_TOKEN: process.env.BETTERSTACK_TOKEN,
      BETTERSTACK_ENDPOINT: process.env.BETTERSTACK_ENDPOINT || 'https://in.logs.betterstack.com'
    };
  }
} catch (error) {
  // Fallback to environment variables if there's an issue
  console.warn('Logger: Failed to import config module, using environment variables directly');
  config = {
    NODE_ENV: process.env.NODE_ENV || 'development',
    LOG_LEVEL: process.env.LOG_LEVEL || 'INFO',
    BETTERSTACK_ENABLED: process.env.BETTERSTACK_ENABLED === 'true',
    BETTERSTACK_TOKEN: process.env.BETTERSTACK_TOKEN,
    BETTERSTACK_ENDPOINT: process.env.BETTERSTACK_ENDPOINT || 'https://in.logs.betterstack.com'
  };
}

class Logger {
  constructor() {
    // Define log levels
    this.LEVELS = {
      ERROR: 0,
      WARN: 1,
      INFO: 2,
      DEBUG: 3
    };

    // Set default level based on environment
    this.currentLevel = config.NODE_ENV === 'production' 
      ? this.LEVELS.INFO
      : this.LEVELS.DEBUG;
      
    // Set log level from environment variable if provided
    if (config.LOG_LEVEL) {
      const envLevel = config.LOG_LEVEL.toUpperCase();
      if (this.LEVELS[envLevel] !== undefined) {
        this.currentLevel = this.LEVELS[envLevel];
      }
    }
    
    // Track log entries for rotation/maintenance/cleanup
    this.logEntries = [];
    this.maxLogEntries = 1000; // Maximum entries to keep in memory
    
    // Set up log rotation if not in development
    if (config.NODE_ENV !== 'development') {
      setInterval(() => this.rotateLogEntries(), 24 * 60 * 60 * 1000); // Daily rotation
    }

    // BetterStack configuration
    this.betterStackEnabled = config.BETTERSTACK_ENABLED;
    this.betterStackToken = config.BETTERSTACK_TOKEN;
    this.betterStackEndpoint = config.BETTERSTACK_ENDPOINT;
    this.betterStackMetricsEndpoint = `${this.betterStackEndpoint}/metrics`;
    
    // Batch logging configuration
    this.logBatch = [];
    this.maxBatchSize = 100;
    this.batchSendInterval = 5000; // 5 seconds
    
    // Set up batch sending if BetterStack logging is enabled
    if (this.betterStackEnabled && this.betterStackToken) {
      this.setupBatchSending();
      this.info('BetterStack logging initialized', { endpoint: this.betterStackEndpoint });
    }
  }

  /**
   * Set up interval for sending batched logs
   * @private
   */
  setupBatchSending() {
    setInterval(() => {
      this.sendLogBatch();
    }, this.batchSendInterval);
    
    // Also set up clean shutdown to send remaining logs
    process.on('SIGTERM', () => {
      console.log('Received SIGTERM, sending remaining logs to BetterStack...');
      this.sendLogBatch();
    });
    
    process.on('SIGINT', () => {
      console.log('Received SIGINT, sending remaining logs to BetterStack...');
      this.sendLogBatch();
    });
  }

  /**
   * Format a log message with timestamp and metadata
   * @private
   */
  _formatLogMessage(level, message, meta = {}) {
    const timestamp = new Date().toISOString();
    
    // Sanitize meta to remove any potential PII or sensitive data
    const sanitizedMeta = this._sanitizeMetadata(meta);
    
    return {
      timestamp,
      level,
      message,
      meta: sanitizedMeta
    };
  }
  
  /**
   * Sanitize metadata to remove sensitive information
   * @private
   */
  _sanitizeMetadata(meta) {
    const sanitized = {...meta};
    
    // List of keys that might contain sensitive data
    const sensitiveKeys = ['password', 'token', 'ip', 'email', 'cookie', 'authorization'];
    
    // Remove or mask sensitive data
    Object.keys(sanitized).forEach(key => {
      const lowerKey = key.toLowerCase();
      
      if (sensitiveKeys.some(sk => lowerKey.includes(sk))) {
        if (lowerKey.includes('ip')) {
          // For IP addresses, use anonymized version if available
          if (sanitized['anonymizedIP'] || sanitized['anonymizedIp']) {
            sanitized[key] = sanitized['anonymizedIP'] || sanitized['anonymizedIp'];
          } else {
            sanitized[key] = '[REDACTED IP]';
          }
        } else {
          sanitized[key] = '[REDACTED]';
        }
      } else if (typeof sanitized[key] === 'object' && sanitized[key] !== null) {
        sanitized[key] = this._sanitizeMetadata(sanitized[key]);
      }
    });
    
    return sanitized;
  }

  /**
   * Send logs to BetterStack
   * @private
   */
  async sendToBetterStack(logEntry) {
    // Skip if BetterStack is not configured
    if (!this.betterStackEnabled || !this.betterStackToken) {
      return;
    }
    
    try {
      // Format the log entry for BetterStack
      const betterStackLog = {
        dt: new Date(logEntry.timestamp).toISOString(),
        level: logEntry.level,
        message: logEntry.message,
        ...logEntry.meta
      };
      
      // Add to batch
      this.logBatch.push(betterStackLog);
      
      // If batch is full, send it immediately
      if (this.logBatch.length >= this.maxBatchSize) {
        await this.sendLogBatch();
      }
    } catch (error) {
      // Don't use own logging methods here to avoid infinite recursion
      console.error('Error queueing log to BetterStack:', error);
    }
  }
  
  /**
   * Send batched logs to BetterStack
   * @private
   */
  async sendLogBatch() {
    if (!this.betterStackEnabled || !this.betterStackToken || this.logBatch.length === 0) {
      return;
    }
    
    const batchToSend = [...this.logBatch];
    this.logBatch = [];
    
    try {
      const responses = await Promise.allSettled(
        batchToSend.map(async (log) => {
          try {
            const response = await fetch(this.betterStackEndpoint, {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${this.betterStackToken}`
              },
              body: JSON.stringify(log)
            });
            
            if (!response.ok) {
              return { ok: false, status: response.status };
            }
            
            return { ok: true };
          } catch (error) {
            console.error('Error sending individual log to BetterStack:', error);
            return { ok: false, error: error.message };
          }
        })
      );
      
      // Check for any failures
      const failedCount = responses.filter(r => r.status === 'rejected' || (r.status === 'fulfilled' && !r.value.ok)).length;
      
      if (failedCount > 0) {
        console.warn(`Failed to send ${failedCount} of ${batchToSend.length} logs to BetterStack`);
      }
    } catch (error) {
      console.error('Error sending log batch to BetterStack:', error);
    }
  }
  
  /**
   * Send a metric to BetterStack
   * @param {string} name - Metric name
   * @param {number} value - Metric value
   * @param {object} tags - Optional tags for the metric
   */
  async sendMetric(name, value, tags = {}) {
    if (!this.betterStackEnabled || !this.betterStackToken) return;
    
    try {
      const metricData = {
        dt: new Date().toISOString(),
        name: `bepasted_${name}`,
        gauge: { value },
        tags
      };
      
      const response = await fetch(this.betterStackMetricsEndpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${this.betterStackToken}`
        },
        body: JSON.stringify(metricData)
      });
      
      if (!response.ok) {
        console.warn(`Failed to send metric to BetterStack: ${response.status} ${response.statusText}`);
      }
    } catch (error) {
      console.error('Error sending metric to BetterStack:', error);
    }
  }

  /**
   * Log an error message
   */
  error(message, meta = {}) {
    if (this.currentLevel >= this.LEVELS.ERROR) {
      const logEntry = this._formatLogMessage('ERROR', message, meta);
      this.logEntries.push(logEntry);
      console.error(`[ERROR] ${logEntry.timestamp} - ${message}`, logEntry.meta);
      
      // Send to BetterStack
      this.sendToBetterStack(logEntry);
    }
  }

  /**
   * Log a warning message
   */
  warn(message, meta = {}) {
    if (this.currentLevel >= this.LEVELS.WARN) {
      const logEntry = this._formatLogMessage('WARN', message, meta);
      this.logEntries.push(logEntry);
      console.warn(`[WARN] ${logEntry.timestamp} - ${message}`, logEntry.meta);
      
      // Send to BetterStack
      this.sendToBetterStack(logEntry);
    }
  }

  /**
   * Log an info message
   */
  info(message, meta = {}) {
    if (this.currentLevel >= this.LEVELS.INFO) {
      const logEntry = this._formatLogMessage('INFO', message, meta);
      this.logEntries.push(logEntry);
      console.info(`[INFO] ${logEntry.timestamp} - ${message}`, logEntry.meta);
      
      // Send to BetterStack for info and above
      this.sendToBetterStack(logEntry);
    }
  }

  /**
   * Log a debug message
   */
  debug(message, meta = {}) {
    if (this.currentLevel >= this.LEVELS.DEBUG) {
      const logEntry = this._formatLogMessage('DEBUG', message, meta);
      this.logEntries.push(logEntry);
      console.debug(`[DEBUG] ${logEntry.timestamp} - ${message}`, logEntry.meta);
      
      // Only send debug logs in non-production to avoid overwhelming BetterStack
      if (config.NODE_ENV !== 'production') {
        this.sendToBetterStack(logEntry);
      }
    }
  }
  
  /**
   * Rotate log entries to prevent memory buildup
   * @private
   */
  rotateLogEntries() {
    if (this.logEntries.length > this.maxLogEntries) {
      this.logEntries = this.logEntries.slice(-Math.floor(this.maxLogEntries / 2));
      this.info(`Log rotation performed, retained ${this.logEntries.length} entries`);
    }
  }
  
  /**
   * Get recent logs, useful for diagnostics endpoints
   */
  getRecentLogs(count = 100) {
    return this.logEntries.slice(-count);
  }
}

// Export a singleton instance
const logger = new Logger();
export default logger; 