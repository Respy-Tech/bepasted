import logger from '../logging/logger.js';

/**
 * ContentScanner provides methods to scan paste content for potentially
 * malicious or harmful code and content.
 */
class ContentScanner {
  constructor() {
    // Initialize patterns for different types of potentially harmful content
    this.patterns = {
      // Common malware signatures
      malware: [
        // Various executable or malicious script patterns
        /<script[\s\S]*?crypto[\s\S]*?miner/i,  // Cryptocurrency miners
        /eval\s*\(\s*(?:atob|btoa|unescape|decodeURIComponent|String\.fromCharCode)/i, // Obfuscated eval
        /document\.cookie\s*=.*?;/i, // Cookie stealing
        /<iframe[^>]*src=["']?https?:\/\/([^"'\s>]+)["']?[^>]*>/i, // Suspicious iframes
        /(?:document|window)\.location(?:\.href)?\s*=\s*["']https?:\/\/([^"'\s>]+)["']/i, // Malicious redirects
      ],
      
      // Common phishing patterns
      phishing: [
        /login.*?password/i,
        /verify.*?account/i,
        /input.*?type=['"]password['"]/i,
        /\b(?:paypal|apple|microsoft|google|facebook|instagram|twitter|amazon)\s*(?:login|account|verification|security)\b/i,
      ],
      
      // Data exfiltration patterns
      dataExfiltration: [
        /fetch\(['"]https:\/\/(?!bepasted\.com)[^'"]+['"], ?\{[\s\S]*method:\s*['"]POST['"]/i,
        /\.open\(['"]POST['"], ['"]https:\/\/(?!bepasted\.com)[^'"]+['"](?:, true)?\)/i,
        /navigator\.sendBeacon\(['"]https:\/\/(?!bepasted\.com)[^'"]+['"],/i,
      ],
      
      // Common sensitive data patterns
      sensitiveData: [
        // Credit card numbers with basic validation
        /(?:\d{4}[- ]?){3}\d{4}/,
        // Social security numbers
        /\b\d{3}-\d{2}-\d{4}\b/,
        // API keys and tokens - look for common patterns
        /(?:api|sk|pk|token|secret)_[a-zA-Z0-9]{20,}/i,
        // Private keys
        /-----BEGIN (?:RSA|OPENSSH|PRIVATE) KEY-----/,
        // AWS access keys
        /AKIA[0-9A-Z]{16}/
      ]
    };
    
    // Initialize scan thresholds
    this.config = {
      maxMalwareScore: 2,
      maxPhishingScore: 2,
      maxDataExfilScore: 1,
      maxSensitiveDataScore: 3,
      contentSampleLength: 5000 // Characters to log if a threat is detected
    };
  }
  
  /**
   * Scan content for potentially harmful code or sensitive data
   * @param {string} content - The content to scan
   * @returns {Object} Scan results with threat level and details
   */
  scanContent(content) {
    if (!content || typeof content !== 'string') {
      return { safe: true, threatLevel: 0, details: [] };
    }
    
    const contentLength = content.length;
    const results = {
      safe: true,
      threatLevel: 0, // 0-10 scale
      details: []
    };
    
    // Check against each pattern category
    this._checkPatterns(content, 'malware', results, 3);
    this._checkPatterns(content, 'phishing', results, 2);
    this._checkPatterns(content, 'dataExfiltration', results, 4);
    this._checkPatterns(content, 'sensitiveData', results, 1);
    
    // Special case: Analyze script density
    const scriptTags = (content.match(/<script[^>]*>([\s\S]*?)<\/script>/gi) || []).length;
    const scriptDensity = (scriptTags / Math.max(1, contentLength / 1000));
    
    if (scriptDensity > 0.5) {  // More than 0.5 script tags per 1000 chars
      results.details.push({
        type: 'highScriptDensity',
        severity: 2,
        description: `High density of script tags (${scriptTags} tags, ${scriptDensity.toFixed(2)} per 1000 chars)`
      });
      results.threatLevel += 2;
    }
    
    // Set final safety assessment
    results.safe = results.threatLevel < 5;
    
    // Log high-threat content for review
    if (results.threatLevel >= 5) {
      const contentSample = content.substring(0, this.config.contentSampleLength);
      logger.warn(`High threat content detected (score ${results.threatLevel})`, { 
        threatDetails: results.details,
        contentSample: contentSample.length < content.length ? 
                      `${contentSample}... (truncated)` : contentSample
      });
    }
    
    return results;
  }
  
  /**
   * Check content against a specific pattern category
   * @private
   */
  _checkPatterns(content, patternType, results, severityMultiplier) {
    const patterns = this.patterns[patternType];
    let matches = 0;
    
    patterns.forEach(pattern => {
      if (pattern.test(content)) {
        matches++;
        results.details.push({
          type: patternType,
          severity: severityMultiplier,
          description: `Potential ${patternType} pattern detected: ${pattern.toString().substring(1, 50)}...`
        });
      }
    });
    
    // Calculate category score
    const maxForCategory = this.config[`max${patternType.charAt(0).toUpperCase() + patternType.slice(1)}Score`] || 5;
    const categoryScore = Math.min(maxForCategory, matches * severityMultiplier);
    
    // Add to total threat level
    results.threatLevel += categoryScore;
  }
  
  /**
   * Determine if content should be blocked based on scan results
   */
  shouldBlockContent(scanResults) {
    return scanResults.threatLevel >= 7;
  }
  
  /**
   * Get a human-readable explanation of scan results
   */
  getReadableReport(scanResults) {
    if (scanResults.safe) {
      return "No significant issues detected with this content.";
    }
    
    // Categorize detected issues
    const issuesByType = {};
    scanResults.details.forEach(detail => {
      if (!issuesByType[detail.type]) {
        issuesByType[detail.type] = [];
      }
      issuesByType[detail.type].push(detail);
    });
    
    // Build readable report
    let report = `Content scan detected potential issues (threat level: ${scanResults.threatLevel}/10):\n`;
    
    Object.keys(issuesByType).forEach(type => {
      const issues = issuesByType[type];
      report += `- ${this._getTypeName(type)} (${issues.length} issue${issues.length > 1 ? 's' : ''})\n`;
    });
    
    if (scanResults.threatLevel >= 7) {
      report += "\nThis content has been flagged as potentially harmful.";
    } else {
      report += "\nContent is available but has been flagged for review.";
    }
    
    return report;
  }
  
  /**
   * Get a user-friendly name for an issue type
   * @private
   */
  _getTypeName(type) {
    const names = {
      malware: "Potentially harmful code",
      phishing: "Possible phishing patterns",
      dataExfiltration: "Data exfiltration risk",
      sensitiveData: "Sensitive data",
      highScriptDensity: "High density of script elements"
    };
    
    return names[type] || type;
  }
}

// Export a singleton instance
const contentScanner = new ContentScanner();
export default contentScanner; 