/**
 * BePasted Syntax Highlighting System
 * Automatically detects and applies syntax highlighting to paste content
 * while preserving the existing alternating line background colors.
 */

class SyntaxHighlighter {
    constructor() {
        // Language mappings from file extensions to highlight.js languages
        this.extensionMap = {
            // Programming languages
            'js': 'javascript',
            'jsx': 'javascript',
            'ts': 'typescript',
            'tsx': 'typescript',
            'py': 'python',
            'rb': 'ruby',
            'php': 'php',
            'java': 'java',
            'c': 'c',
            'cpp': 'cpp',
            'cs': 'csharp',
            'go': 'go',
            'rs': 'rust',
            'swift': 'swift',
            'kt': 'kotlin',
            'scala': 'scala',
            'r': 'r',
            'sh': 'bash',
            'bash': 'bash',
            'ps1': 'powershell',
            'sql': 'sql',

            // Markup and templating
            'html': 'html',
            'htm': 'html',
            'xml': 'xml',
            'svg': 'xml',
            'md': 'markdown',
            'css': 'css',
            'scss': 'scss',
            'sass': 'scss',
            'less': 'less',
            'json': 'json',
            'yaml': 'yaml',
            'yml': 'yaml',
            'toml': 'toml',
            'ini': 'ini',
            'conf': 'apache',
            'csv': 'plaintext',

            // Config files
            'env': 'bash',
            'dockerignore': 'plaintext',
            'gitignore': 'plaintext',
            'gitattributes': 'plaintext',
            'editorconfig': 'ini',

            // Common plaintext
            'txt': 'plaintext',
            'log': 'plaintext'
        };

        // Content-based language detection patterns
        this.contentPatterns = [
            { pattern: /^<\?php/i, language: 'php' },
            { pattern: /^<\?xml/i, language: 'xml' },
            { pattern: /^<!DOCTYPE\s+html>/i, language: 'html' },
            { pattern: /^<html/i, language: 'html' },
            { pattern: /^package\s+[\w.]+;/i, language: 'java' },
            { pattern: /^import\s+[\w.]+;/i, language: 'java' },
            { pattern: /^#!\s*\/usr\/bin\/env\s+python/i, language: 'python' },
            { pattern: /^#!\s*\/usr\/bin\/python/i, language: 'python' },
            { pattern: /^#!\s*\/bin\/bash/i, language: 'bash' },
            { pattern: /^#!\s*\/usr\/bin\/env\s+node/i, language: 'javascript' },
            { pattern: /^using\s+System;/i, language: 'csharp' },
            { pattern: /^import\s+React/i, language: 'javascript' },
            { pattern: /^import\s+{.*}\s+from\s+['"]react['"]/i, language: 'javascript' },
            { pattern: /^SELECT\s+.*\s+FROM\s+.*\s+WHERE/i, language: 'sql' },
            { pattern: /^(---|\+\+\+)\s+/i, language: 'diff' },
            { pattern: /^@@ -\d+,\d+ \+\d+,\d+ @@/i, language: 'diff' },
            { pattern: /^FROM\s+.*\s+/i, language: 'dockerfile' },
            { pattern: /^RUN\s+.*/i, language: 'dockerfile' },
            { pattern: /^COPY\s+.*/i, language: 'dockerfile' }
        ];

        // Load highlight.js if not already loaded
        this.loadHighlightJs().then(() => {
            // Initialize the highlighting for existing content
            this.initializeHighlighting();
        });
    }

    /**
     * Load highlight.js and its CSS if not already loaded
     */
    async loadHighlightJs() {
        // Check if highlight.js is already loaded
        if (window.hljs) {
            return Promise.resolve();
        }

        // Load CSS first
        return Promise.all([
            new Promise((resolve) => {
                const link = document.createElement('link');
                link.rel = 'stylesheet';
                link.href = 'https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/github.min.css';
                link.onload = resolve;
                document.head.appendChild(link);
            }),
            new Promise((resolve) => {
                const script = document.createElement('script');
                script.src = 'https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/highlight.min.js';
                script.onload = resolve;
                document.body.appendChild(script);
            })
        ]).then(() => {
            // Apply custom CSS to maintain alternating line backgrounds
            this.applyCustomCss();
        });
    }

    /**
     * Apply custom CSS to maintain alternating line backgrounds
     */
    applyCustomCss() {
        const style = document.createElement('style');
        style.textContent = `
            /* Preserve alternating line backgrounds with syntax highlighting */
            .paste-content.hljs {
                background-image: linear-gradient(
                    to bottom,
                    var(--line-odd) 50%,
                    var(--line-even) 50%
                );
                background-size: 100% 48px;
                background-position: 0 0;
                background-attachment: local;
                padding: 0 10px;
                white-space: pre;
                tab-size: 4;
            }
            
            /* Keep line height consistent */
            .hljs {
                line-height: 24px;
                font-family: monospace;
                font-size: 14px;
            }
            
            /* Make sure token colors have enough contrast */
            .hljs-keyword, .hljs-selector-tag, .hljs-title, .hljs-section, .hljs-doctag, .hljs-name, .hljs-strong {
                font-weight: bold;
            }
            
            /* Ensure code is readable on both alternating backgrounds */
            .hljs-comment, .hljs-quote, .hljs-meta {
                color: #408080 !important;
                font-style: italic;
            }
            
            /* Improve visibility of string literals */
            .hljs-string, .hljs-symbol, .hljs-bullet, .hljs-regexp {
                color: #d14 !important;
            }
        `;
        document.head.appendChild(style);
    }

    /**
     * Initialize syntax highlighting for all paste content elements
     */
    initializeHighlighting() {
        // Wait for highlight.js to be available
        if (!window.hljs) {
            setTimeout(() => this.initializeHighlighting(), 100);
            return;
        }

        // Find all paste content elements
        const pasteContents = document.querySelectorAll('.paste-content');
        
        // Apply highlighting to each element
        pasteContents.forEach((content, index) => {
            // Get tab name if available (for extension detection)
            const tabElement = document.querySelector(`.tab[data-tab="${index + 1}"]`);
            const tabName = tabElement ? tabElement.querySelector('.tab-name').textContent.trim() : '';
            
            this.highlightElement(content, tabName);
        });

        // Set up highlighting for tab switching
        this.setupTabSwitchHighlighting();
    }

    /**
     * Set up highlighting for tab switching
     */
    setupTabSwitchHighlighting() {
        const tabsContainer = document.getElementById('tabs');
        if (!tabsContainer) return;

        tabsContainer.addEventListener('click', (e) => {
            const tab = e.target.closest('.tab');
            if (!tab) return;

            // There's a slight delay before the tab content becomes active
            setTimeout(() => {
                const tabId = tab.getAttribute('data-tab');
                const editor = document.querySelector(`.editor-wrapper[data-tab="${tabId}"]`);
                if (editor) {
                    const content = editor.querySelector('.paste-content');
                    const tabName = tab.querySelector('.tab-name').textContent.trim();
                    
                    // Apply highlighting to the newly active tab
                    this.highlightElement(content, tabName);
                }
            }, 10);
        });
    }

    /**
     * Apply syntax highlighting to a single element
     * @param {HTMLElement} element - The element to highlight
     * @param {string} tabName - The name of the tab, used for extension detection
     */
    highlightElement(element, tabName) {
        if (!element || !window.hljs) return;

        // Store original content
        const originalContent = element.textContent;
        if (!originalContent.trim()) return;

        // Detect language
        const language = this.detectLanguage(originalContent, tabName);
        
        try {
            // Only proceed if we have a language and it's not plaintext
            if (language && language !== 'plaintext') {
                // Apply highlighting
                const result = language === 'auto' 
                    ? window.hljs.highlightAuto(originalContent)
                    : window.hljs.highlight(originalContent, { language });
                
                // Replace content with highlighted HTML
                element.innerHTML = result.value;
                element.classList.add('hljs');
            }
        } catch (error) {
            console.error('Error applying syntax highlighting:', error);
            // Restore original content if highlighting fails
            element.textContent = originalContent;
        }
    }

    /**
     * Detect the language based on content and tab name
     * @param {string} content - The content to analyze
     * @param {string} tabName - The name of the tab
     * @returns {string} - The detected language or 'plaintext'
     */
    detectLanguage(content, tabName) {
        // Try to detect language from tab name first (if it contains a file extension)
        if (tabName) {
            const lastDotIndex = tabName.lastIndexOf('.');
            if (lastDotIndex !== -1 && lastDotIndex < tabName.length - 1) {
                const extension = tabName.substring(lastDotIndex + 1).toLowerCase();
                if (this.extensionMap[extension]) {
                    return this.extensionMap[extension];
                }
            }
        }

        // Try content pattern matching
        const firstLines = content.split('\n').slice(0, 5).join('\n');
        for (const { pattern, language } of this.contentPatterns) {
            if (pattern.test(firstLines)) {
                return language;
            }
        }

        // If the content is over a certain length and has enough unique characters, use auto-detection
        if (content.length > 50 && new Set(content).size > 20) {
            return 'auto';
        }

        // Default to plaintext
        return 'plaintext';
    }
}

// Initialize the syntax highlighter when the DOM is loaded
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => new SyntaxHighlighter());
} else {
    new SyntaxHighlighter();
} 