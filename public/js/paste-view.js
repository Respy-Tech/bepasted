// Initialize line numbers and scroll sync
function initializeLineNumbers() {
    const editors = document.querySelectorAll('.editor-wrapper');
    editors.forEach(editor => {
        const lineNumbers = editor.querySelector('.line-numbers-content');
        const content = editor.querySelector('.paste-content');
        if (!lineNumbers || !content) return;

        // Set up line numbers
        const lines = content.textContent.split('\n');
        lineNumbers.innerHTML = '';
        lines.forEach((_, i) => {
            const div = document.createElement('div');
            div.className = 'line-number';
            div.textContent = i + 1;
            lineNumbers.appendChild(div);
        });

        // Set up scroll synchronization
        content.addEventListener('scroll', () => {
            lineNumbers.style.transform = `translateY(-${content.scrollTop}px)`;
        });
    });
}

// Handle tab switching
function initializeTabSwitching() {
    const tabsContainer = document.getElementById('tabs');
    if (!tabsContainer) return;

    tabsContainer.addEventListener('click', (e) => {
        const tab = e.target.closest('.tab');
        if (!tab) return;

        const tabId = tab.getAttribute('data-tab');
        
        // Remove active class from all tabs and editors
        document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
        document.querySelectorAll('.editor-wrapper').forEach(e => e.classList.remove('active'));
        
        // Add active class to selected tab and editor
        tab.classList.add('active');
        const editor = document.querySelector(`.editor-wrapper[data-tab="${tabId}"]`);
        if (editor) {
            editor.classList.add('active');
            
            // Apply syntax highlighting to the newly active tab if SyntaxHighlighter is available
            if (window.SyntaxHighlighter && typeof window.SyntaxHighlighter.prototype.highlightElement === 'function') {
                const content = editor.querySelector('.paste-content');
                const tabName = tab.querySelector('.tab-name').textContent.trim();
                
                // Create a temporary instance to use the highlightElement method
                const highlighter = new SyntaxHighlighter();
                highlighter.highlightElement(content, tabName);
            }
        }
    });
}

// Handle copy functionality
function initializeCopyButton() {
    const copyButton = document.getElementById('copy-button');
    if (!copyButton) return;

    copyButton.addEventListener('click', async () => {
        try {
            const activeEditor = document.querySelector('.editor-wrapper.active');
            if (!activeEditor) return;

            // Get the original text content, not the HTML with syntax highlighting
            const content = activeEditor.querySelector('.paste-content').textContent;
            await navigator.clipboard.writeText(content);
            showNotification('Tab content copied to clipboard!', 'success');
        } catch (error) {
            console.error('Failed to copy:', error);
            showNotification('Failed to copy tab content', 'error');
        }
    });
}

// Show notification
function showNotification(message, type = 'success') {
    // Remove existing notification
    const existingNotification = document.querySelector('.notification');
    if (existingNotification) {
        existingNotification.remove();
    }

    // Create notification container
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    
    // Create notification content container
    const contentDiv = document.createElement('div');
    contentDiv.className = 'notification-content';
    
    // Create and add icon
    const icon = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    icon.setAttribute('width', '16');
    icon.setAttribute('height', '16');
    icon.setAttribute('viewBox', '0 0 16 16');
    icon.setAttribute('fill', 'none');
    
    const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    if (type === 'success') {
        path.setAttribute('d', 'M13.3334 4L6.00008 11.3333L2.66675 8');
    } else {
        path.setAttribute('d', 'M8 5.33333V8M8 10.6667H8.00667M14.6667 8C14.6667 11.6819 11.6819 14.6667 8 14.6667C4.3181 14.6667 1.33333 11.6819 1.33333 8C1.33333 4.3181 4.3181 1.33333 8 1.33333C11.6819 1.33333 14.6667 4.3181 14.6667 8Z');
    }
    path.setAttribute('stroke', 'currentColor');
    path.setAttribute('stroke-width', type === 'success' ? '2' : '1.5');
    path.setAttribute('stroke-linecap', 'round');
    path.setAttribute('stroke-linejoin', 'round');
    
    icon.appendChild(path);
    contentDiv.appendChild(icon);
    
    // Add message
    const messageSpan = document.createElement('span');
    messageSpan.textContent = message;
    contentDiv.appendChild(messageSpan);
    
    notification.appendChild(contentDiv);
    document.body.appendChild(notification);

    // Trigger animation
    requestAnimationFrame(() => {
        notification.classList.add('show');
    });

    // Remove notification after delay
    setTimeout(() => {
        notification.classList.remove('show');
        setTimeout(() => notification.remove(), 300);
    }, 3000);
}

// Initialize everything when DOM is loaded
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initializeAll);
} else {
    initializeAll();
}

function initializeAll() {
    initializeLineNumbers();
    initializeTabSwitching();
    initializeCopyButton();
} 