class PasteEditor {
    constructor() {
        // Initialize error popup elements first
        if (!this.initializeErrorElements()) {
            console.error('Failed to initialize error elements');
            return;
        }

        this.initializeElements();
        this.setupEventListeners();
        this.tabs = new Map();
        this.activeTab = 1;
        this.tabs.set(1, { content: '', name: 'Tab 1' });
        this.tabIdCounter = 1; // Keep track of the highest tab ID used
        
        // Create the first tab with proper buttons
        this.createFirstTab();
        this.initializeTurnstile();
    }

    initializeErrorElements() {
        try {
            // Create error popup elements if they don't exist
            if (!document.querySelector('.error-popup')) {
                const errorHtml = `
                    <div class="error-popup">
                        <div class="error-popup-content">
                            <h3 class="error-popup-title">Error</h3>
                            <p class="error-popup-message"></p>
                            <button class="error-popup-button">OK</button>
                        </div>
                    </div>
                    <div class="error-popup-overlay"></div>
                `;
                document.body.insertAdjacentHTML('beforeend', errorHtml);
            }

            // Initialize error popup elements
            this.errorPopup = document.querySelector('.error-popup');
            this.errorPopupMessage = document.querySelector('.error-popup-message');
            this.errorPopupOverlay = document.querySelector('.error-popup-overlay');
            this.errorPopupButton = document.querySelector('.error-popup-button');

            if (!this.errorPopup || !this.errorPopupMessage || !this.errorPopupOverlay || !this.errorPopupButton) {
                throw new Error('Error popup elements not found');
            }

            // Setup error popup event listeners
            this.errorPopupButton.addEventListener('click', () => this.hideError());
            this.errorPopupOverlay.addEventListener('click', () => this.hideError());

            return true;
        } catch (error) {
            console.error('Error initializing error elements:', error);
            return false;
        }
    }

    // Show custom error message
    showError(message, title = 'Error') {
        if (!this.errorPopup || !this.errorPopupMessage) {
            console.error('Error popup not initialized:', message);
            alert(message); // Fallback to alert if error popup is not available
            return;
        }

        this.errorPopupMessage.textContent = message;
        this.errorPopup.querySelector('.error-popup-title').textContent = title;
        this.errorPopup.classList.add('show');
        this.errorPopupOverlay.classList.add('show');
    }

    // Hide error popup
    hideError() {
        if (!this.errorPopup || !this.errorPopupOverlay) return;
        this.errorPopup.classList.remove('show');
        this.errorPopupOverlay.classList.remove('show');
    }

    initializeTurnstile() {
        try {
            // Check if turnstile container exists
            const turnstileContainer = document.querySelector('#turnstile-container');
            if (!turnstileContainer) {
                throw new Error('Turnstile container element not found');
            }

            // Check for site key in window context
            if (!window.TURNSTILE_SITE_KEY || window.TURNSTILE_SITE_KEY === "") {
                console.warn('Turnstile site key not configured properly. Using development fallback.');
                // In development mode, use a fallback token system
                this.turnstileToken = "devmode_token_bypass";
                turnstileContainer.innerHTML = `
                    <div class="dev-mode-turnstile">
                        <div class="dev-notice">Development Mode: Turnstile Bypassed</div>
                    </div>
                `;
                return;
            }

            // Wait for turnstile to be available
            const waitForTurnstile = () => {
                if (window.turnstile) {
                    // Render the widget
                    this.turnstileWidget = window.turnstile.render('#turnstile-container', {
                        sitekey: window.TURNSTILE_SITE_KEY,
                        theme: 'light',
                        callback: (token) => {
                            console.log('Turnstile verification completed');
                            this.turnstileToken = token;
                        },
                        'expired-callback': () => {
                            console.log('Turnstile verification expired');
                            this.turnstileToken = null;
                        },
                        'error-callback': (error) => {
                            console.error('Turnstile error:', error);
                            if (error.includes('110200')) {
                                this.showError(
                                    'Domain not authorized for Turnstile. Please ensure your domain is added to the Cloudflare Turnstile configuration.',
                                    'Configuration Error'
                                );
                            } else {
                                this.showError('Security verification error: ' + error);
                            }
                            this.turnstileToken = null;
                        }
                    });
                } else {
                    // Check again in 100ms
                    setTimeout(waitForTurnstile, 100);
                }
            };

            // Start waiting for turnstile
            waitForTurnstile();
        } catch (error) {
            console.error('Turnstile initialization error:', error);
            this.showError('Error initializing security verification: ' + error.message);
        }
    }

    validateTabState() {
        // Ensure DOM tabs match our tab state
        const domTabs = document.querySelectorAll('.tab:not(#new-tab)');
        const tabCount = this.tabs.size;

        if (domTabs.length !== tabCount) {
            this.showError('Tab state mismatch detected. Rebuilding tabs...');
            this.rebuildTabs();
            return false;
        }

        // Validate tab IDs and update tabIdCounter
        const domTabIds = Array.from(domTabs).map(tab => parseInt(tab.getAttribute('data-tab')));
        const stateTabIds = Array.from(this.tabs.keys());
        
        // Update tabIdCounter to be the highest ID
        this.tabIdCounter = Math.max(...stateTabIds, this.tabIdCounter);
        
        if (!domTabIds.every(id => stateTabIds.includes(id))) {
            this.showError('Tab ID mismatch detected. Rebuilding tabs...');
            this.rebuildTabs();
            return false;
        }

        return true;
    }

    addNewTab() {
        if (this.tabs.size >= 10) {
            this.showError('Maximum of 10 tabs allowed');
            return;
        }
        
        // Increment tab counter and create a new tab
        this.tabIdCounter++;
        const newTabId = this.tabIdCounter;
        this.tabs.set(newTabId, { content: '', name: `Tab ${newTabId}` });
        
        // Rebuild the tabs UI
        this.rebuildTabs();
        
        // Switch to the new tab
        this.switchTab(newTabId);
        
        // Update raw access options since tab count has changed
        this.updateRawAccess();
    }

    deleteTab(tabId) {
        // Cannot delete if only one tab remains
        if (this.tabs.size <= 1) {
            return;
        }
        
        // Delete tab from storage
        this.tabs.delete(parseInt(tabId));
        
        // If we deleted the active tab, switch to another one
        if (this.activeTab === parseInt(tabId)) {
            const remainingTabs = Array.from(this.tabs.keys());
            this.switchTab(remainingTabs[0]);
        }
        
        // Rebuild tabs UI
        this.rebuildTabs();
        
        // Update raw access options since tab count has changed
        this.updateRawAccess();
    }

    switchTab(tabId) {
        if (!this.tabs.has(tabId)) {
            this.showError('Attempted to switch to non-existent tab:', tabId);
            return;
        }

        // Save current tab content
        this.saveTabContent();
        
        // Update active tab
        this.activeTab = tabId;
        
        // Load tab content
        const tab = this.tabs.get(tabId);
        this.editor.value = tab.content;
        this.updateLineNumbers();
        this.updateWordCount();

        // Apply syntax highlighting if available
        if (window.SyntaxHighlighter && this.editor) {
            const highlighter = new SyntaxHighlighter();
            highlighter.highlightElement(this.editor, tab.name);
        }

        // Rebuild tabs to ensure correct state
        this.rebuildTabs();
    }

    updateRawAccess() {
        const isMultiTab = this.tabs.size > 1;
        const isPrivate = this.isPrivateCheckbox && this.isPrivateCheckbox.checked;
        const rawAccessCard = document.getElementById('raw-access-card');
        const warningText = document.getElementById('raw-warning-text');
        
        if (this.allowRawCheckbox) {
            this.allowRawCheckbox.disabled = isMultiTab || isPrivate;
            if (isMultiTab || isPrivate) {
                this.allowRawCheckbox.checked = false;
                
                // Add disabled class to the card for visual feedback
                rawAccessCard.classList.add('disabled');
                
                // Update warning message based on the reason(s)
                if (isMultiTab && isPrivate) {
                    warningText.textContent = 'Disabled due to MULTI_TAB and PRIVATE PASTE';
                } else if (isMultiTab) {
                    warningText.textContent = 'Disabled due to MULTI_TAB';
                } else if (isPrivate) {
                    warningText.textContent = 'Disabled due to PRIVATE PASTE';
                }
            } else {
                // Remove disabled class if neither condition is true
                rawAccessCard.classList.remove('disabled');
            }
        }
    }

    initializeElements() {
        // Get editor elements
        this.editor = document.getElementById('paste-content');
        this.lineNumbers = document.querySelector('.line-numbers');
        
        // Create a container for line numbers content
        this.lineNumbersContent = document.createElement('div');
        this.lineNumbersContent.className = 'line-numbers-content';
        this.lineNumbers.appendChild(this.lineNumbersContent);
        
        this.wordCounter = document.getElementById('word-counter');
        this.tabsContainer = document.getElementById('tabs');
        this.newTabButton = document.getElementById('new-tab');
        this.submitButton = document.getElementById('submit-paste');
        this.loadingOverlay = document.getElementById('loading-overlay');
        
        // Options elements
        this.isPrivateCheckbox = document.getElementById('is-private');
        this.passwordSection = document.getElementById('password-section');
        this.allowRawCheckbox = document.getElementById('allow-raw');
        this.enableExpiryCheckbox = document.getElementById('enable-expiry');
        this.expirySection = document.getElementById('expiry-section');
        this.enableBurnCheckbox = document.getElementById('enable-burn');
        this.burnSection = document.getElementById('burn-section');

        // Initialize drag state
        this.dragState = {
            isDragging: false,
            draggedTab: null,
            dragStartX: 0,
            originalX: 0,
            currentDropTarget: null
        };

        // Ensure initial state
        if (!this.editor || !this.lineNumbers || !this.wordCounter) {
            this.showError('Required elements not found');
            return;
        }

        // Initialize the editor
        this.editor.value = '';
        this.updateLineNumbers();
        this.updateWordCount();
    }

    setupEventListeners() {
        if (!this.editor) return;

        // Editor content changes
        this.editor.addEventListener('input', () => {
            this.updateLineNumbers();
            this.updateWordCount();
            this.saveTabContent();
        });

        // Sync line numbers scrolling with editor
        this.editor.addEventListener('scroll', () => {
            if (this.lineNumbersContent) {
                this.lineNumbersContent.style.transform = `translateY(-${this.editor.scrollTop}px)`;
            }
        });

        // Tab management
        this.newTabButton.addEventListener('click', () => this.addNewTab());
        
        if (this.tabsContainer) {
            this.tabsContainer.addEventListener('click', (e) => this.handleTabClick(e));
            this.tabsContainer.addEventListener('mousedown', (e) => this.handleTabDragStart(e));
        }

        document.addEventListener('mousemove', (e) => this.handleTabDrag(e));
        document.addEventListener('mouseup', () => this.handleTabDragEnd());

        // Options events
        if (this.isPrivateCheckbox && this.passwordSection) {
            this.isPrivateCheckbox.addEventListener('change', () => {
                this.passwordSection.classList.toggle('hidden');
                this.updateRawAccess();
            });
        }

        if (this.enableExpiryCheckbox && this.expirySection) {
            this.enableExpiryCheckbox.addEventListener('change', () => {
                this.expirySection.classList.toggle('hidden');
            });
        }

        if (this.enableBurnCheckbox && this.burnSection) {
            this.enableBurnCheckbox.addEventListener('change', () => {
                this.burnSection.classList.toggle('hidden');
            });
        }

        // Submit event
        if (this.submitButton) {
            this.submitButton.addEventListener('click', () => this.submitPaste());
        }

        // Add window resize listener for tab spacing
        window.addEventListener('resize', () => {
            this.updateTabSpacing();
        });
    }

    updateLineNumbers() {
        if (!this.editor || !this.lineNumbersContent) return;
        
        const content = this.editor.value;
        const lines = content.split('\n');
        const lineCount = Math.max(lines.length, 1);
        
        // Clear existing line numbers
        this.lineNumbersContent.innerHTML = '';
        
        // Add line numbers
        for (let i = 1; i <= lineCount; i++) {
            const div = document.createElement('div');
            div.className = 'line-number';
            div.textContent = i;
            this.lineNumbersContent.appendChild(div);
        }
    }

    updateWordCount() {
        if (!this.editor || !this.wordCounter) return;
        
        const text = this.editor.value;
        const trimmedText = text.trim();
        
        // Calculate metrics
        const charCount = text.length;
        const wordCount = trimmedText ? trimmedText.split(/\s+/).length : 0;
        const lineCount = text ? text.split('\n').length : 0;
        
        // Calculate true file size using Blob (accurate byte count for UTF-8 encoding)
        const trueBytes = new Blob([text]).size;
        const formattedSize = this.formatFileSize(trueBytes);
        
        // Calculate UTF-8/ASCII ratio to show encoding efficiency
        const asciiCount = (text.match(/[\x00-\x7F]/g) || []).length;
        const nonAsciiCount = charCount - asciiCount;
        const encodingRatio = charCount > 0 ? (trueBytes / charCount).toFixed(2) : 0;
        
        // Create efficiency indicator based on ratio
        let encodingEfficiency = '';
        if (nonAsciiCount > 0) {
            const efficiencyTitle = `${nonAsciiCount} non-ASCII characters detected that use multiple bytes in UTF-8 encoding`;
            encodingEfficiency = ` | <span title="${efficiencyTitle}" class="${encodingRatio > 1.5 ? 'encoding-high' : ''}">${this.formatNumber(asciiCount)} ASCII + ${this.formatNumber(nonAsciiCount)} multi-byte</span>`;
        }
        
        // Format the statistics display
        this.wordCounter.innerHTML = `
            <span title="Characters including spaces">Chars: ${this.formatNumber(charCount)}</span> | 
            <span title="Word count">Words: ${this.formatNumber(wordCount)}</span> | 
            <span title="Line count">Lines: ${this.formatNumber(lineCount)}</span> | 
            <span title="True file size (UTF-8 encoded)">Size: ${formattedSize}</span>${encodingEfficiency}
        `;
    }
    
    /**
     * Format a number with thousands separators
     * @param {number} num - The number to format
     * @returns {string} Formatted number
     */
    formatNumber(num) {
        return num.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
    }
    
    /**
     * Format file size in appropriate units
     * @param {number} bytes - Size in bytes
     * @returns {string} Formatted size
     */
    formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        
        const units = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(1024));
        
        // For bytes, show the exact count
        if (i === 0) return `${bytes} ${units[i]}`;
        
        // For KB and above, show with 2 decimal places
        return `${(bytes / Math.pow(1024, i)).toFixed(2)} ${units[i]}`;
    }

    createFirstTab() {
        const tabButton = document.createElement('button');
        tabButton.className = 'tab active';
        tabButton.setAttribute('data-tab', '1');
        
        const tabName = document.createElement('span');
        tabName.className = 'tab-name';
        tabName.setAttribute('data-tab', '1');
        tabName.textContent = 'Tab 1';

        const actionsDiv = document.createElement('div');
        actionsDiv.className = 'tab-actions';

        // Rename button
        const renameBtn = document.createElement('button');
        renameBtn.className = 'tab-action rename-tab';
        renameBtn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"></path><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"></path></svg>';
        renameBtn.title = 'Rename tab';
        renameBtn.setAttribute('aria-label', 'Rename tab');

        actionsDiv.appendChild(renameBtn);
        
        tabButton.appendChild(tabName);
        tabButton.appendChild(actionsDiv);
        
        // Clear existing tabs and add the first one
        this.tabsContainer.innerHTML = '';
        this.tabsContainer.appendChild(tabButton);
        this.tabsContainer.appendChild(this.newTabButton);

        // Update tab spacing
        this.updateTabSpacing();
    }

    handleTabClick(e) {
        const tabButton = e.target.closest('.tab');
        if (!tabButton) return;

        const tabId = parseInt(tabButton.getAttribute('data-tab'));
        
        // Handle rename button click
        if (e.target.closest('.rename-tab')) {
            this.startTabRename(tabButton.querySelector('.tab-name'));
            return;
        }

        // Handle delete button click
        if (e.target.closest('.delete-tab')) {
            this.deleteTab(tabId);
            return;
        }

        // Switch to tab if clicking anywhere else
        this.switchTab(tabId);
    }

    saveTabContent() {
        const tab = this.tabs.get(this.activeTab);
        if (tab) {
            tab.content = this.editor.value;
        }
    }

    startTabRename(tabNameElement) {
        const tabId = parseInt(tabNameElement.getAttribute('data-tab'));
        const currentTab = this.tabs.get(tabId);
        if (!currentTab) return;

        // Create popup if it doesn't exist
        let popup = document.querySelector('.tab-rename-popup');
        if (!popup) {
            popup = document.createElement('div');
            popup.className = 'tab-rename-popup';
            popup.innerHTML = `
                <input type="text" maxlength="50" placeholder="Enter tab name">
                <div class="buttons">
                    <button class="cancel">Cancel</button>
                    <button class="save">Save</button>
                </div>
            `;
            document.body.appendChild(popup);
        }

        const input = popup.querySelector('input');
        const saveBtn = popup.querySelector('.save');
        const cancelBtn = popup.querySelector('.cancel');
        
        // Set current tab name before showing popup
        input.value = currentTab.name;

        // Calculate position before showing popup
        const tabRect = tabNameElement.getBoundingClientRect();
        const popupWidth = 250; // min-width from CSS
        
        // Calculate left position to ensure popup doesn't go off-screen
        let leftPos = Math.min(
            tabRect.left,
            window.innerWidth - popupWidth - 16 // 16px padding from window edge
        );
        leftPos = Math.max(16, leftPos); // Ensure at least 16px from left edge

        // Position popup
        popup.style.top = `${tabRect.bottom + 8}px`;
        popup.style.left = `${leftPos}px`;
        
        // Add show class in next frame to ensure smooth animation
        requestAnimationFrame(() => {
            popup.classList.add('show');
            input.focus();
            input.select();
        });

        // Helper function to validate and sanitize tab name
        const sanitizeTabName = (name) => {
            const sanitized = name.replace(/[<>]/g, '').trim();
            const normalized = sanitized.replace(/\s+/g, ' ');
            return normalized.slice(0, 50);
        };

        // Helper function to close popup
        const closePopup = () => {
            popup.classList.remove('show');
            // Remove event listeners and popup after animation
            setTimeout(() => {
                document.removeEventListener('mousedown', handleOutsideClick);
                document.removeEventListener('keydown', handleKeyDown);
            }, 200); // Match transition duration from CSS
        };

        // Handle save
        const handleSave = () => {
            const newName = sanitizeTabName(input.value);
            if (newName.length >= 1) {
                currentTab.name = newName;
                this.tabs.set(tabId, currentTab);
                this.rebuildTabs();
                closePopup();
            } else {
                input.classList.add('error');
                setTimeout(() => input.classList.remove('error'), 300);
            }
        };

        // Event handlers
        const handleKeyDown = (e) => {
            if (e.key === 'Enter' && document.activeElement === input) {
                handleSave();
            } else if (e.key === 'Escape') {
                closePopup();
            }
        };

        const handleOutsideClick = (e) => {
            if (!popup.contains(e.target) && !tabNameElement.contains(e.target)) {
                closePopup();
            }
        };

        // Add event listeners
        saveBtn.onclick = handleSave;
        cancelBtn.onclick = closePopup;
        document.addEventListener('mousedown', handleOutsideClick);
        document.addEventListener('keydown', handleKeyDown);

        // Handle input validation
        input.oninput = () => {
            if (input.classList.contains('error')) {
                input.classList.remove('error');
            }
        };
    }

    rebuildTabs() {
        // Clear all tabs except the new tab button
        const tabsContainer = document.getElementById('tabs');
        while (tabsContainer.firstChild) {
            if (tabsContainer.firstChild.id === 'new-tab') break;
            tabsContainer.removeChild(tabsContainer.firstChild);
        }

        // Use the current order from the Map
        Array.from(this.tabs.entries()).forEach(([id, data]) => {
            const tabButton = document.createElement('button');
            tabButton.className = 'tab' + (id === this.activeTab ? ' active' : '');
            tabButton.setAttribute('data-tab', id);
            
            const tabName = document.createElement('span');
            tabName.className = 'tab-name';
            tabName.setAttribute('data-tab', id);
            tabName.textContent = data.name;

            const actionsDiv = document.createElement('div');
            actionsDiv.className = 'tab-actions';

            // Rename button
            const renameBtn = document.createElement('button');
            renameBtn.className = 'tab-action rename-tab';
            renameBtn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"></path><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"></path></svg>';
            renameBtn.title = 'Rename tab';
            renameBtn.setAttribute('aria-label', 'Rename tab');
            actionsDiv.appendChild(renameBtn);

            // Delete button (if more than one tab)
            if (this.tabs.size > 1) {
                const deleteBtn = document.createElement('button');
                deleteBtn.className = 'tab-action delete-tab';
                deleteBtn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 6L6 18"></path><path d="M6 6l12 12"></path></svg>';
                deleteBtn.title = 'Delete tab';
                deleteBtn.setAttribute('aria-label', 'Delete tab');
                actionsDiv.appendChild(deleteBtn);
            }
            
            tabButton.appendChild(tabName);
            tabButton.appendChild(actionsDiv);
            tabsContainer.insertBefore(tabButton, this.newTabButton);
        });

        // Update tab spacing
        this.updateTabSpacing();
    }

    updateTabSpacing() {
        const tabs = Array.from(document.querySelectorAll('.tab:not(#new-tab)'));
        const container = document.getElementById('tabs');
        const containerWidth = container.clientWidth;
        const newTabButtonWidth = this.newTabButton.offsetWidth;
        const availableWidth = containerWidth - newTabButtonWidth - 16; // 16px for container padding
        
        if (tabs.length === 0) return;

        // Calculate minimum width needed for all tabs
        const totalMinWidth = tabs.length * 100; // 100px minimum width per tab
        
        if (totalMinWidth <= availableWidth) {
            // If we have enough space, distribute evenly
            const tabWidth = Math.min(200, Math.floor(availableWidth / tabs.length));
            tabs.forEach(tab => {
                tab.style.width = `${tabWidth}px`;
                tab.style.flex = '0 0 auto';
            });
        } else {
            // If space is limited, let tabs scroll horizontally
            tabs.forEach(tab => {
                tab.style.width = '100px';
                tab.style.flex = '0 0 auto';
            });
        }
    }

    handleTabDragStart(e) {
        const tabButton = e.target.closest('.tab:not(#new-tab)');
        if (!tabButton || this.tabs.size <= 1) return;

        // Prevent text selection during drag
        e.preventDefault();

        this.dragState.isDragging = true;
        this.dragState.draggedTab = tabButton;
        this.dragState.dragStartX = e.clientX;
        this.dragState.originalX = tabButton.offsetLeft;

        // Add dragging styles
        tabButton.classList.add('dragging');
        document.body.style.cursor = 'grabbing';

        // Create and style ghost element
        const ghost = tabButton.cloneNode(true);
        ghost.classList.add('tab-ghost');
        ghost.style.position = 'absolute';
        ghost.style.left = `${this.dragState.originalX}px`;
        ghost.style.top = `${tabButton.offsetTop}px`;
        ghost.style.width = `${tabButton.offsetWidth}px`;
        ghost.style.pointerEvents = 'none';
        ghost.style.opacity = '0.8';
        ghost.style.transform = 'scale(1.05)';
        ghost.style.transition = 'transform 0.15s ease';
        
        this.dragState.ghost = ghost;
        this.tabsContainer.appendChild(ghost);

        // Add placeholder styles to original tab
        tabButton.style.opacity = '0.4';
    }

    handleTabDrag(e) {
        if (!this.dragState.isDragging) return;

        const deltaX = e.clientX - this.dragState.dragStartX;
        const newX = this.dragState.originalX + deltaX;

        // Move the ghost element
        this.dragState.ghost.style.left = `${newX}px`;

        // Find potential drop target
        const tabs = Array.from(this.tabsContainer.querySelectorAll('.tab:not(#new-tab):not(.dragging)'));
        const dropTarget = tabs.find(tab => {
            const rect = tab.getBoundingClientRect();
            return e.clientX < rect.right && e.clientX > rect.left;
        });

        // Update drop target styles
        if (this.dragState.currentDropTarget && this.dragState.currentDropTarget !== dropTarget) {
            this.dragState.currentDropTarget.classList.remove('drop-target');
        }
        if (dropTarget) {
            dropTarget.classList.add('drop-target');
            this.dragState.currentDropTarget = dropTarget;
        }
    }

    handleTabDragEnd() {
        if (!this.dragState.isDragging) return;

        const draggedTabId = parseInt(this.dragState.draggedTab.getAttribute('data-tab'));
        const dropTarget = this.dragState.currentDropTarget;

        if (dropTarget) {
            const targetTabId = parseInt(dropTarget.getAttribute('data-tab'));
            this.reorderTabs(draggedTabId, targetTabId);
        }

        // Clean up drag state
        this.dragState.draggedTab.classList.remove('dragging');
        this.dragState.draggedTab.style.opacity = '';
        if (this.dragState.currentDropTarget) {
            this.dragState.currentDropTarget.classList.remove('drop-target');
        }
        if (this.dragState.ghost) {
            this.dragState.ghost.remove();
        }
        document.body.style.cursor = '';

        // Reset drag state
        this.dragState = {
            isDragging: false,
            draggedTab: null,
            dragStartX: 0,
            originalX: 0,
            currentDropTarget: null,
            ghost: null
        };
    }

    reorderTabs(sourceId, targetId) {
        // Get the current order of tabs
        const tabOrder = Array.from(this.tabs.keys());
        const sourceIndex = tabOrder.indexOf(sourceId);
        const targetIndex = tabOrder.indexOf(targetId);

        // Remove source tab from array
        tabOrder.splice(sourceIndex, 1);
        // Insert it at the target position
        tabOrder.splice(targetIndex, 0, sourceId);

        // Create new Map with the updated order
        const reorderedTabs = new Map();
        tabOrder.forEach(id => {
            reorderedTabs.set(id, this.tabs.get(id));
        });

        // Update tabs Map and rebuild UI
        this.tabs = reorderedTabs;
        this.rebuildTabs();
    }

    async submitPaste() {
        try {
            // Save current tab content before submitting
            this.saveTabContent();

            // Filter out empty tabs and prepare tabs data
            const nonEmptyTabs = Array.from(this.tabs.entries())
                .filter(([_, tab]) => tab.content && tab.content.trim().length > 0)
                .map(([id, tab]) => ({
                    id: parseInt(id),
                    name: tab.name,
                    content: tab.content
                }));

            if (nonEmptyTabs.length === 0) {
                this.showError('At least one tab must have content');
                return;
            }

            // Check size limit for each tab
            for (const tab of nonEmptyTabs) {
                const contentSize = new Blob([tab.content]).size;
                if (contentSize > 2 * 1024 * 1024) {
                    this.showError(`Content in tab "${tab.name}" exceeds 2MB limit`);
                    return;
                }
            }

            // Check turnstile token - skip validation in development mode
            if (!this.turnstileToken && window.TURNSTILE_SITE_KEY && window.TURNSTILE_SITE_KEY !== "") {
                this.showError('Please complete the security verification');
                
                // If the widget is not visible, try refreshing it
                if (this.turnstileWidget && window.turnstile) {
                    window.turnstile.reset(this.turnstileWidget);
                }
                
                return;
            }

            // Show loading overlay
            this.loadingOverlay.style.display = 'flex';
            this.updateLoadingProgress(10); // Start progress indication

            // Prepare paste data
            const pasteData = {
                tabs: nonEmptyTabs,
                token: this.turnstileToken || "development_token" // Fallback for dev mode
            };

            // Add optional fields if they are enabled
            if (this.isPrivateCheckbox && this.isPrivateCheckbox.checked) {
                pasteData.isPrivate = true;
                pasteData.password = document.getElementById('paste-password').value;
            }

            if (this.allowRawCheckbox && this.allowRawCheckbox.checked) {
                pasteData.allowRaw = true;
            }

            if (this.enableExpiryCheckbox && this.enableExpiryCheckbox.checked) {
                const expiryValue = document.getElementById('expiry-value').value;
                if (!expiryValue || isNaN(parseInt(expiryValue))) {
                    this.loadingOverlay.style.display = 'none';
                    this.showError('Please enter a valid expiration value');
                    return;
                }
                
                pasteData.expiry = {
                    value: parseInt(expiryValue),
                    unit: document.getElementById('expiry-unit').value
                };
            }

            if (this.enableBurnCheckbox && this.enableBurnCheckbox.checked) {
                const burnCount = document.getElementById('burn-count').value;
                if (!burnCount || isNaN(parseInt(burnCount))) {
                    this.loadingOverlay.style.display = 'none';
                    this.showError('Please enter a valid view limit number');
                    return;
                }
                
                pasteData.burnCount = parseInt(burnCount);
            }

            this.updateLoadingProgress(30); // Update progress

            // Get CSRF token from header
            const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || 
                             document.head.querySelector('[name="csrf-token"]')?.getAttribute('content');

            // Set up fetch timeout
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 30000); // 30 second timeout

            try {
                this.updateLoadingProgress(50); // Update progress
                
                // Submit paste with timeout
                const response = await fetch('/paste', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRF-Token': csrfToken || ''
                    },
                    body: JSON.stringify(pasteData),
                    signal: controller.signal
                });

                this.updateLoadingProgress(80); // Update progress

                // Clear timeout since request completed
                clearTimeout(timeoutId);

                // Process response
                const result = await response.json();

                if (!response.ok) {
                    throw new Error(result.error || 'Failed to create paste');
                }

                this.updateLoadingProgress(100); // Complete progress
                
                // Redirect to the new paste
                window.location.href = `/paste/${result.id}`;
            } catch (error) {
                clearTimeout(timeoutId);
                
                if (error.name === 'AbortError') {
                    throw new Error('Request timed out. Please try again.');
                }
                throw error;
            }
        } catch (error) {
            this.loadingOverlay.style.display = 'none';
            
            // If the error is related to Turnstile, refresh the widget
            if (error.message.includes('security verification') && this.turnstileWidget && window.turnstile) {
                window.turnstile.reset(this.turnstileWidget);
            }
            
            this.showError(error.message);
        }
    }
    
    // Helper method to update loading progress
    updateLoadingProgress(percentage) {
        if (!this.loadingOverlay) return;
        
        const progressBar = this.loadingOverlay.querySelector('.progress-bar-fill');
        const loadingText = this.loadingOverlay.querySelector('.loading-text');
        
        if (progressBar) {
            progressBar.style.width = `${percentage}%`;
        }
        
        if (loadingText) {
            loadingText.textContent = `Submitting... ${percentage}%`;
        }
    }

    getOptions() {
        return {
            isPrivate: this.isPrivateCheckbox && this.isPrivateCheckbox.checked,
            password: this.isPrivateCheckbox && this.isPrivateCheckbox.checked ? document.getElementById('paste-password').value : undefined,
            allowRaw: this.allowRawCheckbox && this.allowRawCheckbox.checked,
            expiry: this.enableExpiryCheckbox && this.enableExpiryCheckbox.checked ? {
                value: parseInt(document.getElementById('expiry-value').value),
                unit: document.getElementById('expiry-unit').value
            } : undefined,
            burnCount: this.enableBurnCheckbox && this.enableBurnCheckbox.checked ? parseInt(document.getElementById('burn-count').value) : undefined
        };
    }

    getTurnstileToken() {
        return new Promise((resolve) => {
            if (this.turnstileToken) {
                resolve(this.turnstileToken);
            } else {
                const intervalId = setInterval(() => {
                    if (this.turnstileToken) {
                        clearInterval(intervalId);
                        resolve(this.turnstileToken);
                    }
                }, 100);
            }
        });
    }

    initializeAll() {
        this.initializeLineNumbers();
        this.initializeTabSwitching();
        this.initializeCopyButton();
        
        // Initialize syntax highlighting if available
        if (window.SyntaxHighlighter) {
            new SyntaxHighlighter();
        }
    }

    createTab(name = '', content = '') {
        // Generate a new tab ID
        this.tabIdCounter++;
        const tabId = this.tabIdCounter;
        
        // Add tab to the collection
        this.tabs.set(tabId, { name: name || `Tab ${tabId}`, content });
        
        // Switch to the new tab
        this.switchTab(tabId);
        
        // Apply syntax highlighting if available
        if (window.SyntaxHighlighter && this.editor) {
            const highlighter = new SyntaxHighlighter();
            highlighter.highlightElement(this.editor, name);
        }
        
        return tabId;
    }
}

// Initialize the editor when the DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.pasteEditor = new PasteEditor();
});
