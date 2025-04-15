document.addEventListener('DOMContentLoaded', () => {
    // Remove loader after everything is loaded
    window.addEventListener('load', () => {
        const loader = document.querySelector('.dashboard-loader');
        if (loader) {
            loader.classList.add('loaded');
            setTimeout(() => {
                loader.style.display = 'none';
            }, 500);
        }
    });
    
    // Load all graphs from HTML files
    loadAllGraphs();
    
    // Setup refresh buttons
    setupRefreshButtons();
    
    // Setup expand buttons
    setupExpandButtons();
    
    // Setup modal close button
    setupModalClose();
    
    // Update current time
    updateCurrentTime();
    setInterval(updateCurrentTime, 1000);
    
    // Format all number elements
    formatAllNumbers();
});

// Function to load all graphs from HTML files
function loadAllGraphs() {
    const graphContainers = document.querySelectorAll('.graph-container');
    
    graphContainers.forEach(container => {
        const url = container.getAttribute('data-url');
        if (url) {
            // Create or get existing iframe
            let iframe = container.querySelector('iframe');
            
            if (!iframe) {
                iframe = document.createElement('iframe');
                iframe.style.width = '100%';
                iframe.style.height = '100%';
                iframe.style.border = 'none';
                container.appendChild(iframe);
                
                // Add loading animation
                const loader = document.createElement('div');
                loader.className = 'graph-loader';
                loader.innerHTML = '<div class="spinner"></div>';
                container.appendChild(loader);
                
                // Add error handling
                iframe.onerror = () => {
                    handleIframeError(container, iframe);
                };
                
                // Handle iframe load event
                iframe.onload = () => {
                    const loader = container.querySelector('.graph-loader');
                    if (loader) {
                        loader.remove();
                    }
                    
                    // Check if the iframe loaded properly
                    try {
                        // Try to access iframe content to detect errors
                        setTimeout(() => {
                            if (iframe.contentDocument && 
                                iframe.contentDocument.title && 
                                iframe.contentDocument.title.includes("Not Found")) {
                                handleIframeError(container, iframe);
                            }
                        }, 500);
                    } catch (e) {
                        // If we can't access iframe content (CORS), just continue
                        console.log("Could not check iframe content: ", e);
                    }
                };
            }
            
            // Set iframe source
            iframe.src = url;
        }
    });
}

// Handle iframe loading errors
function handleIframeError(container, iframe) {
    // Create a fallback display
    const fallbackDiv = document.createElement('div');
    fallbackDiv.className = 'iframe-error';
    fallbackDiv.innerHTML = `
        <div class="error-content">
            <i class="fas fa-exclamation-circle"></i>
            <h3>Loading Graph...</h3>
            <p>The data is being processed. This graph will appear once data is available.</p>
        </div>
    `;
    
    // Replace the iframe with the fallback content
    container.innerHTML = '';
    container.appendChild(fallbackDiv);
    
    // Style the fallback content
    const style = document.createElement('style');
    style.textContent = `
        .iframe-error {
            width: 100%;
            height: 100%;
            display: flex;
            align-items: center;
            justify-content: center;
            background-color: rgba(0, 0, 0, 0.03);
            border-radius: var(--border-radius);
        }
        
        .error-content {
            text-align: center;
            padding: 20px;
            max-width: 80%;
        }
        
        .error-content i {
            font-size: 2.5rem;
            color: var(--text-light);
            margin-bottom: 15px;
        }
        
        .error-content h3 {
            margin-bottom: 10px;
            color: var(--text-color);
        }
        
        .error-content p {
            color: var(--text-light);
            font-size: 0.9rem;
        }
    `;
    
    if (!document.getElementById('iframe-error-styles')) {
        style.id = 'iframe-error-styles';
        document.head.appendChild(style);
    }
}

// Function to setup refresh buttons
function setupRefreshButtons() {
    const refreshButtons = document.querySelectorAll('.refresh-btn');
    
    refreshButtons.forEach(button => {
        button.addEventListener('click', () => {
            const targetId = button.getAttribute('data-target');
            const container = document.getElementById(targetId);
            
            if (container) {
                // Add spinning animation to refresh button
                button.classList.add('spinning');
                
                // Get the iframe and refresh it
                const iframe = container.querySelector('iframe');
                if (iframe) {
                    const url = container.getAttribute('data-url');
                    if (url) {
                        // Add timestamp to break cache and force reload
                        const timestamp = new Date().getTime();
                        const separator = url.includes('?') ? '&' : '?';
                        iframe.src = `${url}${separator}t=${timestamp}`;
                        
                        // Remove spinning class after animation completes
                        setTimeout(() => {
                            button.classList.remove('spinning');
                        }, 1000);
                    }
                }
            }
        });
    });
}

// Function to setup expand buttons
function setupExpandButtons() {
    const expandButtons = document.querySelectorAll('.expand-btn');
    const modal = document.getElementById('graph-modal');
    const modalTitle = document.getElementById('modal-title');
    const expandedGraph = document.getElementById('expanded-graph');
    
    if (!modal || !modalTitle || !expandedGraph) return;
    
    expandButtons.forEach(button => {
        button.addEventListener('click', () => {
            const targetId = button.getAttribute('data-target');
            const container = document.getElementById(targetId);
            
            if (container) {
                // Get the title
                const headerElement = container.parentElement.querySelector('h3');
                const title = headerElement ? headerElement.textContent : 'Graph';
                
                // Get the URL
                const url = container.getAttribute('data-url');
                
                // Set modal title
                modalTitle.textContent = title;
                
                // Create iframe in expanded graph container
                expandedGraph.innerHTML = '';
                const iframe = document.createElement('iframe');
                iframe.style.width = '100%';
                iframe.style.height = '100%';
                iframe.style.border = 'none';
                iframe.src = url;
                
                expandedGraph.appendChild(iframe);
                
                // Show modal
                modal.classList.add('active');
            }
        });
    });
}

// Function to setup modal close button
function setupModalClose() {
    const modal = document.getElementById('graph-modal');
    const closeButton = document.querySelector('.close-modal');
    
    if (!modal || !closeButton) return;
    
    closeButton.addEventListener('click', () => {
        modal.classList.remove('active');
    });
    
    // Close modal when clicking outside of modal content
    modal.addEventListener('click', (e) => {
        if (e.target === modal) {
            modal.classList.remove('active');
        }
    });
    
    // Close modal with Escape key
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape' && modal.classList.contains('active')) {
            modal.classList.remove('active');
        }
    });
}

// Function to update current timestamp
function updateCurrentTime() {
    const currentTimeElement = document.getElementById('current-time');
    if (currentTimeElement) {
        const now = new Date();
        const formattedTime = now.toLocaleString('en-US', {
            year: 'numeric',
            month: 'short',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit'
        });
        currentTimeElement.textContent = formattedTime;
    }
}

// Function to format numbers with commas as thousands separators
function formatNumber(num) {
    return num.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
}

// Format all number elements
function formatAllNumbers() {
    const numberElements = document.querySelectorAll('.stat-value');
    numberElements.forEach(element => {
        const value = parseInt(element.textContent);
        if (!isNaN(value)) {
            element.textContent = formatNumber(value);
        }
    });
}

// Add CSS for the graph loader and spinning animation
const style = document.createElement('style');
style.textContent = `
    .graph-loader {
        position: absolute;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        display: flex;
        justify-content: center;
        align-items: center;
        background-color: rgba(248, 249, 250, 0.7);
    }
    
    .dark-theme .graph-loader {
        background-color: rgba(30, 30, 30, 0.7);
    }
    
    .spinner {
        width: 40px;
        height: 40px;
        border: 4px solid rgba(74, 144, 226, 0.3);
        border-top: 4px solid var(--primary-color);
        border-radius: 50%;
        animation: spin 1s linear infinite;
    }
    
    @keyframes spin {
        0% { transform: rotate(0deg); }
        100% { transform: rotate(360deg); }
    }
    
    .refresh-btn.spinning i {
        animation: spin 1s linear infinite;
    }

    /* Table styles for all data tables */
    .data-section {
        margin-bottom: 2rem;
    }
    
    .search-container {
        margin-bottom: 1rem;
    }
    
    .search-input {
        width: 100%;
        padding: 0.75rem 1rem;
        border: 1px solid var(--border-color);
        border-radius: var(--border-radius);
        background-color: var(--card-bg);
        color: var(--text-color);
        font-size: 1rem;
        transition: all 0.3s ease;
    }
    
    .search-input:focus {
        outline: none;
        border-color: var(--primary-color);
        box-shadow: 0 0 0 3px rgba(74, 144, 226, 0.1);
    }
    
    .table-container {
        overflow-x: auto;
        background-color: var(--card-bg);
        border-radius: var(--border-radius-large);
        box-shadow: var(--shadow-medium);
        border: 1px solid var(--border-color);
    }
    
    .data-table {
        width: 100%;
        border-collapse: collapse;
    }
    
    .data-table th, .data-table td {
        padding: 1rem;
        text-align: left;
        border-bottom: 1px solid var(--border-color);
    }
    
    .data-table th {
        background-color: rgba(0, 0, 0, 0.02);
        font-weight: 600;
        position: relative;
    }
    
    .data-table th::after {
        content: '';
        position: absolute;
        right: 0.5rem;
        top: 50%;
        transform: translateY(-50%);
        width: 0;
        height: 0;
    }
    
    .data-table th.sort-asc::after {
        content: '▲';
        font-size: 0.7rem;
    }
    
    .data-table th.sort-desc::after {
        content: '▼';
        font-size: 0.7rem;
    }
    
    .data-table tbody tr:last-child td {
        border-bottom: none;
    }
    
    .data-table tbody tr:hover {
        background-color: rgba(0, 0, 0, 0.02);
    }

    /* Router button styles */
    .router-button {
        display: inline-flex;
        align-items: center;
        gap: var(--spacing-sm);
        padding: var(--spacing-md) var(--spacing-lg);
        border-radius: var(--border-radius-large);
        background: var(--gradient-secondary);
        color: white;
        border: none;
        box-shadow: var(--shadow-medium);
        font-weight: 600;
        letter-spacing: 0.5px;
        margin-right: 1rem;
        transition: all 0.3s cubic-bezier(0.175, 0.885, 0.32, 1.275);
    }
    
    .router-button i {
        font-size: 1.4rem;
    }
    
    .router-button:hover {
        background: linear-gradient(135deg, var(--secondary-color), var(--secondary-dark));
        color: white;
        transform: translateY(-3px) scale(1.05);
        box-shadow: var(--shadow-large), 0 0 15px rgba(155, 89, 182, 0.5);
    }
    
    .router-button:active {
        transform: translateY(0) scale(0.98);
    }
`;

document.head.appendChild(style);
