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
    
    // Auto-refresh graphs every 5 seconds (changed from 0.5 seconds to reduce load)
    setInterval(() => {
        loadAllGraphs();
    }, 5000);
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
                                (iframe.contentDocument.title.includes("Not Found") || 
                                 iframe.contentDocument.body.innerHTML.includes("Not Found"))) {
                                handleIframeError(container, iframe);
                            }
                        }, 500);
                    } catch (e) {
                        // If we can't access iframe content (CORS), just continue
                        console.log("Could not check iframe content: ", e);
                    }
                };
            }
            
            // Add timestamp to break cache and force reload
            const timestamp = new Date().getTime();
            // Fix URL path if needed - ensure it starts with correct path
            let correctedUrl = url;
            if (!correctedUrl.startsWith('/')) {
                correctedUrl = '/' + correctedUrl;
            }
            
            // For development: Try fallback to placeholder if real graphs don't exist
            if (iframe.src === '' || iframe.src.includes('?')) {
                // First attempt with the provided URL
                const separator = correctedUrl.includes('?') ? '&' : '?';
                iframe.src = `${correctedUrl}${separator}t=${timestamp}`;
            }
        }
    });
}

// Handle iframe loading errors
function handleIframeError(container, iframe) {
    console.log("Handling iframe error for:", container.id);
    
    // Create a fallback display
    const fallbackDiv = document.createElement('div');
    fallbackDiv.className = 'iframe-error';
    fallbackDiv.innerHTML = `
        <div class="error-content">
            <i class="fas fa-chart-line"></i>
            <h3>Loading Graph...</h3>
            <p>Generating visualization. This graph will appear once data is available.</p>
            <div class="placeholder-chart">
                <div class="placeholder-line"></div>
                <div class="placeholder-line"></div>
                <div class="placeholder-line"></div>
                <div class="placeholder-line"></div>
                <div class="placeholder-axis-x"></div>
                <div class="placeholder-axis-y"></div>
            </div>
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
            color: var(--primary-color);
            margin-bottom: 15px;
            opacity: 0.7;
        }
        
        .error-content h3 {
            margin-bottom: 10px;
            color: var(--text-color);
        }
        
        .error-content p {
            color: var(--text-light);
            font-size: 0.9rem;
            margin-bottom: 20px;
        }
        
        .placeholder-chart {
            height: 100px;
            width: 100%;
            position: relative;
            margin-top: 20px;
            border-left: 1px dashed var(--border-color);
            border-bottom: 1px dashed var(--border-color);
        }
        
        .placeholder-line {
            position: absolute;
            height: 2px;
            background: var(--primary-light);
            opacity: 0.5;
            width: 80%;
            bottom: 10%;
            left: 10%;
            border-radius: 2px;
            animation: placeholder-pulse 2s infinite;
        }
        
        .placeholder-line:nth-child(1) {
            bottom: 30%;
            width: 70%;
            left: 15%;
            animation-delay: 0.3s;
        }
        
        .placeholder-line:nth-child(2) {
            bottom: 50%;
            width: 60%;
            left: 20%;
            animation-delay: 0.6s;
        }
        
        .placeholder-line:nth-child(3) {
            bottom: 70%;
            width: 80%;
            left: 10%;
            animation-delay: 0.9s;
        }
        
        .placeholder-line:nth-child(4) {
            bottom: 85%;
            width: 60%;
            left: 25%;
            animation-delay: 1.2s;
        }
        
        @keyframes placeholder-pulse {
            0%, 100% { opacity: 0.3; }
            50% { opacity: 0.6; }
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
                } else {
                    // If iframe doesn't exist (fallback is showing), try reloading
                    loadAllGraphs();
                    setTimeout(() => {
                        button.classList.remove('spinning');
                    }, 1000);
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
                
                // Add error handling
                iframe.onerror = () => {
                    expandedGraph.innerHTML = '<div class="modal-fallback">Graph data is being processed. Please try again later.</div>';
                };
                
                // Add timestamp to break cache and force reload
                const timestamp = new Date().getTime();
                const separator = url.includes('?') ? '&' : '?';
                iframe.src = `${url}${separator}t=${timestamp}`;
                
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
    
    .modal-fallback {
        display: flex;
        align-items: center;
        justify-content: center;
        height: 100%;
        padding: 20px;
        text-align: center;
        color: var(--text-light);
    }
`;

document.head.appendChild(style);
