// Main JavaScript functionality
document.addEventListener('DOMContentLoaded', () => {
    // Note: Theme toggle functionality has been moved to theme-toggle.js
    
    // Custom cursor glow effect
    const cursorGlow = document.createElement('div');
    cursorGlow.className = 'cursor-glow primary';
    document.body.appendChild(cursorGlow);
    
    // Track mouse movement
    document.addEventListener('mousemove', (e) => {
        cursorGlow.style.display = 'block';
        cursorGlow.style.left = `${e.clientX}px`;
        cursorGlow.style.top = `${e.clientY}px`;
    });
    
    // Change glow color based on element being hovered
    const primaryElements = document.querySelectorAll('a, .cluster-card[data-cluster="1"], .device-card:nth-child(1), .metric-card:nth-child(3n+1)');
    const secondaryElements = document.querySelectorAll('.cluster-card[data-cluster="2"], .device-card:nth-child(2), .metric-card:nth-child(3n+2)');
    const tertiaryElements = document.querySelectorAll('.cluster-card[data-cluster="3"], .device-card:nth-child(3), .metric-card:nth-child(3n+3)');
    const accentElements = document.querySelectorAll('.sos-button, button.danger, .device-status.offline');
    const quaternaryElements = document.querySelectorAll('.device-card:nth-child(4), .stat-card:nth-child(4)');
    
    // Apply interactions for primary color elements
    primaryElements.forEach(element => {
        element.addEventListener('mouseenter', () => {
            cursorGlow.className = 'cursor-glow primary';
            cursorGlow.style.width = '400px';
            cursorGlow.style.height = '400px';
        });
        
        element.addEventListener('mouseleave', () => {
            cursorGlow.className = 'cursor-glow primary';
            cursorGlow.style.width = '300px';
            cursorGlow.style.height = '300px';
        });
    });
    
    // Apply interactions for secondary color elements
    secondaryElements.forEach(element => {
        element.addEventListener('mouseenter', () => {
            cursorGlow.className = 'cursor-glow secondary';
            cursorGlow.style.width = '400px';
            cursorGlow.style.height = '400px';
        });
        
        element.addEventListener('mouseleave', () => {
            cursorGlow.className = 'cursor-glow primary';
            cursorGlow.style.width = '300px';
            cursorGlow.style.height = '300px';
        });
    });
    
    // Apply interactions for tertiary color elements
    tertiaryElements.forEach(element => {
        element.addEventListener('mouseenter', () => {
            cursorGlow.className = 'cursor-glow tertiary';
            cursorGlow.style.width = '400px';
            cursorGlow.style.height = '400px';
        });
        
        element.addEventListener('mouseleave', () => {
            cursorGlow.className = 'cursor-glow primary';
            cursorGlow.style.width = '300px';
            cursorGlow.style.height = '300px';
        });
    });
    
    // Apply interactions for accent color elements
    accentElements.forEach(element => {
        element.addEventListener('mouseenter', () => {
            cursorGlow.className = 'cursor-glow accent';
            cursorGlow.style.width = '400px';
            cursorGlow.style.height = '400px';
        });
        
        element.addEventListener('mouseleave', () => {
            cursorGlow.className = 'cursor-glow primary';
            cursorGlow.style.width = '300px';
            cursorGlow.style.height = '300px';
        });
    });
    
    // Apply interactions for quaternary color elements
    quaternaryElements.forEach(element => {
        element.addEventListener('mouseenter', () => {
            cursorGlow.className = 'cursor-glow quaternary';
            cursorGlow.style.width = '400px';
            cursorGlow.style.height = '400px';
        });
        
        element.addEventListener('mouseleave', () => {
            cursorGlow.className = 'cursor-glow primary';
            cursorGlow.style.width = '300px';
            cursorGlow.style.height = '300px';
        });
    });
    
    // Intersection Observer for animated elements
    const animatedElements = document.querySelectorAll('.section-title, .overview-content, .team-video, .cluster-card');
    
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('animated');
                observer.unobserve(entry.target);
            }
        });
    }, {
        threshold: 0.1
    });
    
    animatedElements.forEach(element => {
        observer.observe(element);
    });
});

// Function to format numbers with commas as thousands separators
function formatNumber(num) {
    return num.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
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

// Initialize common elements
document.addEventListener('DOMContentLoaded', () => {
    updateCurrentTime();
    setInterval(updateCurrentTime, 1000);
    formatAllNumbers();
});
