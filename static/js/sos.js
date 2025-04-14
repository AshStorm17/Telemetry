document.addEventListener('DOMContentLoaded', () => {
    // Emergency Action Button
    const emergencyButton = document.querySelector('.emergency-action-btn');
    if (emergencyButton) {
        emergencyButton.addEventListener('click', (e) => {
            e.preventDefault();
            
            // Show confirmation dialog
            const confirm = window.confirm('Are you sure you want to initiate emergency protocol? This will alert all network administrators.');
            
            if (confirm) {
                // Simulated emergency protocol initiation
                emergencyButton.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Initiating Protocol...';
                emergencyButton.style.backgroundColor = '#c0392b';
                emergencyButton.style.pointerEvents = 'none';
                
                // Simulate response after 3 seconds
                setTimeout(() => {
                    emergencyButton.innerHTML = '<i class="fas fa-check"></i> Protocol Initiated';
                    
                    // Show alert
                    showAlert('Emergency protocol initiated. Administrators have been notified.', 'success');
                    
                    // Simulate status change
                    updateNetworkStatus();
                }, 3000);
            }
        });
    }
    
    // Call buttons
    const callButtons = document.querySelectorAll('.contact-call-btn');
    callButtons.forEach(button => {
        button.addEventListener('click', () => {
            const contactName = button.closest('.contact').querySelector('.contact-name').textContent;
            const phoneNumber = button.closest('.contact').querySelector('.contact-phone').textContent.replace(/[^0-9+]/g, '');
            
            // Simulate call initiation
            button.innerHTML = '<i class="fas fa-phone-volume"></i>';
            
            // Show alert
            showAlert(`Calling ${contactName}...`, 'info');
            
            // Reset button after 2 seconds
            setTimeout(() => {
                button.innerHTML = '<i class="fas fa-phone"></i>';
            }, 2000);
        });
    });
    
    // Resource links
    const resourceLinks = document.querySelectorAll('.resource-item');
    resourceLinks.forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            
            const resourceName = link.querySelector('span').textContent;
            
            // Show alert for resource download
            showAlert(`Downloading ${resourceName}...`, 'info');
        });
    });
    
    // Real-time network status update simulation
    setInterval(updateNetworkStatusTime, 10000);
    
    // Add animated background
    addAnimatedBackground();
});

// Function to show alerts
function showAlert(message, type) {
    // Check if alert container exists
    let alertContainer = document.querySelector('.alert-container');
    
    // Create alert container if it doesn't exist
    if (!alertContainer) {
        alertContainer = document.createElement('div');
        alertContainer.className = 'alert-container';
        alertContainer.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            z-index: 1000;
            width: 300px;
        `;
        document.body.appendChild(alertContainer);
    }
    
    // Create the alert
    const alert = document.createElement('div');
    alert.className = `alert alert-${type}`;
    alert.innerHTML = message;
    
    // Style the alert
    alert.style.cssText = `
        background-color: ${getAlertColor(type)};
        color: white;
        padding: 12px 15px;
        border-radius: 20px;
        margin-bottom: 10px;
        box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        opacity: 0;
        transform: translateX(50px);
        transition: opacity 0.3s, transform 0.3s;
    `;
    
    // Add to container
    alertContainer.appendChild(alert);
    
    // Trigger animation
    setTimeout(() => {
        alert.style.opacity = '1';
        alert.style.transform = 'translateX(0)';
    }, 10);
    
    // Remove after 5 seconds
    setTimeout(() => {
        alert.style.opacity = '0';
        alert.style.transform = 'translateX(50px)';
        
        setTimeout(() => {
            alert.remove();
        }, 300);
    }, 5000);
}

// Function to get alert color based on type
function getAlertColor(type) {
    switch(type) {
        case 'success': return '#2ecc71';
        case 'warning': return '#f39c12';
        case 'danger': return '#e74c3c';
        case 'info': default: return '#3498db';
    }
}

// Function to simulate network status changes
function updateNetworkStatus() {
    const statusValues = document.querySelectorAll('.status-value');
    
    // Simulate warning status for one area
    statusValues[1].textContent = 'Warning';
    statusValues[1].className = 'status-value warning';
    
    // Update last checked time
    const timeValue = statusValues[statusValues.length - 1];
    timeValue.textContent = 'Just now';
    
    // Add pulsing effect to warning status
    statusValues[1].style.animation = 'pulse 2s infinite';
    
    // Add alert
    showAlert('Warning: Unusual traffic detected in Hostel Area', 'warning');
}

// Function to update the "last checked" time
function updateNetworkStatusTime() {
    const timeValue = document.querySelector('.status-item:last-child .status-value');
    if (timeValue) {
        timeValue.textContent = 'Just now';
    }
}

// Function to add animated background
function addAnimatedBackground() {
    const container = document.querySelector('.sos-container');
    if (!container) return;
    
    // Add background pattern
    const pattern = document.createElement('div');
    pattern.className = 'sos-background-pattern';
    pattern.style.cssText = `
        position: absolute;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        pointer-events: none;
        z-index: -1;
        opacity: 0.03;
        background-image: radial-gradient(circle at 20px 20px, var(--danger-color) 2px, transparent 0);
        background-size: 40px 40px;
    `;
    
    container.style.position = 'relative';
    container.appendChild(pattern);
    
    // Add keyframes for emergency pulse animation if it doesn't exist
    if (!document.getElementById('emergencyPulseKeyframes')) {
        const keyframes = document.createElement('style');
        keyframes.id = 'emergencyPulseKeyframes';
        keyframes.textContent = `
            @keyframes pulse {
                0%, 100% {
                    opacity: 1;
                    transform: scale(1);
                }
                50% {
                    opacity: 0.8;
                    transform: scale(1.05);
                }
            }
        `;
        document.head.appendChild(keyframes);
    }
    
    // Add subtle animation to cards
    const sosCards = document.querySelectorAll('.sos-card');
    sosCards.forEach((card, index) => {
        card.style.transition = 'transform 0.3s ease, box-shadow 0.3s ease';
        
        card.addEventListener('mouseenter', () => {
            card.style.transform = 'translateY(-5px)';
            card.style.boxShadow = '0 10px 20px rgba(0,0,0,0.1)';
        });
        
        card.addEventListener('mouseleave', () => {
            card.style.transform = 'translateY(0)';
            card.style.boxShadow = '';
        });
    });
}
