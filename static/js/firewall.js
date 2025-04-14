document.addEventListener('DOMContentLoaded', () => {
    // Animate the packet elements in the SVG diagram
    animatePackets();
    
    // Placeholder button effect
    const placeholderButton = document.querySelector('.placeholder-button');
    if (placeholderButton) {
        placeholderButton.addEventListener('click', () => {
            placeholderButton.innerHTML = '<i class="fas fa-check"></i> Coming Soon';
            placeholderButton.style.backgroundColor = '#2ecc71';
            
            // Reset after 2 seconds
            setTimeout(() => {
                placeholderButton.innerHTML = 'Check Back Later';
                placeholderButton.style.backgroundColor = '';
            }, 2000);
        });
    }
    
    // Add interactive elements to the diagram
    makeNetworkDiagramInteractive();
});

// Function to animate the packet elements in SVG
function animatePackets() {
    const packets = document.querySelectorAll('.packet');
    
    // Set different animation delays for each packet
    packets.forEach((packet, index) => {
        // Create a different animation for each packet
        const pathAnimation = document.createElementNS('http://www.w3.org/2000/svg', 'animate');
        pathAnimation.setAttribute('attributeName', 'opacity');
        pathAnimation.setAttribute('values', '0;1;1;0');
        pathAnimation.setAttribute('keyTimes', '0;0.3;0.7;1');
        pathAnimation.setAttribute('dur', '3s');
        pathAnimation.setAttribute('begin', `${index * 0.7}s`);
        pathAnimation.setAttribute('repeatCount', 'indefinite');
        
        packet.appendChild(pathAnimation);
        
        // Different patterns for different packets
        let cx, cy;
        switch(index) {
            case 0: // Router to Firewall
                animatePacketPath(packet, 290, 150, 350, 150, 3, index * 0.7);
                break;
            case 1: // Firewall to Switch 1
                animatePacketPath(packet, 510, 120, 565, 95, 3, index * 0.7);
                break;
            case 2: // Firewall to Switch 2
                animatePacketPath(packet, 510, 180, 565, 205, 3, index * 0.7);
                break;
            case 3: // Internet to Router
                animatePacketPath(packet, 145, 150, 160, 150, 3, index * 0.7);
                break;
        }
    });
}

// Function to animate a packet along a path
function animatePacketPath(packet, startX, startY, endX, endY, duration, delay) {
    // Animate X coordinate
    const animateX = document.createElementNS('http://www.w3.org/2000/svg', 'animate');
    animateX.setAttribute('attributeName', 'cx');
    animateX.setAttribute('from', startX);
    animateX.setAttribute('to', endX);
    animateX.setAttribute('dur', `${duration}s`);
    animateX.setAttribute('begin', `${delay}s`);
    animateX.setAttribute('repeatCount', 'indefinite');
    packet.appendChild(animateX);
    
    // Animate Y coordinate
    const animateY = document.createElementNS('http://www.w3.org/2000/svg', 'animate');
    animateY.setAttribute('attributeName', 'cy');
    animateY.setAttribute('from', startY);
    animateY.setAttribute('to', endY);
    animateY.setAttribute('dur', `${duration}s`);
    animateY.setAttribute('begin', `${delay}s`);
    animateY.setAttribute('repeatCount', 'indefinite');
    packet.appendChild(animateY);
}

// Function to make the network diagram interactive
function makeNetworkDiagramInteractive() {
    const svgElements = document.querySelectorAll('.firewall-diagram circle, .firewall-diagram rect');
    const firewall = document.querySelector('.firewall-diagram circle:first-child');
    
    // Make elements interactive
    svgElements.forEach(element => {
        // Original styles
        const originalFill = element.getAttribute('fill');
        const originalStroke = element.getAttribute('stroke');
        
        // Add hover effect
        element.addEventListener('mouseenter', () => {
            element.style.cursor = 'pointer';
            element.setAttribute('fill', lightenColor(originalFill, 20));
            element.setAttribute('stroke-width', '3');
            
            // Show a tooltip
            showTooltip(element);
        });
        
        // Remove hover effect
        element.addEventListener('mouseleave', () => {
            element.style.cursor = 'default';
            element.setAttribute('fill', originalFill);
            element.setAttribute('stroke-width', '2');
            
            // Hide tooltip
            hideTooltip();
        });
        
        // Click effect
        element.addEventListener('click', () => {
            // Pulse animation
            element.animate([
                { transform: 'scale(1)', opacity: 1 },
                { transform: 'scale(1.1)', opacity: 0.8 },
                { transform: 'scale(1)', opacity: 1 }
            ], {
                duration: 500,
                iterations: 1
            });
            
            // Show info for the clicked element
            showDeviceInfo(element);
        });
    });
    
    // Special handling for firewall
    if (firewall) {
        // Make firewall glow periodically
        setInterval(() => {
            const glowFilter = document.createElementNS('http://www.w3.org/2000/svg', 'filter');
            glowFilter.setAttribute('id', 'firewall-glow');
            
            const feGaussianBlur = document.createElementNS('http://www.w3.org/2000/svg', 'feGaussianBlur');
            feGaussianBlur.setAttribute('stdDeviation', '3');
            feGaussianBlur.setAttribute('result', 'blur');
            
            const feColorMatrix = document.createElementNS('http://www.w3.org/2000/svg', 'feColorMatrix');
            feColorMatrix.setAttribute('in', 'blur');
            feColorMatrix.setAttribute('type', 'matrix');
            feColorMatrix.setAttribute('values', '1 0 0 0 0  0 1 0 0 0  0 0 1 0 0  0 0 0 18 -7');
            feColorMatrix.setAttribute('result', 'glow');
            
            const feMerge = document.createElementNS('http://www.w3.org/2000/svg', 'feMerge');
            
            const feMergeNode1 = document.createElementNS('http://www.w3.org/2000/svg', 'feMergeNode');
            feMergeNode1.setAttribute('in', 'glow');
            
            const feMergeNode2 = document.createElementNS('http://www.w3.org/2000/svg', 'feMergeNode');
            feMergeNode2.setAttribute('in', 'SourceGraphic');
            
            feMerge.appendChild(feMergeNode1);
            feMerge.appendChild(feMergeNode2);
            
            glowFilter.appendChild(feGaussianBlur);
            glowFilter.appendChild(feColorMatrix);
            glowFilter.appendChild(feMerge);
            
            const defs = document.querySelector('.firewall-diagram defs');
            if (defs && !document.getElementById('firewall-glow')) {
                defs.appendChild(glowFilter);
                firewall.setAttribute('filter', 'url(#firewall-glow)');
                
                setTimeout(() => {
                    firewall.removeAttribute('filter');
                    if (document.getElementById('firewall-glow')) {
                        document.getElementById('firewall-glow').remove();
                    }
                }, 2000);
            }
        }, 5000);
    }
}

// Utility function to lighten a color
function lightenColor(color, percent) {
    if (color.startsWith('#')) {
        // HEX color
        let r = parseInt(color.substring(1, 3), 16);
        let g = parseInt(color.substring(3, 5), 16);
        let b = parseInt(color.substring(5, 7), 16);
        
        r = Math.min(255, Math.round(r + (255 - r) * (percent / 100)));
        g = Math.min(255, Math.round(g + (255 - g) * (percent / 100)));
        b = Math.min(255, Math.round(b + (255 - b) * (percent / 100)));
        
        return `#${r.toString(16).padStart(2, '0')}${g.toString(16).padStart(2, '0')}${b.toString(16).padStart(2, '0')}`;
    } else {
        // Assume it's a named color
        return color;
    }
}

// Function to show tooltip
function showTooltip(element) {
    const tooltip = document.createElement('div');
    tooltip.className = 'svg-tooltip';
    
    // Get element info
    const elementType = element.tagName;
    let tooltipText = '';
    
    if (elementType === 'circle') {
        const adjacentText = element.nextElementSibling;
        if (adjacentText && adjacentText.tagName === 'text') {
            tooltipText = adjacentText.textContent;
        }
    } else if (elementType === 'rect') {
        const adjacentText = element.nextElementSibling;
        if (adjacentText && adjacentText.tagName === 'text') {
            tooltipText = adjacentText.textContent;
        }
    }
    
    tooltip.textContent = tooltipText || 'Network Device';
    
    // Style the tooltip
    tooltip.style.cssText = `
        position: absolute;
        background-color: rgba(0, 0, 0, 0.7);
        color: white;
        padding: 5px 10px;
        border-radius: 4px;
        font-size: 14px;
        pointer-events: none;
        z-index: 1000;
        transition: opacity 0.3s;
    `;
    
    // Position tooltip near the mouse
    const updateTooltipPosition = (e) => {
        tooltip.style.left = `${e.clientX + 15}px`;
        tooltip.style.top = `${e.clientY - 25}px`;
    };
    
    // Add event listener for moving the tooltip with the mouse
    document.addEventListener('mousemove', updateTooltipPosition);
    
    // Add the tooltip to the body
    document.body.appendChild(tooltip);
    
    // Store reference to the event listener for cleanup
    tooltip.updatePosition = updateTooltipPosition;
}

// Function to hide tooltip
function hideTooltip() {
    const tooltip = document.querySelector('.svg-tooltip');
    if (tooltip) {
        // Remove event listener
        if (tooltip.updatePosition) {
            document.removeEventListener('mousemove', tooltip.updatePosition);
        }
        
        // Fade out and remove
        tooltip.style.opacity = '0';
        setTimeout(() => {
            tooltip.remove();
        }, 300);
    }
}

// Function to show device info
function showDeviceInfo(element) {
    const elementType = element.tagName;
    let deviceName = '';
    
    if (elementType === 'circle') {
        const adjacentText = element.nextElementSibling;
        if (adjacentText && adjacentText.tagName === 'text') {
            deviceName = adjacentText.textContent;
        }
    } else if (elementType === 'rect') {
        const adjacentText = element.nextElementSibling;
        if (adjacentText && adjacentText.tagName === 'text') {
            deviceName = adjacentText.textContent;
        }
    }
    
    // Create info popup
    const infoPopup = document.createElement('div');
    infoPopup.className = 'device-info-popup';
    
    // Device specific info
    let deviceInfo = '';
    switch(deviceName) {
        case 'Firewall':
            deviceInfo = `
                <h3>Firewall</h3>
                <p><strong>Status:</strong> Active</p>
                <p><strong>IP:</strong> 192.168.1.254</p>
                <p><strong>Active Rules:</strong> 87</p>
                <p><strong>Blocked Connections:</strong> 1,532</p>
                <p><strong>Last Updated:</strong> 5 minutes ago</p>
            `;
            break;
        case 'Router':
            deviceInfo = `
                <h3>Router</h3>
                <p><strong>Status:</strong> Active</p>
                <p><strong>IP:</strong> 192.168.1.1</p>
                <p><strong>Connected Devices:</strong> 24</p>
                <p><strong>Uptime:</strong> 7 days, 3 hours</p>
                <p><strong>Traffic:</strong> 45 Mbps</p>
            `;
            break;
        case 'Switch 1':
            deviceInfo = `
                <h3>Switch 1</h3>
                <p><strong>Status:</strong> Active</p>
                <p><strong>MAC:</strong> AA:BB:CC:DD:EE:FF</p>
                <p><strong>Ports:</strong> 24 (16 active)</p>
                <p><strong>Traffic:</strong> 28 Mbps</p>
                <p><strong>Errors:</strong> 0</p>
            `;
            break;
        case 'Switch 2':
            deviceInfo = `
                <h3>Switch 2</h3>
                <p><strong>Status:</strong> Active</p>
                <p><strong>MAC:</strong> 11:22:33:44:55:66</p>
                <p><strong>Ports:</strong> 24 (12 active)</p>
                <p><strong>Traffic:</strong> 18 Mbps</p>
                <p><strong>Errors:</strong> 2</p>
            `;
            break;
        case 'Internet':
            deviceInfo = `
                <h3>Internet Connection</h3>
                <p><strong>Status:</strong> Connected</p>
                <p><strong>Download:</strong> 92 Mbps</p>
                <p><strong>Upload:</strong> 35 Mbps</p>
                <p><strong>Latency:</strong> 24ms</p>
                <p><strong>Provider:</strong> Campus Network</p>
            `;
            break;
        default:
            deviceInfo = `<h3>${deviceName || 'Network Device'}</h3><p>No detailed information available</p>`;
    }
    
    // Style the popup
    infoPopup.style.cssText = `
        position: fixed;
        top: 50%;
        left: 50%;
        transform: translate(-50%, -50%);
        background-color: var(--card-bg);
        border-radius: 20px;
        padding: 20px;
        box-shadow: 0 10px 25px rgba(0, 0, 0, 0.2);
        z-index: 1000;
        max-width: 300px;
        text-align: left;
        opacity: 0;
        transition: opacity 0.3s, transform 0.3s;
    `;
    
    // Add close button
    const closeButton = document.createElement('button');
    closeButton.innerHTML = '&times;';
    closeButton.style.cssText = `
        position: absolute;
        top: 10px;
        right: 10px;
        background: none;
        border: none;
        font-size: 20px;
        cursor: pointer;
        color: var(--text-color);
    `;
    
    // Add content
    infoPopup.innerHTML = deviceInfo;
    infoPopup.appendChild(closeButton);
    
    // Add overlay
    const overlay = document.createElement('div');
    overlay.style.cssText = `
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background-color: rgba(0, 0, 0, 0.5);
        z-index: 999;
        opacity: 0;
        transition: opacity 0.3s;
    `;
    
    // Add to body
    document.body.appendChild(overlay);
    document.body.appendChild(infoPopup);
    
    // Animate in
    setTimeout(() => {
        overlay.style.opacity = '1';
        infoPopup.style.opacity = '1';
    }, 10);
    
    // Close handlers
    closeButton.addEventListener('click', closePopup);
    overlay.addEventListener('click', closePopup);
    
    function closePopup() {
        overlay.style.opacity = '0';
        infoPopup.style.opacity = '0';
        infoPopup.style.transform = 'translate(-50%, -50%) scale(0.9)';
        
        setTimeout(() => {
            overlay.remove();
            infoPopup.remove();
        }, 300);
    }
}

// Add CSS for the packet animations
const style = document.createElement('style');
style.textContent = `
    @keyframes packetPulse {
        0%, 100% {
            r: 3;
            opacity: 0;
        }
        20%, 80% {
            r: 5;
            opacity: 1;
        }
    }
    
    .packet {
        animation: packetPulse 3s infinite;
    }
`;

document.head.appendChild(style);
