document.addEventListener('DOMContentLoaded', () => {
    console.log('Index page script loaded');
    
    // Generate particles for background
    const heroParticles = document.querySelector('.hero-particles');
    if (heroParticles) {
        generateParticles(heroParticles, 50); // Increased particle count
    }
    
    // Add floating elements
    addFloatingElements();
    
    // Animate cluster cards on hover
    const clusterCards = document.querySelectorAll('.cluster-card');
    clusterCards.forEach(card => {
        card.addEventListener('mouseenter', (e) => {
            const cluster = card.getAttribute('data-cluster');
            // Generate different animation for each cluster
            switch(cluster) {
                case '1':
                    createRippleEffect(card, 'rgba(74, 144, 226, 0.2)');
                    break;
                case '2':
                    createFloatingDotsEffect(card);
                    break;
                case '3':
                    createGlowEffect(card);
                    break;
            }
        });
    });
    
    // Add scroll animations
    initScrollAnimations();
    
    // Animate title with a typing effect
    animateTitle();
    
    // Add interactive background
    createInteractiveBackground();
});

// Create glowing dots in the background
function generateParticles(container, count) {
    for (let i = 0; i < count; i++) {
        const particle = document.createElement('div');
        particle.className = 'particle';
        
        // Random position
        const posX = Math.random() * 100;
        const posY = Math.random() * 100;
        
        // Random size
        const size = Math.random() * 10 + 5;
        
        // Random animation duration
        const duration = Math.random() * 10 + 10;
        
        // Random delay
        const delay = Math.random() * 5;
        
        // Set styles
        particle.style.cssText = `
            position: absolute;
            left: ${posX}%;
            top: ${posY}%;
            width: ${size}px;
            height: ${size}px;
            background-color: rgba(255, 255, 255, 0.1);
            border-radius: 50%;
            animation: pulse ${duration}s ease-in-out ${delay}s infinite;
            z-index: 1;
        `;
        
        container.appendChild(particle);
    }
}

// Create ripple effect on element
function createRippleEffect(element, color) {
    const ripple = document.createElement('div');
    ripple.className = 'ripple-effect';
    
    ripple.style.cssText = `
        position: absolute;
        top: 50%;
        left: 50%;
        transform: translate(-50%, -50%);
        width: 0;
        height: 0;
        background-color: ${color};
        border-radius: 50%;
        z-index: -1;
        animation: ripple 1s ease-out forwards;
    `;
    
    element.appendChild(ripple);
    
    // Remove ripple after animation completes
    setTimeout(() => {
        ripple.remove();
    }, 1000);
}

// Create floating dots effect
function createFloatingDotsEffect(element) {
    const dotsContainer = document.createElement('div');
    dotsContainer.className = 'floating-dots';
    dotsContainer.style.cssText = `
        position: absolute;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        overflow: hidden;
        z-index: -1;
    `;
    
    const dotsCount = 15;
    
    for (let i = 0; i < dotsCount; i++) {
        const dot = document.createElement('div');
        
        // Random position
        const posX = Math.random() * 100;
        const posY = Math.random() * 100;
        
        // Random size
        const size = Math.random() * 6 + 3;
        
        // Random animation duration
        const duration = Math.random() * 3 + 2;
        
        dot.style.cssText = `
            position: absolute;
            left: ${posX}%;
            top: ${posY}%;
            width: ${size}px;
            height: ${size}px;
            background-color: rgba(74, 144, 226, 0.3);
            border-radius: 50%;
            animation: float ${duration}s ease-in-out infinite;
        `;
        
        dotsContainer.appendChild(dot);
    }
    
    element.appendChild(dotsContainer);
    
    // Remove dots after mouse leaves
    element.addEventListener('mouseleave', () => {
        setTimeout(() => {
            const dots = element.querySelector('.floating-dots');
            if (dots) {
                dots.remove();
            }
        }, 3000);
    });
}

// Create glow effect
function createGlowEffect(element) {
    const originalBoxShadow = element.style.boxShadow;
    
    element.style.transition = 'box-shadow 0.3s ease';
    element.style.boxShadow = '0 0 20px rgba(74, 144, 226, 0.5), 0 0 30px rgba(74, 144, 226, 0.3), 0 0 40px rgba(74, 144, 226, 0.1)';
    
    // Remove glow effect after mouse leaves
    element.addEventListener('mouseleave', () => {
        element.style.boxShadow = originalBoxShadow;
    });
}

// Add floating decorative elements to the home page
function addFloatingElements() {
    const hero = document.querySelector('.hero');
    const overview = document.querySelector('.overview-section');
    
    if (hero) {
        // Add floating circles to hero
        for (let i = 0; i < 8; i++) {
            const floatingEl = document.createElement('div');
            const size = Math.random() * 80 + 20; // 20px to 100px
            const posX = Math.random() * 100;
            const posY = Math.random() * 100;
            const delay = Math.random() * 5;
            const duration = Math.random() * 10 + 10;
            const color = [
                'rgba(74, 144, 226, 0.1)',
                'rgba(155, 89, 182, 0.1)',
                'rgba(46, 204, 113, 0.1)',
                'rgba(243, 156, 18, 0.1)'
            ][Math.floor(Math.random() * 4)];
            
            floatingEl.className = 'floating-element';
            floatingEl.style.cssText = `
                position: absolute;
                width: ${size}px;
                height: ${size}px;
                border-radius: 50%;
                background-color: ${color};
                left: ${posX}%;
                top: ${posY}%;
                z-index: 1;
                animation: floatingObject ${duration}s ease-in-out ${delay}s infinite;
                opacity: 0.6;
                box-shadow: 0 0 20px ${color.replace('0.1', '0.3')};
            `;
            
            hero.appendChild(floatingEl);
        }
    }
    
    if (overview) {
        // Add floating geometric shapes to overview
        const shapes = ['circle', 'square', 'triangle'];
        for (let i = 0; i < 6; i++) {
            const floatingEl = document.createElement('div');
            const size = Math.random() * 60 + 20; // 20px to 80px
            const posX = Math.random() * 100;
            const posY = Math.random() * 100;
            const delay = Math.random() * 3;
            const duration = Math.random() * 10 + 8;
            const shape = shapes[Math.floor(Math.random() * shapes.length)];
            const color = [
                'rgba(74, 144, 226, 0.08)',
                'rgba(155, 89, 182, 0.08)',
                'rgba(46, 204, 113, 0.08)',
                'rgba(243, 156, 18, 0.08)'
            ][Math.floor(Math.random() * 4)];
            
            let shapeStyle = '';
            if (shape === 'circle') {
                shapeStyle = `
                    border-radius: 50%;
                    background-color: ${color};
                `;
            } else if (shape === 'square') {
                shapeStyle = `
                    border-radius: 4px;
                    background-color: ${color};
                    transform: rotate(45deg);
                `;
            } else if (shape === 'triangle') {
                shapeStyle = `
                    width: 0;
                    height: 0;
                    border-left: ${size/2}px solid transparent;
                    border-right: ${size/2}px solid transparent;
                    border-bottom: ${size}px solid ${color};
                    background-color: transparent;
                `;
            }
            
            floatingEl.className = 'floating-element';
            floatingEl.style.cssText = `
                position: absolute;
                width: ${size}px;
                height: ${size}px;
                left: ${posX}%;
                top: ${posY}%;
                z-index: 0;
                animation: floatingObject ${duration}s ease-in-out ${delay}s infinite;
                opacity: 0.6;
                pointer-events: none;
                ${shapeStyle}
            `;
            
            overview.appendChild(floatingEl);
        }
    }
}

// Initialize scroll animations
function initScrollAnimations() {
    // Add animation classes to elements
    const animatedElements = [
        { selector: '.section-title', animation: 'fadeInUp', delay: 0 },
        { selector: '.video-container', animation: 'fadeInUp', delay: 0.2 },
        { selector: '.cluster-card:nth-child(1)', animation: 'fadeInLeft', delay: 0.3 },
        { selector: '.cluster-card:nth-child(2)', animation: 'fadeInUp', delay: 0.4 },
        { selector: '.cluster-card:nth-child(3)', animation: 'fadeInRight', delay: 0.5 },
        { selector: '.overview-text', animation: 'fadeInLeft', delay: 0.2 },
        { selector: '.overview-image', animation: 'fadeInRight', delay: 0.4 },
        { selector: '.feature-list li', animation: 'fadeInLeft', delay: 0.1, increment: 0.1 }
    ];
    
    // Add custom animation style
    animatedElements.forEach(item => {
        const elements = document.querySelectorAll(item.selector);
        elements.forEach((el, index) => {
            el.style.opacity = '0';
            el.style.animation = 'none';
            
            let delay = item.delay;
            if (item.increment) {
                delay += index * item.increment;
            }
            
            el.setAttribute('data-animation', item.animation);
            el.setAttribute('data-delay', delay);
        });
    });
    
    // Create intersection observer
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                const animation = entry.target.getAttribute('data-animation');
                const delay = entry.target.getAttribute('data-delay');
                
                entry.target.style.animation = `${animation} 0.8s ease-out ${delay}s forwards`;
                observer.unobserve(entry.target);
            }
        });
    }, {
        threshold: 0.1,
        rootMargin: '0px 0px -100px 0px'
    });
    
    // Observe all animated elements
    animatedElements.forEach(item => {
        const elements = document.querySelectorAll(item.selector);
        elements.forEach(el => {
            observer.observe(el);
        });
    });
}

// Animate title with typing effect
function animateTitle() {
    const title = document.querySelector('.title');
    if (!title) return;
    
    const titleText = title.textContent;
    title.innerHTML = '';
    
    const typingContainer = document.createElement('div');
    typingContainer.className = 'typing-container';
    typingContainer.style.cssText = `
        display: inline-block;
        position: relative;
    `;
    
    const typingText = document.createElement('span');
    typingText.className = 'typing-text';
    typingText.textContent = titleText;
    typingText.style.cssText = `
        display: inline-block;
        overflow: hidden;
        white-space: nowrap;
        animation: typing 3.5s steps(40, end) 0.5s forwards, blink 0.75s step-end infinite;
        width: 0;
        border-right: 4px solid var(--primary-color);
    `;
    
    typingContainer.appendChild(typingText);
    title.appendChild(typingContainer);
}

// Create interactive background with parallax effect
function createInteractiveBackground() {
    const hero = document.querySelector('.hero');
    if (!hero) return;
    
    // Add subtle parallax effect to hero section
    document.addEventListener('mousemove', (e) => {
        const mouseX = e.clientX / window.innerWidth;
        const mouseY = e.clientY / window.innerHeight;
        
        const particles = document.querySelector('.hero-particles');
        if (particles) {
            particles.style.transform = `translate(${mouseX * -20}px, ${mouseY * -20}px)`;
        }
        
        const floatingElements = document.querySelectorAll('.hero .floating-element');
        floatingElements.forEach((el, index) => {
            const depth = 0.05 + (index % 3) * 0.05;
            el.style.transform = `translate(${mouseX * -50 * depth}px, ${mouseY * -50 * depth}px) rotate(${mouseX * 10}deg)`;
        });
    });
    
    // Add shimmer effect to hero content
    const heroContent = document.querySelector('.hero-content');
    if (heroContent) {
        heroContent.style.position = 'relative';
        heroContent.style.overflow = 'hidden';
        
        const shimmer = document.createElement('div');
        shimmer.className = 'content-shimmer';
        shimmer.style.cssText = `
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: linear-gradient(
                90deg,
                rgba(255, 255, 255, 0) 0%,
                rgba(255, 255, 255, 0.2) 50%,
                rgba(255, 255, 255, 0) 100%
            );
            background-size: 200% 100%;
            pointer-events: none;
            z-index: 1;
            animation: shimmer 6s infinite linear;
        `;
        
        heroContent.appendChild(shimmer);
    }
}

// Add animation keyframes dynamically
const style = document.createElement('style');
style.textContent = `
    @keyframes pulse {
        0%, 100% {
            transform: scale(1);
            opacity: 0.3;
        }
        50% {
            transform: scale(1.2);
            opacity: 0.7;
        }
    }
    
    @keyframes ripple {
        0% {
            width: 0;
            height: 0;
            opacity: 0.5;
        }
        100% {
            width: 200%;
            height: 200%;
            opacity: 0;
        }
    }
    
    @keyframes float {
        0%, 100% {
            transform: translateY(0) translateX(0);
        }
        25% {
            transform: translateY(-10px) translateX(5px);
        }
        50% {
            transform: translateY(5px) translateX(10px);
        }
        75% {
            transform: translateY(10px) translateX(-5px);
        }
    }
    
    @keyframes fadeInUp {
        from {
            opacity: 0;
            transform: translateY(30px);
        }
        to {
            opacity: 1;
            transform: translateY(0);
        }
    }
    
    @keyframes fadeInLeft {
        from {
            opacity: 0;
            transform: translateX(-30px);
        }
        to {
            opacity: 1;
            transform: translateX(0);
        }
    }
    
    @keyframes fadeInRight {
        from {
            opacity: 0;
            transform: translateX(30px);
        }
        to {
            opacity: 1;
            transform: translateX(0);
        }
    }
    
    @keyframes typing {
        from { width: 0 }
        to { width: 100% }
    }
    
    @keyframes blink {
        50% { border-color: transparent }
    }
    
    @keyframes floatingObject {
        0%, 100% {
            transform: translateY(0) rotate(0deg);
        }
        33% {
            transform: translateY(-15px) rotate(2deg);
        }
        66% {
            transform: translateY(10px) rotate(-2deg);
        }
    }
    
    @keyframes colorShift {
        0%, 100% {
            filter: hue-rotate(0deg);
        }
        50% {
            filter: hue-rotate(30deg);
        }
    }
    
    @keyframes shimmer {
        0% {
            background-position: -100% 0;
        }
        100% {
            background-position: 200% 0;
        }
    }
`;

document.head.appendChild(style);
