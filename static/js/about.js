document.addEventListener('DOMContentLoaded', () => {
    console.log('About page script loaded');
    
    // Add animations to about page elements
    animateAboutElements();
    
    // Add parallax effect to header
    addHeaderParallax();
    
    // Animate cards on scroll
    initScrollAnimations();
    
    // Add floating elements for visual appeal
    addFloatingElements();
});

// Function to animate about page elements
function animateAboutElements() {
    // Animate section title
    const sectionTitles = document.querySelectorAll('.section-title');
    sectionTitles.forEach((title, index) => {
        title.style.opacity = '0';
        title.style.transform = 'translateY(20px)';
        
        setTimeout(() => {
            title.style.transition = 'opacity 0.8s ease, transform 0.8s ease';
            title.style.opacity = '1';
            title.style.transform = 'translateY(0)';
        }, 300 + (index * 200));
    });
    
    // Animate overview content
    const overviewItems = document.querySelectorAll('.overview-text p, .overview-text ul, .overview-image');
    overviewItems.forEach((item, index) => {
        item.style.opacity = '0';
        item.style.transform = 'translateY(20px)';
        
        setTimeout(() => {
            item.style.transition = 'opacity 0.8s ease, transform 0.8s ease';
            item.style.opacity = '1';
            item.style.transform = 'translateY(0)';
        }, 500 + (index * 200));
    });
    
    // Add shimmer to feature-list icons
    const featureIcons = document.querySelectorAll('.feature-list li i');
    featureIcons.forEach((icon) => {
        icon.style.position = 'relative';
        icon.style.overflow = 'hidden';
        
        const shimmer = document.createElement('span');
        shimmer.style.cssText = `
            position: absolute;
            top: -50%;
            left: -100%;
            width: 50%;
            height: 200%;
            background: linear-gradient(
                90deg,
                transparent,
                rgba(255, 255, 255, 0.3),
                transparent
            );
            transform: rotate(25deg);
            animation: shimmerIcon 3s infinite;
        `;
        
        // Add keyframes for shimmer animation
        if (!document.getElementById('shimmerIconKeyframes')) {
            const keyframes = document.createElement('style');
            keyframes.id = 'shimmerIconKeyframes';
            keyframes.textContent = `
                @keyframes shimmerIcon {
                    0% { left: -100%; }
                    100% { left: 200%; }
                }
            `;
            document.head.appendChild(keyframes);
        }
        
        icon.appendChild(shimmer);
    });
}

// Function to add parallax effect to header
function addHeaderParallax() {
    const header = document.querySelector('.about-header');
    if (!header) return;
    
    window.addEventListener('scroll', () => {
        const scrollY = window.scrollY;
        if (scrollY < 500) {
            header.style.backgroundPosition = `50% ${scrollY * 0.5}px`;
            
            // Also shift the title slightly
            const title = header.querySelector('h1');
            if (title) {
                title.style.transform = `translateY(${scrollY * 0.1}px)`;
            }
        }
    });
    
    // Add mouse move parallax to header
    header.addEventListener('mousemove', (e) => {
        const mouseX = e.clientX / window.innerWidth - 0.5;
        const mouseY = e.clientY / window.innerHeight - 0.5;
        
        const title = header.querySelector('h1');
        if (title) {
            title.style.transform = `translate(${mouseX * 20}px, ${mouseY * 20}px)`;
        }
        
        const decoration = header.querySelector('.header-decoration');
        if (decoration) {
            decoration.style.transform = `translate(${mouseX * -30}px, ${mouseY * -10}px)`;
        }
    });
}

// Function to initialize scroll animations
function initScrollAnimations() {
    const aboutCards = document.querySelectorAll('.about-card');
    
    const observer = new IntersectionObserver((entries) => {
        entries.forEach((entry, index) => {
            if (entry.isIntersecting) {
                setTimeout(() => {
                    entry.target.style.opacity = '1';
                    entry.target.style.transform = 'translateY(0)';
                }, index * 150);
                
                observer.unobserve(entry.target);
            }
        });
    }, {
        threshold: 0.1,
        rootMargin: '0px 0px -50px 0px'
    });
    
    aboutCards.forEach(card => {
        card.style.opacity = '0';
        card.style.transform = 'translateY(30px)';
        card.style.transition = 'opacity 0.8s ease, transform 0.8s ease';
        observer.observe(card);
    });
    
    // Add hover effect to overview image
    const overviewImage = document.querySelector('.overview-image img');
    if (overviewImage) {
        overviewImage.addEventListener('mousemove', (e) => {
            const boundingRect = overviewImage.getBoundingClientRect();
            const mouseX = e.clientX - boundingRect.left;
            const mouseY = e.clientY - boundingRect.top;
            
            const centerX = boundingRect.width / 2;
            const centerY = boundingRect.height / 2;
            
            const moveX = (mouseX - centerX) / 20;
            const moveY = (mouseY - centerY) / 20;
            
            overviewImage.style.transform = `translate(${moveX}px, ${moveY}px) scale(1.02)`;
        });
        
        overviewImage.addEventListener('mouseleave', () => {
            overviewImage.style.transform = 'translate(0, 0) scale(1)';
        });
    }
}

// Function to add floating elements for visual appeal
function addFloatingElements() {
    const overviewSection = document.querySelector('.overview-section');
    const aboutDetails = document.querySelector('.about-details');
    
    if (overviewSection) {
        for (let i = 0; i < 5; i++) {
            createFloatingElement(overviewSection, i);
        }
    }
    
    if (aboutDetails) {
        for (let i = 0; i < 8; i++) {
            createFloatingElement(aboutDetails, i);
        }
    }
}

// Helper function to create floating elements
function createFloatingElement(parent, index) {
    const shapes = ['circle', 'square', 'triangle'];
    const floatingEl = document.createElement('div');
    const size = Math.random() * 40 + 10; // 10px to 50px
    const posX = Math.random() * 100;
    const posY = Math.random() * 100;
    const delay = Math.random() * 5;
    const duration = Math.random() * 10 + 15;
    const shape = shapes[Math.floor(Math.random() * shapes.length)];
    
    // Select color based on index
    let color;
    if (index % 4 === 0) {
        color = 'rgba(74, 144, 226, 0.05)';
    } else if (index % 4 === 1) {
        color = 'rgba(155, 89, 182, 0.05)';
    } else if (index % 4 === 2) {
        color = 'rgba(46, 204, 113, 0.05)';
    } else {
        color = 'rgba(243, 156, 18, 0.05)';
    }
    
    // Apply shape-specific styling
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
    } else {
        shapeStyle = `
            width: 0;
            height: 0;
            border-left: ${size/2}px solid transparent;
            border-right: ${size/2}px solid transparent;
            border-bottom: ${size}px solid ${color};
            background-color: transparent;
        `;
    }
    
    // Apply general styling and animation
    floatingEl.className = 'floating-element';
    floatingEl.style.cssText = `
        position: absolute;
        width: ${size}px;
        height: ${size}px;
        left: ${posX}%;
        top: ${posY}%;
        z-index: 0;
        pointer-events: none;
        ${shapeStyle}
        animation: float${index % 3 + 1} ${duration}s ease-in-out ${delay}s infinite;
    `;
    
    // Add the element to the parent
    parent.appendChild(floatingEl);
    
    // Add keyframes for floating animations if they don't exist yet
    if (!document.getElementById('floatKeyframes')) {
        const keyframes = document.createElement('style');
        keyframes.id = 'floatKeyframes';
        keyframes.textContent = `
            @keyframes float1 {
                0%, 100% { transform: translate(0, 0) rotate(0deg); }
                33% { transform: translate(-15px, -20px) rotate(5deg); }
                66% { transform: translate(15px, 10px) rotate(-5deg); }
            }
            
            @keyframes float2 {
                0%, 100% { transform: translate(0, 0) rotate(0deg); }
                33% { transform: translate(20px, -15px) rotate(-3deg); }
                66% { transform: translate(-10px, 15px) rotate(3deg); }
            }
            
            @keyframes float3 {
                0%, 100% { transform: translate(0, 0) rotate(0deg); }
                33% { transform: translate(-10px, 20px) rotate(-5deg); }
                66% { transform: translate(15px, -15px) rotate(5deg); }
            }
        `;
        document.head.appendChild(keyframes);
    }
}
