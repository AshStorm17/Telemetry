/**
 * Dashboard functionality
 */

// State variables
let selectedDeviceId = null;
let timeRange = 30; // minutes
let socket = null;

// DOM elements
const deviceSelector = document.getElementById('device-selector');
const refreshButton = document.getElementById('refresh-btn');
const timeRangeButtons = document.querySelectorAll('.time-range');

/**
 * Initialize the dashboard
 */
document.addEventListener('DOMContentLoaded', function() {
    console.log('Initializing dashboard...');
    
    // Initialize charts
    initCharts();
    
    // Load devices list
    loadDevices();
    
    // Set up socket connection
    setupSocketConnection();
    
    // Set up event listeners
    setupEventListeners();
    
    // Check URL parameters for pre-selected device
    const urlParams = new URLSearchParams(window.location.search);
    const deviceParam = urlParams.get('device');
    if (deviceParam) {
        console.log(`Device selected from URL parameter: ${deviceParam}`);
        // Set device selector value (will be done once devices are loaded)
        selectedDeviceId = deviceParam;
    }
});

/**
 * Set up Socket.IO connection
 */
function setupSocketConnection() {
    console.log('Setting up Socket.IO connection...');
    
    // Connect to the Socket.IO server
    socket = io();
    
    // Connection event
    socket.on('connect', function() {
        console.log('Connected to Socket.IO server');
        updateConnectionStatus(true);
        
        // Request initial update if we already have a device selected
        if (selectedDeviceId) {
            requestUpdate();
        }
    });
    
    // Disconnection event
    socket.on('disconnect', function() {
        console.log('Disconnected from Socket.IO server');
        updateConnectionStatus(false);
    });
    
    // Telemetry update event
    socket.on('telemetry_update', function(data) {
        console.log('Received telemetry update');
        
        // Process the update if it's for our selected device
        if (selectedDeviceId && data[selectedDeviceId]) {
            const deviceMetrics = {};
            for (const [metricType, [timestamp, value]] of Object.entries(data[selectedDeviceId])) {
                // Only use the latest value for real-time updates
                deviceMetrics[metricType] = [[timestamp, value]];
            }
            
            // Update charts with the new data points
            updateMetricCards(data[selectedDeviceId]);
            
            // If we want to fully refresh the charts, we need to fetch all data
            // to maintain the time series history
            refreshDeviceData();
        }
    });
}

/**
 * Set up event listeners
 */
function setupEventListeners() {
    // Device selector change
    deviceSelector.addEventListener('change', function() {
        selectedDeviceId = this.value;
        console.log(`Device changed to: ${selectedDeviceId}`);
        
        if (selectedDeviceId) {
            resetCharts();
            refreshDeviceData();
            
            // Update URL parameter
            const url = new URL(window.location);
            url.searchParams.set('device', selectedDeviceId);
            window.history.pushState({}, '', url);
        }
    });
    
    // Refresh button click
    refreshButton.addEventListener('click', function() {
        if (selectedDeviceId) {
            refreshDeviceData();
        }
    });
    
    // Time range buttons click
    timeRangeButtons.forEach(button => {
        button.addEventListener('click', function(e) {
            e.preventDefault();
            
            // Update the active class
            timeRangeButtons.forEach(btn => btn.classList.remove('active'));
            this.classList.add('active');
            
            // Update the dropdown button text
            document.getElementById('time-range-btn').textContent = this.textContent;
            
            // Update the time range
            timeRange = parseInt(this.getAttribute('data-range'), 10);
            console.log(`Time range changed to: ${timeRange} minutes`);
            
            // Refresh data with new time range
            if (selectedDeviceId) {
                refreshDeviceData();
            }
        });
    });
}

/**
 * Load the list of network devices
 */
function loadDevices() {
    console.log('Loading devices...');
    
    fetch('/api/devices')
        .then(response => response.json())
        .then(devices => {
            // Clear the device selector
            deviceSelector.innerHTML = '';
            
            // Add a default option
            const defaultOption = document.createElement('option');
            defaultOption.value = '';
            defaultOption.textContent = 'Select a device...';
            defaultOption.disabled = true;
            defaultOption.selected = !selectedDeviceId;
            deviceSelector.appendChild(defaultOption);
            
            // Add device options
            devices.forEach(device => {
                const option = document.createElement('option');
                option.value = device.id;
                option.textContent = `${device.name} (${device.ip_address})`;
                
                // Check if this device should be selected (from URL parameter)
                if (selectedDeviceId && selectedDeviceId == device.id) {
                    option.selected = true;
                    refreshDeviceData();
                }
                
                deviceSelector.appendChild(option);
            });
            
            // Refresh button state
            refreshButton.disabled = !selectedDeviceId;
        })
        .catch(error => {
            console.error('Error loading devices:', error);
            const option = document.createElement('option');
            option.textContent = 'Error loading devices';
            deviceSelector.appendChild(option);
        });
}

/**
 * Refresh data for the selected device
 */
function refreshDeviceData() {
    if (!selectedDeviceId) return;
    console.log(`Refreshing data for device ${selectedDeviceId}`);
    
    // Show loading indicators
    toggleLoading(true);
    
    // Calculate the time range in milliseconds
    const rangeMs = timeRange * 60 * 1000;
    
    // Fetch metrics for the selected device
    fetch(`/api/metrics/${selectedDeviceId}`)
        .then(response => response.json())
        .then(metrics => {
            // Process the metrics data
            const processedMetrics = {};
            
            // Calculate the cutoff time
            const cutoffTime = new Date(Date.now() - rangeMs);
            
            // Filter metrics based on time range
            for (const [metricType, metricData] of Object.entries(metrics)) {
                processedMetrics[metricType] = metricData.filter(point => {
                    return new Date(point[0]) >= cutoffTime;
                });
            }
            
            // Update the charts
            updateCharts(selectedDeviceId, processedMetrics);
            
            // Hide loading indicators
            toggleLoading(false);
        })
        .catch(error => {
            console.error('Error fetching metrics:', error);
            toggleLoading(false);
        });
}

/**
 * Request an immediate update from the server
 */
function requestUpdate() {
    if (socket && socket.connected) {
        console.log('Requesting telemetry update');
        socket.emit('request_update', { device_id: selectedDeviceId });
    }
}

/**
 * Update the connection status indicator
 */
function updateConnectionStatus(connected) {
    const statusIndicator = document.querySelector('.navbar-text .fas');
    if (statusIndicator) {
        if (connected) {
            statusIndicator.className = 'fas fa-circle text-success me-1';
            document.querySelector('.navbar-text').textContent = 'Telemetry Active';
        } else {
            statusIndicator.className = 'fas fa-circle text-danger me-1';
            document.querySelector('.navbar-text').textContent = 'Telemetry Inactive';
        }
    }
}

/**
 * Toggle loading indicators for charts
 */
function toggleLoading(isLoading) {
    refreshButton.disabled = isLoading;
    
    if (isLoading) {
        refreshButton.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Loading...';
    } else {
        refreshButton.innerHTML = '<i class="fas fa-sync-alt me-2"></i>Refresh';
    }
}