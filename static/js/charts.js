/**
 * Chart configuration and initialization
 */

// Chart objects
const charts = {
    bandwidth: null,
    packetLoss: null,
    latency: null,
    resource: null
};

// Chart colors
const chartColors = {
    bandwidth: {
        borderColor: 'rgba(13, 110, 253, 0.8)',
        backgroundColor: 'rgba(13, 110, 253, 0.1)'
    },
    packetLoss: {
        borderColor: 'rgba(220, 53, 69, 0.8)',
        backgroundColor: 'rgba(220, 53, 69, 0.1)'
    },
    latency: {
        borderColor: 'rgba(255, 193, 7, 0.8)',
        backgroundColor: 'rgba(255, 193, 7, 0.1)'
    },
    cpu: {
        borderColor: 'rgba(40, 167, 69, 0.8)',
        backgroundColor: 'rgba(40, 167, 69, 0.1)'
    },
    memory: {
        borderColor: 'rgba(23, 162, 184, 0.8)',
        backgroundColor: 'rgba(23, 162, 184, 0.1)'
    },
    errorRate: {
        borderColor: 'rgba(108, 117, 125, 0.8)',
        backgroundColor: 'rgba(108, 117, 125, 0.1)'
    }
};

/**
 * Initialize all charts
 */
function initCharts() {
    console.log('Initializing charts...');
    
    // Bandwidth Usage Chart
    const bandwidthCtx = document.getElementById('bandwidth-chart').getContext('2d');
    charts.bandwidth = new Chart(bandwidthCtx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'Bandwidth Usage (Mbps)',
                data: [],
                borderColor: chartColors.bandwidth.borderColor,
                backgroundColor: chartColors.bandwidth.backgroundColor,
                borderWidth: 2,
                fill: true,
                tension: 0.4
            }]
        },
        options: getChartOptions('Bandwidth Usage (Mbps)')
    });
    
    // Packet Loss Chart
    const packetLossCtx = document.getElementById('packet-loss-chart').getContext('2d');
    charts.packetLoss = new Chart(packetLossCtx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'Packet Loss (%)',
                data: [],
                borderColor: chartColors.packetLoss.borderColor,
                backgroundColor: chartColors.packetLoss.backgroundColor,
                borderWidth: 2,
                fill: true,
                tension: 0.4
            }]
        },
        options: getChartOptions('Packet Loss (%)', {
            suggestedMin: 0,
            suggestedMax: 2
        })
    });
    
    // Latency Chart
    const latencyCtx = document.getElementById('latency-chart').getContext('2d');
    charts.latency = new Chart(latencyCtx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'Latency (ms)',
                data: [],
                borderColor: chartColors.latency.borderColor,
                backgroundColor: chartColors.latency.backgroundColor,
                borderWidth: 2,
                fill: true,
                tension: 0.4
            }]
        },
        options: getChartOptions('Latency (ms)')
    });
    
    // Resource Usage Chart
    const resourceCtx = document.getElementById('resource-chart').getContext('2d');
    charts.resource = new Chart(resourceCtx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [
                {
                    label: 'CPU Usage (%)',
                    data: [],
                    borderColor: chartColors.cpu.borderColor,
                    backgroundColor: 'transparent',
                    borderWidth: 2,
                    tension: 0.4
                },
                {
                    label: 'Memory Usage (%)',
                    data: [],
                    borderColor: chartColors.memory.borderColor,
                    backgroundColor: 'transparent',
                    borderWidth: 2,
                    tension: 0.4
                },
                {
                    label: 'Error Rate (errors/sec)',
                    data: [],
                    borderColor: chartColors.errorRate.borderColor,
                    backgroundColor: 'transparent',
                    borderWidth: 2,
                    tension: 0.4,
                    yAxisID: 'y1'
                }
            ]
        },
        options: getResourceChartOptions()
    });
}

/**
 * Get common chart options
 */
function getChartOptions(title, scales = {}) {
    return {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            title: {
                display: false,
                text: title
            },
            tooltip: {
                mode: 'index',
                intersect: false
            },
            legend: {
                display: false
            }
        },
        scales: {
            x: {
                type: 'time',
                time: {
                    tooltipFormat: 'HH:mm:ss',
                    displayFormats: {
                        millisecond: 'HH:mm:ss.SSS',
                        second: 'HH:mm:ss',
                        minute: 'HH:mm',
                        hour: 'HH'
                    }
                },
                ticks: {
                    autoSkip: true,
                    maxTicksLimit: 10
                }
            },
            y: {
                beginAtZero: true,
                ...scales
            }
        },
        interaction: {
            intersect: false,
            mode: 'nearest'
        },
        animation: {
            duration: 300
        }
    };
}

/**
 * Get resource chart options (with dual Y axes)
 */
function getResourceChartOptions() {
    return {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            tooltip: {
                mode: 'index',
                intersect: false
            },
            legend: {
                position: 'top'
            }
        },
        scales: {
            x: {
                type: 'time',
                time: {
                    tooltipFormat: 'HH:mm:ss',
                    displayFormats: {
                        millisecond: 'HH:mm:ss.SSS',
                        second: 'HH:mm:ss',
                        minute: 'HH:mm',
                        hour: 'HH'
                    }
                },
                ticks: {
                    autoSkip: true,
                    maxTicksLimit: 10
                }
            },
            y: {
                beginAtZero: true,
                suggestedMax: 100,
                title: {
                    display: true,
                    text: 'Usage (%)'
                }
            },
            y1: {
                beginAtZero: true,
                position: 'right',
                grid: {
                    drawOnChartArea: false
                },
                title: {
                    display: true,
                    text: 'Error Rate (errors/sec)'
                }
            }
        },
        interaction: {
            intersect: false,
            mode: 'nearest'
        },
        animation: {
            duration: 300
        }
    };
}

/**
 * Update charts with new data
 */
function updateCharts(deviceId, metrics) {
    if (!metrics || !deviceId) return;
    
    console.log('Updating charts with new metrics data');
    
    // Extract metrics by type
    const bandwidthData = metrics['bandwidth_usage'] || [];
    const packetLossData = metrics['packet_loss'] || [];
    const latencyData = metrics['latency'] || [];
    const cpuData = metrics['cpu_usage'] || [];
    const memoryData = metrics['memory_usage'] || [];
    const errorRateData = metrics['error_rate'] || [];
    
    // Transform data for Chart.js
    // Format: array of {x: timestamp, y: value}
    const formatDataPoints = (data) => {
        return data.map(point => ({
            x: new Date(point[0]),
            y: point[1]
        }));
    };
    
    // Update bandwidth chart
    if (charts.bandwidth && bandwidthData.length > 0) {
        charts.bandwidth.data.datasets[0].data = formatDataPoints(bandwidthData);
        charts.bandwidth.update();
    }
    
    // Update packet loss chart
    if (charts.packetLoss && packetLossData.length > 0) {
        charts.packetLoss.data.datasets[0].data = formatDataPoints(packetLossData);
        charts.packetLoss.update();
    }
    
    // Update latency chart
    if (charts.latency && latencyData.length > 0) {
        charts.latency.data.datasets[0].data = formatDataPoints(latencyData);
        charts.latency.update();
    }
    
    // Update resource chart
    if (charts.resource) {
        if (cpuData.length > 0) {
            charts.resource.data.datasets[0].data = formatDataPoints(cpuData);
        }
        if (memoryData.length > 0) {
            charts.resource.data.datasets[1].data = formatDataPoints(memoryData);
        }
        if (errorRateData.length > 0) {
            charts.resource.data.datasets[2].data = formatDataPoints(errorRateData);
        }
        charts.resource.update();
    }
    
    // Update latest metric values in cards
    updateMetricCards(metrics);
}

/**
 * Update metric cards with the latest values
 */
function updateMetricCards(metrics) {
    // Get the latest values from each metric
    const getLatestValue = (metricData) => {
        if (!metricData || metricData.length === 0) return '--';
        return metricData[metricData.length - 1][1];
    };
    
    // Update the values in the cards
    document.getElementById('bandwidth-value').textContent = getLatestValue(metrics['bandwidth_usage']);
    document.getElementById('packet-loss-value').textContent = getLatestValue(metrics['packet_loss']);
    document.getElementById('latency-value').textContent = getLatestValue(metrics['latency']);
    document.getElementById('cpu-usage-value').textContent = getLatestValue(metrics['cpu_usage']);
    document.getElementById('memory-usage-value').textContent = getLatestValue(metrics['memory_usage']);
    document.getElementById('error-rate-value').textContent = getLatestValue(metrics['error_rate']);
}

/**
 * Reset all charts to empty state
 */
function resetCharts() {
    // Reset all chart data
    if (charts.bandwidth) {
        charts.bandwidth.data.datasets[0].data = [];
        charts.bandwidth.update();
    }
    
    if (charts.packetLoss) {
        charts.packetLoss.data.datasets[0].data = [];
        charts.packetLoss.update();
    }
    
    if (charts.latency) {
        charts.latency.data.datasets[0].data = [];
        charts.latency.update();
    }
    
    if (charts.resource) {
        charts.resource.data.datasets.forEach(dataset => {
            dataset.data = [];
        });
        charts.resource.update();
    }
    
    // Reset the cards
    document.getElementById('bandwidth-value').textContent = '--';
    document.getElementById('packet-loss-value').textContent = '--';
    document.getElementById('latency-value').textContent = '--';
    document.getElementById('cpu-usage-value').textContent = '--';
    document.getElementById('memory-usage-value').textContent = '--';
    document.getElementById('error-rate-value').textContent = '--';
}