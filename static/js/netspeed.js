// NetSpeed JavaScript - Network Speed Testing and Visualization

let speedChart = null;
let speedGauge = null;
let testHistory = [];
let isTestRunning = false;

// Initialize the netspeed page
document.addEventListener('DOMContentLoaded', function() {
    initSpeedometer();
    initNetworkChart();
    loadTestHistory();
    
    document.getElementById('start-test-btn').addEventListener('click', startSpeedTest);
});

// Initialize the speedometer gauge
function initSpeedometer() {
    const canvas = document.getElementById('speedometer');
    const ctx = canvas.getContext('2d');
    
    function drawSpeedometer(speed = 0, maxSpeed = 100) {
        const centerX = canvas.width / 2;
        const centerY = canvas.height - 20;
        const radius = 80;
        
        // Clear canvas
        ctx.clearRect(0, 0, canvas.width, canvas.height);
        
        // Draw outer circle
        ctx.beginPath();
        ctx.arc(centerX, centerY, radius, Math.PI, 2 * Math.PI);
        ctx.strokeStyle = '#e9ecef';
        ctx.lineWidth = 20;
        ctx.stroke();
        
        // Draw speed arc
        const angle = Math.PI + (speed / maxSpeed) * Math.PI;
        ctx.beginPath();
        ctx.arc(centerX, centerY, radius, Math.PI, angle);
        ctx.strokeStyle = getSpeedColor(speed);
        ctx.lineWidth = 20;
        ctx.stroke();
        
        // Draw center circle
        ctx.beginPath();
        ctx.arc(centerX, centerY, 10, 0, 2 * Math.PI);
        ctx.fillStyle = '#495057';
        ctx.fill();
        
        // Draw speed text
        ctx.font = 'bold 24px Arial';
        ctx.fillStyle = '#495057';
        ctx.textAlign = 'center';
        ctx.fillText(speed.toFixed(1), centerX, centerY - 30);
        
        ctx.font = '12px Arial';
        ctx.fillText('Mbps', centerX, centerY - 10);
        
        // Draw scale marks
        for (let i = 0; i <= 10; i++) {
            const markAngle = Math.PI + (i / 10) * Math.PI;
            const x1 = centerX + (radius - 30) * Math.cos(markAngle);
            const y1 = centerY + (radius - 30) * Math.sin(markAngle);
            const x2 = centerX + (radius - 15) * Math.cos(markAngle);
            const y2 = centerY + (radius - 15) * Math.sin(markAngle);
            
            ctx.beginPath();
            ctx.moveTo(x1, y1);
            ctx.lineTo(x2, y2);
            ctx.strokeStyle = '#6c757d';
            ctx.lineWidth = 2;
            ctx.stroke();
        }
    }
    
    // Initial draw
    drawSpeedometer(0);
    
    // Store function for later use
    window.updateSpeedometer = drawSpeedometer;
}

function getSpeedColor(speed) {
    if (speed < 10) return '#dc3545'; // Red
    if (speed < 25) return '#fd7e14'; // Orange
    if (speed < 50) return '#ffc107'; // Yellow
    if (speed < 75) return '#20c997'; // Teal
    return '#28a745'; // Green
}

// Initialize the real-time network chart
function initNetworkChart() {
    const ctx = document.getElementById('network-chart').getContext('2d');
    
    speedChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'Download Speed (Mbps)',
                data: [],
                borderColor: '#007bff',
                backgroundColor: 'rgba(0, 123, 255, 0.1)',
                tension: 0.4
            }, {
                label: 'Upload Speed (Mbps)',
                data: [],
                borderColor: '#28a745',
                backgroundColor: 'rgba(40, 167, 69, 0.1)',
                tension: 0.4
            }, {
                label: 'Ping (ms)',
                data: [],
                borderColor: '#ffc107',
                backgroundColor: 'rgba(255, 193, 7, 0.1)',
                tension: 0.4,
                yAxisID: 'y1'
            }]
        },
        options: {
            responsive: true,
            interaction: {
                mode: 'index',
                intersect: false,
            },
            scales: {
                x: {
                    display: true,
                    title: {
                        display: true,
                        text: 'Time'
                    }
                },
                y: {
                    type: 'linear',
                    display: true,
                    position: 'left',
                    title: {
                        display: true,
                        text: 'Speed (Mbps)'
                    }
                },
                y1: {
                    type: 'linear',
                    display: true,
                    position: 'right',
                    title: {
                        display: true,
                        text: 'Ping (ms)'
                    },
                    grid: {
                        drawOnChartArea: false,
                    },
                }
            },
            plugins: {
                legend: {
                    display: true
                }
            }
        }
    });
}

// Start speed test
async function startSpeedTest() {
    if (isTestRunning) return;
    
    isTestRunning = true;
    const startBtn = document.getElementById('start-test-btn');
    const progressContainer = document.getElementById('test-progress');
    const progressBar = document.getElementById('progress-bar');
    const statusText = document.getElementById('test-status');
    
    startBtn.disabled = true;
    startBtn.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Testing...';
    progressContainer.style.display = 'block';
    
    try {
        // Reset displays
        document.getElementById('download-speed').textContent = '--';
        document.getElementById('upload-speed').textContent = '--';
        document.getElementById('ping-time').textContent = '--';
        
        // Real ping test
        updateProgress(10, 'Testing ping...');
        const ping = await performRealPing();
        if (ping !== null) {
            document.getElementById('ping-time').textContent = ping.toFixed(0);
        } else {
            document.getElementById('ping-time').textContent = 'Error';
        }
        
        // Real download test
        updateProgress(30, 'Testing download speed...');
        const downloadSpeed = await performRealDownloadTest();
        if (downloadSpeed !== null) {
            document.getElementById('download-speed').textContent = downloadSpeed.toFixed(1);
            updateSpeedometer(downloadSpeed);
        } else {
            document.getElementById('download-speed').textContent = 'Error';
        }
        
        // Real upload test
        updateProgress(70, 'Testing upload speed...');
        const uploadSpeed = await performRealUploadTest();
        if (uploadSpeed !== null) {
            document.getElementById('upload-speed').textContent = uploadSpeed.toFixed(1);
        } else {
            document.getElementById('upload-speed').textContent = 'Error';
        }
        
        updateProgress(100, 'Test completed!');
        
        // Save test result (only if we have valid data)
        if (ping !== null && downloadSpeed !== null && uploadSpeed !== null) {
            const testResult = {
                timestamp: new Date(),
                download: downloadSpeed,
                upload: uploadSpeed,
                ping: ping
            };
            
            testHistory.push(testResult);
            saveTestHistory();
            updateTestHistory();
            updateChart(testResult);
            updateStatistics();
        }
        
        setTimeout(() => {
            progressContainer.style.display = 'none';
        }, 1000);
        
    } catch (error) {
        console.error('Speed test error:', error);
        statusText.textContent = 'Test failed. Please try again.';
        statusText.className = 'text-danger';
    } finally {
        isTestRunning = false;
        startBtn.disabled = false;
        startBtn.innerHTML = '<i class="fas fa-play me-2"></i>Start Speed Test';
    }
}

function updateProgress(percent, status) {
    document.getElementById('progress-bar').style.width = percent + '%';
    document.getElementById('test-status').textContent = status;
}

// Real network tests using backend APIs
async function performRealPing() {
    try {
        const response = await fetch('/api/speed-test/ping', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ target: '8.8.8.8' })
        });
        
        const data = await response.json();
        if (data.success) {
            return data.ping;
        } else {
            console.error('Ping test failed:', data.error);
            return null;
        }
    } catch (error) {
        console.error('Ping test error:', error);
        return null;
    }
}

async function performRealDownloadTest() {
    try {
        // Show intermediate progress
        let progress = 30;
        const progressInterval = setInterval(() => {
            progress += 2;
            if (progress <= 65) {
                updateProgress(progress, 'Testing download speed...');
            }
        }, 200);
        
        const response = await fetch('/api/speed-test/download', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            }
        });
        
        clearInterval(progressInterval);
        
        const data = await response.json();
        if (data.success) {
            return data.download_speed;
        } else {
            console.error('Download test failed:', data.error);
            return null;
        }
    } catch (error) {
        console.error('Download test error:', error);
        return null;
    }
}

async function performRealUploadTest() {
    try {
        // Show intermediate progress
        let progress = 70;
        const progressInterval = setInterval(() => {
            progress += 2;
            if (progress <= 95) {
                updateProgress(progress, 'Testing upload speed...');
            }
        }, 200);
        
        const response = await fetch('/api/speed-test/upload', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            }
        });
        
        clearInterval(progressInterval);
        
        const data = await response.json();
        if (data.success) {
            return data.upload_speed;
        } else {
            console.error('Upload test failed:', data.error);
            return null;
        }
    } catch (error) {
        console.error('Upload test error:', error);
        return null;
    }
}

// Update chart with new data
function updateChart(testResult) {
    const time = testResult.timestamp.toLocaleTimeString();
    
    speedChart.data.labels.push(time);
    speedChart.data.datasets[0].data.push(testResult.download);
    speedChart.data.datasets[1].data.push(testResult.upload);
    speedChart.data.datasets[2].data.push(testResult.ping);
    
    // Keep only last 10 data points
    if (speedChart.data.labels.length > 10) {
        speedChart.data.labels.shift();
        speedChart.data.datasets.forEach(dataset => dataset.data.shift());
    }
    
    speedChart.update();
}

// Update test history display
function updateTestHistory() {
    const historyContainer = document.getElementById('speed-history');
    
    if (testHistory.length === 0) {
        historyContainer.innerHTML = `
            <div class="text-center text-muted">
                <i class="fas fa-history fa-2x mb-2"></i>
                <p>No tests performed yet</p>
            </div>
        `;
        return;
    }
    
    const recentTests = testHistory.slice(-5).reverse();
    let html = '';
    
    recentTests.forEach(test => {
        const time = test.timestamp.toLocaleTimeString();
        html += `
            <div class="border-bottom pb-2 mb-2">
                <small class="text-muted">${time}</small><br>
                <strong class="text-primary">${test.download.toFixed(1)}</strong> / 
                <strong class="text-success">${test.upload.toFixed(1)}</strong> Mbps<br>
                <small class="text-warning">Ping: ${test.ping.toFixed(0)}ms</small>
            </div>
        `;
    });
    
    historyContainer.innerHTML = html;
}

// Update statistics
function updateStatistics() {
    if (testHistory.length === 0) return;
    
    const avgDownload = testHistory.reduce((sum, test) => sum + test.download, 0) / testHistory.length;
    const avgUpload = testHistory.reduce((sum, test) => sum + test.upload, 0) / testHistory.length;
    const avgPing = testHistory.reduce((sum, test) => sum + test.ping, 0) / testHistory.length;
    
    document.getElementById('avg-download').textContent = avgDownload.toFixed(1) + ' Mbps';
    document.getElementById('avg-upload').textContent = avgUpload.toFixed(1) + ' Mbps';
    document.getElementById('avg-ping').textContent = avgPing.toFixed(0) + ' ms';
    document.getElementById('test-count').textContent = testHistory.length;
}

// Local storage functions
function saveTestHistory() {
    localStorage.setItem('netspeed-history', JSON.stringify(testHistory));
}

function loadTestHistory() {
    const saved = localStorage.getItem('netspeed-history');
    if (saved) {
        testHistory = JSON.parse(saved).map(test => ({
            ...test,
            timestamp: new Date(test.timestamp)
        }));
        updateTestHistory();
        updateStatistics();
    }
}