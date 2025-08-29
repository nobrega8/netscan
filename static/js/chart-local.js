// Simple Chart.js replacement for basic line charts
window.Chart = function(ctx, config) {
    this.ctx = ctx;
    this.config = config;
    this.data = config.data;
    
    this.update = function() {
        this.draw();
    };
    
    this.draw = function() {
        const canvas = this.ctx.canvas;
        const width = canvas.width;
        const height = canvas.height;
        
        // Clear canvas
        this.ctx.clearRect(0, 0, width, height);
        
        // Draw simple line chart
        if (this.data.labels.length > 0) {
            const margin = 40;
            const chartWidth = width - margin * 2;
            const chartHeight = height - margin * 2;
            
            // Find max values for scaling
            let maxY = 0;
            this.data.datasets.forEach(dataset => {
                dataset.data.forEach(value => {
                    if (value > maxY) maxY = value;
                });
            });
            
            if (maxY === 0) maxY = 100; // Default max
            
            // Draw axes
            this.ctx.strokeStyle = '#dee2e6';
            this.ctx.lineWidth = 1;
            this.ctx.beginPath();
            this.ctx.moveTo(margin, margin);
            this.ctx.lineTo(margin, height - margin);
            this.ctx.lineTo(width - margin, height - margin);
            this.ctx.stroke();
            
            // Draw grid lines
            const gridLines = 5;
            for (let i = 0; i <= gridLines; i++) {
                const y = margin + (chartHeight / gridLines) * i;
                this.ctx.beginPath();
                this.ctx.moveTo(margin, y);
                this.ctx.lineTo(width - margin, y);
                this.ctx.stroke();
            }
            
            // Draw data lines
            this.data.datasets.forEach((dataset, datasetIndex) => {
                if (dataset.data.length === 0) return;
                
                this.ctx.strokeStyle = dataset.borderColor || '#007bff';
                this.ctx.lineWidth = 2;
                this.ctx.beginPath();
                
                dataset.data.forEach((value, index) => {
                    const x = margin + (chartWidth / (dataset.data.length - 1)) * index;
                    const y = height - margin - (value / maxY) * chartHeight;
                    
                    if (index === 0) {
                        this.ctx.moveTo(x, y);
                    } else {
                        this.ctx.lineTo(x, y);
                    }
                });
                
                this.ctx.stroke();
                
                // Draw points
                this.ctx.fillStyle = dataset.borderColor || '#007bff';
                dataset.data.forEach((value, index) => {
                    const x = margin + (chartWidth / (dataset.data.length - 1)) * index;
                    const y = height - margin - (value / maxY) * chartHeight;
                    
                    this.ctx.beginPath();
                    this.ctx.arc(x, y, 3, 0, 2 * Math.PI);
                    this.ctx.fill();
                });
            });
            
            // Draw labels
            this.ctx.fillStyle = '#6c757d';
            this.ctx.font = '12px Arial';
            this.ctx.textAlign = 'center';
            
            this.data.labels.forEach((label, index) => {
                const x = margin + (chartWidth / (this.data.labels.length - 1)) * index;
                this.ctx.fillText(label, x, height - margin + 20);
            });
            
            // Y-axis labels
            this.ctx.textAlign = 'right';
            for (let i = 0; i <= gridLines; i++) {
                const value = (maxY / gridLines) * (gridLines - i);
                const y = margin + (chartHeight / gridLines) * i;
                this.ctx.fillText(value.toFixed(0), margin - 10, y + 4);
            }
        }
    };
    
    // Initial draw
    this.draw();
    
    return this;
};