# Use Python 3.11 slim image as base
FROM python:3.11-slim

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Install system dependencies
RUN apt-get update && apt-get install -y \
    nmap \
    libcap2-bin \
    locales \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Configure locales
RUN echo "en_US.UTF-8 UTF-8" > /etc/locale.gen && \
    locale-gen && \
    update-locale LANG=en_US.UTF-8 LC_CTYPE=en_US.UTF-8

# Set locale environment variables
ENV LANG=en_US.UTF-8
ENV LC_CTYPE=en_US.UTF-8

# Enable nmap SYN scans without root privileges
RUN setcap cap_net_raw,cap_net_admin+eip /usr/bin/nmap

# Create app user and directory
RUN useradd --create-home --shell /bin/bash app
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p instance static/uploads

# Set ownership of application files
RUN chown -R app:app /app

# Switch to app user
USER app

# Set Flask app
ENV FLASK_APP=app.py

# Create database and run migrations
RUN python -c "from app import app, db; app.app_context().push(); db.create_all()" && \
    flask db upgrade || echo "Database migration completed or not needed"

# Expose port
EXPOSE 2530

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:2530/healthz || exit 1

# Default command - run the service
CMD ["python", "service.py"]