# Use Python 3.11 slim image as base
FROM python:3.11-slim

# Install system dependencies including nmap
RUN apt-get update && apt-get install -y \
    nmap \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create directory for scan results
RUN mkdir -p /app/scan_results

# Expose port 5000
EXPOSE 5000

# Run the application
CMD ["python", "app.py"]
