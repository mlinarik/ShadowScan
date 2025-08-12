#!/bin/bash

# ShadowScan Docker Setup and Run Script

echo "ShadowScan - Security Scanning Suite"
echo "===================================="

# Check if Docker is running
if ! docker info &> /dev/null; then
    echo "❌ Docker is not running. Please start Docker Desktop and try again."
    exit 1
fi

echo "✅ Docker is running"

# Stop any existing containers
echo "🔄 Stopping existing containers..."
docker-compose down 2>/dev/null || true

# Remove old images if requested
if [ "$1" = "--rebuild" ]; then
    echo "🔄 Rebuilding image..."
    docker-compose build --no-cache
else
    echo "🔄 Building image..."
    docker-compose build
fi

# Start the application
echo "🚀 Starting ShadowScan..."
docker-compose up -d

# Check if container started successfully
if docker-compose ps | grep -q "Up"; then
    echo "✅ ShadowScan is running successfully!"
    echo "📱 Access the application at: http://localhost:5000"
    echo "📊 To view logs: docker-compose logs -f"
    echo "🛑 To stop: docker-compose down"
else
    echo "❌ Failed to start ShadowScan. Check logs:"
    docker-compose logs
    exit 1
fi
