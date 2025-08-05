#!/bin/bash

# Nmap Web Scanner - Build and Run Script

echo "🚀 Starting Nmap Web Scanner..."

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "❌ Docker is not running. Please start Docker and try again."
    exit 1
fi

# Check if docker-compose is available
if ! command -v docker-compose > /dev/null 2>&1; then
    echo "❌ docker-compose is not installed. Please install docker-compose and try again."
    exit 1
fi

# Create scan_results directory if it doesn't exist
mkdir -p scan_results

# Build and start the application
echo "🔨 Building and starting the application..."
docker-compose up -d --build

# Wait a moment for the service to start
sleep 3

# Check if the service is running
if docker-compose ps | grep -q "Up"; then
    echo "✅ Nmap Web Scanner is now running!"
    echo "🌐 Open your browser and go to: http://localhost:5000"
    echo ""
    echo "📋 Management commands:"
    echo "  - Stop:    docker-compose down"
    echo "  - Logs:    docker-compose logs -f"
    echo "  - Restart: docker-compose restart"
    echo ""
    echo "⚠️  Security reminder:"
    echo "  - Only scan networks you own or have permission to test"
    echo "  - Be mindful of local laws and regulations"
    echo "  - Consider access controls if exposing to untrusted networks"
else
    echo "❌ Failed to start the application. Check the logs:"
    docker-compose logs
    exit 1
fi
