# ShadowScan Docker Setup and Run Script for Windows
# Usage: .\docker-run.ps1 [--rebuild]

param(
    [switch]$Rebuild
)

Write-Host "ShadowScan - Security Scanning Suite" -ForegroundColor Cyan
Write-Host "====================================" -ForegroundColor Cyan

# Check if Docker is running
try {
    docker info | Out-Null
    Write-Host "✅ Docker is running" -ForegroundColor Green
} catch {
    Write-Host "❌ Docker is not running. Please start Docker Desktop and try again." -ForegroundColor Red
    exit 1
}

# Stop any existing containers
Write-Host "🔄 Stopping existing containers..." -ForegroundColor Yellow
docker-compose down 2>$null

# Build the image
if ($Rebuild) {
    Write-Host "🔄 Rebuilding image..." -ForegroundColor Yellow
    docker-compose build --no-cache
} else {
    Write-Host "🔄 Building image..." -ForegroundColor Yellow
    docker-compose build
}

# Start the application
Write-Host "🚀 Starting ShadowScan..." -ForegroundColor Yellow
docker-compose up -d

# Check if container started successfully
$status = docker-compose ps
if ($status -match "Up") {
    Write-Host "✅ ShadowScan is running successfully!" -ForegroundColor Green
    Write-Host "📱 Access the application at: http://localhost:5000" -ForegroundColor Cyan
    Write-Host "📊 To view logs: docker-compose logs -f" -ForegroundColor Gray
    Write-Host "🛑 To stop: docker-compose down" -ForegroundColor Gray
} else {
    Write-Host "❌ Failed to start ShadowScan. Check logs:" -ForegroundColor Red
    docker-compose logs
    exit 1
}
