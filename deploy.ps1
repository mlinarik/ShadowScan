# Docker Health Check and Deployment Script
# This script checks Docker status and deploys ShadowScan

Write-Host "ShadowScan Docker Deployment Script" -ForegroundColor Cyan
Write-Host "====================================" -ForegroundColor Cyan

# Function to check if Docker is running
function Test-DockerStatus {
    try {
        docker info 2>$null
        if ($LASTEXITCODE -eq 0) {
            Write-Host "Docker is running" -ForegroundColor Green
            return $true
        } else {
            Write-Host "Docker daemon is not responding" -ForegroundColor Red
            return $false
        }
    } catch {
        Write-Host "Docker is not available" -ForegroundColor Red
        return $false
    }
}

# Check Docker status
if (-not (Test-DockerStatus)) {
    Write-Host "Alternative: Run ShadowScan locally with Python:" -ForegroundColor Cyan
    Write-Host "   python app.py" -ForegroundColor Gray
    Write-Host ""
    Write-Host "To fix Docker issues:" -ForegroundColor Cyan
    Write-Host "   1. Restart Docker Desktop" -ForegroundColor Gray
    Write-Host "   2. Check Windows Subsystem for Linux (WSL2)" -ForegroundColor Gray
    exit 1
}

# Build and deploy with Docker
Write-Host "Building ShadowScan Docker image..." -ForegroundColor Yellow
docker build -t shadowscan .

if ($LASTEXITCODE -eq 0) {
    Write-Host "Docker image built successfully!" -ForegroundColor Green
    
    Write-Host "Starting ShadowScan container..." -ForegroundColor Yellow
    docker-compose down 2>$null
    docker-compose up -d
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "ShadowScan is now running!" -ForegroundColor Green
        Write-Host "Access the application at: http://localhost:5000" -ForegroundColor Cyan
        Write-Host "To view logs: docker-compose logs -f" -ForegroundColor Gray
        Write-Host "To stop: docker-compose down" -ForegroundColor Gray
    } else {
        Write-Host "Failed to start container" -ForegroundColor Red
        Write-Host "Check logs: docker-compose logs" -ForegroundColor Gray
    }
} else {
    Write-Host "Failed to build Docker image" -ForegroundColor Red
    Write-Host "Try building manually: docker build -t shadowscan ." -ForegroundColor Gray
}
