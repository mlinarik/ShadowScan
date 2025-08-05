# Nmap Web Scanner - Build and Run Script (PowerShell)

Write-Host "🚀 Starting Nmap Web Scanner..." -ForegroundColor Green

# Check if Docker is running
try {
    docker info | Out-Null
} catch {
    Write-Host "❌ Docker is not running. Please start Docker and try again." -ForegroundColor Red
    exit 1
}

# Check if docker-compose is available
if (!(Get-Command docker-compose -ErrorAction SilentlyContinue)) {
    Write-Host "❌ docker-compose is not installed. Please install docker-compose and try again." -ForegroundColor Red
    exit 1
}

# Create scan_results directory if it doesn't exist
if (!(Test-Path "scan_results")) {
    New-Item -ItemType Directory -Path "scan_results" | Out-Null
}

# Build and start the application
Write-Host "🔨 Building and starting the application..." -ForegroundColor Yellow
docker-compose up -d --build

# Wait a moment for the service to start
Start-Sleep -Seconds 3

# Check if the service is running
$running = docker-compose ps | Select-String "Up"
if ($running) {
    Write-Host "✅ Nmap Web Scanner is now running!" -ForegroundColor Green
    Write-Host "🌐 Open your browser and go to: http://localhost:5000" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "📋 Management commands:" -ForegroundColor Yellow
    Write-Host "  - Stop:    docker-compose down"
    Write-Host "  - Logs:    docker-compose logs -f"
    Write-Host "  - Restart: docker-compose restart"
    Write-Host ""
    Write-Host "⚠️  Security reminder:" -ForegroundColor Red
    Write-Host "  - Only scan networks you own or have permission to test"
    Write-Host "  - Be mindful of local laws and regulations"
    Write-Host "  - Consider access controls if exposing to untrusted networks"
} else {
    Write-Host "❌ Failed to start the application. Check the logs:" -ForegroundColor Red
    docker-compose logs
    exit 1
}
