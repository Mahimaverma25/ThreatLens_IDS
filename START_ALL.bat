@echo off
REM ThreatLens Complete Startup Script
REM This script sets up and starts all components

setlocal enabledelayedexpansion

cls
echo.
echo +---------------------------------------------------------------------------+
echo ^| ThreatLens Multi-Tenant SaaS - Complete Startup                          ^|
echo +---------------------------------------------------------------------------+
echo.

REM Check if MongoDB is running
echo [1/5] Checking MongoDB...
tasklist /FI "IMAGENAME eq mongod.exe" 2>NUL | find /I /N "mongod.exe">NUL
if "%ERRORLEVEL%"=="0" (
    echo  ✓ MongoDB is running
) else (
    echo  ⚠ MongoDB not detected - make sure mongod is running in another terminal
    echo    Open Command Prompt and run: mongod
    pause
)

REM Setup API Server
echo.
echo [2/5] Setting up API Server...
cd /d "d:\Major Project\ThreatLens\backend\api-server"

if not exist ".env" (
    echo  Creating .env file...
    (
        echo NODE_ENV=development
        echo PORT=3000
        echo MONGO_URI=mongodb://127.0.0.1:27017/threatlens
        echo JWT_SECRET=dev-secret-change-in-production
        echo REFRESH_TOKEN_SECRET=dev-refresh-secret
        echo CORS_ORIGIN=http://localhost:3000
        echo IDS_ENGINE_URL=http://localhost:5001
    ) > .env
    echo  ✓ Created .env
) else (
    echo  ✓ .env already exists
)

REM Start API Server in new window
echo  Starting API Server on port 3000...
start /B "ThreatLens API Server" cmd /k "npm start"
timeout /t 3 /nobreak

REM Setup API Key
echo.
echo [3/5] Creating API key in database...
node setup-api-key.js
if !ERRORLEVEL! neq 0 (
    echo  ⚠ Warning: Setup script had issues, but continuing...
)

REM Setup Agent
echo.
echo [4/5] Setting up Agent...
cd /d "d:\Major Project\ThreatLens\backend\agent"

if not exist ".env" (
    echo  Creating .env file...
    (
        echo THREATLENS_API_URL=http://localhost:3000
        echo THREATLENS_API_KEY=key_test_agent_001
        echo THREATLENS_API_SECRET=secret_very_secure_test_key
        echo ASSET_ID=asset-dev-laptop
        echo NODE_ENV=development
        echo LOG_LEVEL=info
        echo BATCH_SIZE=50
        echo BATCH_TIMEOUT_MS=10000
    ) > .env
    echo  ✓ Created .env
) else (
    echo  ✓ .env already exists
)

REM Start Agent
echo  Starting Agent...
start /B "ThreatLens Agent" cmd /k "npm start"
timeout /t 2 /nobreak

REM Setup Frontend
echo.
echo [5/5] Setting up Frontend...
cd /d "d:\Major Project\ThreatLens\frontend"

echo  Starting Frontend on port 3001...
start /B "ThreatLens Frontend" cmd /k "npm start"

echo.
echo +---------------------------------------------------------------------------+
echo ^| ✓ All services started!                                                 ^|
echo +---------------------------------------------------------------------------+
echo.
echo URLs:
echo   Dashboard:  http://localhost:3000
echo   API Server: http://localhost:3000/api
echo   Frontend:   http://localhost:3001 (if backend route fails)
echo.
echo Logs:
echo   API Server:  [ThreatLens API Server] window
echo   Agent:       [ThreatLens Agent] window
echo   Frontend:    [ThreatLens Frontend] window
echo.
echo Next steps:
echo   1. Wait 10 seconds for frontend to compile
echo   2. Open http://localhost:3000 in browser
echo   3. Click "Register" and create account
echo   4. Watch dashboard update as agent sends events
echo.
echo To stop all services:
echo   - Close each terminal window
echo   - Or run: taskkill /IM node.exe /F (stops all Node processes)
echo.

pause
