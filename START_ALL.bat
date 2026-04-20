@echo off
setlocal enabledelayedexpansion

cls
echo.
echo +---------------------------------------------------------------------------+
echo ^| ThreatLens Real-Time Startup                                              ^|
echo +---------------------------------------------------------------------------+
echo.

echo [1/6] Checking MongoDB...
tasklist /FI "IMAGENAME eq mongod.exe" 2>NUL | find /I /N "mongod.exe" >NUL
if "%ERRORLEVEL%"=="0" (
    echo   MongoDB is running
) else (
    echo   MongoDB was not detected. Start mongod in another terminal before continuing.
    pause
)

echo.
echo [2/6] Preparing API Server...
cd /d "D:\Major Project\ThreatLens\backend\api-server"
if not exist ".env" copy ".env.example" ".env" >NUL
start "ThreatLens API Server" cmd /k "cd /d D:\Major Project\ThreatLens\backend\api-server && npm start"
timeout /t 3 /nobreak >NUL

echo.
echo [3/6] Creating or refreshing agent credentials...
node setup-dev-keys.js

echo.
echo [4/6] Starting Python IDS Engine...
cd /d "D:\Major Project\ThreatLens\backend\ids-engine"
start "ThreatLens IDS Engine" cmd /k "cd /d D:\Major Project\ThreatLens\backend\ids-engine && python train_model.py && python app.py"
timeout /t 2 /nobreak >NUL

echo.
echo [5/6] Starting ThreatLens Agent...
cd /d "D:\Major Project\ThreatLens\backend\agent"
if not exist ".env" copy ".env.example" ".env" >NUL
start "ThreatLens Agent" cmd /k "cd /d D:\Major Project\ThreatLens\backend\agent && npm start"
timeout /t 2 /nobreak >NUL

echo.
echo [6/6] Starting Frontend...
cd /d "D:\Major Project\ThreatLens\frontend"
start "ThreatLens Frontend" cmd /k "cd /d D:\Major Project\ThreatLens\frontend && npm start"

echo.
echo +---------------------------------------------------------------------------+
echo ^| ThreatLens services started                                               ^|
echo +---------------------------------------------------------------------------+
echo.
echo Backend   : http://localhost:5000
echo IDS Engine: http://localhost:8000
echo Frontend  : http://localhost:3000
echo.
echo Before expecting live data, make sure backend\agent\.env points to the real Snort log file:
echo   SNORT_FAST_LOG_PATH=...
echo   or
echo   SNORT_EVE_JSON_PATH=...
echo.
echo Close the spawned windows to stop the services.
pause
