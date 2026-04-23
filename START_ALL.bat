@echo off
setlocal enabledelayedexpansion

cls
echo.
echo +---------------------------------------------------------------------------+
echo ^| ThreatLens HIDS + Real-Time Startup                                       ^|
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
echo [3/6] Creating or refreshing collector credentials...
node setup-dev-keys.js

echo.
echo [4/6] Starting Python IDS Engine...
cd /d "D:\Major Project\ThreatLens\backend\ids-engine"
start "ThreatLens IDS Engine" cmd /k "cd /d D:\Major Project\ThreatLens\backend\ids-engine && python train_model.py && python app.py"
timeout /t 2 /nobreak >NUL

echo.
echo [5/6] Starting ThreatLens Unified Agent (HIDS + NIDS)...
cd /d "D:\Major Project\ThreatLens\backend\collector"
if not exist ".env" copy ".env.example" ".env" >NUL
start "ThreatLens Unified Agent" cmd /k "cd /d D:\Major Project\ThreatLens\backend\collector && python agent.py"
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
echo Collector defaults now live in backend\collector\.env
echo HIDS mode:
echo   SENSOR_TYPE=host
echo   HOST_EVENTS_PATH=D:\Major Project\ThreatLens\backend\collector\sample-host-events.jsonl
echo Network IDS mode:
echo   SENSOR_TYPE=snort
echo   SNORT_FAST_LOG_PATH=...
echo   or
echo   SENSOR_TYPE=suricata
echo   SURICATA_EVE_JSON_PATH=...
echo.
echo Close the spawned windows to stop the services.
pause
