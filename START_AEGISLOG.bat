@echo off
title AegisLog - NTRO Defense Platform
color 1F

echo.
echo  ============================================================
echo   AegisLog ^| NTRO Universal Log Pre-processing Framework
echo   SIH26156 ^| Starting all services...
echo  ============================================================
echo.

cd /d "%~dp0"

echo  [1/2] Starting FastAPI Backend + Command Portal Website...
echo        Website will be available at: http://localhost:8000/portal/index.html
echo        API Swagger Docs:             http://localhost:8000/docs
echo.
start "AegisLog API" cmd /k ".venv\Scripts\uvicorn.exe api.app:app --host 127.0.0.1 --port 8000 --reload"

timeout /t 3 /nobreak >nul

echo  [2/2] Starting Streamlit Analytics Dashboard...
echo        Dashboard:                    http://localhost:8501
echo.
start "AegisLog Dashboard" cmd /k ".venv\Scripts\streamlit.exe run ui\dashboard.py"

timeout /t 4 /nobreak >nul

echo.
echo  ============================================================
echo   All services running! Opening browser...
echo  ============================================================
echo.

start "" "http://localhost:8000/portal/index.html"

echo  Press any key to stop all services and exit.
pause >nul

taskkill /FI "WINDOWTITLE eq AegisLog API*" /T /F >nul 2>&1
taskkill /FI "WINDOWTITLE eq AegisLog Dashboard*" /T /F >nul 2>&1
echo  All services stopped. Goodbye.

