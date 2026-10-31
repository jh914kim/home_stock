@echo off
chcp 65001 >nul
echo Starting Integrated Stock Portfolio (home_stock) Web Dashboard...
start "" "http://localhost:8080"
python "%~dp0server.py"
pause
