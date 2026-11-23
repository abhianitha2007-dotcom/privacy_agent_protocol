@echo off
cd /d "%~dp0"
echo Installing required Python libraries...
python -m pip install -r requirements.txt
if errorlevel 1 (
  echo Dependency installation failed. Verify Python and pip, then retry.
  pause
  exit /b 1
)
echo Starting local research dashboard at http://127.0.0.1:8000
python main.py --web --port 8000
pause
