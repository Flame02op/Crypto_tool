@echo off
REM Check if Python is installed
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo Python is not installed. Please install Python and try again.
    exit /b 1
)

REM Create a virtual environment
echo Creating virtual environment...
python -m venv venv

REM Activate the virtual environment
echo Activating virtual environment...
call venv\Scripts\activate

REM Upgrade pip
echo Upgrading pip...
python -m pip install --upgrade pip

REM Install necessary packages
echo Installing necessary packages...
pip install --upgrade PyQt5 cryptography crcmod

REM Deactivate the virtual environment
echo Deactivating virtual environment...
deactivate

echo Setup complete. To activate the virtual environment, run:
echo call venv\Scripts\activate