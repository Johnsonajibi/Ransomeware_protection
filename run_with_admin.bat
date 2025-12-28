@echo off
REM Run Anti-Ransomware with Administrator Privileges
REM This enables TPM access for MAXIMUM security level

REM CRITICAL: Change to script directory first (fixes System32 issue)
cd /d "%~dp0"

echo ========================================
echo Anti-Ransomware - Admin Mode
echo ========================================
echo.
echo Working Directory: %CD%
echo.

REM Check if running as admin
net session >nul 2>&1
if %errorLevel% == 0 (
    echo [OK] Running with Administrator privileges
    echo.
) else (
    echo [ERROR] Not running as Administrator!
    echo.
    echo Please right-click this file and select:
    echo "Run as administrator"
    echo.
    pause
    exit /b 1
)

REM Activate virtual environment
echo Activating Python virtual environment...
call ".venv\Scripts\activate.bat"

if %errorLevel% neq 0 (
    echo [ERROR] Virtual environment not found
    echo Run: python -m venv .venv
    pause
    exit /b 1
)

echo.
echo ========================================
echo Testing TPM Access
echo ========================================
echo.

REM Test TPM status
python test_tpm.py

echo.
echo ========================================
echo Quick WMI TPM Test
echo ========================================
echo.

REM Quick WMI test
python test_wmi_tpm.py

if %errorLevel% == 0 (
    echo.
    echo [SUCCESS] TPM is accessible and ready!
) else (
    echo.
    echo [WARNING] TPM test failed - will use software fallback
)

echo.
echo ========================================
echo Running Tri-Factor Authentication Demo
echo ========================================
echo.
echo Expected Results with TPM:
echo - TPM Available: True
echo - Security Level: HIGH or MAXIMUM
echo - Three factors: TPM + DeviceFP + USB
echo - PCR values displayed (proof of TPM use)
echo.

REM Run the demo
python trifactor_auth_manager.py

echo.
echo ========================================
echo Verifying TPM Cryptographic Proof
echo ========================================
echo.

REM Run TPM proof verification
python verify_tpm_proof.py

echo.
echo ========================================
echo Demo Complete
echo ========================================
echo.

REM Show summary
if exist ".trifactor_tokens" (
    echo Token metadata saved in: .trifactor_tokens\
    dir /b .trifactor_tokens
)

echo.
echo Press any key to exit...
pause
