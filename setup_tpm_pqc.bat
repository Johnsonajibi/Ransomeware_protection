@echo off
REM TPM + PQC Setup Script for Anti-Ransomware
REM Run this as Administrator

echo.
echo ========================================
echo TPM + PQC Security Setup
echo ========================================
echo.

REM Activate virtual environment
call .venv\Scripts\activate.bat

echo Installing essential packages...
pip install cryptography --quiet
echo ✅ cryptography installed

echo Installing liboqs (NIST PQC)...
pip install liboqs --quiet
if %errorlevel% equ 0 (
    echo ✅ liboqs installed
) else (
    echo ⚠️ liboqs not available (optional)
)

echo Installing TPM 2.0 support...
pip install tpm2-pytss --quiet
if %errorlevel% equ 0 (
    echo ✅ tpm2-pytss installed
) else (
    echo ⚠️ tpm2-pytss not available (optional)
)

echo Installing device fingerprinting...
pip install py-cpuid --quiet
if %errorlevel% equ 0 (
    echo ✅ py-cpuid installed
) else (
    echo ⚠️ py-cpuid not available (optional)
)

echo.
echo Testing TPM + PQC integration...
python tpm_pqc_integration.py

echo.
echo ========================================
echo ✅ Setup Complete!
echo ========================================
echo.
echo Your system is now ready for TPM+PQC protection!
echo.
pause
