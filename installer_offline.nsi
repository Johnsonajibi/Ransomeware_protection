; Anti-Ransomware Protection Platform Installer (OFFLINE VERSION)
; NSIS Modern User Interface
; Requires NSIS 3.08 or later

!define PRODUCT_NAME "Anti-Ransomware Protection"
!define PRODUCT_VERSION "1.0.0"
!define PRODUCT_PUBLISHER "Anti-Ransomware Security"
!define PRODUCT_WEB_SITE "https://github.com/Johnsonajibi/Ransomeware_protection"
!define PRODUCT_DIR_REGKEY "Software\Microsoft\Windows\CurrentVersion\App Paths\AntiRansomware.exe"
!define PRODUCT_UNINST_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}"
!define PRODUCT_UNINST_ROOT_KEY "HKLM"
!define SERVICE_NAME "AntiRansomwareProtection"
!define DRIVER_NAME "AntiRansomwareDriver"

; MUI 1.67 compatible
!include "MUI2.nsh"
!include "FileFunc.nsh"
!include "LogicLib.nsh"
!include "x64.nsh"

; MUI Settings
!define MUI_ABORTWARNING
!define MUI_ICON "${NSISDIR}\Contrib\Graphics\Icons\modern-install.ico"
!define MUI_UNICON "${NSISDIR}\Contrib\Graphics\Icons\modern-uninstall.ico"

; Welcome page
!insertmacro MUI_PAGE_WELCOME
; License page
!define MUI_LICENSEPAGE_CHECKBOX
!insertmacro MUI_PAGE_LICENSE "LICENSE.txt"
; Components page
!insertmacro MUI_PAGE_COMPONENTS
; Directory page
!insertmacro MUI_PAGE_DIRECTORY
; Instfiles page
!insertmacro MUI_PAGE_INSTFILES
; Finish page
!define MUI_FINISHPAGE_RUN "$INSTDIR\desktop_app.exe"
!define MUI_FINISHPAGE_SHOWREADME "$INSTDIR\README.md"
!insertmacro MUI_PAGE_FINISH

; Uninstaller pages
!insertmacro MUI_UNPAGE_INSTFILES

; Language files
!insertmacro MUI_LANGUAGE "English"

; MUI end

; Helper function for string search
Function StrStr
  Exch $R1 ; needle
  Exch
  Exch $R2 ; haystack
  Push $R3
  Push $R4
  Push $R5
  StrLen $R3 $R1
  StrCpy $R4 0
  loop:
    StrCpy $R5 $R2 $R3 $R4
    StrCmp $R5 $R1 done
    StrCmp $R5 "" done
    IntOp $R4 $R4 + 1
    Goto loop
  done:
    StrCpy $R1 $R2 "" $R4
    Pop $R5
    Pop $R4
    Pop $R3
    Pop $R2
    Exch $R1
FunctionEnd

; Installer attributes
Name "${PRODUCT_NAME} ${PRODUCT_VERSION} (Offline)"
OutFile "AntiRansomware-Setup-${PRODUCT_VERSION}-offline.exe"
InstallDir "$PROGRAMFILES64\AntiRansomware"
InstallDirRegKey HKLM "${PRODUCT_DIR_REGKEY}" ""
ShowInstDetails show
ShowUnInstDetails show
RequestExecutionLevel admin

; Pre-installation checks
Function .onInit
    ; Check for admin rights
    UserInfo::GetAccountType
    Pop $0
    ${If} $0 != "admin"
        MessageBox MB_ICONSTOP "Administrator rights required!"
        SetErrorLevel 740
        Quit
    ${EndIf}
    
    ; Check for 64-bit system
    ${If} ${RunningX64}
        SetRegView 64
    ${Else}
        MessageBox MB_ICONSTOP "This software requires 64-bit Windows 10 or later."
        Abort
    ${EndIf}
    
    ; Check Windows version (Windows 10 or later - version 10.0)
    ; Get Windows version from registry
    ReadRegStr $0 HKLM "SOFTWARE\Microsoft\Windows NT\CurrentVersion" "CurrentMajorVersionNumber"
    ${If} $0 >= 10
        ; Windows 10 or later detected
    ${Else}
        MessageBox MB_ICONEXCLAMATION "Warning: This software is designed for Windows 10 or later. Some features may not work correctly."
    ${EndIf}
FunctionEnd

Section "Core Files (Required)" SEC01
    SectionIn RO
    SetOutPath "$INSTDIR"
    
    ; Main application files
    File "desktop_app.py"
    File "unified_antiransomware.py"
    File "config_manager.py"
    File /nonfatal "ml_detector.py"
    File /nonfatal "attack_simulation.py"
    File /nonfatal "realtime_file_blocker.py"
    File /nonfatal "enterprise_security_real.py"
    File /nonfatal "kernel_driver_manager.py"
    File /nonfatal "kernel_level_blocker.py"
    File /nonfatal "shadow_copy_protection.py"
    File /nonfatal "emergency_kill_switch.py"
    File /nonfatal "email_alerting.py"
    File /nonfatal "siem_integration.py"
    File /nonfatal "tpm_integration.py"
    File /nonfatal "tpm_pqc_integration.py"
    File /nonfatal "kernel_protection_interface.py"
    File /nonfatal "system_health_checker.py"
    File "requirements.txt"
    File /nonfatal "README.md"
    File /nonfatal "config.json"
    File /nonfatal "config.yaml"
    
    ; Additional Python modules
    File /nonfatal /r "utils"
    File /nonfatal /r "core"
    File /nonfatal /r "protection"
    
    ; Configuration directories
    CreateDirectory "$INSTDIR\logs"
    CreateDirectory "$INSTDIR\backups"
    CreateDirectory "$INSTDIR\quarantine"
    CreateDirectory "$INSTDIR\models"
    CreateDirectory "$INSTDIR\policies"
    CreateDirectory "$INSTDIR\certs"
    
    ; Database
    File /nonfatal "protection_db.sqlite"
    
    ; ML Model (if exists)
    SetOutPath "$INSTDIR\models"
    File /nonfatal "models\ransomware_classifier.pkl"
SectionEnd

Section "Python Runtime & Dependencies (Required)" SEC02
    SectionIn RO
    
    DetailPrint "Checking Python installation..."
    
    ; Check if Python is already installed
    nsExec::ExecToStack 'python --version'
    Pop $0
    Pop $1
    StrCmp $0 0 pythonFound pythonNotFound
    
    pythonNotFound:
        MessageBox MB_ICONEXCLAMATION "Python 3.11+ is required but not found.$\n$\nPlease install Python from https://www.python.org/downloads/ and run this installer again.$\n$\nMake sure to check 'Add Python to PATH' during installation."
        Abort
    
    pythonFound:
        DetailPrint "Python found: $1"
    
    ; Copy vendor packages
    DetailPrint "Installing Python dependencies from bundled packages..."
    SetOutPath "$INSTDIR\vendor"
    File /nonfatal /r "vendor\*.*"
    
    ; Install from vendor directory (offline)
    SetOutPath "$INSTDIR"
    nsExec::ExecToLog '"python" -m pip install --no-index --find-links="$INSTDIR\vendor" -r requirements.txt --no-warn-script-location'
    
    ; Clean up vendor directory after installation
    DetailPrint "Cleaning up installation files..."
    RMDir /r "$INSTDIR\vendor"
SectionEnd

Section "Kernel Driver (Optional)" SEC03
    SetOutPath "$INSTDIR\driver"
    
    ; Copy kernel driver
    IfFileExists "build_production\AntiRansomwareDriver.sys" 0 skipDriver
        File "build_production\AntiRansomwareDriver.sys"
        File /nonfatal "RealAntiRansomwareDriver.inf"
        
        ; Check test-signing
        nsExec::ExecToStack 'bcdedit /enum {current}'
        Pop $0
        Pop $1
        Push $1
        Push "testsigning"
        Call StrStr
        Pop $2
        StrCmp $2 "" askTestSigning driverReady
        
        askTestSigning:
            MessageBox MB_YESNO|MB_ICONQUESTION \
                "Test-signing mode is not enabled. The kernel driver requires this.$\n$\nWould you like to enable it now? (requires reboot)" \
                IDYES enableTestSigning IDNO skipDriver
            
            enableTestSigning:
                DetailPrint "Enabling test-signing mode..."
                nsExec::ExecToLog 'bcdedit /set testsigning on'
                Pop $0
                IntCmp $0 0 testSigningOk testSigningFailed testSigningFailed
                
                testSigningOk:
                    MessageBox MB_OK "Test-signing enabled. You must restart your computer before the driver can be loaded."
                    Goto driverReady
                
                testSigningFailed:
                    MessageBox MB_ICONEXCLAMATION "Failed to enable test-signing. The driver will not be installed."
                    Goto skipDriver
        
        driverReady:
            ; Create driver service
            DetailPrint "Creating driver service..."
            nsExec::ExecToLog 'sc create ${DRIVER_NAME} type= kernel start= demand binPath= "$INSTDIR\driver\AntiRansomwareDriver.sys"'
            Goto endDriverSection
    
    skipDriver:
        DetailPrint "Kernel driver not found, skipping..."
        MessageBox MB_ICONINFORMATION "Kernel driver binary not found. The system will use Python-based file protection."
    
    endDriverSection:
SectionEnd

Section "Windows Service" SEC04
    SetOutPath "$INSTDIR"
    
    ; Create service wrapper script
    FileOpen $0 "$INSTDIR\service_wrapper.py" w
    FileWrite $0 "import sys$\r$\n"
    FileWrite $0 "import os$\r$\n"
    FileWrite $0 "import servicemanager$\r$\n"
    FileWrite $0 "import win32serviceutil$\r$\n"
    FileWrite $0 "import win32service$\r$\n"
    FileWrite $0 "$\r$\n"
    FileWrite $0 "class AntiRansomwareService(win32serviceutil.ServiceFramework):$\r$\n"
    FileWrite $0 "    _svc_name_ = '${SERVICE_NAME}'$\r$\n"
    FileWrite $0 "    _svc_display_name_ = 'Anti-Ransomware Protection Service'$\r$\n"
    FileWrite $0 "    _svc_description_ = 'Real-time ransomware protection and monitoring'$\r$\n"
    FileWrite $0 "$\r$\n"
    FileWrite $0 "    def SvcDoRun(self):$\r$\n"
    FileWrite $0 "        os.chdir(r'$INSTDIR')$\r$\n"
    FileWrite $0 "        exec(open('unified_antiransomware.py').read())$\r$\n"
    FileWrite $0 "$\r$\n"
    FileWrite $0 "    def SvcStop(self):$\r$\n"
    FileWrite $0 "        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)$\r$\n"
    FileWrite $0 "$\r$\n"
    FileWrite $0 "if __name__ == '__main__':$\r$\n"
    FileWrite $0 "    win32serviceutil.HandleCommandLine(AntiRansomwareService)$\r$\n"
    FileClose $0
    
    ; Install pywin32 for service support
    DetailPrint "Installing Windows service support..."
    nsExec::ExecToLog '"python" -m pip install pywin32 --no-warn-script-location'
    
    ; Register service
    DetailPrint "Registering Windows service..."
    nsExec::ExecToLog '"python" "$INSTDIR\service_wrapper.py" install'
SectionEnd

Section "Desktop Integration" SEC05
    SetOutPath "$INSTDIR"
    
    ; Create Start Menu shortcuts
    CreateDirectory "$SMPROGRAMS\${PRODUCT_NAME}"
    CreateShortcut "$SMPROGRAMS\${PRODUCT_NAME}\Anti-Ransomware Dashboard.lnk" "python" '"$INSTDIR\desktop_app.py"' "$INSTDIR" 0
    CreateShortcut "$SMPROGRAMS\${PRODUCT_NAME}\Uninstall.lnk" "$INSTDIR\uninst.exe"
    CreateShortcut "$SMPROGRAMS\${PRODUCT_NAME}\Configuration.lnk" "notepad" '"$INSTDIR\config.json"'
    
    ; Desktop shortcut
    CreateShortcut "$DESKTOP\Anti-Ransomware.lnk" "python" '"$INSTDIR\desktop_app.py"' "$INSTDIR" 0
    
    ; Startup entry (optional - can be configured later)
    ; CreateShortcut "$SMSTARTUP\Anti-Ransomware.lnk" "python" '"$INSTDIR\unified_antiransomware.py"' "$INSTDIR" 0 SW_SHOWMINIMIZED
SectionEnd

Section "Registry Integration" SEC06
    ; Write installation path
    WriteRegStr HKLM "${PRODUCT_DIR_REGKEY}" "" "$INSTDIR\desktop_app.exe"
    WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "DisplayName" "$(^Name)"
    WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "UninstallString" "$INSTDIR\uninst.exe"
    WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "DisplayIcon" "$INSTDIR\desktop_app.exe"
    WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "DisplayVersion" "${PRODUCT_VERSION}"
    WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "URLInfoAbout" "${PRODUCT_WEB_SITE}"
    WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "Publisher" "${PRODUCT_PUBLISHER}"
    
    ; Firewall rules
    DetailPrint "Configuring Windows Firewall..."
    nsExec::ExecToLog 'netsh advfirewall firewall add rule name="Anti-Ransomware Protection" dir=in action=allow program="$INSTDIR\desktop_app.exe" enable=yes'
SectionEnd

Section -Post
    WriteUninstaller "$INSTDIR\uninst.exe"
SectionEnd

; Section descriptions
!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
  !insertmacro MUI_DESCRIPTION_TEXT ${SEC01} "Core application files and configuration (Required)"
  !insertmacro MUI_DESCRIPTION_TEXT ${SEC02} "Python runtime and dependencies bundled offline (Required)"
  !insertmacro MUI_DESCRIPTION_TEXT ${SEC03} "Kernel-level driver for advanced protection (Optional, requires test-signing)"
  !insertmacro MUI_DESCRIPTION_TEXT ${SEC04} "Windows background service for automatic protection"
  !insertmacro MUI_DESCRIPTION_TEXT ${SEC05} "Start menu shortcuts and desktop integration"
  !insertmacro MUI_DESCRIPTION_TEXT ${SEC06} "Registry entries and firewall configuration"
!insertmacro MUI_FUNCTION_DESCRIPTION_END

; Uninstaller
Section Uninstall
    ; Stop and remove service
    DetailPrint "Stopping Windows service..."
    nsExec::ExecToLog 'net stop ${SERVICE_NAME}'
    nsExec::ExecToLog 'sc delete ${SERVICE_NAME}'
    
    ; Stop and remove driver
    DetailPrint "Stopping kernel driver..."
    nsExec::ExecToLog 'net stop ${DRIVER_NAME}'
    nsExec::ExecToLog 'sc delete ${DRIVER_NAME}'
    
    ; Ask to preserve user data
    MessageBox MB_YESNO|MB_ICONQUESTION \
        "Do you want to keep your protection logs, backups, and quarantine files?$\n$\nClick YES to keep your data.$\nClick NO to remove everything." \
        IDYES preserveData
    
    ; Remove all data
    RMDir /r "$INSTDIR\logs"
    RMDir /r "$INSTDIR\backups"
    RMDir /r "$INSTDIR\quarantine"
    Delete "$INSTDIR\protection_db.sqlite"
    Goto continueUninstall
    
    preserveData:
        DetailPrint "Preserving user data..."
    
    continueUninstall:
    ; Remove program files
    Delete "$INSTDIR\*.py"
    Delete "$INSTDIR\*.pyc"
    Delete "$INSTDIR\*.pyo"
    Delete "$INSTDIR\*.exe"
    Delete "$INSTDIR\*.dll"
    Delete "$INSTDIR\*.txt"
    Delete "$INSTDIR\*.md"
    Delete "$INSTDIR\*.json"
    Delete "$INSTDIR\*.yaml"
    RMDir /r "$INSTDIR\driver"
    RMDir /r "$INSTDIR\python"
    RMDir /r "$INSTDIR\utils"
    RMDir /r "$INSTDIR\core"
    RMDir /r "$INSTDIR\protection"
    RMDir /r "$INSTDIR\models"
    RMDir /r "$INSTDIR\policies"
    RMDir /r "$INSTDIR\certs"
    
    ; Remove shortcuts
    Delete "$DESKTOP\Anti-Ransomware.lnk"
    Delete "$SMSTARTUP\Anti-Ransomware.lnk"
    RMDir /r "$SMPROGRAMS\${PRODUCT_NAME}"
    
    ; Remove registry entries
    DeleteRegKey ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}"
    DeleteRegKey HKLM "${PRODUCT_DIR_REGKEY}"
    
    ; Remove firewall rules
    nsExec::ExecToLog 'netsh advfirewall firewall delete rule name="Anti-Ransomware Protection"'
    
    ; Remove installation directory if empty
    RMDir "$INSTDIR"
    
    SetAutoClose true
SectionEnd
