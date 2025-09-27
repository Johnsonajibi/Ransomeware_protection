/*
 * Real Anti-Ransomware Driver Installer and Manager
 * C++ application for installing and managing the kernel driver
 */

#include <windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include <fstream>
#include <sstream>
#include <setupapi.h>
#include <newdev.h>
#include <cfgmgr32.h>

#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "newdev.lib")
#pragma comment(lib, "cfgmgr32.lib")

// IOCTL codes (must match driver)
#define IOCTL_AR_SET_PROTECTION     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_AR_GET_STATUS         CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_AR_GET_STATISTICS     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_READ_ACCESS)

// Protection levels (must match driver)
enum ProtectionLevel {
    ProtectionDisabled = 0,
    ProtectionMonitoring = 1,
    ProtectionActive = 2,
    ProtectionMaximum = 3
};

// Driver statistics structure (must match driver)
struct DriverStatistics {
    volatile LONG FilesBlocked;
    volatile LONG ProcessesBlocked;
    volatile LONG EncryptionAttempts;
    volatile LONG TotalOperations;
    volatile LONG SuspiciousPatterns;
};

class AntiRansomwareManager {
private:
    static constexpr const char* DRIVER_NAME = "RealAntiRansomwareDriver";
    static constexpr const char* SERVICE_NAME = "RealAntiRansomwareFilter";
    static constexpr const char* DEVICE_NAME = "\\\\.\\AntiRansomwareFilter";
    static constexpr const char* SYSTEM_DRIVERS_PATH = "C:\\Windows\\System32\\drivers\\";
    
    HANDLE deviceHandle;
    SC_HANDLE scManager;
    SC_HANDLE service;

public:
    AntiRansomwareManager() : deviceHandle(INVALID_HANDLE_VALUE), scManager(nullptr), service(nullptr) {
        // Initialize COM for device management
        CoInitialize(nullptr);
        
        // Open service control manager
        scManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
        if (!scManager) {
            std::cerr << "Failed to open Service Control Manager. Error: " << GetLastError() << std::endl;
        }
    }

    ~AntiRansomwareManager() {
        if (deviceHandle != INVALID_HANDLE_VALUE) {
            CloseHandle(deviceHandle);
        }
        if (service) {
            CloseServiceHandle(service);
        }
        if (scManager) {
            CloseServiceHandle(scManager);
        }
        CoUninitialize();
    }

    bool IsRunningAsAdmin() {
        bool isAdmin = false;
        HANDLE token = nullptr;
        
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
            TOKEN_ELEVATION elevation;
            DWORD size = sizeof(TOKEN_ELEVATION);
            
            if (GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size)) {
                isAdmin = elevation.TokenIsElevated != 0;
            }
            
            CloseHandle(token);
        }
        
        return isAdmin;
    }

    bool CheckSystemRequirements() {
        std::cout << "Checking system requirements..." << std::endl;
        
        // Check Windows version
        OSVERSIONINFOEX osvi = {};
        osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
        osvi.dwMajorVersion = 10; // Windows 10/11
        
        DWORDLONG conditionMask = 0;
        VER_SET_CONDITION(conditionMask, VER_MAJORVERSION, VER_GREATER_EQUAL);
        
        if (!VerifyVersionInfo(&osvi, VER_MAJORVERSION, conditionMask)) {
            std::cerr << "Error: Windows 10 or later required" << std::endl;
            return false;
        }

        // Check if running on 64-bit system
        BOOL isWow64 = FALSE;
        if (!IsWow64Process(GetCurrentProcess(), &isWow64)) {
            std::cerr << "Error: Unable to determine system architecture" << std::endl;
            return false;
        }

        #ifdef _WIN64
        std::cout << "✓ 64-bit Windows detected" << std::endl;
        #else
        if (isWow64) {
            std::cout << "✓ 64-bit Windows detected (running 32-bit installer)" << std::endl;
        } else {
            std::cerr << "Error: 64-bit Windows required" << std::endl;
            return false;
        }
        #endif

        // Check administrator privileges
        if (!IsRunningAsAdmin()) {
            std::cerr << "Error: Administrator privileges required" << std::endl;
            return false;
        }
        std::cout << "✓ Administrator privileges confirmed" << std::endl;

        // Check if Filter Manager service is available
        SC_HANDLE fltMgr = OpenService(scManager, TEXT("FltMgr"), SERVICE_QUERY_STATUS);
        if (!fltMgr) {
            std::cerr << "Error: Filter Manager service not available" << std::endl;
            return false;
        }
        CloseServiceHandle(fltMgr);
        std::cout << "✓ Filter Manager service available" << std::endl;

        std::cout << "All system requirements met!" << std::endl;
        return true;
    }

    bool InstallDriver() {
        std::cout << "\n=== Installing Real Anti-Ransomware Kernel Driver ===" << std::endl;
        
        if (!CheckSystemRequirements()) {
            return false;
        }

        // Check if driver files exist
        std::string driverSource = std::string(DRIVER_NAME) + ".sys";
        std::string infFile = std::string(DRIVER_NAME) + ".inf";
        
        if (!FileExists(driverSource)) {
            std::cerr << "Error: Driver file not found: " << driverSource << std::endl;
            std::cerr << "Please compile the driver first using WDK build tools" << std::endl;
            return false;
        }

        if (!FileExists(infFile)) {
            std::cerr << "Error: INF file not found: " << infFile << std::endl;
            return false;
        }

        std::cout << "Installing driver files..." << std::endl;

        // Copy driver to system directory
        std::string targetPath = std::string(SYSTEM_DRIVERS_PATH) + DRIVER_NAME + ".sys";
        if (!CopyFileA(driverSource.c_str(), targetPath.c_str(), FALSE)) {
            std::cerr << "Failed to copy driver file. Error: " << GetLastError() << std::endl;
            return false;
        }
        std::cout << "✓ Driver file copied to system directory" << std::endl;

        // Install INF file
        std::cout << "Installing driver INF file..." << std::endl;
        std::wstring wideInfFile = StringToWString(infFile);
        
        if (!SetupCopyOEMInfW(wideInfFile.c_str(), nullptr, SPOST_PATH, 0, nullptr, 0, nullptr, nullptr)) {
            DWORD error = GetLastError();
            if (error != ERROR_FILE_EXISTS) {
                std::cerr << "Failed to install INF file. Error: " << error << std::endl;
                return false;
            }
        }
        std::cout << "✓ INF file installed" << std::endl;

        // Create and start service
        std::cout << "Creating kernel service..." << std::endl;
        
        std::wstring wideServiceName = StringToWString(SERVICE_NAME);
        std::wstring wideTargetPath = StringToWString(targetPath);
        
        service = CreateServiceW(
            scManager,
            wideServiceName.c_str(),
            L"Real Anti-Ransomware Protection Filter",
            SERVICE_ALL_ACCESS,
            SERVICE_FILE_SYSTEM_DRIVER,
            SERVICE_DEMAND_START,
            SERVICE_ERROR_NORMAL,
            wideTargetPath.c_str(),
            L"FSFilter Activity Monitor",
            nullptr,
            L"FltMgr\0",
            nullptr,
            nullptr
        );

        if (!service) {
            DWORD error = GetLastError();
            if (error == ERROR_SERVICE_EXISTS) {
                std::cout << "Service already exists, opening existing service..." << std::endl;
                service = OpenServiceW(scManager, wideServiceName.c_str(), SERVICE_ALL_ACCESS);
                if (!service) {
                    std::cerr << "Failed to open existing service. Error: " << GetLastError() << std::endl;
                    return false;
                }
            } else {
                std::cerr << "Failed to create service. Error: " << error << std::endl;
                return false;
            }
        }
        std::cout << "✓ Service created successfully" << std::endl;

        // Start the service
        std::cout << "Starting anti-ransomware protection..." << std::endl;
        if (!StartService(service, 0, nullptr)) {
            DWORD error = GetLastError();
            if (error == ERROR_SERVICE_ALREADY_RUNNING) {
                std::cout << "✓ Service is already running" << std::endl;
            } else {
                std::cerr << "Failed to start service. Error: " << error << std::endl;
                std::cerr << "The driver may still be installed but not running" << std::endl;
            }
        } else {
            std::cout << "✓ Anti-ransomware protection started successfully!" << std::endl;
        }

        return true;
    }

    bool UninstallDriver() {
        std::cout << "\n=== Uninstalling Anti-Ransomware Driver ===" << std::endl;
        
        if (!scManager) {
            std::cerr << "Service Control Manager not available" << std::endl;
            return false;
        }

        // Open service
        std::wstring wideServiceName = StringToWString(SERVICE_NAME);
        service = OpenServiceW(scManager, wideServiceName.c_str(), SERVICE_ALL_ACCESS);
        
        if (service) {
            // Stop service
            std::cout << "Stopping service..." << std::endl;
            SERVICE_STATUS status;
            ControlService(service, SERVICE_CONTROL_STOP, &status);
            
            // Wait for service to stop
            int attempts = 0;
            while (attempts < 30) { // Wait up to 30 seconds
                if (QueryServiceStatus(service, &status)) {
                    if (status.dwCurrentState == SERVICE_STOPPED) {
                        break;
                    }
                }
                Sleep(1000);
                attempts++;
            }
            
            // Delete service
            std::cout << "Removing service..." << std::endl;
            if (DeleteService(service)) {
                std::cout << "✓ Service removed successfully" << std::endl;
            } else {
                std::cerr << "Failed to remove service. Error: " << GetLastError() << std::endl;
            }
            
            CloseServiceHandle(service);
            service = nullptr;
        } else {
            std::cout << "Service not found or already removed" << std::endl;
        }

        // Remove driver file
        std::string driverPath = std::string(SYSTEM_DRIVERS_PATH) + DRIVER_NAME + ".sys";
        std::cout << "Removing driver file..." << std::endl;
        if (DeleteFileA(driverPath.c_str())) {
            std::cout << "✓ Driver file removed" << std::endl;
        } else {
            DWORD error = GetLastError();
            if (error == ERROR_FILE_NOT_FOUND) {
                std::cout << "Driver file already removed" << std::endl;
            } else {
                std::cerr << "Failed to remove driver file. Error: " << error << std::endl;
            }
        }

        std::cout << "Uninstallation completed" << std::endl;
        return true;
    }

    bool ConnectToDriver() {
        if (deviceHandle != INVALID_HANDLE_VALUE) {
            return true; // Already connected
        }

        deviceHandle = CreateFileA(
            DEVICE_NAME,
            GENERIC_READ | GENERIC_WRITE,
            0,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr
        );

        if (deviceHandle == INVALID_HANDLE_VALUE) {
            std::cerr << "Failed to connect to driver. Error: " << GetLastError() << std::endl;
            std::cerr << "Make sure the driver is installed and running" << std::endl;
            return false;
        }

        return true;
    }

    bool SetProtectionLevel(ProtectionLevel level) {
        if (!ConnectToDriver()) {
            return false;
        }

        DWORD bytesReturned;
        BOOL result = DeviceIoControl(
            deviceHandle,
            IOCTL_AR_SET_PROTECTION,
            &level,
            sizeof(level),
            nullptr,
            0,
            &bytesReturned,
            nullptr
        );

        if (!result) {
            std::cerr << "Failed to set protection level. Error: " << GetLastError() << std::endl;
            return false;
        }

        std::cout << "Protection level set to: ";
        switch (level) {
            case ProtectionDisabled: std::cout << "Disabled"; break;
            case ProtectionMonitoring: std::cout << "Monitoring"; break;
            case ProtectionActive: std::cout << "Active"; break;
            case ProtectionMaximum: std::cout << "Maximum"; break;
        }
        std::cout << std::endl;

        return true;
    }

    bool GetStatus() {
        if (!ConnectToDriver()) {
            return false;
        }

        ProtectionLevel currentLevel;
        DWORD bytesReturned;
        
        BOOL result = DeviceIoControl(
            deviceHandle,
            IOCTL_AR_GET_STATUS,
            nullptr,
            0,
            &currentLevel,
            sizeof(currentLevel),
            &bytesReturned,
            nullptr
        );

        if (!result) {
            std::cerr << "Failed to get protection status. Error: " << GetLastError() << std::endl;
            return false;
        }

        std::cout << "\n=== Anti-Ransomware Protection Status ===" << std::endl;
        std::cout << "Current Protection Level: ";
        switch (currentLevel) {
            case ProtectionDisabled: std::cout << "Disabled (No protection)"; break;
            case ProtectionMonitoring: std::cout << "Monitoring (Logging only)"; break;
            case ProtectionActive: std::cout << "Active (Blocking threats)"; break;
            case ProtectionMaximum: std::cout << "Maximum (Aggressive protection)"; break;
        }
        std::cout << std::endl;

        // Get statistics
        DriverStatistics stats;
        result = DeviceIoControl(
            deviceHandle,
            IOCTL_AR_GET_STATISTICS,
            nullptr,
            0,
            &stats,
            sizeof(stats),
            &bytesReturned,
            nullptr
        );

        if (result) {
            std::cout << "\n=== Protection Statistics ===" << std::endl;
            std::cout << "Files Blocked: " << stats.FilesBlocked << std::endl;
            std::cout << "Processes Blocked: " << stats.ProcessesBlocked << std::endl;
            std::cout << "Encryption Attempts Detected: " << stats.EncryptionAttempts << std::endl;
            std::cout << "Total Operations Monitored: " << stats.TotalOperations << std::endl;
            std::cout << "Suspicious Patterns Detected: " << stats.SuspiciousPatterns << std::endl;
        }

        return true;
    }

private:
    bool FileExists(const std::string& filename) {
        DWORD attributes = GetFileAttributesA(filename.c_str());
        return (attributes != INVALID_FILE_ATTRIBUTES && !(attributes & FILE_ATTRIBUTE_DIRECTORY));
    }

    std::wstring StringToWString(const std::string& str) {
        if (str.empty()) return std::wstring();
        int size = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), nullptr, 0);
        std::wstring result(size, 0);
        MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &result[0], size);
        return result;
    }
};

void PrintUsage() {
    std::cout << "Real Anti-Ransomware Driver Manager" << std::endl;
    std::cout << "Usage: RealAntiRansomwareManager.exe [command]" << std::endl;
    std::cout << std::endl;
    std::cout << "Commands:" << std::endl;
    std::cout << "  install     - Install the kernel driver" << std::endl;
    std::cout << "  uninstall   - Uninstall the kernel driver" << std::endl;
    std::cout << "  status      - Show protection status and statistics" << std::endl;
    std::cout << "  enable      - Enable active protection" << std::endl;
    std::cout << "  disable     - Disable protection" << std::endl;
    std::cout << "  monitor     - Set to monitoring mode (logging only)" << std::endl;
    std::cout << "  maximum     - Set to maximum protection level" << std::endl;
    std::cout << std::endl;
}

int main(int argc, char* argv[]) {
    std::cout << "Real Anti-Ransomware Kernel Driver Manager v1.0" << std::endl;
    std::cout << "=================================================" << std::endl;

    if (argc < 2) {
        PrintUsage();
        return 1;
    }

    std::string command = argv[1];
    AntiRansomwareManager manager;

    if (command == "install") {
        if (manager.InstallDriver()) {
            std::cout << "\n🎉 Driver installation completed successfully!" << std::endl;
            std::cout << "Your system is now protected by kernel-level anti-ransomware technology." << std::endl;
            return 0;
        } else {
            std::cout << "\n❌ Driver installation failed." << std::endl;
            return 1;
        }
    }
    else if (command == "uninstall") {
        if (manager.UninstallDriver()) {
            std::cout << "\n✓ Driver uninstalled successfully." << std::endl;
            return 0;
        } else {
            std::cout << "\n❌ Driver uninstallation failed." << std::endl;
            return 1;
        }
    }
    else if (command == "status") {
        manager.GetStatus();
        return 0;
    }
    else if (command == "enable") {
        if (manager.SetProtectionLevel(ProtectionActive)) {
            std::cout << "✓ Active protection enabled" << std::endl;
            return 0;
        }
        return 1;
    }
    else if (command == "disable") {
        if (manager.SetProtectionLevel(ProtectionDisabled)) {
            std::cout << "✓ Protection disabled" << std::endl;
            return 0;
        }
        return 1;
    }
    else if (command == "monitor") {
        if (manager.SetProtectionLevel(ProtectionMonitoring)) {
            std::cout << "✓ Monitoring mode enabled" << std::endl;
            return 0;
        }
        return 1;
    }
    else if (command == "maximum") {
        if (manager.SetProtectionLevel(ProtectionMaximum)) {
            std::cout << "✓ Maximum protection enabled" << std::endl;
            return 0;
        }
        return 1;
    }
    else {
        std::cout << "Unknown command: " << command << std::endl;
        PrintUsage();
        return 1;
    }
}
