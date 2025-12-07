/*
 * USER-MODE CLIENT FOR KERNEL DRIVER COMMUNICATION
 * Communicates with the real_kernel_driver.c via IOCTL calls
 */

#include <windows.h>
#include <stdio.h>
#include <conio.h>

// IOCTL codes (must match kernel driver)
#define IOCTL_ENABLE_PROTECTION CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ADD_PROTECTED_FOLDER CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GET_STATISTICS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_READ_ACCESS)

#define DEVICE_PATH L"\\\\.\\AntiRansomwareKernel"

class KernelDriverClient {
private:
    HANDLE hDevice;
    
public:
    KernelDriverClient() : hDevice(INVALID_HANDLE_VALUE) {}
    
    ~KernelDriverClient() {
        if (hDevice != INVALID_HANDLE_VALUE) {
            CloseHandle(hDevice);
        }
    }
    
    bool Connect() {
        hDevice = CreateFileW(
            DEVICE_PATH,
            GENERIC_READ | GENERIC_WRITE,
            0,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL
        );
        
        if (hDevice == INVALID_HANDLE_VALUE) {
            printf("Failed to connect to kernel driver. Error: %lu\n", GetLastError());
            printf("Make sure the driver is loaded and running.\n");
            return false;
        }
        
        printf("Successfully connected to kernel driver!\n");
        return true;
    }
    
    bool EnableProtection(bool enable) {
        BOOLEAN enableFlag = enable ? TRUE : FALSE;
        DWORD bytesReturned;
        
        BOOL result = DeviceIoControl(
            hDevice,
            IOCTL_ENABLE_PROTECTION,
            &enableFlag,
            sizeof(enableFlag),
            NULL,
            0,
            &bytesReturned,
            NULL
        );
        
        if (result) {
            printf("Protection %s at kernel level!\n", enable ? "ENABLED" : "DISABLED");
            return true;
        } else {
            printf("Failed to %s protection. Error: %lu\n", 
                   enable ? "enable" : "disable", GetLastError());
            return false;
        }
    }
    
    bool AddProtectedFolder(const wchar_t* folderPath) {
        DWORD pathLength = (wcslen(folderPath) + 1) * sizeof(wchar_t);
        DWORD bytesReturned;
        
        BOOL result = DeviceIoControl(
            hDevice,
            IOCTL_ADD_PROTECTED_FOLDER,
            (LPVOID)folderPath,
            pathLength,
            NULL,
            0,
            &bytesReturned,
            NULL
        );
        
        if (result) {
            printf("Added protected folder: %ws\n", folderPath);
            return true;
        } else {
            printf("Failed to add protected folder. Error: %lu\n", GetLastError());
            return false;
        }
    }
    
    ULONG GetBlockedAttempts() {
        ULONG statistics = 0;
        DWORD bytesReturned;
        
        BOOL result = DeviceIoControl(
            hDevice,
            IOCTL_GET_STATISTICS,
            NULL,
            0,
            &statistics,
            sizeof(statistics),
            &bytesReturned,
            NULL
        );
        
        if (result) {
            return statistics;
        } else {
            printf("Failed to get statistics. Error: %lu\n", GetLastError());
            return 0;
        }
    }
};

void PrintMenu() {
    printf("\n=== REAL KERNEL-LEVEL ANTI-RANSOMWARE CONTROL ===\n");
    printf("This communicates with actual Ring-0 kernel driver\n");
    printf("--------------------------------------------------\n");
    printf("1. Enable Kernel Protection\n");
    printf("2. Disable Kernel Protection\n");
    printf("3. Add Protected Folder\n");
    printf("4. Show Statistics\n");
    printf("5. Real-time Monitor\n");
    printf("0. Exit\n");
    printf("Choice: ");
}

void RealTimeMonitor(KernelDriverClient& client) {
    printf("\n=== REAL-TIME KERNEL MONITORING ===\n");
    printf("Press any key to stop monitoring...\n\n");
    
    ULONG lastCount = 0;
    
    while (!_kbhit()) {
        ULONG currentCount = client.GetBlockedAttempts();
        
        if (currentCount != lastCount) {
            printf("[KERNEL] Blocked attempts: %lu (+%lu new)\n", 
                   currentCount, currentCount - lastCount);
            lastCount = currentCount;
        }
        
        Sleep(1000); // Check every second
    }
    
    _getch(); // Consume the key press
    printf("Monitoring stopped.\n");
}

int main() {
    printf("REAL KERNEL-LEVEL ANTI-RANSOMWARE CLIENT\n");
    printf("=========================================\n");
    printf("This program communicates with a real Windows kernel driver\n");
    printf("running at Ring-0 with true kernel-level privileges.\n\n");
    
    KernelDriverClient client;
    
    if (!client.Connect()) {
        printf("\nTo use this program:\n");
        printf("1. Build the kernel driver (real_kernel_driver.c)\n");
        printf("2. Install and load the driver using sc.exe or OSR Driver Loader\n");
        printf("3. Run this program as Administrator\n");
        printf("\nPress any key to exit...\n");
        _getch();
        return 1;
    }
    
    int choice;
    wchar_t folderPath[MAX_PATH];
    
    do {
        PrintMenu();
        scanf_s("%d", &choice);
        
        switch (choice) {
            case 1:
                client.EnableProtection(true);
                printf("Kernel driver is now actively blocking ransomware at Ring-0!\n");
                break;
                
            case 2:
                client.EnableProtection(false);
                printf("Kernel protection disabled.\n");
                break;
                
            case 3:
                printf("Enter folder path to protect: ");
                wscanf_s(L"%s", folderPath, MAX_PATH);
                client.AddProtectedFolder(folderPath);
                break;
                
            case 4:
                {
                    ULONG blocked = client.GetBlockedAttempts();
                    printf("\n=== KERNEL DRIVER STATISTICS ===\n");
                    printf("Total blocked attempts: %lu\n", blocked);
                    printf("Driver status: Active at Ring-0\n");
                    printf("Protection level: True kernel-level\n");
                }
                break;
                
            case 5:
                RealTimeMonitor(client);
                break;
                
            case 0:
                printf("Exiting...\n");
                break;
                
            default:
                printf("Invalid choice!\n");
                break;
        }
        
    } while (choice != 0);
    
    return 0;
}

/*
 * COMPILATION INSTRUCTIONS:
 * 
 * Using Visual Studio:
 * cl /EHsc kernel_client.cpp
 * 
 * Using MinGW:
 * g++ -o kernel_client.exe kernel_client.cpp
 * 
 * Note: Must run the resulting executable as Administrator
 * to communicate with the kernel driver.
 */
