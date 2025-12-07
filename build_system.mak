# COMPREHENSIVE C/C++ ANTI-RANSOMWARE BUILD SYSTEM
# Complete build configuration for kernel driver and user application

# Project Configuration
PROJECT_NAME = AntiRansomware
KERNEL_DRIVER = antiransomware_kernel.sys
USER_CLIENT = antiransomware_client.exe

# Compiler and Tools
CC = cl.exe
CXX = cl.exe
LINK = link.exe
RC = rc.exe

# Windows Driver Kit paths (adjust for your WDK installation)
WDK_ROOT = C:\Program Files (x86)\Windows Kits\10
WDK_VERSION = 10.0.22621.0
WDK_INC = $(WDK_ROOT)\Include\$(WDK_VERSION)
WDK_LIB = $(WDK_ROOT)\Lib\$(WDK_VERSION)

# Visual Studio paths
VS_ROOT = C:\Program Files\Microsoft Visual Studio\2022\Community
VS_TOOLS = $(VS_ROOT)\VC\Tools\MSVC\14.35.32215

# Include directories
KERNEL_INCLUDES = \
    /I"$(WDK_INC)\km" \
    /I"$(WDK_INC)\shared" \
    /I"$(WDK_INC)\km\crt"

USER_INCLUDES = \
    /I"$(WDK_INC)\um" \
    /I"$(WDK_INC)\shared" \
    /I"$(VS_TOOLS)\include"

# Library directories
KERNEL_LIBPATH = \
    /LIBPATH:"$(WDK_LIB)\km\x64"

USER_LIBPATH = \
    /LIBPATH:"$(WDK_LIB)\um\x64" \
    /LIBPATH:"$(VS_TOOLS)\lib\x64"

# Compiler flags
KERNEL_CFLAGS = \
    /c /Zp8 /Gy /W3 /Gz /hotpatch /EHs-c- /GR- /GF /Z7 \
    /kernel /D_WIN64 /D_AMD64_ /DAMD64 /D_KERNEL_MODE \
    /D_X64_ /DSTD_CALL /DFLT_MGR_BASELINE=1 \
    /D_WIN32_WINNT=0x0601 /DWINVER=0x0601 \
    /DWINNT=1 /D_WINDLL /DWIN32_LEAN_AND_MEAN \
    /DDEVL=1 /DFPO=0 /DNDEBUG

USER_CFLAGS = \
    /c /W3 /EHsc /MD /O2 /D_WIN64 /D_AMD64_ /DAMD64 \
    /D_WIN32_WINNT=0x0601 /DWINVER=0x0601 \
    /DWIN32_LEAN_AND_MEAN /DUNICODE /D_UNICODE

# Linker flags
KERNEL_LDFLAGS = \
    /DRIVER /ENTRY:DriverEntry /SUBSYSTEM:NATIVE \
    /NODEFAULTLIB /RELEASE /NOLOGO /DEBUGTYPE:cv \
    /VERSION:10.0 /osversion:10.0 /MERGE:_PAGE=PAGE \
    /MERGE:_TEXT=.text /SECTION:INIT,d /OPT:REF /OPT:ICF \
    /IGNORE:4198,4010,4037,4039,4065,4070,4078,4087,4089,4221,4108,4088,4218,4218,4235

USER_LDFLAGS = \
    /SUBSYSTEM:WINDOWS /NOLOGO /RELEASE /OPT:REF /OPT:ICF

# Libraries
KERNEL_LIBS = \
    ntoskrnl.lib \
    hal.lib \
    fltmgr.lib \
    wdmsec.lib \
    ntstrsafe.lib \
    BufferOverflowK.lib

USER_LIBS = \
    kernel32.lib \
    user32.lib \
    gdi32.lib \
    advapi32.lib \
    comctl32.lib \
    shell32.lib \
    ole32.lib \
    oleaut32.lib

# Source files
KERNEL_SOURCES = antiransomware_kernel.c
USER_SOURCES = antiransomware_client.cpp

# Object files
KERNEL_OBJECTS = $(KERNEL_SOURCES:.c=.obj)
USER_OBJECTS = $(USER_SOURCES:.cpp=.obj)

# Build rules
all: $(KERNEL_DRIVER) $(USER_CLIENT)

$(KERNEL_DRIVER): $(KERNEL_OBJECTS)
	@echo Building kernel driver...
	$(LINK) $(KERNEL_LDFLAGS) $(KERNEL_LIBPATH) /OUT:$@ $(KERNEL_OBJECTS) $(KERNEL_LIBS)

$(USER_CLIENT): $(USER_OBJECTS)
	@echo Building user application...
	$(LINK) $(USER_LDFLAGS) $(USER_LIBPATH) /OUT:$@ $(USER_OBJECTS) $(USER_LIBS)

# Kernel object compilation
antiransomware_kernel.obj: antiransomware_kernel.c
	@echo Compiling kernel driver source...
	$(CC) $(KERNEL_CFLAGS) $(KERNEL_INCLUDES) antiransomware_kernel.c

# User object compilation  
antiransomware_client.obj: antiransomware_client.cpp
	@echo Compiling user application source...
	$(CXX) $(USER_CFLAGS) $(USER_INCLUDES) antiransomware_client.cpp

# Clean build artifacts
clean:
	@echo Cleaning build artifacts...
	del /Q *.obj *.pdb *.exp *.lib *.sys *.exe 2>nul || exit 0

# Install driver (requires Administrator privileges)
install: $(KERNEL_DRIVER)
	@echo Installing kernel driver...
	sc create AntiRansomwareKernel type=kernel start=demand error=normal binpath=%CD%\$(KERNEL_DRIVER) displayname="Anti-Ransomware Kernel Protection"
	sc start AntiRansomwareKernel

# Uninstall driver
uninstall:
	@echo Uninstalling kernel driver...
	sc stop AntiRansomwareKernel
	sc delete AntiRansomwareKernel

# Load driver for testing
load: $(KERNEL_DRIVER)
	@echo Loading driver for testing...
	sc start AntiRansomwareKernel

# Stop driver
stop:
	@echo Stopping driver...
	sc stop AntiRansomwareKernel

# Sign driver for Windows 10/11 (requires code signing certificate)
sign: $(KERNEL_DRIVER)
	@echo Signing kernel driver...
	signtool sign /v /fd SHA256 /ac "path\to\cross-cert.cer" /f "path\to\certificate.pfx" /p "password" $(KERNEL_DRIVER)

# Enable test signing (for development only)
enable-testsigning:
	@echo Enabling test signing mode...
	bcdedit /set testsigning on
	@echo Reboot required for test signing to take effect

# Disable test signing
disable-testsigning:
	@echo Disabling test signing mode...
	bcdedit /set testsigning off
	@echo Reboot required for changes to take effect

# Create installation package
package: $(KERNEL_DRIVER) $(USER_CLIENT)
	@echo Creating installation package...
	mkdir AntiRansomware_Package 2>nul || exit 0
	copy $(KERNEL_DRIVER) AntiRansomware_Package\
	copy $(USER_CLIENT) AntiRansomware_Package\
	copy install.bat AntiRansomware_Package\
	copy uninstall.bat AntiRansomware_Package\
	copy README.txt AntiRansomware_Package\
	@echo Package created in AntiRansomware_Package directory

# Help target
help:
	@echo Available targets:
	@echo   all              - Build both kernel driver and user application
	@echo   $(KERNEL_DRIVER) - Build kernel driver only
	@echo   $(USER_CLIENT)   - Build user application only
	@echo   clean            - Remove build artifacts
	@echo   install          - Install and start kernel driver
	@echo   uninstall        - Stop and remove kernel driver
	@echo   load             - Start the kernel driver
	@echo   stop             - Stop the kernel driver
	@echo   sign             - Sign the kernel driver (requires certificate)
	@echo   enable-testsigning - Enable test signing mode (development)
	@echo   disable-testsigning - Disable test signing mode
	@echo   package          - Create installation package
	@echo   help             - Show this help message
	@echo.
	@echo Prerequisites:
	@echo   - Windows Driver Kit (WDK) 10
	@echo   - Visual Studio 2019 or later
	@echo   - Administrator privileges for driver operations
	@echo.
	@echo For development:
	@echo   1. Run 'make enable-testsigning' and reboot
	@echo   2. Run 'make all' to build
	@echo   3. Run 'make install' to install driver
	@echo   4. Run antiransomware_client.exe to use

.PHONY: all clean install uninstall load stop sign enable-testsigning disable-testsigning package help
