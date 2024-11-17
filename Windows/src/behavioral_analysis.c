#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <detours.h>  // Include Microsoft Detours header
#include "behavioral_analysis.h"


// Global variable for the log file
FILE *log_file = NULL;

// Utility function to log events
void log_event(const char *message) {
    printf("[EVENT]: %s\n", message);  // Display on the terminal

    // Write to the log file
    if (log_file) {
        fprintf(log_file, "[EVENT]: %s\n", message);
        fflush(log_file);  // Ensure the log is written immediately
    }
}



// Original function pointers
static HANDLE(WINAPI *OriginalCreateFileW)(
    LPCWSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile) = CreateFileW;

static LONG(WINAPI *OriginalRegSetValueExW)(
    HKEY hKey,
    LPCWSTR lpValueName,
    DWORD Reserved,
    DWORD dwType,
    const BYTE *lpData,
    DWORD cbData) = RegSetValueExW;

// Hooked function for CreateFileW
HANDLE WINAPI HookedCreateFileW(
    LPCWSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile) {
    // Log the file operation
    wprintf(L"[HOOK] CreateFileW called for: %ls\n", lpFileName);

    // Call the original CreateFileW function
    return OriginalCreateFileW(lpFileName, dwDesiredAccess, dwShareMode,
                               lpSecurityAttributes, dwCreationDisposition,
                               dwFlagsAndAttributes, hTemplateFile);
}

// Hooked function for RegSetValueExW
LONG WINAPI HookedRegSetValueExW(
    HKEY hKey,
    LPCWSTR lpValueName,
    DWORD Reserved,
    DWORD dwType,
    const BYTE *lpData,
    DWORD cbData) {
    // Log the registry modification
    wprintf(L"[HOOK] RegSetValueExW called. Key: %p, ValueName: %ls\n", hKey, lpValueName);

    // Call the original RegSetValueExW function
    return OriginalRegSetValueExW(hKey, lpValueName, Reserved, dwType, lpData, cbData);
}

// Monitor system calls
void monitor_system_calls() {
    log_event("Starting system call monitoring...");

    // Attach hooks for CreateFileW and RegSetValueExW
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(&(PVOID &)OriginalCreateFileW, HookedCreateFileW);
    DetourAttach(&(PVOID &)OriginalRegSetValueExW, HookedRegSetValueExW);

    if (DetourTransactionCommit() == NO_ERROR) {
        log_event("Successfully hooked CreateFileW and RegSetValueExW.");
    } else {
        log_event("Failed to hook CreateFileW or RegSetValueExW.");
        return;
    }

    log_event("System call monitoring active. Press Ctrl+C to stop.");

    // Wait indefinitely to keep the hooks active
    while (1) {
        Sleep(1000);
    }

    // Detach the hooks (not reached unless the program terminates cleanly)
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourDetach(&(PVOID &)OriginalCreateFileW, HookedCreateFileW);
    DetourDetach(&(PVOID &)OriginalRegSetValueExW, HookedRegSetValueExW);
    DetourTransactionCommit();

    log_event("System call monitoring stopped.");
}



// Utility function to log events
void log_event(const char *message) {
    printf("[EVENT]: %s\n", message);
}

// Monitor a folder and its subdirectories
void monitor_folder(const char *folder_path) {
    log_event("Starting folder monitoring...");
    HANDLE hDir = CreateFile(
        folder_path,
        FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        NULL
    );

    if (hDir == INVALID_HANDLE_VALUE) {
        log_event("Failed to open directory handle for monitoring.");
        return;
    }

    char buffer[1024];
    DWORD bytesReturned;

    while (1) {
        if (ReadDirectoryChangesW(
            hDir,
            buffer,
            sizeof(buffer),
            TRUE, // Monitor subdirectories
            FILE_NOTIFY_CHANGE_FILE_NAME |
            FILE_NOTIFY_CHANGE_DIR_NAME |
            FILE_NOTIFY_CHANGE_ATTRIBUTES |
            FILE_NOTIFY_CHANGE_SIZE |
            FILE_NOTIFY_CHANGE_LAST_WRITE,
            &bytesReturned,
            NULL,
            NULL
        )) {
            FILE_NOTIFY_INFORMATION *info = (FILE_NOTIFY_INFORMATION *)buffer;
            do {
                WCHAR fileName[MAX_PATH_LENGTH];
                wcsncpy(fileName, info->FileName, info->FileNameLength / sizeof(WCHAR));
                fileName[info->FileNameLength / sizeof(WCHAR)] = L'\0';

                wchar_t log_message[512];
                swprintf(log_message, 512, L"[MONITOR] File changed: %ls\n", fileName);
                wprintf(log_message);  // Display on the terminal
                if (log_file) fwprintf(log_file, log_message);  // Write to the log file

                wprintf(L"[MONITOR] File changed: %ls\n", fileName);
                info = info->NextEntryOffset ? (FILE_NOTIFY_INFORMATION *)((BYTE *)info + info->NextEntryOffset) : NULL;
            } while (info);
        } else {
            log_event("Failed to read directory changes.");
            break;
        }
    }

    CloseHandle(hDir);
    log_event("Folder monitoring stopped.");
}

// Monitor registry changes in critical paths
void monitor_registry_changes() {
    log_event("Monitoring registry changes...");

    HKEY hKey;
    HANDLE hEvent;

    // Open the key to monitor (e.g., Startup entries)
    if (RegOpenKeyEx(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_NOTIFY, &hKey) != ERROR_SUCCESS) {
        log_event("Failed to open registry key.");
        return;
    }

    // Create an event object for notifications
    hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (!hEvent) {
        log_event("Failed to create event object.");
        RegCloseKey(hKey);
        return;
    }

    // Set up registry notification
    if (RegNotifyChangeKeyValue(hKey, TRUE, REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET, hEvent, TRUE) != ERROR_SUCCESS) {
        log_event("Failed to set registry notification.");
        CloseHandle(hEvent);
        RegCloseKey(hKey);
        return;
    }

    log_event("Registry monitoring active...");

    // Monitor registry changes indefinitely
    while (1) {
        DWORD result = WaitForSingleObject(hEvent, INFINITE);
        if (result == WAIT_OBJECT_0) {
            log_event("Registry change detected!");

            // Re-arm the registry notification
            if (RegNotifyChangeKeyValue(hKey, TRUE, REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET, hEvent, TRUE) != ERROR_SUCCESS) {
                log_event("Failed to re-arm registry notification.");
                break;
            }
        } else {
            log_event("Error or termination detected in registry monitoring.");
            break;
        }
    }

    CloseHandle(hEvent);
    RegCloseKey(hKey);
    log_event("Registry monitoring stopped.");
}

// Start behavioral analysis
void start_behavior_analysis(const char *folder_path) {
    log_file = fopen("behavior_analysis.log", "a");  // Open the log file in append mode
    if (!log_file) {
        printf("[ERROR]: Failed to open log file for writing.\n");
        return;
    }

    log_event("Starting Behavioral Analysis...");
    monitor_folder(folder_path);
    monitor_registry_changes();
    monitor_system_calls();
    fclose(log_file);  // Close the log file
}
