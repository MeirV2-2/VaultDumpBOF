/*
 * BOF Dynamic Function Resolution (DFR) Declarations
 * Declares Win32 API functions in LIBRARY$Function format for BOF context.
 * Based on AdaptixC2 Extension-Kit bofdefs.h pattern.
 */
#pragma once
#ifndef BOFDEFS_H_
#define BOFDEFS_H_

#include <windows.h>
#include <winternl.h>

/* ========================================================================
 * Convenience Macros (matching AdaptixC2 Extension-Kit conventions)
 * ======================================================================== */

#define intAlloc(size)          KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, size)
#define intRealloc(ptr, size)   KERNEL32$HeapReAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, ptr, size)
#define intFree(ptr)            KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, ptr)
#define intZeroMemory(ptr, sz)  MSVCRT$memset(ptr, 0, sz)

/* ========================================================================
 * KERNEL32.DLL
 * ======================================================================== */

DECLSPEC_IMPORT HANDLE  WINAPI KERNEL32$GetProcessHeap(void);
DECLSPEC_IMPORT LPVOID  WINAPI KERNEL32$HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$HeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem);
DECLSPEC_IMPORT LPVOID  WINAPI KERNEL32$HeapReAlloc(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem, SIZE_T dwBytes);
DECLSPEC_IMPORT DWORD   WINAPI KERNEL32$GetLastError(void);
DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$LoadLibraryW(LPCWSTR lpLibFileName);
DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$GetModuleHandleA(LPCSTR lpModuleName);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$CloseHandle(HANDLE hObject);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
DECLSPEC_IMPORT HANDLE  WINAPI KERNEL32$GetStdHandle(DWORD nStdHandle);
DECLSPEC_IMPORT HLOCAL  WINAPI KERNEL32$LocalAlloc(UINT uFlags, SIZE_T uBytes);
DECLSPEC_IMPORT HLOCAL  WINAPI KERNEL32$LocalFree(HLOCAL hMem);
DECLSPEC_IMPORT void    WINAPI KERNEL32$OutputDebugStringA(LPCSTR lpOutputString);
DECLSPEC_IMPORT void    WINAPI KERNEL32$OutputDebugStringW(LPCWSTR lpOutputString);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$GetConsoleMode(HANDLE hConsoleHandle, LPDWORD lpMode);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$WriteConsoleA(HANDLE hConsoleOutput, const void* lpBuffer, DWORD nNumberOfCharsToWrite, LPDWORD lpNumberOfCharsWritten, LPVOID lpReserved);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$WriteConsoleW(HANDLE hConsoleOutput, const void* lpBuffer, DWORD nNumberOfCharsToWrite, LPDWORD lpNumberOfCharsWritten, LPVOID lpReserved);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$WriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped);
// DECLSPEC_IMPORT HANDLE  WINAPI KERNEL32$OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);

/* ========================================================================
 * ADVAPI32.DLL
 * ======================================================================== */

DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$OpenProcessToken(HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$LookupPrivilegeValueW(LPCWSTR lpSystemName, LPCWSTR lpName, PLUID lpLuid);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$AdjustTokenPrivileges(HANDLE TokenHandle, BOOL DisableAllPrivileges, PTOKEN_PRIVILEGES NewState, DWORD BufferLength, PTOKEN_PRIVILEGES PreviousState, PDWORD ReturnLength);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$GetTokenInformation(HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, LPVOID TokenInformation, DWORD TokenInformationLength, PDWORD ReturnLength);

/* ========================================================================
 * USER32.DLL
 * ======================================================================== */

DECLSPEC_IMPORT int WINAPI USER32$wvsprintfA(LPSTR lpOutput, LPCSTR lpFmt, va_list arglist);
DECLSPEC_IMPORT int WINAPI USER32$wsprintfA(LPSTR lpOutput, LPCSTR lpFmt, ...);
DECLSPEC_IMPORT int WINAPI USER32$wvsprintfW(LPWSTR lpOutput, LPCWSTR lpFmt, va_list arglist);
DECLSPEC_IMPORT int WINAPI USER32$wsprintfW(LPWSTR lpOutput, LPCWSTR lpFmt, ...);

/* ========================================================================
 * MSVCRT.DLL
 * ======================================================================== */

DECLSPEC_IMPORT void* __cdecl MSVCRT$memset(void* dest, int c, size_t count);
DECLSPEC_IMPORT void* __cdecl MSVCRT$memcpy(void* dest, const void* src, size_t count);
DECLSPEC_IMPORT int   __cdecl MSVCRT$_stricmp(const char* str1, const char* str2);

#endif /* BOFDEFS_H_ */
