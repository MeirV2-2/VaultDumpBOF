#pragma once

#include <windows.h>

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _LDR_MODULE {
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID      BaseAddress;
    PVOID      EntryPoint;
    ULONG      SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_MODULE, * PLDR_MODULE;

typedef struct _PEB_LDR_DATA {
    ULONG      Length;
    BOOLEAN    Initialized;
    PVOID      SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _PEB {
    BOOLEAN        InheritedAddressSpace;
    BOOLEAN        ReadImageFileExecOptions;
    BOOLEAN        BeingDebugged;
    BOOLEAN        Spare;
    HANDLE         Mutant;
    PVOID          ImageBaseAddress;
    PPEB_LDR_DATA  LoaderData;
} PEB, * PPEB;

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
    GUID            SchemaId;
    PWSTR           FriendlyName;
    PVAULT_ITEM_DATA Resource;
    PVAULT_ITEM_DATA Identity;
    PVAULT_ITEM_DATA Authenticator;
    PVAULT_ITEM_DATA Package;
    FILETIME        LastWritten;
    DWORD           Flags;
    DWORD           PropertiesCount;
    PVAULT_ITEM_DATA Properties;
} VAULT_ITEM, * PVAULT_ITEM;

HMODULE GetNtdllBOF(void);
void    EnableBackupPrivilegeBOF(void);
void    DumpVaultsBOF(void);
