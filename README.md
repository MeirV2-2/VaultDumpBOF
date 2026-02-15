# VaultDumpBOF
A Beacon Object File (BOF) for the **Adaptix C2** framework designed to harvest Windows Vaults and Generic Credentials.

## 📖 Usage

This BOF supports two modes based on the arguments passed via the Adaptix console:

### 1. General System Audit
Runs without arguments. Dumps vaults for the current process context (e.g., SYSTEM) and crawls `C:\Users\` to identify vault locations for all users.
```text
beacon > vault_dump
```

### 2. Targeted Dump
The BOF performs thread impersonation to unlock DPAPI keys, allowing for the extraction of plaintext passwords from both Vaults and Generic Credentials.
```text
beacon > vault_dump <Username> <Password>
```
