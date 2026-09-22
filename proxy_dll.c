// Stub DLL to proxy SWPtest.dll calls
// Compile with: cl /LD /Fe:"SWPtest_Proxy.dll" proxy.c
// Or use: x86 cl /LD /Fe:"SWPtest_Proxy.dll" proxy.c

#include <windows.h>
#include <stdio.h>
#include <string.h>

// Original DLL - we load it and forward calls
HMODULE g_hOriginalDLL = NULL;
BOOL g_bInitialized = FALSE;

// Function pointers to original exports
typedef BOOL (WINCRTDECL *pfnSetPassThroughType)(DWORD);
typedef DWORD (WINCRTDECL *pfnDriveReset)(DWORD, DWORD, PVOID);
typedef BOOL (WINCRTDECL *pfnDownloadMPISP)(DWORD, PVOID, WORD, PVOID);
typedef BOOL (WINCRTDECL *pfnLoadDgISP)(DWORD, PVOID, PVOID, PVOID);
typedef BOOL (WINCRTDECL *pfnCheckRunMode)(DWORD, PVOID, PVOID);
typedef BOOL (WINCRTDECL *pfnReadFlashID)(DWORD, DWORD, PVOID);
typedef BOOL (WINCRTDECL *pfnScanSMIDrive)(DWORD, DWORD, PVOID);
typedef BOOL (WINCRTDECL *pfnDownloadISP)(DWORD, PVOID, WORD, PVOID);

pfnSetPassThroughType pSetPassThroughType = NULL;
pfnDriveReset pDriveReset = NULL;
pfnDownloadMPISP pDownloadMPISP = NULL;
pfnLoadDgISP pLoadDgISP = NULL;
pfnCheckRunMode pCheckRunMode = NULL;
pfnReadFlashID pReadFlashID = NULL;
pfnScanSMIDrive pScanSMIDrive = NULL;
pfnDownloadISP pDownloadISP = NULL;

// Logging helper
void LogCall(const char* funcName, const char* paramsFmt, ...)
{
    char buffer[1024];
    FILE* f = fopen("C:\\SM2258XT_MPTool\\proxy_calls.log", "a");
    if (f) {
        va_list args;
        va_start(args, paramsFmt);
        vsnprintf(buffer, sizeof(buffer), paramsFmt, args);
        fprintf(f, "[%s] %s\n", funcName, buffer);
        fclose(f);
        va_end(args);
    }
}

// Initialize proxy - loads original DLL and resolves exports
BOOL InitializeProxy()
{
    if (g_bInitialized) return TRUE;

    // Load the original SWPtest.dll
    g_hOriginalDLL = LoadLibraryA("Dll\\SWPtest.dll");
    if (!g_hOriginalDLL) {
        g_hOriginalDLL = LoadLibraryA("SWPtest.dll");
    }

    if (!g_hOriginalDLL) {
        LogCall("Init", "FAILED - Cannot load original SWPtest.dll");
        return FALSE;
    }

    // Resolve all exports we care about
    pSetPassThroughType = (pfnSetPassThroughType)GetProcAddress(g_hOriginalDLL, "_SMISetPassThroughType");
    pDriveReset = (pfnDriveReset)GetProcAddress(g_hOriginalDLL, "_SMIPtestDriveReset");
    pDownloadMPISP = (pfnDownloadMPISP)GetProcAddress(g_hOriginalDLL, "_SMIPtestDownloadMPISP");
    pLoadDgISP = (pfnLoadDgISP)GetProcAddress(g_hOriginalDLL, "_SMIPtestLoadDgISP");
    pCheckRunMode = (pfnCheckRunMode)GetProcAddress(g_hOriginalDLL, "_SMIPtestCheckRunMode");
    pReadFlashID = (pfnReadFlashID)GetProcAddress(g_hOriginalDLL, "_SMIReadFlashID");
    pScanSMIDrive = (pfnScanSMIDrive)GetProcAddress(g_hOriginalDLL, "_SMIScanSMIDrive");
    pDownloadISP = (pfnDownloadISP)GetProcAddress(g_hOriginalDLL, "_SMIPtestDownloadISP");

    g_bInitialized = TRUE;
    LogCall("Init", "SUCCESS - SWPtest.dll loaded, exports resolved");
    return TRUE;
}

// DLL entry point
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hinstDLL);
        // Force immediate initialization on load
        OutputDebugStringA("[PROXY] DllMain called - attempting init");
        if (!InitializeProxy()) {
            OutputDebugStringA("[PROXY] FAILED to initialize");
            return FALSE;
        }
        OutputDebugStringA("[PROXY] Initialized successfully");
        break;
    case DLL_PROCESS_DETACH:
        if (g_hOriginalDLL) {
            LogCall("Shutdown", "Unloading original DLL");
            FreeLibrary(g_hOriginalDLL);
        }
        break;
    }
    return TRUE;
}

// We need to export at least one symbol for the proxy to be a valid DLL
// This makes it a valid SWPtest.dll replacement from the loader's perspective
__declspec(dllexport) BOOL WINAPI DummyExport()
{
    LogCall("DummyExport", "Called - proxy active");
    return InitializeProxy();
}
