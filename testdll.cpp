// testdll.cpp — DLL di prova x64: quando viene iniettata mostra una MessageBox.
// (inda punti all'intero file DLL di caricamento, quindi niente LoadLibrary in DllMain:
//  user32 viene risolta dal loader prima di chiamare DllMain — ben coerente coi limiti di DllMain)
#include <windows.h>

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved)
{
    switch (reason) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        MessageBoxW(NULL,
            L"La DLL e' stata iniettata con successo!", L"Kernel Injector — test",
            MB_ICONINFORMATION | MB_OK);
        break;
    default:
        break;
    }
    return TRUE;
}
