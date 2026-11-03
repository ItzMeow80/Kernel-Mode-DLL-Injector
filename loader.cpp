// loader.cpp — client user-mode del driver ModernInjector.
// Uso: loader.exe <TargetPid> <PathDLL>
// Trova il primo thread del processo target con Toolhelp (user-mode, documentato)
// e invia { TargetPid, TargetTid, DllPath } al driver via IOCTL.
#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>

#define IOCTL_INJECT_DLL CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

struct INJECTION_REQUEST {
    ULONG TargetPid;
    ULONG TargetTid;
    WCHAR DllPath[260];
};

static std::wstring ToWide(const char* s) {
    int len = MultiByteToWideChar(CP_UTF8, 0, s, -1, nullptr, 0);
    std::wstring out(len ? (size_t)len - 1 : 0, L'\0');
    if (len) MultiByteToWideChar(CP_UTF8, 0, s, -1, &out[0], len);
    return out;
}

static DWORD FindFirstThreadOf(DWORD pid) {
    DWORD tid = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    THREADENTRY32 te{}; te.dwSize = sizeof(te);
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) { tid = te.th32ThreadID; break; }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    return tid;
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Uso: " << argv[0] << " <PID target> <percorso.dll>\n"
                  << "Esempio: loader.exe 5678 C:\\test\\testdll.dll\n";
        return 1;
    }

    ULONG pid = (ULONG)strtoul(argv[1], nullptr, 0);
    if (!pid) { std::cerr << "PID non valido\n"; return 1; }

    // verifica che il processo esista prima di tutto
    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProc) {
        std::cerr << "Processo " << pid << " non trovato (errore " << GetLastError() << ")\n";
        return 1;
    }
    CloseHandle(hProc);

    DWORD tid = FindFirstThreadOf(pid);
    if (!tid) {
        std::cerr << "Nessun thread trovato per il PID " << pid << "\n";
        return 1;
    }

    std::wstring dllPath = ToWide(argv[2]);
    if (dllPath.size() >= 260) {
        std::cerr << "Percorso troppo lungo (max 259 caratteri)\n";
        return 1;
    }

    HANDLE hDevice = CreateFileW(L"\\\\.\\ModernInjector", GENERIC_READ | GENERIC_WRITE,
        0, NULL, OPEN_EXISTING, 0, NULL);
    if (hDevice == INVALID_HANDLE_VALUE) {
        std::cerr << "Impossibile aprire il driver (errore " << GetLastError() << "): "
                  << "controlla il caricamento: sc query ModernInjector\n";
        return 1;
    }

    INJECTION_REQUEST request{};
    request.TargetPid = pid;
    request.TargetTid = tid;
    wcscpy_s(request.DllPath, dllPath.c_str());

    DWORD bytesReturned = 0;
    if (!DeviceIoControl(hDevice, IOCTL_INJECT_DLL, &request, sizeof(request),
        NULL, 0, &bytesReturned, NULL)) {
        std::cerr << "IOCTL fallita (errore " << GetLastError() << ")\n";
        return 1;
    }

    std::cout << "Iniezione richiesta: PID " << pid << ", TID " << tid
              << ", DLL " << argv[2] << "\n";
    CloseHandle(hDevice);
    return 0;
}
