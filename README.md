# kernel-injector-lab - WDM x64 kernel driver + user-mode loader: manual-map DLL injection for lab use (PID/TID via IOCTL, DllMain through thread hijack)

Educational / lab-only kernel injection project based on a broken Copilot-generated
source (fixed and rebuilt on windows 10/11 SDK 26100 + MSVC 14.51).

## Contents
- `modern_injector.cpp` - WDM kernel driver: device `\\.\ModernInjector`, IOCTL 0x801 receives `{TargetPid, TargetTid, DllPath}`, manual-maps a PE64 image into the target process using `MmCopyVirtualMemory` + base relocation (`DIR64`/`HIGHLOW`), then launches DllMain by hijacking a thread of the TARGET process (`ZwSuspendThread` → `PsGetContextThread`/`PsSetContextThread` → `ZwResumeThread`).
- `loader.cpp` - user-mode client: finds the first thread of the target PID with Toolhelp, sends the injection request.
- `testdll.cpp` - minimal test DLL that pops a `MessageBox` when injected.
- `build_driver.cmd` - builds `ModernInjector.sys` with `cl /kernel` + link (`ntoskrnl.lib`, `BufferOverflowFastFailK.lib`, x64, `/DRIVER /SUBSYSTEM:NATIVE`).
- `sign_all.cmd`-ish self-signed code-signing via `certreq` + `signtool` (see notes).

## Why manual prototypes
The 26100 WDK headers no longer declare `ZwWriteVirtualMemory`, `PsGetContextThread`,
`PsGetNextProcessThread`, `KeSuspendThread`... The functions still exist as `ntoskrnl` exports.
This project declares only what is actually present in the official
`ntoskrnl.lib` import library (verified with `dumpbin /linkermember`), and moves the
TID hunting to the user-mode loader (documented Toolhelp APIs) while the kernel
driver keeps to supported copy/context paths.

## Build (x64 only)
```
:: needs Visual Studio Build Tools (MSVC) + Windows SDK 10.0.26100 + WDK 26100
build_driver.cmd
```

## Lab usage (own machines only) — after enabling test signing
```
sc create ModernInjector type= kernel start= demand binPath= <no-spaces-path>\ModernInjector.sys
sc start ModernInjector
start notepad.exe
loader.exe <notepadPID> testdll.dll
```

## Known limits
- Thread hijack keeps the suspended thread's user-mode `Rsp`: after a non-blocking
  DllMain returns there is no clean path back → may crash the target thread.
  Use the injected thread only for spawn-your-own-thread DLLs.
- No PID filtering: it targets whatever you pass (lab discipline required).
- Test signing + self-signed certs land in the Root/TrustedPublisher stores:
  remove them when done ("note & clean-up" below).

## Clean-up after tests
```
sc stop ModernInjector & sc delete ModernInjector
certutil -delstore Root ModernInjectorTestCert
certutil -delstore TrustedPublisher ModernInjectorTestCert
bcdedit /set testsigning off
```

## Disclaimer
Educational research / personal lab use only. Do not use against accounting,
multiplayer games, anticheat-protected software or third-party software you do not
own. Provided as-is, no warranty.

## License
MIT
