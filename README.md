[![Typing SVG](https://readme-typing-svg.demolab.com?font=JetBrains+Mono&weight=700&size=22&pause=1200&color=00FFB3&center=true&vCenter=true&width=850&lines=Kernel-Mode+DLL+Injector;WDM+x64+Kernel+Driver+%2B+User-Mode+Loader;Manual-Map+%C2%B7+IOCTL+0x801+%C2%B7+Thread+Hijack;Lab+Only+%C2%B7+Windows+Driver)](https://readme-typing-svg.demolab.com)

---

> [!CAUTION]
> **LAB ONLY** - inject ONLY into processes you own (your apps, `notepad.exe`, a VM).
> Loading the driver requires **Test Mode** (test signing) and a self-signed cert in
> your Root store. Both leave traces: clean them up (see the end).
>
> Do not use against multiplayer games, anticheat-protected software
> (EAC, BattlEye, Vanguard, Byfron) or third-party software you do not own.

### `about`

```
Tool      :  Kernel-Mode DLL Injector
Version   :  1.0
Author    :  ItzMeow80
Target    :  Any module you pass (x64 PE, lab process of your own)
Type      :  WDM kernel driver + console client - manual map + thread hijack
Vectors   :  IOCTL 0x801 Device: \\.\ModernInjector  (PID + TID + path)
Technique :  MmCopyVirtualMemory  >  base relocation  >  PsGet/PsSetContextThread
Severity  :  [ LAB DISCIPLINE REQUIRED ]
```

---

## 📦 Contents

```
modern_injector.cpp     WDM driver - device \\.\ModernInjector
                        IOCTL 0x801 {Pid, Tid, DllPath[260]}
                        manual map: MmCopyVirtualMemory + reloc DIR64/HIGHLOW
                        launch DllMain: ZwSuspendThread > PsGet/SetContextThread
loader.cpp              console client - finds first thread of PID (Toolhelp32)
testdll.cpp             test DLL - MessageBox on inject
build_driver.cmd        cl /kernel + link (ntoskrnl.lib, x64, /DRIVER)
code_signing.cmd        certreq self-signed CodeSigningCert + signtool
```

## 🔨 Build (x64 only)

```
:: Visual Studio Build Tools (MSVC 14.5x) + Windows SDK 26100 + WDK 26100
build_driver.cmd     ->  x64\Debug\ModernInjector.sys
code_signing.cmd     ->  signs .sys / .exe / .dll with ModernInjectorTestCert
```

The 26100 WDK headers no longer declare `ZwWriteVirtualMemory`, `PsGetContextThread`,
`KeSuspendThread`... They are still official `ntoskrnl` exports (verified with
`dumpbin /linkermember`): the driver declares and links only those present in the
import lib, and keeps the TID hunting to documented user-mode APIs.

## ⚡ Quick start

**Test Mode is mandatory** for an unsigned/test-signed kernel driver - if Secure
Boot is ON, `bcdedit /set testsigning on` is refused: disable Secure Boot in UEFI,
reboot, then:

```powershell
bcdedit /set testsigning on            # reboot required
certutil -addstore -f Root .\testcert.cer
certutil -addstore -f TrustedPublisher .\testcert.cer

sc create ModernInjector type= kernel binPath= <no-spaces-path>\ModernInjector.sys start= demand
sc start ModernInjector                # STATE: RUNNING

start notepad.exe
.\loader.exe <notepadPID> .\testdll.dll   # MessageBox inside notepad = chain works
```

Single interactive driver: **`PASSO_UNICO`-style flow** (copy to `C:\KMI`, R/C
reboot choice, auto-PID): ask me to include it — the plain scripts are in the repo.

## 🧠 Technique

```
1. loader.exe             Toolhelp32 -> first thread TID of the target PID
2. IOCTL 0x801            {Pid, Tid, Path} -> \\.\ModernInjector
3. driver reads DLL       ZwCreateFile + ZwReadFile (kernel buffer)
4. layout mapper          headers + sections placed at virtual offsets
                          base relocation patched on the kernel copy
5. allocation in target   ZwAllocateVirtualMemory (attach) - RWX
6. copy in target         MmCopyVirtualMemory (cross-process, no attach)
7. DllMain launch         ZwSuspendThread + PsSetContextThread(Rip)
                          + ZwResumeThread on a TARGET thread
```

## ⚠ Known limits

- the hijacked thread keeps its original user `Rsp`: after a non-blocking DllMain
  returns there is no clean path back → target thread may crash. Use DLLs that
  spawn their own thread and return.
- no PID filtering: it injects wherever you point it.
- WDM, no KTM/WDF: keep it for a lab VM, not a daily-driver host.

## 🧹 Clean-up (admin)

```
sc stop ModernInjector & sc delete ModernInjector
certutil -delstore Root ModernInjectorTestCert
certutil -delstore TrustedPublisher ModernInjectorTestCert
bcdedit /set testsigning off            # reboot
```

---

*Research / personal lab use only. Provided as-is, no warranty. MIT.*
