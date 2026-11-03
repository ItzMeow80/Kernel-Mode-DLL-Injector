@echo off
setlocal enabledelayedexpansion
call "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
set WDK=C:\Program Files (x86)\Windows Kits\10
set WV=10.0.26100.0
set "INCLUDE=%WDK%\Include\%WV%\km;%WDK%\Include\%WV%\shared;%INCLUDE%"
cd /d "C:\Users\siria\Desktop\JAILBREAK MD\kernelmodelinjector-src\kernelmodelinjector"

echo [1/2] Compile driver...
cl /nologo /kernel /GR- /GS /Gs999999 /W4 /EHs-c- /DNDEBUG ^
  /DNTDDI_VERSION=0x0A00000C /D_WIN32_WINNT=0x0A000000 /D_WIN64 /D_AMD64_ /DAMD64 ^
  /D_UNICODE /DUNICODE ^
  /I"%WDK%\Include\%WV%\km" /I"%WDK%\Include\%WV%\shared" ^
  /c modern_injector.cpp /Fo:x64\Debug\modern_injector.obj
if errorlevel 1 goto :err

echo [2/2] Link driver...
link /nologo /DRIVER /SUBSYSTEM:NATIVE,10.00 /MACHINE:X64 /MANIFEST:NO ^
  /ENTRY:GsDriverEntry ^
  /OUT:x64\Debug\ModernInjector.sys ^
  x64\Debug\modern_injector.obj ^
  "%WDK%\Lib\%WV%\km\x64\ntoskrnl.lib" ^
  "%WDK%\Lib\%WV%\km\x64\hal.lib" ^
  "%WDK%\Lib\%WV%\km\x64\BufferOverflowFastFailK.lib"
if errorlevel 1 goto :err

echo BUILD OK: x64\Debug\ModernInjector.sys
exit /b 0
:err
echo BUILD FALLITA
exit /b 1
