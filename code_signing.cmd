@echo off
:: Self-signed test code-signing (no admin required to create the cert)
:: 1) certreq creates + installs CN=ModernInjectorTestCert in the user store
:: 2) signtool signs every artifact from x64\Debug
setlocal
set BIN=%~dp0x64\Debug
set ST="C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe"

certreq -new "%~dp0code_signing.inf" "%BIN%\testcert.cer"
for %%F in ("ModernInjector.sys" "loader.exe" "testdll.dll") do (
  %ST% sign /fd SHA256 /n "ModernInjectorTestCert" /t http://timestamp.digicert.com "%BIN%\%%~F"
)
echo Cert installed in user store %USERNAME%. Install cere with: certutil -addstore -f Root + TrustedPublisher (admin).
