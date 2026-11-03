@echo off
:: ===== CLEANUP — eseguire come Amministratore =====
:: Rimuove servizio driver, certificati di test, C:\KMI e disattiva test signing.

echo [1/4] Rimuovi il servizio driver...
sc stop ModernInjector >nul 2>&1
sc delete ModernInjector >nul 2>&1

echo [2/4] Rimuovi i certificati di test dai store Root e TrustedPublisher...
certutil -delstore Root ModernInjectorTestCert >nul 2>&1
certutil -delstore TrustedPublisher ModernInjectorTestCert >nul 2>&1

echo [3/4] Rimuovi la formula C:\KMI...
if exist C:\KMI rmdir /s /q C:\KMI

echo [4/4] Disattiva test signing (verra' effettivo al prossimo riavvio)...
bcdedit /set testsigning off
echo.
echo COMPLETATO. Riavvia il PC per rendere effettive le modifiche.
pause
