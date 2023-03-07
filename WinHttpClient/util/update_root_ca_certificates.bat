@cd /d "%~dp0"
@call powershell.exe -ExecutionPolicy Bypass ^
  ./update_root_ca_certificates.ps1 trusted_root_ca_certificates.txt
@if ERRORLEVEL 1 (
  type trusted_root_ca_certificates.txt
  del  trusted_root_ca_certificates.txt
)
@exit /b
