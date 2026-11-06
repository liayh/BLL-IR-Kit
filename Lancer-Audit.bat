@echo off
rem BLL Audit-Kit - lanceur (droits administrateur)
rem chemin passe par une variable d'environnement : fonctionne meme avec une apostrophe (ex. Jean d'Arc)
set "BLL_BAT=%~f0"
net session >nul 2>&1
if %errorlevel% neq 0 (
  powershell -NoProfile -Command "try { Start-Process -FilePath $env:BLL_BAT -Verb RunAs -ErrorAction Stop } catch { Write-Host ' Droits administrateur refuses.' -ForegroundColor Yellow; Start-Sleep -Seconds 3 }"
  exit /b
)
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Audit-Kit.ps1"
