@echo off
rem BLL Audit Microsoft 365 (lecture seule) - a lancer depuis le poste du technicien
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Audits\Audit-M365.ps1"
