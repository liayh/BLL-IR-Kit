@echo off
rem BLL IR-Kit - point d'entree unique. Les droits administrateur ne sont demandes que si le choix l'exige.
setlocal
cd /d "%~dp0"
title BLL IR-Kit

:menu
cls
echo.
echo  BLL IR-Kit
echo  ==========
echo.
echo  1) Collecte de preuves      - incident en cours, sur le poste suspect   (administrateur)
echo  2) Audit de securite poste  - prevention, note sur 100                  (administrateur)
echo  3) Audit Microsoft 365      - depuis VOTRE poste, compte admin du tenant
echo  4) Installer la surveillance continue - sur un poste SAIN              (administrateur)
echo  5) Retirer la surveillance                                              (administrateur)
echo  0) Quitter
echo.
set "c="
set /p "c= Choix : "
if "%c%"=="1" ( call :admin "IR-Kit.ps1" & goto suite )
if "%c%"=="2" ( call :admin "Audit-Kit.ps1" & goto suite )
if "%c%"=="3" ( powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Audits\Audit-M365.ps1" -Menu & goto suite )
if "%c%"=="4" ( call :admin "Outils\Installer-Surveillance.ps1" & goto suite )
if "%c%"=="5" ( call :admin "Outils\Desinstaller-Surveillance.ps1" & goto suite )
if "%c%"=="0" exit /b 0
goto menu

:suite
rem fin d'une analyse : code 99 = l'utilisateur a choisi de fermer l'outil, sinon retour au menu
if errorlevel 99 exit /b 0
goto menu

:admin
rem Lance le script dans une fenetre administrateur, attend sa fin et renvoie son code de sortie.
rem Le chemin passe par une variable d'environnement : pas de probleme d'espaces ou d'apostrophes.
set "BLL_SCRIPT=%~dp0%~1"
powershell -NoProfile -Command "try { $p = Start-Process -FilePath powershell.exe -Verb RunAs -PassThru -ArgumentList ('-NoProfile -ExecutionPolicy Bypass -File \"' + $env:BLL_SCRIPT + '\" -Menu') -ErrorAction Stop; $null = $p.Handle; $p.WaitForExit(); exit [int]$p.ExitCode } catch { Write-Host ''; Write-Host ' Droits administrateur refuses : action annulee.' -ForegroundColor Yellow; Start-Sleep -Seconds 3; exit 0 }"
exit /b %errorlevel%
