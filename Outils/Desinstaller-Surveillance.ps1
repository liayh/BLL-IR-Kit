param([switch]$Menu)   # lance depuis BLL-IR-Kit.bat : proposer une autre action a la fin
$id = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $id.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { Write-Host 'Lancez en administrateur.' -ForegroundColor Red; exit 1 }
Unregister-ScheduledTask -TaskName 'BLL Surveillance' -Confirm:$false -ErrorAction SilentlyContinue
if ((Read-Host 'Supprimer aussi le dossier C:\ProgramData\BLL\Surveillance (journal, reference) ? (O/N)') -match '^[oOyY]') { Remove-Item -LiteralPath 'C:\ProgramData\BLL\Surveillance' -Recurse -Force -ErrorAction SilentlyContinue }
Write-Host 'Surveillance desinstallee.' -ForegroundColor Green
# lance depuis BLL-IR-Kit.bat (-Menu) : proposer une autre action ou fermer (code 99 = fermer l'outil)
if ($Menu) {
    Write-Host ''
    Write-Host ' Que voulez-vous faire ?' -ForegroundColor Cyan
    Write-Host '   1 (ou Entree) = autre test / autre action (retour au menu)'
    Write-Host '   0             = fermer BLL IR-Kit'
    if ("$(Read-Host ' Choix')".Trim() -eq '0') { exit 99 }
    exit 0
}
Read-Host 'Entree pour fermer' | Out-Null
