$id = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $id.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { Write-Host 'Lancez en administrateur.' -ForegroundColor Red; exit 1 }
Unregister-ScheduledTask -TaskName 'BLL Surveillance' -Confirm:$false -ErrorAction SilentlyContinue
if ((Read-Host 'Supprimer aussi le dossier C:\ProgramData\BLL\Surveillance (journal, reference) ? (O/N)') -match '^[oOyY]') { Remove-Item -LiteralPath 'C:\ProgramData\BLL\Surveillance' -Recurse -Force -ErrorAction SilentlyContinue }
Write-Host 'Surveillance desinstallee.' -ForegroundColor Green
