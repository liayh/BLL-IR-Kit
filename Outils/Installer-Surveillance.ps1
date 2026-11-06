<#
 Installe la surveillance continue sur ce poste (copie dans C:\ProgramData\BLL\Surveillance + tache planifiee SYSTEM).
 A lancer sur un poste SAIN, en administrateur. Demande : nom du site, webhook (Teams/Slack/Discord/ntfy) et/ou mail.
#>
$id = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $id.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { Write-Host 'Lancez en administrateur.' -ForegroundColor Red; exit 1 }
$kit = Split-Path -Parent $PSScriptRoot
$dest = 'C:\ProgramData\BLL\Surveillance'
Write-Host ''
Write-Host 'Installation de la surveillance BLL' -ForegroundColor Cyan
Write-Host 'Ce poste doit etre considere comme SAIN : son etat actuel devient la reference.' -ForegroundColor Yellow
if ((Read-Host 'Taper OUI pour continuer') -ne 'OUI') { exit 0 }

$site = Read-Host 'Nom de la pharmacie / du site (ex. Pharmacie X Angers)'
$hook = Read-Host 'URL de webhook pour les alertes (Teams, Slack, Discord, ntfy) - vide pour ignorer'
$mail = $null
if ((Read-Host 'Configurer aussi l''envoi par mail ? (O/N)') -match '^[oOyY]') {
    $smtp = Read-Host 'Serveur SMTP (ex. smtp.office365.com)'; $port = Read-Host 'Port (ex. 587)'
    $from = Read-Host 'Adresse expediteur'; $to = Read-Host 'Adresse(s) destinataire (separees par une virgule)'
    $user = Read-Host 'Utilisateur SMTP (vide si aucun)'; $prot = ''
    if ($user) {
        $sec = Read-Host 'Mot de passe SMTP (de preference un mot de passe d''application)' -AsSecureString
        $plain = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec))
        Add-Type -AssemblyName System.Security
        $prot = [Convert]::ToBase64String([Security.Cryptography.ProtectedData]::Protect([Text.Encoding]::UTF8.GetBytes($plain), $null, 'LocalMachine'))
    }
    $mail = [ordered]@{ Smtp = $smtp; Port = [int]$port; Ssl = $true; From = $from; To = @($to -split '\s*,\s*'); User = $user; PassProtegee = $prot }
}
New-Item -ItemType Directory -Path $dest -Force | Out-Null
Copy-Item -LiteralPath (Join-Path $kit 'Surveillance\Surveiller.ps1') -Destination $dest -Force
if (Test-Path (Join-Path $kit 'config\autorises.txt')) { Copy-Item -LiteralPath (Join-Path $kit 'config\autorises.txt') -Destination (Join-Path $dest 'autorises.txt') -Force } else { Set-Content (Join-Path $dest 'autorises.txt') '# motifs autorises' }
$cfg = [ordered]@{ Site = $site; Webhook = @($hook | Where-Object { $_ }); Email = $mail; HeartbeatJours = 7 }
($cfg | ConvertTo-Json -Depth 5) | Set-Content -LiteralPath (Join-Path $dest 'alerte.json') -Encoding UTF8
# seuls SYSTEM et les administrateurs peuvent modifier ce dossier
& icacls.exe $dest /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'BUILTIN\Administrators:(OI)(CI)F' 'BUILTIN\Users:(OI)(CI)RX' | Out-Null
try { if (-not [System.Diagnostics.EventLog]::SourceExists('BLL-Surveillance')) { New-EventLog -LogName Application -Source 'BLL-Surveillance' } } catch { }

$script = Join-Path $dest 'Surveiller.ps1'
$act = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ('-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "' + $script + '"')
$t1 = New-ScheduledTaskTrigger -AtStartup
$t2 = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(5) -RepetitionInterval (New-TimeSpan -Hours 4) -RepetitionDuration (New-TimeSpan -Days 3650)
$pri = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$set = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 30) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Unregister-ScheduledTask -TaskName 'BLL Surveillance' -Confirm:$false -ErrorAction SilentlyContinue
Register-ScheduledTask -TaskName 'BLL Surveillance' -Action $act -Trigger @($t1, $t2) -Principal $pri -Settings $set -Description 'Detecte les changements de securite et envoie une alerte' | Out-Null

Write-Host 'Creation de la reference (30 secondes environ)...'
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $script -Init
Write-Host 'Envoi d''une alerte de test...'
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $script -Test
Write-Host ''
Write-Host 'Surveillance installee : controle toutes les 4 h et au demarrage.' -ForegroundColor Green
Write-Host ('Dossier : ' + $dest + ' (journal_surveillance.log, autorises.txt, alerte.json)')
Write-Host 'Apres un changement legitime : powershell -File "' $script '" -Init'
Read-Host 'Entree pour fermer' | Out-Null
