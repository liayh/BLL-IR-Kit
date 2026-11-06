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
while ($true) {
    $hook = (Read-Host 'URL de webhook pour les alertes (Teams, Slack, Discord, ntfy) - vide pour ignorer').Trim()
    if (-not $hook -or $hook -match '^https://[^\s]+$') { break }
    Write-Host 'Adresse refusee : elle doit commencer par https:// (les alertes contiennent des noms de postes et de comptes).' -ForegroundColor Yellow
}
if ($hook -match '(?i)ntfy') { Write-Host 'ntfy : un sujet public est lisible par quiconque connait son nom. Utilisez un nom long et aleatoire ou un serveur protege par mot de passe.' -ForegroundColor Yellow }
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
# Le script tourne en SYSTEM : personne d'autre que SYSTEM et les administrateurs ne doit pouvoir lire ou modifier ce dossier
# (sinon un simple utilisateur pourrait remplacer le script et prendre le controle du poste, ou lire le mot de passe SMTP).
# Un utilisateur peut creer C:\ProgramData\BLL AVANT l'installation et s'y donner des droits : ils sont donc tous effaces,
# les liens/jonctions sont refuses, et le resultat est verifie. SID plutot que noms : fonctionne sur un Windows en francais.
function Stop-Install { param([string]$m) Write-Host ('ERREUR : ' + $m + ' Installation annulee.') -ForegroundColor Red; Read-Host 'Entree pour fermer' | Out-Null; exit 1 }
$bll = Split-Path -Parent $dest
if (-not (Test-Path -LiteralPath $bll)) { New-Item -ItemType Directory -Path $bll -ErrorAction Stop | Out-Null }
$rp = @(@(Get-Item -LiteralPath $bll -Force) + @(Get-ChildItem -LiteralPath $bll -Recurse -Force -ErrorAction SilentlyContinue) | Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint })
if ($rp.Count -gt 0) { Stop-Install ('lien ou jonction suspect dans ' + $bll + ' : ' + ($rp[0].FullName) + '. Supprimez ce dossier puis relancez.') }
$null = & icacls.exe $bll /setowner '*S-1-5-32-544' /T /C /Q 2>&1
$null = & icacls.exe $bll /reset /T /C /Q 2>&1
$null = & icacls.exe $bll /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' /C /Q 2>&1
if ($LASTEXITCODE -ne 0) { Stop-Install ('impossible de proteger ' + $bll + '.') }
if (@(Get-ChildItem -LiteralPath $bll -Force).Count -gt 0) { $null = & icacls.exe (Join-Path $bll '*') /reset /T /C /Q 2>&1 }
New-Item -ItemType Directory -Path $dest -Force | Out-Null
function Test-AdminOnly {
    param([string]$Path)
    try {
        foreach ($r in (Get-Acl -LiteralPath $Path -ErrorAction Stop).GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
            if ($r.AccessControlType -eq 'Allow' -and $r.IdentityReference.Value -notin 'S-1-5-18', 'S-1-5-32-544') { return $false }
        }
        return $true
    } catch { return $false }
}
$bad = @(@(Get-Item -LiteralPath $bll -Force) + @(Get-ChildItem -LiteralPath $bll -Recurse -Force) | Where-Object { -not (Test-AdminOnly $_.FullName) })
if ($bad.Count -gt 0) { Stop-Install ($bll + ' reste accessible a d''autres comptes (' + $bad[0].FullName + ').') }
Copy-Item -LiteralPath (Join-Path $kit 'Surveillance\Surveiller.ps1') -Destination $dest -Force
if (Test-Path (Join-Path $kit 'config\autorises.txt')) { Copy-Item -LiteralPath (Join-Path $kit 'config\autorises.txt') -Destination (Join-Path $dest 'autorises.txt') -Force } else { Set-Content (Join-Path $dest 'autorises.txt') '# motifs autorises' }
$cfg = [ordered]@{ Site = $site; Webhook = @($hook | Where-Object { $_ }); Email = $mail; HeartbeatJours = 7 }
($cfg | ConvertTo-Json -Depth 5) | Set-Content -LiteralPath (Join-Path $dest 'alerte.json') -Encoding UTF8
try { if (-not [System.Diagnostics.EventLog]::SourceExists('BLL-Surveillance')) { New-EventLog -LogName Application -Source 'BLL-Surveillance' } } catch { }

$script = Join-Path $dest 'Surveiller.ps1'
$act = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ('-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "' + $script + '"')
$t1 = New-ScheduledTaskTrigger -AtStartup
$t2 = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(5) -RepetitionInterval (New-TimeSpan -Hours 4) -RepetitionDuration (New-TimeSpan -Days 3650)
$pri = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$set = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 30) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Unregister-ScheduledTask -TaskName 'BLL Surveillance' -Confirm:$false -ErrorAction SilentlyContinue
Register-ScheduledTask -TaskName 'BLL Surveillance' -Action $act -Trigger @($t1, $t2) -Principal $pri -Settings $set -Description 'Detecte les changements de securite et envoie une alerte' | Out-Null
if (-not (Get-ScheduledTask -TaskName 'BLL Surveillance' -ErrorAction SilentlyContinue)) {
    Write-Host 'ERREUR : la tache planifiee n''a pas pu etre creee. Surveillance NON installee.' -ForegroundColor Red
    Read-Host 'Entree pour fermer' | Out-Null; exit 1
}

Write-Host 'Creation de la reference (30 secondes environ)...'
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $script -Init
Write-Host 'Envoi d''une alerte de test...'
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $script -Test
Write-Host ''
Write-Host 'Surveillance installee : controle toutes les 4 h et au demarrage.' -ForegroundColor Green
Write-Host ('Dossier : ' + $dest + ' (journal_surveillance.log, autorises.txt, alerte.json)')
Write-Host ('Apres un changement legitime (en administrateur) : powershell -ExecutionPolicy Bypass -File "' + $script + '" -Init')
Read-Host 'Entree pour fermer' | Out-Null
