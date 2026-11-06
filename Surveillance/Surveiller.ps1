<#
 BLL Surveillance - detecte les changements depuis une reference (baseline) et envoie une alerte.
 Lance par la tache planifiee installee par Outils\Installer-Surveillance.ps1
   -Init  : (re)cree la reference = etat actuel considere comme sain
   -Test  : envoie une alerte de test
#>
param([switch]$Init, [switch]$Test)
$ErrorActionPreference = 'SilentlyContinue'
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
$cfgPath = Join-Path $dir 'alerte.json'; $statePath = Join-Path $dir 'etat.json'
$logPath = Join-Path $dir 'journal_surveillance.log'; $allowPath = Join-Path $dir 'autorises.txt'
$now = (Get-Date).ToUniversalTime()

function Log { param([string]$m) try { Add-Content -LiteralPath $logPath -Value ('{0:yyyy-MM-dd HH:mm:ss}Z {1}' -f (Get-Date).ToUniversalTime(), $m) -Encoding UTF8 } catch { } }

$cfg = $null
if (Test-Path -LiteralPath $cfgPath) { try { $cfg = Get-Content -LiteralPath $cfgPath -Raw -Encoding UTF8 | ConvertFrom-Json } catch { } }
$site = $env:COMPUTERNAME; if ($cfg -and $cfg.Site) { $site = [string]$cfg.Site + ' / ' + $env:COMPUTERNAME }
$allow = @(); if (Test-Path -LiteralPath $allowPath) { $allow = @(Get-Content -LiteralPath $allowPath -Encoding UTF8 | ForEach-Object { $_.Trim() } | Where-Object { $_ -and -not $_.StartsWith('#') }) }

$toolsRx = '(?i)anydesk|teamviewer|splashtop|srserver|screenconnect|connectwise|rustdesk|ultraviewer|supremo|ammyy|tightvnc|ultravnc|realvnc|winvnc|radmin|logmein|gotoassist|meshagent|meshcentral|atera|ninjarmm|action1|zoho assist|dwservice|dwagent|nomachine|remoting_host|tailscale|zerotier|ngrok|cloudflared|frpc|chisel|psexec|paexec|mimikatz|lazagne|rclone|megasync|cobaltstrike|sliver'

function Get-Snapshot {
    $s = [ordered]@{}
    $s.service = @(Get-CimInstance Win32_Service | Where-Object { $_.PathName -and $_.PathName -notmatch '(?i)^"?[A-Z]:\\Windows\\(System32|SysWOW64)\\' } | ForEach-Object { $_.Name + ' | ' + $_.PathName })
    $s.tache = @(Get-ScheduledTask | Where-Object { $_.TaskPath -notmatch '^\\Microsoft\\' } | ForEach-Object { $a = ($_.Actions | ForEach-Object { ($_.Execute + ' ' + $_.Arguments).Trim() }) -join ' ; '; $_.TaskPath + $_.TaskName + ' | ' + $a })
    $run = @()
    $keys = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run')
    foreach ($sid in (Get-ChildItem Registry::HKEY_USERS | Where-Object { $_.PSChildName -match '^S-1-5-21-' -and $_.PSChildName -notmatch '_Classes$' })) { $keys += ('Registry::HKEY_USERS\' + $sid.PSChildName + '\Software\Microsoft\Windows\CurrentVersion\Run') }
    foreach ($k in $keys) { $p = Get-ItemProperty -LiteralPath $k; if ($p) { foreach ($n in $p.PSObject.Properties) { if ($n.Name -notmatch '^PS') { $run += ($k -replace '^.*\\(S-1-5-21-[^\\]+)\\.*$', '$1' -replace 'HKLM:\\SOFTWARE\\', '') + ' | ' + $n.Name + ' = ' + $n.Value } } } }
    $s.demarrage_registre = @($run)
    $st = @()
    foreach ($d in 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp') { $st += @(Get-ChildItem -LiteralPath $d -File -Force | ForEach-Object { $_.FullName }) }
    foreach ($u in (Get-ChildItem 'C:\Users' -Directory -Force)) { $st += @(Get-ChildItem -LiteralPath (Join-Path $u.FullName 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup') -File -Force | ForEach-Object { $_.FullName }) }
    $s.dossier_demarrage = @($st)
    # $null si illisible (compte orphelin...) : la reference precedente est alors conservee, sans fausse alerte
    $s.administrateur = $null
    try { $s.administrateur = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop | ForEach-Object { [string]$_.Name }) } catch { }
    $s.utilisateur_actif = @(Get-LocalUser | Where-Object { $_.Enabled } | ForEach-Object { $_.Name })
    $tools = @()
    foreach ($k in 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*') { $tools += @(Get-ItemProperty -Path $k | Where-Object { $_.DisplayName -match $toolsRx } | ForEach-Object { 'Installe : ' + $_.DisplayName }) }
    $tools += @(Get-Process | Where-Object { ($_.ProcessName + ' ' + $_.Path) -match $toolsRx } | ForEach-Object { 'Processus : ' + $_.ProcessName + ' (' + $_.Path + ')' } | Sort-Object -Unique)
    $s.outil_acces_distant = @($tools | Sort-Object -Unique)
    $s.logiciel = @(@(Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' | Where-Object { $_.DisplayName } | ForEach-Object { [string]$_.DisplayName }) | Sort-Object -Unique)
    $fw = @()
    $rk = Get-Item 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules'
    if ($rk) { foreach ($n in $rk.GetValueNames()) { $v = [string]$rk.GetValue($n); if ($v -match 'Active=TRUE' -and $v -match 'Dir=In' -and $v -match 'Action=Allow') { $app = ''; if ($v -match '\|App=([^|]+)\|') { $app = $Matches[1] }; $nm = $n; if ($v -match '\|Name=([^|]+)\|') { $nm = $Matches[1] }; if ($app) { $fw += ($nm + ' | ' + $app) } } } }
    $s.pare_feu_entrant_programme = @($fw | Sort-Object -Unique)
    $procs = @{}; Get-Process | ForEach-Object { $procs[[int]$_.Id] = $_.ProcessName }
    $s.port_en_ecoute = @(Get-NetTCPConnection -State Listen | Where-Object { $_.LocalAddress -notmatch '^(127\.|::1)' -and $_.LocalPort -lt 49152 } | ForEach-Object { [string]$_.LocalPort + '/' + $procs[[int]$_.OwningProcess] } | Sort-Object -Unique)
    $ex = @(); try { $mp = Get-MpPreference; $ex = @($mp.ExclusionPath) + @($mp.ExclusionProcess) + @($mp.ExclusionExtension) | Where-Object { $_ } } catch { }
    $s.exclusion_defender = @($ex)
    $s.portproxy = @((& netsh.exe interface portproxy show all 2>$null) | Where-Object { $_ -match '\d+\.\d+\.\d+\.\d+|\*' })
    $s.hosts = @(Get-Content -LiteralPath "$env:SystemRoot\System32\drivers\etc\hosts" | Where-Object { $_.Trim() -and -not $_.Trim().StartsWith('#') })
    $s.partage_smb = @(Get-SmbShare | Where-Object { -not $_.Special } | ForEach-Object { $_.Name + ' | ' + $_.Path })
    $rdp = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections
    $s.rdp = @($(if ($rdp -and $rdp.fDenyTSConnections -eq 0) { 'RDP active' } else { 'RDP desactive' }))
    # protections coupees (geste classique d'un attaquant avant chiffrement)
    $prot = @()
    try { $mp = Get-MpComputerStatus -ErrorAction Stop
        $prot += ('Defender protection temps reel : ' + $(if ($mp.RealTimeProtectionEnabled) { 'active' } else { 'DESACTIVEE' }))
        $prot += ('Defender protection anti-falsification : ' + $(if ($mp.IsTamperProtected) { 'active' } else { 'DESACTIVEE' })) } catch { }
    try { Get-NetFirewallProfile -ErrorAction Stop | ForEach-Object { $prot += ('Pare-feu profil ' + $_.Name + ' : ' + $(if ($_.Enabled) { 'active' } else { 'DESACTIVE' })) } } catch { }
    $s.protection = @($prot)
    return $s
}

$sevMap = @{ protection = 'ELEVE'; administrateur = 'ELEVE'; utilisateur_actif = 'ELEVE'; outil_acces_distant = 'ELEVE'; exclusion_defender = 'ELEVE'; portproxy = 'ELEVE'; hosts = 'ELEVE'; rdp = 'ELEVE'; service = 'MOYEN'; tache = 'MOYEN'; demarrage_registre = 'MOYEN'; dossier_demarrage = 'MOYEN'; pare_feu_entrant_programme = 'MOYEN'; partage_smb = 'MOYEN'; port_en_ecoute = 'FAIBLE'; logiciel = 'FAIBLE' }
$label = @{ protection = 'Protection coupee'; administrateur = 'Nouvel administrateur local'; utilisateur_actif = 'Nouveau compte local actif'; outil_acces_distant = 'Outil d''acces distant / d''attaque detecte'; exclusion_defender = 'Nouvelle exclusion Defender'; portproxy = 'Redirection de port (portproxy)'; hosts = 'Modification du fichier hosts'; rdp = 'Etat RDP modifie'; service = 'Nouveau service'; tache = 'Nouvelle tache planifiee'; demarrage_registre = 'Nouveau programme au demarrage (registre)'; dossier_demarrage = 'Nouveau fichier dans un dossier Demarrage'; pare_feu_entrant_programme = 'Nouvelle regle de pare-feu entrante'; partage_smb = 'Nouveau partage reseau'; port_en_ecoute = 'Nouveau port en ecoute'; logiciel = 'Nouveau logiciel installe' }

function Send-Alert {
    # renvoie $true si l'alerte est partie par au moins un canal (ou si aucun canal n'est configure)
    param([string]$Subject, [string]$Body)
    Log ('ALERTE : ' + $Subject)
    $canaux = 0; $ok = 0
    try { if (-not [System.Diagnostics.EventLog]::SourceExists('BLL-Surveillance')) { New-EventLog -LogName Application -Source 'BLL-Surveillance' }; Write-EventLog -LogName Application -Source 'BLL-Surveillance' -EntryType Warning -EventId 4100 -Message ($Body.Substring(0, [Math]::Min($Body.Length, 30000))) } catch { }
    if (-not $cfg) { return $true }
    foreach ($u in @($cfg.Webhook)) {
        if (-not $u) { continue }
        $canaux++
        if ($u -notmatch '^https://') { Log ('Webhook refuse (HTTPS obligatoire) : ' + $u); continue }
        try {
            $js = (@{ text = ($Subject + "`n" + $Body); content = ($Subject + "`n" + $Body) } | ConvertTo-Json)
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Invoke-RestMethod -Uri $u -Method Post -Body ([Text.Encoding]::UTF8.GetBytes($js)) -ContentType 'application/json; charset=utf-8' -TimeoutSec 20 | Out-Null
            $ok++
        } catch { Log ('Webhook en echec : ' + $_.Exception.Message) }
    }
    $m = $cfg.Email
    if ($m -and $m.Smtp -and $m.To) {
        $canaux++
        try {
            $p = @{ SmtpServer = $m.Smtp; Port = [int]$m.Port; From = $m.From; To = @($m.To); Subject = $Subject; Body = $Body; Encoding = [Text.Encoding]::UTF8 }
            if ($m.Ssl) { $p.UseSsl = $true }
            if ($m.User -and $m.PassProtegee) {
                Add-Type -AssemblyName System.Security
                $plain = [Text.Encoding]::UTF8.GetString([Security.Cryptography.ProtectedData]::Unprotect([Convert]::FromBase64String($m.PassProtegee), $null, 'LocalMachine'))
                $p.Credential = New-Object Management.Automation.PSCredential($m.User, (ConvertTo-SecureString $plain -AsPlainText -Force))
            }
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Send-MailMessage @p -ErrorAction Stop
            $ok++
        } catch { Log ('Mail en echec : ' + $_.Exception.Message) }
    }
    return (($canaux -eq 0) -or ($ok -gt 0))
}

# ------------------------------------------------------------------ test
if ($Test) {
    $r = Send-Alert ('[BLL] TEST de surveillance - ' + $site) ('Ceci est un message de test envoye le ' + $now.ToString('yyyy-MM-dd HH:mm') + ' UTC.')
    if ($r) { Write-Host 'Alerte de test envoyee. Verifiez sa reception.' -ForegroundColor Green; exit 0 }
    Write-Host ('ECHEC de l''envoi de l''alerte de test : voir ' + $logPath) -ForegroundColor Red; exit 3
}

$snap = Get-Snapshot
$state = $null
if (Test-Path -LiteralPath $statePath) { try { $state = Get-Content -LiteralPath $statePath -Raw -Encoding UTF8 | ConvertFrom-Json } catch { } }

$tvFile = 'C:\Program Files\TeamViewer\Connections_incoming.txt'
if (-not (Test-Path -LiteralPath $tvFile)) { $tvFile = 'C:\Program Files (x86)\TeamViewer\Connections_incoming.txt' }
$tvLines = 0; if (Test-Path -LiteralPath $tvFile) { $tvLines = @(Get-Content -LiteralPath $tvFile).Count }

# ------------------------------------------------------------------ init
if ($Init -or -not $state) {
    $o = [ordered]@{ Base = $snap; DerniereExecutionUtc = $now.ToString('o'); TvLignes = $tvLines; DernierRythme = $now.ToString('o') }
    ($o | ConvertTo-Json -Depth 6) | Set-Content -LiteralPath $statePath -Encoding UTF8
    Log 'Reference (baseline) creee.'
    Write-Host 'Reference creee : l''etat actuel est considere comme sain.'
    exit 0
}

if ($null -eq $snap['administrateur']) {
    Log 'Membres du groupe Administrateurs illisibles : reference precedente conservee.'
    $snap['administrateur'] = @($state.Base.administrateur)
}

$last = $now.AddHours(-6); try { $last = ([datetime]$state.DerniereExecutionUtc).ToUniversalTime() } catch { }
$alerts = New-Object System.Collections.Generic.List[object]
function Is-Allowed { param([string]$t) foreach ($rx in $allow) { try { if ($t -match $rx) { return $true } } catch { } }; return $false }

# 1. changements de configuration
foreach ($cat in $snap.Keys) {
    if ($state.Base.PSObject.Properties.Name -notcontains $cat) { continue }   # nouvelle categorie (mise a jour) : apprise sans alerte
    $baseItems = @($state.Base.$cat)
    $cur = @($snap[$cat])
    $new = @($cur | Where-Object { $_ -and ($baseItems -notcontains $_) -and -not (Is-Allowed $_) })
    if ($cat -eq 'protection') { $new = @($new | Where-Object { $_ -match 'DESACTIVE' }) }
    if ($cat -eq 'rdp' -or $cat -eq 'hosts') { if ($new.Count -gt 0) { $alerts.Add([pscustomobject]@{ Sev = $sevMap[$cat]; Txt = ($label[$cat] + ' : ' + ($new -join ' ; ')) }) } ; continue }
    foreach ($n in ($new | Select-Object -First 15)) { $alerts.Add([pscustomobject]@{ Sev = $sevMap[$cat]; Txt = ($label[$cat] + ' : ' + $n) }) }
    if ($new.Count -gt 15) { $alerts.Add([pscustomobject]@{ Sev = 'FAIBLE'; Txt = ($label[$cat] + ' : ' + ($new.Count - 15) + ' autres') }) }
}

# 2. evenements depuis la derniere execution
$since = $last.ToLocalTime()
function Ev { param($f) try { Get-WinEvent -FilterHashtable $f -MaxEvents 200 -ErrorAction Stop } catch { @() } }
foreach ($e in (Ev @{ LogName = 'Security'; Id = 1102; StartTime = $since })) { $alerts.Add([pscustomobject]@{ Sev = 'ELEVE'; Txt = ('Journal Securite efface le ' + $e.TimeCreated.ToUniversalTime().ToString('yyyy-MM-dd HH:mm') + ' UTC') }) }
foreach ($e in (Ev @{ LogName = 'System'; Id = 104; ProviderName = 'Microsoft-Windows-Eventlog'; StartTime = $since })) { $alerts.Add([pscustomobject]@{ Sev = 'ELEVE'; Txt = ('Journal Windows efface le ' + $e.TimeCreated.ToUniversalTime().ToString('yyyy-MM-dd HH:mm') + ' UTC') }) }
foreach ($e in (Ev @{ LogName = 'Security'; Id = 4720; StartTime = $since })) { $alerts.Add([pscustomobject]@{ Sev = 'ELEVE'; Txt = ('Compte cree le ' + $e.TimeCreated.ToUniversalTime().ToString('yyyy-MM-dd HH:mm') + ' UTC') }) }
foreach ($e in (Ev @{ LogName = 'Security'; Id = 4624; StartTime = $since })) {
    try {
        $x = [xml]$e.ToXml(); $d = @{}; foreach ($dd in $x.Event.EventData.Data) { $d[$dd.Name] = $dd.'#text' }
        if ($d['LogonType'] -eq '10' -and $d['IpAddress'] -notmatch '^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|::1|-$|\s*$)') {
            $alerts.Add([pscustomobject]@{ Sev = 'ELEVE'; Txt = ('Session RDP depuis une IP publique ' + $d['IpAddress'] + ' (compte ' + $d['TargetUserName'] + ') le ' + $e.TimeCreated.ToUniversalTime().ToString('yyyy-MM-dd HH:mm') + ' UTC') })
        }
    } catch { }
}
foreach ($e in (Ev @{ LogName = 'Microsoft-Windows-Windows Defender/Operational'; Id = 1116, 1117; StartTime = $since })) { $alerts.Add([pscustomobject]@{ Sev = 'MOYEN'; Txt = ('Defender : menace detectee ' + $e.TimeCreated.ToUniversalTime().ToString('yyyy-MM-dd HH:mm') + ' UTC') }) }

# 3. connexions entrantes AnyDesk / TeamViewer depuis la derniere execution
$adFiles = @('C:\ProgramData\AnyDesk\ad_svc.trace') + @(Get-ChildItem 'C:\Users' -Directory -Force | ForEach-Object { Join-Path $_.FullName 'AppData\Roaming\AnyDesk\ad.trace' })
foreach ($f in $adFiles) {
    if (-not (Test-Path -LiteralPath $f)) { continue }
    try {
        $fs = [IO.File]::Open($f, 'Open', 'Read', 'ReadWrite'); $len = [int][Math]::Min($fs.Length, 2MB)
        $null = $fs.Seek(-$len, 'End'); $b = New-Object byte[] $len; $null = $fs.Read($b, 0, $len); $fs.Dispose()
        $nul = 0; for ($i = 0; $i -lt [Math]::Min($len, 2000); $i++) { if ($b[$i] -eq 0) { $nul++ } }
        if ($nul -gt 400) { $t = [Text.Encoding]::Unicode.GetString($b) } else { $t = [Text.Encoding]::UTF8.GetString($b) }
        foreach ($m in [regex]::Matches($t, '(?m)^\s*\w+\s+(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)\.\d+\s+.*Accepting from (\d+)')) {
            $dt = [datetime]::ParseExact($m.Groups[1].Value, 'yyyy-MM-dd HH:mm:ss', [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal)
            $idd = $m.Groups[2].Value
            if ($dt -gt $last -and -not (Is-Allowed $idd)) { $alerts.Add([pscustomobject]@{ Sev = 'ELEVE'; Txt = ('Connexion AnyDesk ENTRANTE de l''ID ' + $idd + ' le ' + $dt.ToString('yyyy-MM-dd HH:mm:ss') + ' UTC') }) }
        }
    } catch { }
}
if ($tvLines -gt [int]$state.TvLignes) {
    $newTv = @(Get-Content -LiteralPath $tvFile | Select-Object -Last ($tvLines - [int]$state.TvLignes))
    foreach ($l in $newTv) { if (-not (Is-Allowed $l)) { $alerts.Add([pscustomobject]@{ Sev = 'MOYEN'; Txt = ('Connexion TeamViewer entrante : ' + ($l -replace "`t", ' | ')) }) } }
}

# 4. envoi
$sevOrder = @{ 'ELEVE' = 0; 'MOYEN' = 1; 'FAIBLE' = 2 }
$delivered = $true
$sorted = @($alerts | Sort-Object @{ Expression = { $sevOrder[$_.Sev] } })
$needSend = @($sorted | Where-Object { $_.Sev -ne 'FAIBLE' }).Count -gt 0
if ($sorted.Count -gt 0) {
    $body = ('Site : {0}' + "`n" + 'Date : {1} UTC' + "`n`n") -f $site, $now.ToString('yyyy-MM-dd HH:mm')
    foreach ($a in $sorted) { $body += ('[{0}] {1}' + "`n") -f $a.Sev, $a.Txt }
    $body += "`nSi ces changements sont normaux : ajoutez un motif dans autorises.txt ou relancez Surveiller.ps1 -Init."
    if ($needSend) { $nE = @($sorted | Where-Object { $_.Sev -eq 'ELEVE' }).Count; $delivered = Send-Alert ('[BLL] ALERTE securite - {0} ({1} critiques)' -f $site, $nE) $body } else { Log ('Changements mineurs : ' + (($sorted | ForEach-Object { $_.Txt }) -join ' ; ')) }
}

# 5. signe de vie hebdomadaire (l'absence de message signale une panne de surveillance)
$hbDays = 7; if ($cfg -and $cfg.HeartbeatJours -ne $null) { $hbDays = [int]$cfg.HeartbeatJours }
$lastHb = $now.AddDays(-365); try { $lastHb = ([datetime]$state.DernierRythme).ToUniversalTime() } catch { }
$hb = $state.DernierRythme
if ($hbDays -gt 0 -and ($now - $lastHb).TotalDays -ge $hbDays) {
    $null = Send-Alert ('[BLL] Surveillance active - ' + $site) ('Surveillance en fonctionnement. Dernier controle : ' + $now.ToString('yyyy-MM-dd HH:mm') + ' UTC. Changements ces derniers jours : voir journal_surveillance.log.')
    $hb = $now.ToString('o')
}

# 6. nouvelle reference = etat actuel (une alerte n'est envoyee qu'une fois)
#    si l'alerte n'a pu partir par aucun canal, on garde l'ancienne reference : elle sera renvoyee au prochain controle
if ($delivered) { $o = [ordered]@{ Base = $snap; DerniereExecutionUtc = $now.ToString('o'); TvLignes = $tvLines; DernierRythme = $hb } }
else {
    Log 'Alerte NON transmise (webhook/mail en echec) : elle sera renvoyee au prochain controle.'
    $o = [ordered]@{ Base = $state.Base; DerniereExecutionUtc = [string]$state.DerniereExecutionUtc; TvLignes = [int]$state.TvLignes; DernierRythme = $hb }
}
($o | ConvertTo-Json -Depth 6) | Set-Content -LiteralPath $statePath -Encoding UTF8
Log ('Controle termine : {0} changement(s).' -f $sorted.Count)
