# Collecte2.ps1 - execution, journaux, reseau, fichiers, copies de preuves

function Test-Broad { return ((($script:WinE - $script:WinS).TotalDays) -gt 3) }

# ---------------------------------------------------------------------------
# TRACES D'EXECUTION : Prefetch (8 dernieres executions), BAM, UserAssist, RunMRU, fichiers recents
# ---------------------------------------------------------------------------
function Mod-Execution {
    $pfDir = 'C:\Windows\Prefetch'
    $rows = New-Object System.Collections.Generic.List[object]
    if (Test-Path -LiteralPath $pfDir) {
        Get-ChildItem -LiteralPath $pfDir -Filter '*.pf' -Force | ForEach-Object {
            $r = $null
            try { $r = Read-Prefetch $_.FullName } catch { }
            $runs = @(); $nb = ''
            if ($r) { $runs = @($r.Executions); $nb = $r.NbExecutions }
            $inWin = $false
            foreach ($x in $runs) { if (InWindow $x) { $inWin = $true } }
            if (-not $r -and ((InWindow $_.LastWriteTimeUtc) -or (InWindow $_.CreationTimeUtc))) { $inWin = $true }
            $rows.Add([pscustomobject]@{
                Programme = $_.Name; NbExecutions = $nb
                DerniereExecUtc = $(if ($runs.Count -gt 0) { U $runs[0] } else { U $_.LastWriteTimeUtc })
                PremiereTraceUtc = (U $_.CreationTimeUtc)
                Dernieres8ExecUtc = (($runs | ForEach-Object { U $_ }) -join ' ; ')
                DansFenetre = $inWin
            })
        }
        Add-CopyJob -Source $pfDir -Dest 'prefetch' -Filter @('*.pf')
    }
    $null = Save-Csv ($rows | Sort-Object DerniereExecUtc -Descending) 'prefetch.csv' '04_execution'
    $inw = @($rows | Where-Object { $_.DansFenetre } | Sort-Object DerniereExecUtc)
    $null = Save-Csv $inw 'programmes_executes_dans_la_fenetre.csv' '04_execution'
    Say ("   Prefetch : {0} programmes, {1} executes dans la fenetre" -f $rows.Count, $inw.Count)
    $lolRx = '(?i)^(POWERSHELL|PWSH|CMD|WSCRIPT|CSCRIPT|MSHTA|CERTUTIL|BITSADMIN|REGSVR32|RUNDLL32|SCHTASKS|WMIC|NET1?|REG|SC|NETSH|ICACLS|TAKEOWN|VSSADMIN|WEVTUTIL|WINRAR|7Z|7ZG|RCLONE)\.EXE-'
    foreach ($p in $inw) {
        $tool = Get-OutilNom $p.Programme
        if ($p.Programme -match $lolRx) {
            Add-Finding 'FAIBLE' 'Execution' ("Programme systeme sensible execute dans la fenetre : {0}" -f ($p.Programme -replace '-[0-9A-F]{8}\.pf$', '')) '' $p.Dernieres8ExecUtc
        } elseif ($tool) {
            Add-Finding 'MOYEN' 'Execution' ("{0} execute dans la fenetre : {1}" -f $tool, ($p.Programme -replace '-[0-9A-F]{8}\.pf$', '')) '' $p.Dernieres8ExecUtc
        }
    }
    foreach ($p in $rows) {
        if ((Get-OutilNom $p.Programme) -eq 'Outils d attaque' -or $p.Programme -match '(?i)^(MIMIKATZ|PSEXEC|PSEXEC64|PROCDUMP|PROCDUMP64|RCLONE|LAZAGNE|NETSCAN|ADVANCED_IP_SCANNER)') {
            Add-Finding 'ELEVE' 'Execution' ("Trace d'execution d'un outil d'attaque : {0}" -f $p.Programme) '' ('Dernieres executions : ' + $p.Dernieres8ExecUtc)
        }
    }

    # BAM
    $bam = New-Object System.Collections.Generic.List[object]
    foreach ($base in 'HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings', 'HKLM:\SYSTEM\CurrentControlSet\Services\bam\UserSettings') {
        Get-ChildItem $base | ForEach-Object {
            $sid = $_.PSChildName; $k = Get-Item -LiteralPath $_.PSPath
            foreach ($n in $k.GetValueNames()) {
                $v = $k.GetValue($n)
                if ($v -is [byte[]] -and $v.Length -ge 8) {
                    $t = ConvertFrom-FileTimeSafe ([BitConverter]::ToUInt64($v, 0))
                    if ($t) { $bam.Add([pscustomobject]@{ SID = $sid; Chemin = $n; DerniereExecUtc = (U $t); DansFenetre = (InWindow $t) }) }
                }
            }
        }
    }
    $null = Save-Csv ($bam | Sort-Object DerniereExecUtc -Descending) 'bam_derniere_execution.csv' '04_execution'
    foreach ($b in ($bam | Where-Object { $_.DansFenetre -and (Test-RiskPath $_.Chemin) })) {
        Add-Finding 'MOYEN' 'Execution' 'Programme lance depuis un dossier a risque (BAM)' $b.Chemin $b.DerniereExecUtc
    }

    # UserAssist
    $ua = New-Object System.Collections.Generic.List[object]
    foreach ($sid in [Microsoft.Win32.Registry]::Users.GetSubKeyNames() | Where-Object { $_ -match $script:UserSidRx }) {
        Get-ChildItem "Registry::HKEY_USERS\$sid\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist" | ForEach-Object {
            $cnt = Get-Item -LiteralPath ($_.PSPath + '\Count')
            if ($cnt) {
                foreach ($n in $cnt.GetValueNames()) {
                    $v = $cnt.GetValue($n)
                    if ($v -is [byte[]] -and $v.Length -ge 68) {
                        $t = ConvertFrom-FileTimeSafe ([BitConverter]::ToUInt64($v, 60))
                        if ($t) {
                            $name = -join ($n.ToCharArray() | ForEach-Object { $c = [int]$_; if ($c -ge 65 -and $c -le 90) { [char]((($c - 65 + 13) % 26) + 65) } elseif ($c -ge 97 -and $c -le 122) { [char]((($c - 97 + 13) % 26) + 97) } else { $_ } })
                            $ua.Add([pscustomobject]@{ SID = $sid; Programme = $name; DerniereExecUtc = (U $t); DansFenetre = (InWindow $t) })
                        }
                    }
                }
            }
        }
    }
    $null = Save-Csv ($ua | Sort-Object DerniereExecUtc -Descending) 'userassist.csv' '04_execution'

    # Commandes tapees dans Executer (RunMRU) et fichiers recents
    $mru = New-Object System.Collections.Generic.List[object]
    foreach ($sid in [Microsoft.Win32.Registry]::Users.GetSubKeyNames() | Where-Object { $_ -match $script:UserSidRx }) {
        $k = Get-Item -LiteralPath "Registry::HKEY_USERS\$sid\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"
        if ($k) { foreach ($n in $k.GetValueNames()) { if ($n -ne 'MRUList') { $mru.Add([pscustomobject]@{ SID = $sid; Commande = [string]$k.GetValue($n) }) } } }
    }
    $null = Save-Csv $mru 'commandes_executer_runmru.csv' '04_execution'
    $recent = New-Object System.Collections.Generic.List[object]
    $wsh = $null; try { $wsh = New-Object -ComObject WScript.Shell } catch { }
    foreach ($pr in (Get-UserProfiles)) {
        $rd = Join-Path $pr.FullName 'AppData\Roaming\Microsoft\Windows\Recent'
        Get-ChildItem -LiteralPath $rd -Filter '*.lnk' -File -Force -ErrorAction SilentlyContinue | Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 400 | ForEach-Object {
            $target = ''
            if ($wsh) { try { $target = $wsh.CreateShortcut($_.FullName).TargetPath } catch { } }
            $recent.Add([pscustomobject]@{ Utilisateur = $pr.Name; Element = $_.Name; Cible = $target; PremiereOuvertureUtc = (U $_.CreationTimeUtc); DerniereOuvertureUtc = (U $_.LastWriteTimeUtc); DansFenetre = (InWindow $_.LastWriteTimeUtc) })
        }
    }
    $null = Save-Csv ($recent | Sort-Object DerniereOuvertureUtc -Descending) 'fichiers_recents_ouverts.csv' '04_execution'

    # Cles de registre modifiees dans la fenetre
    if ($script:Mode -eq 'Complet' -or -not $script:WinDefault) {
        Say '   Registre : dates de modification des cles (1 a 3 minutes)...'
        $res = New-Object 'System.Collections.Generic.List[string]'
        $lo = $script:WinS.ToFileTimeUtc(); $hi = $script:WinE.ToFileTimeUtc()
        $k1 = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SOFTWARE'); if ($k1) { [RegWalk]::Walk($k1, 'HKLM\SOFTWARE', $lo, $hi, $res) }
        $k2 = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SYSTEM\ControlSet001'); if ($k2) { [RegWalk]::Walk($k2, 'HKLM\SYSTEM\ControlSet001', $lo, $hi, $res) }
        foreach ($sub in [Microsoft.Win32.Registry]::Users.GetSubKeyNames()) { $ku = [Microsoft.Win32.Registry]::Users.OpenSubKey($sub); if ($ku) { [RegWalk]::Walk($ku, "HKU\$sub", $lo, $hi, $res) } }
        $regRows = $res | Sort-Object | ForEach-Object { $p = $_ -split "`t", 2; [pscustomobject]@{ ModifieUtc = $p[0]; Cle = $p[1] } }
        $null = Save-Csv $regRows 'registre_cles_modifiees_fenetre.csv' '04_execution'
        $hot = @($regRows | Where-Object { $_.Cle -match 'Exclusions|PortProxy|Image File Execution|Terminal Server|Winlogon|\\Run$|\\RunOnce$|Schedule\\TaskCache\\Tasks|Policies\\Microsoft\\Windows Defender|WinRM' })
        $null = Save-Csv $hot 'registre_cles_sensibles_modifiees.csv' '04_execution'
        if (-not (Test-Broad)) { foreach ($h in ($hot | Select-Object -First 30)) { Add-Finding 'MOYEN' 'Registre' ('Cle sensible modifiee dans la fenetre : ' + $h.Cle) '' $h.ModifieUtc } }
    }
}

# ---------------------------------------------------------------------------
# JOURNAUX D'EVENEMENTS : couverture, evenements cles, export .evtx
# ---------------------------------------------------------------------------
function Mod-Journaux {
    $broad = Test-Broad
    $locS = $script:WinS.ToLocalTime(); $locE = $script:WinE.ToLocalTime()
    $cov = New-Object System.Collections.Generic.List[object]
    $all = New-Object System.Collections.Generic.List[object]
    $conn = New-Object System.Collections.Generic.List[object]
    $frequentIds = 4624, 4625, 4648, 4672, 4776, 4778, 4779
    $noisy = 5038, 5156, 5158, 5157, 5152, 5153, 4663, 4656, 4658, 4690, 4703, 4670
    $keyIds = @{
        'Security' = 1102, 4624, 4625, 4648, 4672, 4697, 4698, 4699, 4700, 4701, 4702, 4720, 4722, 4723, 4724, 4725, 4726, 4728, 4732, 4740, 4756, 4776, 4778, 4779
        'System' = 104, 41, 1074, 6005, 6006, 6008, 7030, 7034, 7040, 7045
        'Application' = 1000, 1001, 1033, 11707, 11724
        'Microsoft-Windows-PowerShell/Operational' = 4104
        'Windows PowerShell' = 400, 403, 600
        'Microsoft-Windows-TaskScheduler/Operational' = 106, 140, 141, 200, 201
        'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational' = 21, 22, 23, 24, 25, 39, 40
        'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational' = 1149
        'Microsoft-Windows-Windows Defender/Operational' = 1006, 1007, 1008, 1009, 1116, 1117, 1118, 1119, 5001, 5007, 5010, 5012
        'Microsoft-Windows-WMI-Activity/Operational' = 5857, 5858, 5859, 5860, 5861
        'Microsoft-Windows-Bits-Client/Operational' = 3, 59, 60, 61
        'Microsoft-Windows-WinRM/Operational' = 91, 168
        'Microsoft-Windows-SMBServer/Security' = 551, 1006
    }
    # regles par journal : un meme numero d'evenement n'a pas le meme sens d'un journal a l'autre
    $lSec = 'Security'; $lSys = 'System'; $lDef = 'Microsoft-Windows-Windows Defender/Operational'
    $rules = @{
        "$lSec|1102" = @('ELEVE', 'Journal Securite efface'); "$lSys|104" = @('ELEVE', 'Journal efface'); "$lSec|4720" = @('ELEVE', 'Compte cree')
        "$lSec|4722" = @('MOYEN', 'Compte active'); "$lSec|4724" = @('MOYEN', 'Mot de passe reinitialise'); "$lSec|4732" = @('MOYEN', 'Ajout a un groupe local')
        "$lSec|4728" = @('MOYEN', 'Ajout a un groupe global'); "$lSec|4756" = @('MOYEN', 'Ajout a un groupe universel'); "$lSec|4697" = @('MOYEN', 'Service installe (Securite)')
        "$lSys|7045" = @('MOYEN', 'Nouveau service installe'); "$lSec|4698" = @('MOYEN', 'Tache planifiee creee'); "$lSec|4702" = @('FAIBLE', 'Tache planifiee modifiee')
        'Microsoft-Windows-WMI-Activity/Operational|5861' = @('MOYEN', 'Abonnement WMI permanent')
        "$lDef|1116" = @('MOYEN', 'Defender : menace detectee'); "$lDef|1117" = @('MOYEN', 'Defender : action sur menace')
        "$lDef|5007" = @('FAIBLE', 'Defender : configuration modifiee'); "$lDef|5010" = @('MOYEN', 'Defender : analyse desactivee'); "$lDef|5012" = @('MOYEN', 'Defender : analyse desactivee')
        'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational|1149' = @('FAIBLE', 'RDP : authentification reussie')
        "$lSys|1074" = @('INFO', 'Arret/redemarrage demande'); "$lSys|6008" = @('FAIBLE', 'Arret inattendu')
        'Microsoft-Windows-TaskScheduler/Operational|106' = @('FAIBLE', 'Tache planifiee enregistree'); 'Microsoft-Windows-Bits-Client/Operational|59' = @('MOYEN', 'Job BITS cree')
        'Microsoft-Windows-PowerShell/Operational|4104' = @('INFO', 'Script PowerShell')
    }
    $counters = @{}
    # adresses privees : RFC1918, lien local, CGNAT/Tailscale (100.64/10), IPv6 locales (fc00::/7, fe80::), IPv4 mappee ::ffff:
    $privRx = '^(::ffff:)?(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|::1|f[cd][0-9a-f]{2}:|fe80|-$|\s*$)'
    Get-WinEvent -ListLog * -ErrorAction SilentlyContinue | Where-Object { $_.RecordCount -gt 0 } | ForEach-Object {
        $ln = $_.LogName
        $old = Get-WinEvent -LogName $ln -Oldest -MaxEvents 1 -ErrorAction SilentlyContinue
        $oldU = $null; if ($old) { $oldU = $old.TimeCreated.ToUniversalTime() }
        $cov.Add([pscustomobject]@{ Journal = $ln; Enregistrements = $_.RecordCount; TailleMo = [math]::Round($_.FileSize / 1MB, 1); PlusAncienUtc = (U $oldU); CouvreLaFenetre = $(if ($oldU) { $oldU -le $script:WinS } else { $false }) })
        if ($ln -in 'Security', 'System', 'Microsoft-Windows-PowerShell/Operational') {
            if ($oldU -and $oldU -gt $script:WinS) { Add-Finding 'MOYEN' 'Couverture des journaux' ("Le journal {0} ne remonte qu'au {1} UTC : il ne couvre pas le debut de la fenetre analysee" -f $ln, (U $oldU)) '' 'Absence de trace dans ce journal ne prouve rien' }
        }
        if ($broad -and -not $keyIds.ContainsKey($ln)) { return }
        # Windows refuse un filtre de plus de 23 numeros d'evenement ("requete invalide") :
        # les numeros sont donc demandes par lots de 20 (le journal Securite en compte 24).
        $idSets = New-Object System.Collections.Generic.List[object]
        # Les evenements frequents (ouvertures de session...) sont demandes a part : sinon ils rempliraient la limite
        # de 60000 et feraient disparaitre les evenements rares et importants (journal efface, compte cree...).
        if ($broad) {
            $ids = @($keyIds[$ln])
            $freq = @($ids | Where-Object { $_ -in $frequentIds })
            $rare = @($ids | Where-Object { $_ -notin $frequentIds })
            foreach ($grp in @(, $rare) + @(, $freq)) {
                for ($i = 0; $i -lt $grp.Count; $i += 20) { $idSets.Add(@($grp[$i..([Math]::Min($i + 19, $grp.Count - 1))])) }
            }
        } else { $idSets.Add($null) }
        $events = New-Object System.Collections.Generic.List[object]
        foreach ($set in $idSets) {
            $filter = @{ LogName = $ln; StartTime = $locS; EndTime = $locE }
            if ($set) { $filter.Id = $set }
            try {
                $got = @(Get-WinEvent -FilterHashtable $filter -MaxEvents 60000 -ErrorAction Stop)
                foreach ($ev in $got) { $events.Add($ev) }
                if ($got.Count -ge 60000) { Add-Finding 'MOYEN' 'Couverture des journaux' ("Journal {0} : limite de 60000 evenements atteinte, les plus anciens de la fenetre ne sont pas analyses" -f $ln) '' ('ID : ' + (@($set) -join ',')) }
            }
            catch {
                # "aucun evenement" est normal ; toute autre erreur sur un journal cle est signalee
                if ($_.FullyQualifiedErrorId -notmatch 'NoMatchingEventsFound' -and $keyIds.ContainsKey($ln)) { $script:Errors.Add('Journal ' + $ln + ' : ' + $_.Exception.Message) }
            }
        }
        foreach ($e in $events) {
            if ($e.Id -in $noisy -and $ln -eq 'Security') { continue }
            $fullMsg = ([string]$e.Message) -replace '\s+', ' '
            $msg = $fullMsg; if ($msg.Length -gt 350) { $msg = $msg.Substring(0, 350) }
            $t = U $e.TimeCreated
            $all.Add([pscustomobject]@{ TempsUtc = $t; Journal = $ln; Id = $e.Id; Source = $e.ProviderName; Message = $msg })
            if ($ln -eq 'Security' -and ($e.Id -eq 4624 -or $e.Id -eq 4625 -or $e.Id -eq 4648)) {
                $x = $null; try { $x = [xml]$e.ToXml() } catch { }
                if ($x) {
                    $d = @{}; foreach ($dd in $x.Event.EventData.Data) { $d[$dd.Name] = $dd.'#text' }
                    $lt = $d['LogonType']
                    if ($e.Id -ne 4624 -or $lt -in '3', '7', '10', '11') {
                        $conn.Add([pscustomobject]@{ TempsUtc = $t; Id = $e.Id; TypeLogon = $lt; Compte = $d['TargetUserName']; Domaine = $d['TargetDomainName']; IpSource = $d['IpAddress']; Poste = $d['WorkstationName']; Processus = $d['ProcessName'] })
                        if ($e.Id -eq 4624 -and $lt -eq '10') {
                            $sev = 'FAIBLE'; if ($d['IpAddress'] -notmatch $privRx) { $sev = 'ELEVE' }
                            Add-Finding $sev 'Connexion RDP' ("Ouverture de session RDP {0} par {1} depuis {2}" -f $t, $d['TargetUserName'], $d['IpAddress']) '' 'Heure UTC'
                            if ($d['IpAddress'] -notmatch $privRx) { Add-IocSeen 'Adresse IP (RDP)' $d['IpAddress'] 'Journal Securite 4624' $t $d['TargetUserName'] }
                        }
                    }
                }
                continue
            }
            $id = [string]$e.Id
            $rk = $ln + '|' + $id
            if (($id -eq '104' -or $id -eq '1102') -and $e.ProviderName -ne 'Microsoft-Windows-Eventlog') { continue }
            if ($rules.ContainsKey($rk)) {
                if ($id -eq '4104') { if ($fullMsg -notmatch '(?i)-enc\b|frombase64string|downloadstring|downloadfile|invoke-expression|\biex\b|net\.webclient|-executionpolicy\s+bypass|-w(indowstyle)?\s+hidden|invoke-webrequest|start-bitstransfer' -or $fullMsg -match '__cmdletization|BLL IR-Kit|Mod-Journaux|Invoke-Module|Add-Finding|Say \(') { continue } }
                $sev = $rules[$rk][0]
                if ($id -eq '5007' -and $msg -notmatch '(?i)Exclusions|DisableAntiSpyware|DisableRealtimeMonitoring|DisableBehaviorMonitoring|DisableIOAVProtection|TamperProtection|DisableScriptScanning = 0x1|SubmitSamplesConsent') { continue }
                if ($id -eq '59') {
                    if ($msg -match '(?i)https?://[^/\s]*(microsoft|windowsupdate|office|live\.com|dell\.com|google|gvt1|adobe|intel|hp\.com|lenovo|nvidia|mozilla|foxit|teamviewer)') { $sev = 'INFO' }
                }
                if ($id -in '4732', '4728', '4756' -and $msg -match '(?i)Administrators|Administrateurs|S-1-5-32-544') { $sev = 'ELEVE' }
                if ($id -eq '4104') { $sev = 'ELEVE' }
                if ($id -eq '1149' -and $msg -match '(\d{1,3}\.){3}\d{1,3}' -and $Matches[0] -notmatch $privRx) { $sev = 'ELEVE' }
                if (-not $counters.ContainsKey($rk)) { $counters[$rk] = 0 }
                $counters[$rk]++
                if ($counters[$rk] -le 25) { Add-Finding $sev 'Journal Windows' ("{0} : {1} (ID {2}, {3})" -f $t, $rules[$rk][1], $e.Id, $ln) '' $msg }
            }
        }
    }
    $null = Save-Csv ($cov | Sort-Object Journal) 'couverture_des_journaux.csv' '06_journaux'
    $null = Save-Csv ($all | Sort-Object TempsUtc) $(if ($broad) { 'evenements_cles_periode.csv' } else { 'evenements_fenetre_tous.csv' }) '06_journaux'
    $null = Save-Csv ($conn | Sort-Object TempsUtc) 'connexions_comptes_4624_4625.csv' '06_journaux'
    foreach ($k in $counters.Keys) { if ($counters[$k] -gt 25) { Add-Finding 'INFO' 'Journal Windows' ("Evenement {0} : {1} occurrences au total (25 premieres listees)" -f ($k -replace '^(.*)\|(\d+)$', '$2 ($1)'), $counters[$k]) } }
    $fails = @($conn | Where-Object { $_.Id -eq 4625 } | Group-Object IpSource | Where-Object { $_.Count -ge 10 -and $_.Name -notmatch $privRx })
    foreach ($f in $fails) { Add-Finding 'ELEVE' 'Connexion RDP' ("{0} echecs d'authentification depuis l'IP publique {1}" -f $f.Count, $f.Name); Add-IocSeen 'Adresse IP (echecs 4625)' $f.Name 'Journal Securite' '' ([string]$f.Count + ' echecs') }
    if (-not ($cov | Where-Object { $_.Journal -match 'Sysmon' })) { Add-Finding 'INFO' 'Journalisation' 'Sysmon absent : pas de trace detaillee des processus, connexions et fichiers' }

    # Export des journaux .evtx (copie coherente via wevtutil)
    $evtxDir = Join-Path $script:Raw 'evtx'
    $null = New-Item -ItemType Directory -Path $evtxDir -Force
    foreach ($l in 'System', 'Application', 'Security', 'Windows PowerShell', 'Microsoft-Windows-PowerShell/Operational', 'Microsoft-Windows-TaskScheduler/Operational',
        'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational', 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational',
        'Microsoft-Windows-Bits-Client/Operational', 'Microsoft-Windows-WMI-Activity/Operational', 'Microsoft-Windows-Windows Defender/Operational',
        'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall', 'Microsoft-Windows-WinRM/Operational', 'Microsoft-Windows-SMBServer/Security') {
        $f = Join-Path $evtxDir (($l -replace '[\\/ ]', '_') + '.evtx')
        & wevtutil.exe epl "$l" "$f" 2>$null
    }
}

# ---------------------------------------------------------------------------
# RESEAU
# ---------------------------------------------------------------------------
function Mod-Reseau {
    $privRx = '^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.|::1|fe80|0\.0\.0\.0|::$|224\.|239\.|255\.)'
    $procs = @{}
    Get-CimInstance Win32_Process | ForEach-Object { $procs[[int]$_.ProcessId] = $_ }
    $rows = New-Object System.Collections.Generic.List[object]
    Get-NetTCPConnection | Where-Object { $_.State -in 'Established', 'Listen' } | ForEach-Object {
        $p = $procs[[int]$_.OwningProcess]
        $exe = ''; $nm = ''; if ($p) { $exe = $p.ExecutablePath; $nm = $p.Name }
        $outil = Get-OutilNom ($nm + ' ' + $exe)
        $sig = Get-SignInfo $exe
        $rows.Add([pscustomobject]@{ Etat = $_.State; Local = ('{0}:{1}' -f $_.LocalAddress, $_.LocalPort); Distant = ('{0}:{1}' -f $_.RemoteAddress, $_.RemotePort); PID = $_.OwningProcess; Processus = $nm; Chemin = $exe; Signature = $(if ($sig) { $sig.Statut } else { '' }); Outil = $outil })
        if ($_.State -eq 'Established' -and $_.RemoteAddress -notmatch $privRx) {
            $sev = ''
            if ($exe -and (Test-RiskPath $exe)) { $sev = 'ELEVE' }
            elseif ($sig -and -not $sig.Valide -and $exe) { $sev = 'MOYEN' }
            elseif ($outil) { $sev = 'MOYEN' }
            if ($sev) { Add-Finding $sev 'Connexion sortante' ("{0} -> {1}:{2}" -f $nm, $_.RemoteAddress, $_.RemotePort) $exe $(if ($outil) { 'Outil d''acces distant : ' + $outil } else { 'Signature : ' + $sig.Statut }) }
            if ($outil) { Add-IocSeen 'Adresse IP (connexion en cours)' $_.RemoteAddress ('Processus ' + $nm) (U (Get-Date)) $outil }
        }
        if ($_.State -eq 'Listen' -and $_.LocalAddress -notmatch '^(127\.|::1)' -and $exe -and (Test-RiskPath $exe)) {
            Add-Finding 'ELEVE' 'Port en ecoute' ("{0}:{1} ({2})" -f $_.LocalAddress, $_.LocalPort, $nm) $exe 'Binaire dans un dossier a risque'
        }
    }
    $null = Save-Csv $rows 'connexions_tcp_et_ports.csv' '07_reseau'
    $null = Save-Csv (Get-DnsClientCache | Select-Object Entry, Name, Type, Data, TimeToLive) 'cache_dns.csv' '07_reseau'
    $null = Save-Csv (Get-NetNeighbor | Where-Object { $_.State -ne 'Unreachable' } | Select-Object IPAddress, LinkLayerAddress, State, InterfaceAlias) 'arp.csv' '07_reseau'
    $null = Save-Csv (Get-NetIPConfiguration | ForEach-Object { [pscustomobject]@{ Interface = $_.InterfaceAlias; IPv4 = ($_.IPv4Address.IPAddress -join ','); Passerelle = ($_.IPv4DefaultGateway.NextHop -join ','); DNS = ($_.DNSServer.ServerAddresses -join ',') } }) 'interfaces.csv' '07_reseau'
    $fw = New-Object System.Collections.Generic.List[object]
    $script:FwSeen = @()
    # filtres lus en une fois (la lecture regle par regle prenait plusieurs minutes)
    $appF = @{}; $portF = @{}
    try { Get-NetFirewallApplicationFilter -All | ForEach-Object { $appF[[string]$_.InstanceID] = $_.Program } } catch { }
    try { Get-NetFirewallPortFilter -All | ForEach-Object { $portF[[string]$_.InstanceID] = $_.LocalPort } } catch { }
    Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow | ForEach-Object {
        $rid = [string]$_.InstanceID
        if ($appF.ContainsKey($rid)) { $app = $appF[$rid] } else { $app = ($_ | Get-NetFirewallApplicationFilter).Program }
        if ($portF.ContainsKey($rid)) { $port = $portF[$rid] } else { $port = ($_ | Get-NetFirewallPortFilter).LocalPort }
        $fw.Add([pscustomobject]@{ Nom = $_.DisplayName; Profil = $_.Profile; Programme = $app; PortLocal = ($port -join ',') })
        if ($app -and $app -ne 'Any' -and (Test-RiskPath $app) -and $script:FwSeen -notcontains ($_.DisplayName + '|' + $app)) { $script:FwSeen += ($_.DisplayName + '|' + $app); Add-Finding 'ELEVE' 'Pare-feu' ("Regle entrante autorisee pour un binaire a risque : {0}" -f $_.DisplayName) $app }
    }
    $null = Save-Csv $fw 'pare_feu_regles_entrantes.csv' '07_reseau'
    $null = Save-Csv (Get-SmbSession | Select-Object ClientComputerName, ClientUserName, NumOpens, SecondsExists) 'sessions_smb_entrantes.csv' '07_reseau'
}

# ---------------------------------------------------------------------------
# FICHIERS : un seul parcours des disques fixes (mode Complet)
# ---------------------------------------------------------------------------
function Mod-Fichiers {
    $broad = Test-Broad
    $exeExt = '.exe', '.dll', '.sys', '.ps1', '.psm1', '.bat', '.cmd', '.vbs', '.vbe', '.js', '.jse', '.wsf', '.hta', '.msi', '.msix', '.scr', '.jar', '.py', '.pyw', '.reg', '.lnk'
    $skipDir = '(?i)\\WinSxS\\|\\Windows\\servicing\\|\\Windows\\assembly\\|\\SoftwareDistribution\\|\\Windows\\CSC\\|\\Windows\\Installer\\|\\Windows\\System32\\DriverStore\\|\\Windows\\Logs\\'
    $noiseDir = '(?i)\\Microsoft\\(Windows Defender|Edge|EdgeWebView|EdgeUpdate|Teams|OneDrive|WindowsApps)\\|\\Google\\(Chrome|Update)\\|\\Packages\\|\\Windows\\Prefetch\\|\\Windows\\System32\\winevt\\'
    $interest = '(?i)\\Users\\[^\\]+\\(Desktop|Documents|Downloads|AppData\\Roaming|AppData\\Local\\Temp)|\\ProgramData\\|\\Windows\\Temp|\\Users\\Public'
    $noteName = '(?i)(readme|read_me|how.?to|decrypt|restore|recover|instruction|pay|leak|ransom|_help|!!!|unlock|your.?files)'
    $noteExt = '.txt', '.html', '.htm', '.hta', '.rtf', '.md'
    $kw = @(Read-ConfigList (Join-Path $script:KitRoot 'config\mots_cles_note.txt') | ForEach-Object { $_.Valeur })
    if ($kw.Count -eq 0) { $kw = @('pay or leak', 'bitcoin', '.onion', 'your files', 'decrypt', 'ransom') }
    $suspRx = '(?i)(' + $script:OutilsRx + ')'
    $suspExt = '.exe', '.msi', '.zip', '.7z', '.rar', '.bat', '.ps1', '.dll', '.vbs', '.js'
    $pyRx = '(?i)^(python[0-9\.]*\.exe|pythonw\.exe|python-[0-9].*\.exe|.*\.pyw?)$'
    $bizRx = '(?i)^(safipayment.*|sedtrace.*|galss.*)$'
    $cw = New-Object System.Collections.Generic.List[object]
    $ac = New-Object System.Collections.Generic.List[object]
    $sp = New-Object System.Collections.Generic.List[object]
    $py = New-Object System.Collections.Generic.List[object]
    $biz = New-Object System.Collections.Generic.List[object]
    $notes = New-Object System.Collections.Generic.List[object]
    $extCount = @{}
    $recent3 = (Get-Date).ToUniversalTime().AddDays(-3)
    $max = 20000
    $own = @(@($script:KitRoot, $script:Out) | Where-Object { $_ -and $_.TrimEnd('\').Length -gt 3 } | ForEach-Object { [regex]::Escape($_.TrimEnd('\') + '\') })
    $ownRx = $null; if ($own.Count -gt 0) { $ownRx = '(?i)^(' + ($own -join '|') + ')' }
    $drives = [IO.DriveInfo]::GetDrives() | Where-Object { $_.DriveType -eq 'Fixed' -and $_.IsReady }
    foreach ($dr in $drives) {
        Say ("   Parcours de {0} (plusieurs minutes, ne fermez pas la fenetre)..." -f $dr.Name)
        Get-ChildItem -LiteralPath $dr.RootDirectory.FullName -Recurse -Force -File -ErrorAction SilentlyContinue | ForEach-Object {
            $f = $_
            if ($ownRx -and $f.FullName -match $ownRx) { return }   # l'outil et ses resultats ne sont pas des traces du poste
            $c = $f.CreationTimeUtc; $w = $f.LastWriteTimeUtc; $a = $f.LastAccessTimeUtc
            $path = $f.FullName; $ext = $f.Extension.ToLower(); $name = $f.Name
            $inC = ($c -ge $script:WinS -and $c -le $script:WinE); $inW = ($w -ge $script:WinS -and $w -le $script:WinE)
            if ($w -ge $recent3) { if (-not $extCount.ContainsKey($ext)) { $extCount[$ext] = 0 }; $extCount[$ext]++ }
            if (($inC -or $inW) -and $path -notmatch $skipDir) {
                $keep = $true
                if ($broad) { $keep = (($exeExt -contains $ext) -or ($path -match $interest)) -and ($path -notmatch $noiseDir) }
                if ($keep -and $cw.Count -lt $max) {
                    $fl = ''; if ($inC) { $fl += 'C' }; if ($inW) { $fl += 'W' }
                    $cw.Add([pscustomobject]@{ Indicateurs = $fl; Chemin = $path; CreeUtc = (U $c); ModifieUtc = (U $w); AccedeUtc = (U $a); Taille = $f.Length })
                }
            } elseif (-not $broad -and $a -ge $script:WinS -and $a -le $script:WinE -and $path -match '(?i)^[A-Z]:\\(Users|WPHARMA|ProgramData)\\') {
                if ($ac.Count -lt 5000) { $ac.Add([pscustomobject]@{ Chemin = $path; CreeUtc = (U $c); ModifieUtc = (U $w); AccedeUtc = (U $a); Taille = $f.Length }) }
            }
            if ($name -match $suspRx -and ($suspExt -contains $ext) -and $path -notmatch '(?i)\\Windows\\(System32|SysWOW64|WinSxS|assembly)\\|\\Program Files( \(x86\))?\\(Microsoft|WindowsApps|Adobe|Common Files|Windows)') {
                $sp.Add([pscustomobject]@{ Chemin = $path; CreeUtc = (U $c); ModifieUtc = (U $w); Taille = $f.Length })
            }
            if ($name -match $pyRx -and ($path -match $script:UserDirRx -or $inC -or $inW -or (Test-RiskPath $path))) {
                $py.Add([pscustomobject]@{ Chemin = $path; CreeUtc = (U $c); ModifieUtc = (U $w); Taille = $f.Length })
            }
            if ($name -match $bizRx) { $biz.Add([pscustomobject]@{ Chemin = $path; CreeUtc = (U $c); ModifieUtc = (U $w); AccedeUtc = (U $a); Taille = $f.Length }) }
            if ($noteExt -contains $ext -and $f.Length -lt 300KB -and $path -notmatch '(?i)\\Windows\\|\\Program Files|\\AppData\\Local\\(Microsoft|Google|Packages)|\\node_modules\\|\\site-packages\\|\\\.vscode|\\\.git\\|\\\.cargo\\|\\\.nuget\\' -and $name -match $noteName) {
                # une documentation (README de bibliotheque...) peut contenir "decrypt" : il faut 2 mots-cles differents,
                # ou 1 seul si le fichier a ete cree/modifie dans la fenetre analysee
                $found = @()
                try {
                    $head = (Read-TextSmart $path -MaxBytes 200KB) -join ' '
                    foreach ($k in $kw) { if ($head.IndexOf($k, [StringComparison]::OrdinalIgnoreCase) -ge 0) { $found += $k } }
                } catch { }
                $hit = ''
                if ($found.Count -ge 2 -or ($found.Count -ge 1 -and ($inC -or $inW))) { $hit = ($found -join ', ') }
                if ($hit) { $notes.Add([pscustomobject]@{ Chemin = $path; CreeUtc = (U $c); ModifieUtc = (U $w); Taille = $f.Length; MotCle = $hit }) }
            }
        }
    }
    if ($cw.Count -ge $max) { Add-Finding 'MOYEN' 'Couverture' ("Plus de {0} fichiers crees/modifies dans la fenetre : liste tronquee (les dossiers parcourus en dernier, dont C:\Users, peuvent manquer). Reduire la fenetre horaire." -f $max) }
    $null = Save-Csv ($cw | Sort-Object CreeUtc) 'fichiers_crees_ou_modifies_fenetre.csv' '05_fichiers'
    if (-not $broad) { $null = Save-Csv ($ac | Sort-Object AccedeUtc) 'fichiers_consultes_fenetre.csv' '05_fichiers' }
    $null = Save-Csv ($sp | Sort-Object Chemin) 'noms_de_fichiers_outils_acces_distant.csv' '05_fichiers'
    $null = Save-Csv ($py | Sort-Object Chemin) 'fichiers_python.csv' '05_fichiers'
    $null = Save-Csv ($biz | Sort-Object Chemin) 'fichiers_metier_safipayment_sedtrace_galss.csv' '05_fichiers'
    $null = Save-Csv $notes 'notes_de_rancon_probables.csv' '05_fichiers'
    $null = Save-Csv ($extCount.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 40 | ForEach-Object { [pscustomobject]@{ Extension = $_.Key; Fichiers = $_.Value } }) 'extensions_modifiees_3_derniers_jours.csv' '05_fichiers'
    Say ("   {0} fichiers crees/modifies, {1} noms suspects, {2} notes probables, {3} fichiers python" -f $cw.Count, $sp.Count, $notes.Count, $py.Count)

    foreach ($n in $notes) {
        Add-Finding 'ELEVE' 'Note de rancon probable' ("Fichier contenant '{0}'" -f $n.MotCle) $n.Chemin ('Cree le ' + $n.CreeUtc + ' UTC ; modifie le ' + $n.ModifieUtc)
        Add-CopyJob -Source $n.Chemin -Dest 'notes_de_rancon' -Max 1MB
    }
    foreach ($s in $sp) { if (Test-RiskPath $s.Chemin) { Add-Finding 'ELEVE' 'Acces distant' 'Programme d''acces distant ou d''attaque dans un dossier utilisateur ou temporaire' $s.Chemin ('Cree le ' + $s.CreeUtc) } }
    foreach ($p in $py) {
        $sev = 'MOYEN'; if (Test-RiskPath $p.Chemin) { $sev = 'ELEVE' }
        Add-Finding $sev 'Python' 'Python ou script .py present en dehors des installations standards' $p.Chemin ('Cree le ' + $p.CreeUtc)
    }
    foreach ($b in $biz) {
        $da = $null; if ($b.AccedeUtc) { $da = ParseUtc $b.AccedeUtc }
        if ($da -and (InWindow $da) -and -not $script:WinDefault) { Add-Finding 'MOYEN' 'Fichier metier' ("Fichier consulte dans la fenetre : {0}" -f ($b.Chemin | Split-Path -Leaf)) $b.Chemin ('Dernier acces ' + $b.AccedeUtc + ' UTC') }
        elseif (-not $da -or -not (InWindow $da)) { }
    }
    if ($biz.Count -gt 0) { Add-Finding 'INFO' 'Fichier metier' ("{0} fichiers safipayment/sedtrace/galss recenses (copies et dates dans fichiers_metier_*.csv)" -f $biz.Count) }
    if (-not $broad) {
        foreach ($f in ($ac | Where-Object { $_.Chemin -match '(?i)\\Users\\[^\\]+\\(Desktop|Documents)\\' } | Select-Object -First 25)) {
            Add-Finding 'FAIBLE' 'Fichier consulte' ("Consulte dans la fenetre : {0}" -f ($f.Chemin | Split-Path -Leaf)) $f.Chemin ('Dernier acces ' + $f.AccedeUtc + ' UTC')
        }
    }
    $benign = '.jpg', '.jpeg', '.png', '.pdf', '.xlsx', '.docx', '.pptx', '.ldb', '.mui', '.dll', '.cache', '.manifest', '.catalog', '.cab', '.etl', '.pf', '.tmp', '.log', '.json', '.xml', '.txt', '.dat', '.db', '.sqlite', '.html', '.js', '.css', '.exe', '.msi', '.zip', '.tif', '.tiff', '.xls', '.doc', '.csv', '.evtx', '.lnk', '.ini', '.bak', '.mp4', '.gif', '.pak', '.bin', '.ico', '.svg', '.woff', '.woff2', '.map', '.pyc', '.ps1', '.psd1', '.psm1'
    foreach ($kv in ($extCount.GetEnumerator() | Where-Object { $_.Value -gt 300 -and $_.Key.Length -ge 4 -and $benign -notcontains $_.Key })) {
        Add-Finding 'MOYEN' 'Fichiers' ("{0} fichiers d'extension '{1}' modifies ces 3 derniers jours (extension inhabituelle : chiffrement possible ?)" -f $kv.Value, $kv.Key)
    }

    # Empreintes et signatures des executables de la fenetre
    Say '   Empreintes et signatures des executables de la fenetre...'
    $exOut = New-Object System.Collections.Generic.List[object]
    foreach ($x in ($cw | Where-Object { $exeExt -contains ([IO.Path]::GetExtension($_.Chemin).ToLower()) -and $_.Chemin -notmatch '\.lnk$' } | Select-Object -First 3000)) {
        $h = Get-FileHash -LiteralPath $x.Chemin -Algorithm SHA256 -ErrorAction SilentlyContinue
        $g = Get-AuthenticodeSignature -LiteralPath $x.Chemin -ErrorAction SilentlyContinue
        $exOut.Add([pscustomobject]@{ Chemin = $x.Chemin; CreeUtc = $x.CreeUtc; ModifieUtc = $x.ModifieUtc; SHA256 = $h.Hash; Signature = [string]$g.Status; Signataire = $g.SignerCertificate.Subject })
    }
    $null = Save-Csv $exOut 'executables_fenetre_hash_signature.csv' '05_fichiers'
    if (-not $broad) {
        foreach ($x in ($exOut | Where-Object { $_.Signataire -notmatch 'Microsoft' } | Select-Object -First 40)) {
            $sev = 'MOYEN'; if ($x.Signature -eq 'Valid') { $sev = 'FAIBLE' }
            Add-Finding $sev 'Executable recent' ("Executable ou script cree/modifie dans la fenetre (signature : {0})" -f $x.Signature) $x.Chemin ('SHA256 ' + $x.SHA256)
        }
    }
}

# ---------------------------------------------------------------------------
# COPIES DE PREUVES (+ instantane VSS optionnel pour les fichiers verrouilles)
# ---------------------------------------------------------------------------
function Mod-Preuves {
    $nbTot = 0
    foreach ($j in $script:CopyList) {
        $n = Copy-Evidence -Source $j.Source -Dest $j.Dest -Sensible:$j.Sensible -Filter $j.Filter -MaxFileBytes $j.Max -Recurse:$j.Recurse
        $nbTot += $n
    }
    Say ("   {0} fichiers copies (dates d'origine conservees, SHA256 calcule a la lecture)" -f $nbTot)
    if ($script:UseVss) {
        Say '   Instantane VSS temporaire pour les fichiers verrouilles...'
        $link = Join-Path $env:TEMP ('bll_vss_link_' + [guid]::NewGuid().ToString('N'))
        $sc = $null
        $shadowId = $null
        $linkCreated = $false
        try {
            $r = Invoke-CimMethod -ClassName Win32_ShadowCopy -MethodName Create -Arguments @{ Volume = 'C:\'; Context = 'ClientAccessible' }
            if ($r.ReturnValue -ne 0) { throw ('code ' + $r.ReturnValue) }
            $shadowId = $r.ShadowID
            $sc = Get-CimInstance Win32_ShadowCopy | Where-Object { $_.ID -eq $shadowId }
            if (-not $sc) { throw 'Instantane VSS introuvable apres sa creation.' }
            & cmd.exe /c mklink /d "$link" "$($sc.DeviceObject)\" | Out-Null
            if ($LASTEXITCODE -ne 0) { throw 'Impossible de creer le lien vers l instantane VSS.' }
            $linkCreated = $true
            if (-not (Test-Path -LiteralPath $link)) { throw 'Le lien vers l instantane VSS est inaccessible.' }
            $globs = @(
                @{ G = "$link\Windows\AppCompat\Programs\Amcache.hve*"; S = $false }, @{ G = "$link\Windows\System32\config\SYSTEM*"; S = $false },
                @{ G = "$link\Windows\System32\config\SOFTWARE*"; S = $false }, @{ G = "$link\Windows\System32\sru\SRUDB.dat"; S = $false },
                @{ G = "$link\Users\*\NTUSER.DAT*"; S = $false }, @{ G = "$link\Users\*\AppData\Local\Microsoft\Windows\UsrClass.dat*"; S = $false },
                @{ G = "$link\Users\*\AppData\Local\Google\Chrome\User Data\*\History"; S = $true },
                @{ G = "$link\Users\*\AppData\Local\Microsoft\Edge\User Data\*\History"; S = $true },
                @{ G = "$link\Users\*\AppData\Roaming\Mozilla\Firefox\Profiles\*\places.sqlite"; S = $true }
            )
            foreach ($g in $globs) {
                Get-ChildItem -Path $g.G -File -Force -ErrorAction SilentlyContinue | ForEach-Object {
                    $rel = $_.FullName.Substring($link.Length).TrimStart('\') -replace '[\\:]', '_'
                    $root = $script:Raw; if ($g.S) { $root = $script:RawSens }
                    $dst = Join-Path (Join-Path $root 'vss') $rel
                    $row = [ordered]@{ Source = ('VSS : ' + $_.FullName.Substring($link.Length)); Copie = ''; TailleOctets = $_.Length; CreeUtc = (U $_.CreationTimeUtc); ModifieUtc = (U $_.LastWriteTimeUtc); AccedeUtc = ''; SHA256 = ''; Statut = '' }
                    try { $row.SHA256 = Copy-OneFile $_.FullName $dst; $row.Copie = $dst.Substring($script:Out.Length).TrimStart('\', '/'); $row.Statut = 'OK' } catch { $row.Statut = 'ECHEC : ' + $_.Exception.Message }
                    $script:Manifest.Add([pscustomobject]$row)
                }
            }
        } catch {
            $script:Errors.Add('VSS : ' + $_.Exception.Message)
            Say ('   VSS indisponible : ' + $_.Exception.Message) 'Yellow'
        } finally {
            if ($linkCreated -and (Test-Path -LiteralPath $link)) { & cmd.exe /c rmdir "$link" | Out-Null }
            if ($shadowId) { Get-CimInstance Win32_ShadowCopy | Where-Object { $_.ID -eq $shadowId } | Remove-CimInstance }
        }
    }
    $null = Save-Csv $script:Manifest 'manifeste_des_copies.csv' ''
}
