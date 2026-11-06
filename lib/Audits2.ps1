# Audits2.ps1 - sauvegardes, partages/donnees, reseau local, rapport note

# ---------------------------------------------------------------------------
function Mod-Sauvegardes {
    $rows = New-Object System.Collections.Generic.List[object]
    # 1. Logiciels et services de sauvegarde
    $bkRx = '(?i)veeam|acronis|macrium|iperius|cobian|duplicati|backblaze|synology active backup|hyper backup|qnap|nakivo|altaro|hornetsecurity|datto|carbonite|crashplan|cloudberry|msp360|aomei|easeus todo|paragon|nortonghost|duplicacy|restic|rclone|freefilesync|syncback|veritas|commvault|sauvegarde|backup exec|windows server backup|safedeposit|idrive|spideroak|ottomatik'
    $sw = @(Get-InstalledSoftware | Where-Object { $_.Nom -match $bkRx })
    foreach ($s in $sw) { $rows.Add([pscustomobject]@{ Type = 'Logiciel'; Nom = $s.Nom; Detail = $s.Version }) }
    # services Windows integres (presents partout ; "Sauvegarde Windows" sur un Windows en francais) : ne prouvent rien
    $winBk = 'wbengine', 'SDRSVC', 'fhsvc', 'swprv', 'VSS'
    $svcs = @(Get-Service | Where-Object { $_.Name -notin $winBk -and ($_.Name + ' ' + $_.DisplayName) -match $bkRx })
    foreach ($s in $svcs) { $rows.Add([pscustomobject]@{ Type = 'Service'; Nom = $s.DisplayName; Detail = ([string]$s.Status + ' / ' + [string]$s.StartType) }) }
    $wbOk = $false
    try { $wbOk = [bool]((& wbadmin.exe get versions 2>$null) -match '(?i)(Backup time|Heure de la sauvegarde)') } catch { }
    $what = @(@($sw | ForEach-Object { $_.Nom }) + @($svcs | ForEach-Object { $_.DisplayName }) + @($(if ($wbOk) { 'Sauvegarde Windows (wbadmin, versions presentes)' })) | Where-Object { $_ } | Sort-Object -Unique)
    Add-Check 'Sauvegardes' 'Un logiciel ou service de sauvegarde est installe' ($what.Count -gt 0) ($what -join ' ; ') 'Verifier que ce poste (ou son serveur) est bien sauvegarde.' 'ELEVE'

    # 2. Taches planifiees de sauvegarde
    $okTask = $false; $taskTxt = @()
    try {
        Get-ScheduledTask | Where-Object { $_.TaskName -match '(?i)backup|sauveg|save|veeam|acronis|duplicati|cobian|iperius' -and $_.TaskPath -notmatch '^\\Microsoft\\' } | ForEach-Object {
            $i = $_ | Get-ScheduledTaskInfo
            $last = $i.LastRunTime; $res = $i.LastTaskResult
            $rows.Add([pscustomobject]@{ Type = 'Tache planifiee'; Nom = $_.TaskName; Detail = ('derniere execution ' + [string]$last + ' resultat ' + $res) })
            if ($last -and $last -gt (Get-Date).AddDays(-2) -and $res -eq 0) { $okTask = $true }
            $taskTxt += ($_.TaskName + ' : ' + [string]$last + ' (code ' + $res + ')')
        }
    } catch { }
    if ($taskTxt.Count -gt 0) { Add-Check 'Sauvegardes' 'Tache de sauvegarde executee avec succes ces 2 derniers jours' $okTask ($taskTxt -join ' ; ') 'Examiner le dernier resultat de la tache.' 'ELEVE' }

    # 3. Sauvegarde Windows, historique des fichiers, instantanes VSS
    try {
        $wb = & wbadmin.exe get versions 2>$null
        $last = ($wb | Select-String -Pattern '(?i)(Backup time|Heure de la sauvegarde)\s*:\s*(.+)$' | Select-Object -Last 1)
        if ($last) { $rows.Add([pscustomobject]@{ Type = 'Sauvegarde Windows'; Nom = 'wbadmin'; Detail = $last.Matches[0].Groups[2].Value }) }
    } catch { }
    try {
        $sh = @(Get-CimInstance Win32_ShadowCopy)
        $newest = $null; if ($sh.Count -gt 0) { $newest = ($sh | Sort-Object InstallDate -Descending | Select-Object -First 1).InstallDate }
        $rows.Add([pscustomobject]@{ Type = 'Instantanes VSS'; Nom = 'Copies cliches'; Detail = ([string]$sh.Count + ' ; plus recent ' + [string]$newest) })
        Add-Check 'Sauvegardes' 'Des instantanes (points de restauration) existent' ($sh.Count -gt 0) ([string]$sh.Count + ' instantane(s)') 'Activer la protection du systeme (utile contre une erreur, pas contre un rancongiciel avance).' 'FAIBLE'
    } catch { }

    # 4. Destinations configurees : fraicheur + test de lecture
    $cfg = @(Read-ConfigList (Join-Path $script:KitRoot 'config\sauvegardes.txt'))
    foreach ($c in $cfg) {
        $parts = $c.Valeur -split ';'
        $path = $parts[0].Trim(); $maxH = 36; if ($parts.Count -gt 1) { try { $maxH = [int]$parts[1] } catch { } }
        if (-not (Test-Path -LiteralPath $path)) { Add-Check 'Sauvegardes' ('Destination accessible : ' + $path) $false 'introuvable' 'Verifier le disque/partage de sauvegarde.' 'ELEVE'; continue }
        $newest = Get-ChildItem -LiteralPath $path -File -Recurse -Depth 3 -Force -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if (-not $newest) { Add-Check 'Sauvegardes' ('Destination non vide : ' + $path) $false 'aucun fichier' 'La destination est vide.' 'ELEVE'; continue }
        $ageH = [int]((Get-Date) - $newest.LastWriteTime).TotalHours
        Add-Check 'Sauvegardes' ('Sauvegarde recente dans ' + $path + ' (moins de ' + $maxH + ' h)') ($ageH -le $maxH) ('fichier le plus recent : ' + $newest.Name + ', il y a ' + $ageH + ' h') 'Verifier le travail de sauvegarde.' 'ELEVE'
        $rows.Add([pscustomobject]@{ Type = 'Destination'; Nom = $path; Detail = ('plus recent ' + $newest.FullName + ' (' + $newest.LastWriteTime.ToString('yyyy-MM-dd HH:mm') + ', ' + [math]::Round($newest.Length / 1MB, 1) + ' Mo)') })
        # test de lecture : debut + fin du fichier, ouverture si zip
        $readOk = $true; $why = ''
        try {
            $fs = [IO.File]::Open($newest.FullName, 'Open', 'Read', 'ReadWrite')
            try {
                $buf = New-Object byte[] 4194304
                $null = $fs.Read($buf, 0, $buf.Length)
                if ($fs.Length -gt 8388608) { $fs.Seek(-4194304, 'End') | Out-Null; $null = $fs.Read($buf, 0, $buf.Length) }
            } finally { $fs.Dispose() }
            if ($newest.Extension -eq '.zip') {
                Add-Type -AssemblyName System.IO.Compression.FileSystem
                $z = [IO.Compression.ZipFile]::OpenRead($newest.FullName); $why = ($z.Entries.Count.ToString() + ' entrees'); $z.Dispose()
            }
        } catch { $readOk = $false; $why = $_.Exception.Message }
        Add-Check 'Sauvegardes' ('Test de lecture de la derniere sauvegarde (' + $newest.Name + ')') $readOk $why 'Fichier illisible ou corrompu : faire un test de restauration complet.' 'ELEVE'
    }
    if ($cfg.Count -eq 0) { Add-Check 'Sauvegardes' 'Destinations de sauvegarde declarees (config\sauvegardes.txt)' $null 'aucune declaree : fraicheur non verifiee' }

    # 5. Resistance au rancongiciel : destinations accessibles en ecriture depuis le poste
    # Lecteurs reseau mappes par les utilisateurs (lus dans leur registre : la session administrateur ne les voit pas).
    # Lecture seule : aucun fichier de test n'est ecrit sur les partages.
    $risk = New-Object System.Collections.Generic.List[string]
    try {
        foreach ($sid in [Microsoft.Win32.Registry]::Users.GetSubKeyNames() | Where-Object { $_ -match $script:UserSidRx }) {
            Get-ChildItem ("Registry::HKEY_USERS\$sid\Network") -ErrorAction SilentlyContinue | ForEach-Object {
                $rpth = (Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue).RemotePath
                if ($rpth) { $e = ($_.PSChildName.ToUpper() + ': (' + $rpth + ')'); if (-not $risk.Contains($e)) { $risk.Add($e) } }
            }
        }
        Get-PSDrive -PSProvider FileSystem | Where-Object { $_.DisplayRoot -like '\\*' } | ForEach-Object { $e = ($_.Name.ToUpper() + ': (' + $_.DisplayRoot + ')'); if (-not $risk.Contains($e)) { $risk.Add($e) } }
    } catch { }
    # Disques USB (disques durs USB = type "Fixed", cles = "Removable"), hors support du kit lui-meme
    $usb = @()
    $kitDrive = ''; try { $kitDrive = ([IO.Path]::GetPathRoot($script:KitRoot)).Substring(0, 1).ToUpper() } catch { }
    try {
        $usb = @(Get-Disk -ErrorAction Stop | Where-Object { $_.BusType -eq 'USB' } | Get-Partition -ErrorAction SilentlyContinue |
            Where-Object { $_.DriveLetter -and [string]$_.DriveLetter -ne $kitDrive } | ForEach-Object { [string]$_.DriveLetter + ':' } | Sort-Object -Unique)
    } catch {
        try { $usb = @(Get-Volume | Where-Object { $_.DriveType -eq 'Removable' -and $_.DriveLetter -and [string]$_.DriveLetter -ne $kitDrive } | ForEach-Object { [string]$_.DriveLetter + ':' }) } catch { }
    }
    foreach ($r in $risk) { $rows.Add([pscustomobject]@{ Type = 'Lecteur reseau mappe'; Nom = $r; Detail = 'si accessible en ecriture, un rancongiciel le chiffrerait aussi' }) }
    foreach ($r in $usb) { $rows.Add([pscustomobject]@{ Type = 'Disque USB connecte'; Nom = $r; Detail = 'a deconnecter apres sauvegarde' }) }
    Add-Check 'Sauvegardes' 'Aucun lecteur reseau mappe en permanence (cible de rancongiciel)' ($risk.Count -eq 0) ($risk -join ' ; ') 'Verifier qu''aucune sauvegarde ne se trouve sur ces lecteurs ; garder au moins une copie hors ligne ou immuable.' 'MOYEN'
    Add-Check 'Sauvegardes' 'Aucun disque USB laisse branche en permanence' ($usb.Count -eq 0) ($usb -join ' ; ') 'Deconnecter le disque apres la sauvegarde ou alterner deux disques.' 'MOYEN'
    $null = Save-Csv $rows 'inventaire_sauvegardes.csv' '03_sauvegardes'
}

# ---------------------------------------------------------------------------
function Mod-Partages {
    $everyone = '(?i)^(Everyone|Tout le monde|BUILTIN\\Users|BUILTIN\\Utilisateurs|NT AUTHORITY\\Authenticated Users|AUTORITE NT\\Utilisateurs authentifi|Utilisateurs authentifi)'
    $rows = New-Object System.Collections.Generic.List[object]
    try {
        foreach ($s in (Get-SmbShare | Where-Object { $_.Special -eq $false -and $_.Name -notmatch '^(print\$|IPC\$)$' })) {
            $acc = @(Get-SmbShareAccess -Name $s.Name)
            $open = @($acc | Where-Object { $_.AccountName -match $everyone -and $_.AccessRight -in 'Full', 'Change' -and $_.AccessControlType -eq 'Allow' })
            $rows.Add([pscustomobject]@{ Partage = $s.Name; Chemin = $s.Path; Acces = (($acc | ForEach-Object { $_.AccountName + ':' + $_.AccessRight }) -join ' ; ') })
            Add-Check 'Partages' ('Partage ' + $s.Name + ' non ouvert en ecriture a tous') ($open.Count -eq 0) ($s.Path + ' -> ' + (($open | ForEach-Object { $_.AccountName + ':' + $_.AccessRight }) -join ',')) 'Restreindre le partage a des groupes nominatifs.' 'ELEVE'
        }
        $null = Save-Csv $rows 'partages_smb.csv' '04_partages_donnees'
        $ses = @(Get-SmbSession | Select-Object ClientComputerName, ClientUserName, NumOpens, SecondsExists)
        $null = Save-Csv $ses 'sessions_smb_entrantes.csv' '04_partages_donnees'
    } catch { Add-Check 'Partages' 'Partages SMB' $null 'non verifiable' }
    # la strategie (GPO) l'emporte sur le parametre du service ; absente partout = valeur par defaut de l'edition
    $ag = Get-RegVal 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation' 'AllowInsecureGuestAuth' $null
    if ($null -eq $ag) { $ag = Get-RegVal 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' 'AllowInsecureGuestAuth' $null }
    if ($null -eq $ag) { Add-Check 'Partages' 'Acces invite non authentifie aux partages desactive' $null 'non configure (valeur par defaut de Windows)' }
    else { Add-Check 'Partages' 'Acces invite non authentifie aux partages desactive' ($ag -ne 1) ('AllowInsecureGuestAuth=' + $ag) 'Mettre AllowInsecureGuestAuth a 0 (strategie de groupe).' 'MOYEN' }

    # Fichiers sensibles laisses dans des dossiers a risque
    $rx = New-Object System.Collections.Generic.List[string]
    foreach ($d in @('safipayment', 'sedtrace', 'ordonnance', 'vitale', 'patient', 'export.*(client|patient|stock|vente)', 'carte.*(bancaire|bleue)', '\bRIB\b', 'mot.?de.?passe', 'passwords?', '\bmdp\b', 'identifiants', 'sauvegarde.*(winpharma|lgpi|leo|pharmagest)', '\.kdbx$', '\.pfx$', 'id_rsa')) { $rx.Add($d) }
    foreach ($c in (Read-ConfigList (Join-Path $script:KitRoot 'config\fichiers_sensibles.txt'))) { $rx.Add($c.Valeur) }
    $pat = '(?i)(' + (($rx | ForEach-Object { $_ }) -join '|') + ')'
    $hits = New-Object System.Collections.Generic.List[object]
    foreach ($pr in (Get-UserProfiles)) {
        foreach ($sub in 'Desktop', 'Downloads', 'Documents', 'AppData\Local\Temp') {
            $base = Join-Path $pr.FullName $sub
            if (-not (Test-Path -LiteralPath $base)) { continue }
            Get-ChildItem -LiteralPath $base -File -Recurse -Depth 3 -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -match $pat } | Select-Object -First 200 | ForEach-Object {
                $hits.Add([pscustomobject]@{ Chemin = $_.FullName; TailleKo = [math]::Round($_.Length / 1KB); ModifieLe = $_.LastWriteTime.ToString('yyyy-MM-dd'); AgeJours = [int]((Get-Date) - $_.LastWriteTime).TotalDays })
            }
        }
    }
    foreach ($b in 'C:\Users\Public', 'C:\Temp') {
        if (Test-Path -LiteralPath $b) { Get-ChildItem -LiteralPath $b -File -Recurse -Depth 3 -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -match $pat } | Select-Object -First 100 | ForEach-Object { $hits.Add([pscustomobject]@{ Chemin = $_.FullName; TailleKo = [math]::Round($_.Length / 1KB); ModifieLe = $_.LastWriteTime.ToString('yyyy-MM-dd'); AgeJours = [int]((Get-Date) - $_.LastWriteTime).TotalDays }) } }
    }
    $null = Save-Csv $hits 'fichiers_sensibles_hors_logiciel.csv' '04_partages_donnees'
    Add-Check 'Donnees' 'Aucun fichier sensible (exports, mots de passe, donnees patients) dans Bureau/Telechargements/Public' ($hits.Count -eq 0) ([string]$hits.Count + ' fichier(s), voir fichiers_sensibles_hors_logiciel.csv ; ex. ' + (($hits | Select-Object -First 3 | ForEach-Object { $_.Chemin }) -join ' ; ')) 'Deplacer dans un emplacement controle ou supprimer apres usage.' 'MOYEN'
}

# ---------------------------------------------------------------------------
# RESEAU LOCAL (a lancer depuis un poste du reseau de l'officine)
# ---------------------------------------------------------------------------
function Get-DhcpOffers {
    $offers = New-Object System.Collections.Generic.List[object]
    $u = $null
    try {
        $u = New-Object Net.Sockets.UdpClient
        $u.Client.SetSocketOption([Net.Sockets.SocketOptionLevel]::Socket, [Net.Sockets.SocketOptionName]::ReuseAddress, $true)
        $u.Client.Bind((New-Object Net.IPEndPoint([Net.IPAddress]::Any, 68)))
        $u.EnableBroadcast = $true
        $xid = New-Object byte[] 4; (New-Object Random).NextBytes($xid)
        $mac = [byte[]](0x02, 0xB1, 0x1A, 0x00, 0x00, 0x01)
        $p = New-Object byte[] 300
        $p[0] = 1; $p[1] = 1; $p[2] = 6; [Array]::Copy($xid, 0, $p, 4, 4); $p[10] = 0x80
        [Array]::Copy($mac, 0, $p, 28, 6)
        $p[236] = 99; $p[237] = 130; $p[238] = 83; $p[239] = 99; $p[240] = 53; $p[241] = 1; $p[242] = 1; $p[243] = 255
        $null = $u.Send($p, 300, (New-Object Net.IPEndPoint([Net.IPAddress]::Broadcast, 67)))
        $u.Client.ReceiveTimeout = 1500
        $end = (Get-Date).AddSeconds(5)
        while ((Get-Date) -lt $end) {
            try {
                $ep = New-Object Net.IPEndPoint([Net.IPAddress]::Any, 0)
                $r = $u.Receive([ref]$ep)
                if ($r.Length -gt 240 -and $r[0] -eq 2 -and $r[4] -eq $xid[0] -and $r[5] -eq $xid[1]) {
                    $yi = ($r[16..19] -join '.'); $srv = $ep.Address.ToString()
                    $i = 240
                    while ($i -lt $r.Length - 1 -and $r[$i] -ne 255) { if ($r[$i] -eq 54 -and $r[$i + 1] -eq 4) { $srv = ($r[($i + 2)..($i + 5)] -join '.') }; $i += 2 + $r[$i + 1] }
                    $offers.Add([pscustomobject]@{ Serveur = $srv; AdresseProposee = $yi })
                }
            } catch { }
        }
    } catch { } finally { if ($u) { $u.Close() } }
    return $offers
}

function Get-UpnpInfo {
    $found = New-Object System.Collections.Generic.List[object]
    $u = $null
    try {
        $u = New-Object Net.Sockets.UdpClient
        $msg = "M-SEARCH * HTTP/1.1`r`nHOST: 239.255.255.250:1900`r`nMAN: `"ssdp:discover`"`r`nMX: 2`r`nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1`r`n`r`n"
        $b = [Text.Encoding]::ASCII.GetBytes($msg)
        $null = $u.Send($b, $b.Length, (New-Object Net.IPEndPoint([Net.IPAddress]::Parse('239.255.255.250'), 1900)))
        $u.Client.ReceiveTimeout = 1500
        $end = (Get-Date).AddSeconds(4)
        while ((Get-Date) -lt $end) {
            try {
                $ep = New-Object Net.IPEndPoint([Net.IPAddress]::Any, 0)
                $r = [Text.Encoding]::ASCII.GetString($u.Receive([ref]$ep))
                $loc = ''; if ($r -match '(?im)^LOCATION:\s*(\S+)') { $loc = $Matches[1] }
                if ($loc -and -not ($found | Where-Object { $_.Location -eq $loc })) { $found.Add([pscustomobject]@{ Source = $ep.Address.ToString(); Location = $loc }) }
            } catch { }
        }
    } catch { } finally { if ($u) { $u.Close() } }
    return $found
}

function Get-UpnpMappings {
    param([string]$Location)
    $maps = New-Object System.Collections.Generic.List[object]
    try {
        # -MaximumRedirection 0 : un equipement du reseau ne peut pas rediriger la requete vers Internet
        $x = [xml](Invoke-WebRequest -Uri $Location -UseBasicParsing -TimeoutSec 5 -MaximumRedirection 0 -ErrorAction Stop).Content
        $ns = New-Object Xml.XmlNamespaceManager($x.NameTable); $ns.AddNamespace('d', 'urn:schemas-upnp-org:device-1-0')
        $svc = $x.SelectNodes('//d:service', $ns) | Where-Object { $_.serviceType -match 'WANIPConnection|WANPPPConnection' } | Select-Object -First 1
        if (-not $svc) { return $maps }
        $uri = New-Object Uri($Location)
        $cu = New-Object Uri($uri, $svc.controlURL)
        if ($cu.Host -ne $uri.Host) { return $maps }
        $ctl = $cu.AbsoluteUri
        for ($i = 0; $i -lt 60; $i++) {
            $body = '<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body><u:GetGenericPortMappingEntry xmlns:u="' + $svc.serviceType + '"><NewPortMappingIndex>' + $i + '</NewPortMappingIndex></u:GetGenericPortMappingEntry></s:Body></s:Envelope>'
            try {
                $r = Invoke-WebRequest -Uri $ctl -Method Post -Body $body -UseBasicParsing -TimeoutSec 5 -MaximumRedirection 0 -ErrorAction Stop -ContentType 'text/xml; charset="utf-8"' -Headers @{ SOAPAction = ('"' + $svc.serviceType + '#GetGenericPortMappingEntry"') }
                $m = [xml]$r.Content
                $e = $m.GetElementsByTagName('NewExternalPort')[0].InnerText
                $maps.Add([pscustomobject]@{ PortExterne = $e; Protocole = $m.GetElementsByTagName('NewProtocol')[0].InnerText; VersIp = $m.GetElementsByTagName('NewInternalClient')[0].InnerText; PortInterne = $m.GetElementsByTagName('NewInternalPort')[0].InnerText; Description = $m.GetElementsByTagName('NewPortMappingDescription')[0].InnerText })
            } catch { break }
        }
    } catch { }
    return $maps
}

function Mod-ReseauLan {
    $cfg = Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway -and $_.NetAdapter.Status -eq 'Up' } | Select-Object -First 1
    if (-not $cfg) { Add-Check 'Reseau local' 'Reseau detecte' $null 'aucune interface avec passerelle'; return }
    $myIp = $cfg.IPv4Address.IPAddress; $gw = $cfg.IPv4DefaultGateway.NextHop
    $o = $myIp -split '\.'; $prefix = '{0}.{1}.{2}.' -f $o[0], $o[1], $o[2]
    Say ("   Reseau {0}0/24 (poste {1}, passerelle {2})" -f $prefix, $myIp, $gw)

    # Decouverte (ping asynchrone)
    $pings = @{}
    foreach ($i in 1..254) { $ip = $prefix + $i; $p = New-Object Net.NetworkInformation.Ping; $pings[$ip] = @{ P = $p; T = $p.SendPingAsync($ip, 700) } }
    try { [void][Threading.Tasks.Task]::WaitAll(@($pings.Values | ForEach-Object { $_.T }), 10000) } catch { }
    $alive = New-Object System.Collections.Generic.List[string]
    foreach ($k in $pings.Keys) { try { if ($pings[$k].T.IsCompleted -and $pings[$k].T.Result.Status -eq 'Success') { $alive.Add($k) } } catch { } }
    try { Get-NetNeighbor -AddressFamily IPv4 | Where-Object { $_.IPAddress -like ($prefix + '*') -and $_.State -in 'Reachable', 'Stale', 'Permanent', 'Delay', 'Probe' -and $_.LinkLayerAddress -and $_.LinkLayerAddress -ne 'FF-FF-FF-FF-FF-FF' } | ForEach-Object { if (-not $alive.Contains($_.IPAddress)) { $alive.Add($_.IPAddress) } } } catch { }
    $alive = [System.Collections.Generic.List[string]]@($alive | Sort-Object { [int]($_ -split '\.')[3] } -Unique)
    Say ("   {0} equipements detectes" -f $alive.Count)

    # Ports courants (connexions TCP asynchrones)
    $ports = 21, 22, 23, 80, 135, 139, 443, 445, 554, 1433, 3306, 3389, 5900, 5938, 8000, 8080, 8443, 9100, 37777, 34567
    $conn = New-Object System.Collections.Generic.List[object]
    foreach ($ip in $alive) { foreach ($pt in $ports) { $c = New-Object Net.Sockets.TcpClient; $conn.Add(@{ Ip = $ip; Port = $pt; C = $c; R = $c.BeginConnect($ip, $pt, $null, $null) }) } }
    $deadline = (Get-Date).AddSeconds(14)
    foreach ($x in $conn) { $left = [int](($deadline - (Get-Date)).TotalMilliseconds); if ($left -lt 50) { $left = 50 }; try { [void]$x.R.AsyncWaitHandle.WaitOne($left) } catch { } }
    $open = @{}
    foreach ($x in $conn) { try { if ($x.R.IsCompleted -and $x.C.Connected) { if (-not $open.ContainsKey($x.Ip)) { $open[$x.Ip] = @() }; $open[$x.Ip] += $x.Port } } catch { }; try { $x.C.Close() } catch { } }

    $dns = @{}
    $dt = @{}; foreach ($ip in $alive) { try { $dt[$ip] = [Net.Dns]::GetHostEntryAsync($ip) } catch { } }
    try { [void][Threading.Tasks.Task]::WaitAll(@($dt.Values), 6000) } catch { }
    foreach ($k in $dt.Keys) { try { if ($dt[$k].IsCompleted -and -not $dt[$k].IsFaulted) { $dns[$k] = $dt[$k].Result.HostName } } catch { } }
    $mac = @{}; try { Get-NetNeighbor -AddressFamily IPv4 | ForEach-Object { $mac[$_.IPAddress] = $_.LinkLayerAddress } } catch { }

    $devs = New-Object System.Collections.Generic.List[object]
    foreach ($ip in $alive) {
        $pp = @(); if ($open.ContainsKey($ip)) { $pp = @($open[$ip] | Sort-Object) }
        $type = 'Equipement'
        if ($pp -contains 554 -or $pp -contains 37777 -or $pp -contains 34567 -or ($pp -contains 8000 -and $pp -contains 80)) { $type = 'Camera / enregistreur (NVR)' }
        elseif ($pp -contains 9100) { $type = 'Imprimante' }
        elseif ($pp -contains 445 -or $pp -contains 135) { $type = 'Windows / partage' }
        elseif ($ip -eq $gw) { $type = 'Passerelle / box' }
        if ($ip -eq $gw) { $type = 'Passerelle / box' }
        $devs.Add([pscustomobject]@{ Ip = $ip; Nom = [string]$dns[$ip]; Mac = [string]$mac[$ip]; Type = $type; PortsOuverts = ($pp -join ',') })
        if ($pp -contains 23) { Add-Check 'Reseau local' ('Telnet ferme sur ' + $ip) $false ($type + ' ' + $dns[$ip]) 'Desactiver Telnet (protocole non chiffre).' 'ELEVE' }
        if ($pp -contains 21) { Add-Check 'Reseau local' ('FTP ferme sur ' + $ip) $false ($type + ' ' + $dns[$ip]) 'Desactiver FTP ou le remplacer par SFTP.' 'MOYEN' }
        if ($pp -contains 5900) { Add-Check 'Reseau local' ('VNC ferme sur ' + $ip) $false ($type + ' ' + $dns[$ip]) 'Verifier le mot de passe VNC ou desinstaller.' 'MOYEN' }
        if (($pp -contains 1433 -or $pp -contains 3306) -and $type -ne 'Passerelle / box') { Add-Check 'Reseau local' ('Base de donnees non exposee sur ' + $ip) $false ('ports ' + ($pp -join ',')) 'Limiter l''acces au serveur applicatif (pare-feu hote).' 'FAIBLE' }
        if ($type -like 'Camera*') { Add-Check 'Reseau local' ('Camera/NVR ' + $ip + ' : mot de passe et firmware a verifier manuellement') $null ('ports ' + ($pp -join ',') + ' - verifier : mot de passe fort, firmware a jour, aucune redirection vers Internet, reseau dedie') }
    }
    $rdp = @($devs | Where-Object { $_.PortsOuverts -match '(^|,)3389(,|$)' })
    if ($rdp.Count -gt 0) { Add-Check 'Reseau local' 'RDP ouvert sur un minimum d''equipements' ($rdp.Count -le 1) (($rdp | ForEach-Object { $_.Ip }) -join ', ') 'Fermer RDP sur les postes qui n''en ont pas besoin.' 'MOYEN' }
    $gwOpen = @($devs | Where-Object { $_.Ip -eq $gw })
    if ($gwOpen.Count -gt 0 -and $gwOpen[0].PortsOuverts -match '(^|,)(22|23|8080|8443)(,|$)') { Add-Check 'Reseau local' 'Administration de la box limitee (SSH/Telnet/8080 fermes cote LAN)' $false ('ports ' + $gwOpen[0].PortsOuverts) 'Restreindre l''administration de la box.' 'FAIBLE' }
    $null = Save-Csv $devs 'equipements_reseau.csv' '05_reseau_local'

    # DHCP pirate
    $offers = @(Get-DhcpOffers)
    $null = Save-Csv $offers 'offres_dhcp.csv' '05_reseau_local'
    $servers = @($offers | ForEach-Object { $_.Serveur } | Sort-Object -Unique)
    if ($offers.Count -gt 0) { Add-Check 'Reseau local' 'Un seul serveur DHCP repond' ($servers.Count -le 1) ('serveurs : ' + ($servers -join ', ')) 'Identifier les serveurs DHCP supplementaires (box + routeur ? DHCP pirate ?).' 'ELEVE' }
    else { Add-Check 'Reseau local' 'Un seul serveur DHCP repond' $null 'aucune reponse (test non concluant : port 68 occupe ?)' }

    # UPnP et redirections de ports
    $up = @(Get-UpnpInfo)
    $maps = New-Object System.Collections.Generic.List[object]
    # on n'interroge que l'equipement qui a repondu, et seulement s'il est sur le reseau local (aucune URL externe suivie)
    foreach ($g in $up) {
        $h = ''; try { $h = ([Uri]$g.Location).Host } catch { }
        if ($h -eq $g.Source -and $h -match '^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)') { foreach ($m in (Get-UpnpMappings $g.Location)) { $maps.Add($m) } }
        else { Say ('   UPnP ignore (adresse hors reseau local ou incoherente) : ' + $g.Location) 'Yellow' }
    }
    $null = Save-Csv $maps 'redirections_upnp.csv' '05_reseau_local'
    Add-Check 'Reseau local' 'UPnP desactive sur la box' ($up.Count -eq 0) ($up | ForEach-Object { $_.Source }) 'Desactiver UPnP dans la box : il permet a un logiciel de rediriger un port vers Internet sans controle.' 'MOYEN'
    if ($up.Count -gt 0) { Add-Check 'Reseau local' 'Aucune redirection de port UPnP active' ($maps.Count -eq 0) (($maps | ForEach-Object { '{0}/{1} -> {2}:{3} ({4})' -f $_.PortExterne, $_.Protocole, $_.VersIp, $_.PortInterne, $_.Description }) -join ' ; ') 'Supprimer les redirections inutiles ; une camera ou un NVR accessible depuis Internet est une cible prioritaire.' 'ELEVE' }
}

# ---------------------------------------------------------------------------
function HtmlE { param($t) return [System.Net.WebUtility]::HtmlEncode([string]$t) }

function Build-RapportAudit {
    $ok = @($script:Checks | Where-Object { $_.Etat -eq 'OK' }); $ko = @($script:Checks | Where-Object { $_.Etat -eq 'ECART' }); $na = @($script:Checks | Where-Object { $_.Etat -eq 'N/A' })
    $wOk = 0; foreach ($c in $ok) { $wOk += $c.Poids }; $wKo = 0; foreach ($c in $ko) { $wKo += $c.Poids }
    # pas de score sans controles evalues (un audit qui n'a rien pu lire ne doit pas afficher 100/100)
    $score = '--'; $note = '?'
    if (($wOk + $wKo) -gt 0) {
        $score = [int](100 * $wOk / ($wOk + $wKo))
        $note = 'A'; if ($score -lt 90) { $note = 'B' }; if ($score -lt 75) { $note = 'C' }; if ($score -lt 60) { $note = 'D' }; if ($score -lt 40) { $note = 'E' }
    }
    $script:ScoreWarn = ''
    $nAll = $ok.Count + $ko.Count + $na.Count
    if ($nAll -gt 0 -and ($na.Count / $nAll) -gt 0.3) { $script:ScoreWarn = ('Attention : ' + $na.Count + ' controles sur ' + $nAll + ' non verifiables ; score peu representatif.') }
    if ($script:Errors.Count -gt 0) { $script:ScoreWarn = ($script:ScoreWarn + ' Modules en erreur : ' + $script:Errors.Count + ' (voir la fin du rapport).').Trim() }
    $script:Score = $score; $script:Note = $note
    $null = Save-Csv ($script:Checks | Sort-Object Categorie, Etat) 'controles.csv' ''
    $order = @{ 'ELEVE' = 0; 'MOYEN' = 1; 'FAIBLE' = 2 }
    $kos = @($ko | Sort-Object @{ Expression = { $order[$_.Gravite] } }, Categorie)

    $r = New-Object System.Collections.Generic.List[string]
    $r.Add('BLL Audit v' + $script:KitVersion + ' - ' + $env:COMPUTERNAME); $r.Add('=' * 60)
    $r.Add(('Score : {0}/100 (note {1}) - {2} conformes, {3} ecarts, {4} non verifiables' -f $score, $note, $ok.Count, $ko.Count, $na.Count))
    if ($script:ScoreWarn) { $r.Add($script:ScoreWarn) }
    $r.Add('')
    foreach ($k in $kos) { $r.Add(('[{0}] {1} - {2} : {3}' -f $k.Gravite, $k.Categorie, $k.Controle, $k.Valeur)); $r.Add('        -> ' + $k.Recommandation) }
    if ($script:Errors.Count -gt 0) { $r.Add(''); $r.Add('MODULES EN ERREUR :'); foreach ($e in $script:Errors) { $r.Add(' - ' + $e) } }
    Save-Text $r.ToArray() 'RESUME_AUDIT.txt' ''

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8"><title>Audit ' + (HtmlE $env:COMPUTERNAME) + '</title><style>body{font-family:Segoe UI,Arial,sans-serif;margin:24px;color:#222}h1{font-size:22px}h2{font-size:17px;margin-top:26px;border-bottom:1px solid #ccc;padding-bottom:4px}table{border-collapse:collapse;width:100%;font-size:12.5px}th,td{border:1px solid #ddd;padding:4px 6px;text-align:left;vertical-align:top;word-break:break-word}th{background:#f3f3f3}.ELEVE{background:#fde2e2}.MOYEN{background:#fff0d6}.FAIBLE{background:#fffbe0}.OK{background:#e6f5e6}.NA{background:#f1f1f1}.score{font-size:40px;font-weight:700}</style></head><body>')
    [void]$sb.Append('<h1>Audit de securite - ' + (HtmlE $env:COMPUTERNAME) + '</h1><p>' + (U (Get-Date)) + ' UTC - BLL IR-Kit v' + $script:KitVersion + '</p>')
    [void]$sb.Append('<p><span class="score">' + $score + '/100</span> &nbsp; note <b>' + $note + '</b> &nbsp; ' + $ok.Count + ' conformes - ' + $ko.Count + ' ecarts - ' + $na.Count + ' non verifiables</p>')
    if ($script:ScoreWarn) { [void]$sb.Append('<p style="color:#b00"><b>' + (HtmlE $script:ScoreWarn) + '</b></p>') }
    [void]$sb.Append('<p><em>Audit en lecture seule. Le score ponderee par gravite est un indicateur de suivi, pas une certification.</em></p>')
    [void]$sb.Append('<h2>Par categorie</h2><table><tr><th>Categorie</th><th>Conformes</th><th>Ecarts</th></tr>')
    foreach ($g in ($script:Checks | Group-Object Categorie | Sort-Object Name)) { [void]$sb.Append('<tr><td>' + (HtmlE $g.Name) + '</td><td>' + @($g.Group | Where-Object { $_.Etat -eq 'OK' }).Count + '</td><td>' + @($g.Group | Where-Object { $_.Etat -eq 'ECART' }).Count + '</td></tr>') }
    [void]$sb.Append('</table><h2>Ecarts a traiter (par gravite)</h2><table><tr><th>Gravite</th><th>Categorie</th><th>Controle</th><th>Constat</th><th>Recommandation</th></tr>')
    foreach ($k in $kos) { [void]$sb.Append('<tr class="' + $k.Gravite + '"><td>' + $k.Gravite + '</td><td>' + (HtmlE $k.Categorie) + '</td><td>' + (HtmlE $k.Controle) + '</td><td>' + (HtmlE $k.Valeur) + '</td><td>' + (HtmlE $k.Recommandation) + '</td></tr>') }
    [void]$sb.Append('</table><h2>Tous les controles</h2><table><tr><th>Etat</th><th>Categorie</th><th>Controle</th><th>Valeur</th></tr>')
    foreach ($c in ($script:Checks | Sort-Object Categorie, Etat)) { $cl = $c.Etat; if ($cl -eq 'ECART') { $cl = $c.Gravite }; if ($cl -eq 'N/A') { $cl = 'NA' }; [void]$sb.Append('<tr class="' + $cl + '"><td>' + $c.Etat + '</td><td>' + (HtmlE $c.Categorie) + '</td><td>' + (HtmlE $c.Controle) + '</td><td>' + (HtmlE $c.Valeur) + '</td></tr>') }
    [void]$sb.Append('</table>')
    if ($script:Errors.Count -gt 0) { [void]$sb.Append('<h2>Modules en erreur</h2><ul>'); foreach ($e in $script:Errors) { [void]$sb.Append('<li>' + (HtmlE $e) + '</li>') }; [void]$sb.Append('</ul>') }
    [void]$sb.Append('</body></html>')
    [System.IO.File]::WriteAllText((Join-Path $script:Out 'rapport_audit.html'), $sb.ToString(), (New-Object System.Text.UTF8Encoding($true)))
}
