# Collecte1.ps1 - systeme, acces distants (outils + traces), persistance

$script:CopyList = New-Object System.Collections.Generic.List[object]
$script:IocSeen  = New-Object System.Collections.Generic.List[object]

function ParseUtc {
    param([string]$Text)
    $ci = [Globalization.CultureInfo]::InvariantCulture
    $st = [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal
    foreach ($fmt in 'yyyy-MM-dd HH:mm:ss', 'yyyy-MM-dd HH:mm') {
        $d = [datetime]::MinValue
        if ([datetime]::TryParseExact($Text, $fmt, $ci, $st, [ref]$d)) { return $d }
    }
    return $null
}

function Add-IocSeen {
    param([string]$Type, [string]$Valeur, [string]$Source, [string]$Quand = '', [string]$Contexte = '')
    if (-not $Valeur) { return }
    $script:IocSeen.Add([pscustomobject]@{ Type = $Type; Valeur = $Valeur; Source = $Source; Quand = $Quand; Contexte = $Contexte })
}

function Add-CopyJob {
    param([string]$Source, [string]$Dest, [switch]$Sensible, [string[]]$Filter = @('*'), [int64]$Max = 150MB, [switch]$Recurse)
    $script:CopyList.Add([pscustomobject]@{ Source = $Source; Dest = $Dest; Sensible = [bool]$Sensible; Filter = $Filter; Max = $Max; Recurse = [bool]$Recurse })
}

$script:OutilsAD = @(
    @{ Nom = 'AnyDesk'; Rx = 'anydesk' },
    @{ Nom = 'TeamViewer'; Rx = 'teamviewer' },
    @{ Nom = 'Splashtop'; Rx = 'splashtop|srserver|sragent|srmanager|srservice|srutility' },
    @{ Nom = 'ScreenConnect/ConnectWise'; Rx = 'screenconnect|connectwise' },
    @{ Nom = 'RustDesk'; Rx = 'rustdesk' },
    @{ Nom = 'UltraViewer'; Rx = 'ultraviewer' },
    @{ Nom = 'Supremo'; Rx = 'supremo' },
    @{ Nom = 'Ammyy'; Rx = 'ammyy' },
    @{ Nom = 'VNC'; Rx = 'tightvnc|ultravnc|realvnc|winvnc|vncserver|\bvnc\b' },
    @{ Nom = 'Radmin'; Rx = 'radmin' },
    @{ Nom = 'LogMeIn/GoTo'; Rx = 'logmein|gotoassist|gotomypc|goto resolve' },
    @{ Nom = 'MeshCentral'; Rx = 'meshagent|mesh agent|meshcentral' },
    @{ Nom = 'Atera'; Rx = '\batera|ateraagent' },
    @{ Nom = 'NinjaOne'; Rx = 'ninjarmm|ninjaone|ninjaremote' },
    @{ Nom = 'Action1'; Rx = 'action1' },
    @{ Nom = 'Zoho Assist'; Rx = 'zoho assist|zohoassist' },
    @{ Nom = 'DWService'; Rx = 'dwservice|dwagent' },
    @{ Nom = 'NoMachine'; Rx = 'nomachine|nxserver' },
    @{ Nom = 'Chrome Remote Desktop'; Rx = 'remoting_host|chrome remote desktop' },
    @{ Nom = 'Tunnels (Tailscale/ZeroTier/ngrok...)'; Rx = 'tailscale|zerotier|ngrok|cloudflared|frpc|chisel|netbird' },
    @{ Nom = 'PsExec'; Rx = 'psexec|paexec|winexesvc' },
    @{ Nom = 'Outils d attaque'; Rx = 'mimikatz|lazagne|procdump|rclone|megasync|cobaltstrike|meterpreter|sliver|nanocore|asyncrat|quasar|njrat|remcos' }
)
$script:OutilsRx = ($script:OutilsAD | ForEach-Object { '(' + $_.Rx + ')' }) -join '|'

function Get-OutilNom {
    param([string]$Texte)
    foreach ($o in $script:OutilsAD) { if ($Texte -match ('(?i)' + $o.Rx)) { return $o.Nom } }
    return ''
}

# ---------------------------------------------------------------------------
# SYSTEME
# ---------------------------------------------------------------------------
function Mod-Systeme {
    $os = Get-CimInstance Win32_OperatingSystem
    $cs = Get-CimInstance Win32_ComputerSystem
    $tz = $null; try { $tz = Get-TimeZone } catch { }
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add('Machine : ' + $env:COMPUTERNAME)
    $lines.Add('Domaine / groupe : ' + $cs.Domain)
    $lines.Add('Fabricant / modele : ' + $cs.Manufacturer + ' / ' + $cs.Model)
    $lines.Add('Windows : ' + $os.Caption + ' ' + $os.Version + ' (build ' + $os.BuildNumber + ')')
    $lines.Add('Installe le (UTC) : ' + (U $os.InstallDate))
    $lines.Add('Dernier demarrage (UTC) : ' + (U $os.LastBootUpTime))
    if ($tz) { $lines.Add('Fuseau horaire : ' + $tz.Id + ' (decalage ' + $tz.BaseUtcOffset + ')') }
    $lines.Add('Heure locale / UTC de la collecte : ' + (Get-Date).ToString('s') + ' / ' + (U (Get-Date)))
    $w32 = & w32tm.exe /query /status 2>$null
    if ($w32) { $lines.Add('--- Synchronisation horaire ---'); $w32 | ForEach-Object { $lines.Add($_) } }
    Save-Text $lines.ToArray() 'systeme.txt' '01_systeme'

    # Comptes
    $acc = New-Object System.Collections.Generic.List[object]
    Get-LocalUser | ForEach-Object {
        $acc.Add([pscustomobject]@{ Type = 'Utilisateur local'; Nom = $_.Name; Actif = $_.Enabled; DernierLogonUtc = (U $_.LastLogon); MdpChangeUtc = (U $_.PasswordLastSet); Info = $_.Description })
        if ($_.Enabled -and $_.PasswordLastSet -and (InWindow $_.PasswordLastSet)) {
            $sevPw = 'MOYEN'; if ($_.Name -match '(?i)laps') { $sevPw = 'INFO' }
            Add-Finding $sevPw 'Compte' ("Mot de passe du compte local '{0}' change dans la fenetre" -f $_.Name) '' (U $_.PasswordLastSet)
        }
        if ($_.Enabled -and $_.Name -match '(?i)^(support|admin\d*|test|temp|helpdesk|backup|svc.*|sys.*|tech)$') {
            Add-Finding 'FAIBLE' 'Compte' ("Compte local actif au nom generique : {0}" -f $_.Name)
        }
    }
    foreach ($g in @{ N = 'Administrateurs'; S = 'S-1-5-32-544' }, @{ N = 'Bureau a distance'; S = 'S-1-5-32-555' }, @{ N = 'Gestion a distance'; S = 'S-1-5-32-580' }) {
        $mem = Get-GroupMemberNames $g.S
        if ($null -eq $mem) { Say ('   Membres du groupe ' + $g.N + ' illisibles') 'Yellow'; continue }
        foreach ($nm in $mem) {
            $acc.Add([pscustomobject]@{ Type = ('Membre : ' + $g.N); Nom = $nm; Actif = ''; DernierLogonUtc = ''; MdpChangeUtc = ''; Info = '' })
            Add-Finding 'INFO' 'Compte' ("Membre du groupe {0} : {1}" -f $g.N, $nm)
        }
    }
    Get-CimInstance Win32_UserProfile | Where-Object { -not $_.Special } | ForEach-Object {
        $acc.Add([pscustomobject]@{ Type = 'Profil'; Nom = $_.LocalPath; Actif = $_.Loaded; DernierLogonUtc = (U $_.LastUseTime); MdpChangeUtc = ''; Info = $_.SID })
    }
    $null = Save-Csv $acc 'comptes_et_groupes.csv' '01_systeme'

    # Configuration
    $cfg = New-Object System.Collections.Generic.List[string]
    $rdp = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server').fDenyTSConnections
    $cfg.Add('RDP fDenyTSConnections (0 = bureau a distance ACTIF) : ' + $rdp)
    if ($rdp -eq 0) { Add-Finding 'MOYEN' 'Configuration' 'Bureau a distance (RDP) active sur ce poste' }
    Get-Service WinRM, sshd, TermService, RemoteRegistry | ForEach-Object {
        $cfg.Add(('Service {0} : {1} / {2}' -f $_.Name, $_.Status, $_.StartType))
        if ($_.Name -in 'sshd' -and $_.Status -eq 'Running') { Add-Finding 'MOYEN' 'Configuration' 'Serveur OpenSSH (sshd) en cours d''execution' }
    }
    $mp = Get-MpPreference
    if ($mp) {
        $cfg.Add('--- Windows Defender ---')
        $cfg.Add('ExclusionPath : ' + ($mp.ExclusionPath -join '; '))
        $cfg.Add('ExclusionExtension : ' + ($mp.ExclusionExtension -join '; '))
        $cfg.Add('ExclusionProcess : ' + ($mp.ExclusionProcess -join '; '))
        $cfg.Add('DisableRealtimeMonitoring : ' + $mp.DisableRealtimeMonitoring)
        if ($mp.ExclusionPath -or $mp.ExclusionProcess -or $mp.ExclusionExtension) {
            Add-Finding 'MOYEN' 'Defender' 'Exclusions Defender configurees' '' ((@($mp.ExclusionPath) + @($mp.ExclusionProcess) + @($mp.ExclusionExtension)) -join '; ')
        }
        if ($mp.DisableRealtimeMonitoring) { Add-Finding 'MOYEN' 'Defender' 'Protection en temps reel Defender desactivee (normal si un autre antivirus est actif)' }
    }
    $cfg.Add('--- Detections Defender ---')
    Get-MpThreatDetection | ForEach-Object {
        $cfg.Add(('{0} menace {1} : {2}' -f (U $_.InitialDetectionTime), $_.ThreatID, ($_.Resources -join ',')))
        Add-Finding 'MOYEN' 'Defender' ("Detection Defender le {0} (menace {1})" -f (U $_.InitialDetectionTime), $_.ThreatID) (($_.Resources -join ',')) ''
    }
    $cfg.Add('--- portproxy ---')
    $pp = & netsh.exe interface portproxy show all 2>$null
    $pp | ForEach-Object { $cfg.Add($_) }
    if (@($pp | Where-Object { $_ -match '\d+\.\d+\.\d+\.\d+' }).Count -gt 0) { Add-Finding 'ELEVE' 'Reseau' 'Redirection de ports (portproxy) configuree' '' (($pp | Where-Object { $_ -match '\d' }) -join ' / ') }
    $cfg.Add('--- Proxy WinHTTP ---')
    (& netsh.exe winhttp show proxy 2>$null) | ForEach-Object { $cfg.Add($_) }
    $cfg.Add('--- Fichier hosts (lignes actives) ---')
    Get-Content 'C:\Windows\System32\drivers\etc\hosts' | Where-Object { $_.Trim() -and -not $_.Trim().StartsWith('#') } | ForEach-Object {
        $cfg.Add($_); Add-Finding 'MOYEN' 'Reseau' ('Entree dans le fichier hosts : ' + $_.Trim())
    }
    $cfg.Add('--- Partages SMB ---')
    Get-SmbShare | ForEach-Object { $cfg.Add(('{0} -> {1}' -f $_.Name, $_.Path)) }
    $cfg.Add('--- Audit : creation de processus (4688) ---')
    # GUID de la sous-categorie : le nom ("Process Creation") est traduit sur un Windows en francais
    $ap = & auditpol.exe /get /subcategory:'{0CCE922B-69AE-11D9-BED3-505054503030}' 2>$null
    $ap | ForEach-Object { $cfg.Add($_) }
    if (-not ($ap -match '(Succ|Success|Réussite|Reussite)')) {
        Add-Finding 'MOYEN' 'Journalisation' 'Audit de creation de processus (4688) inactif : les programmes lances ne sont pas traces' '' 'Voir Outils\Activer-Journalisation.ps1'
    }
    Save-Text $cfg.ToArray() 'configuration.txt' '01_systeme'

    $apps = foreach ($u in 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall') {
        Get-ChildItem $u | ForEach-Object {
            $p = Get-ItemProperty -LiteralPath $_.PSPath
            if ($p.DisplayName) { [pscustomobject]@{ Nom = $p.DisplayName; Version = $p.DisplayVersion; Editeur = $p.Publisher; DateInstall = $p.InstallDate; Dossier = $p.InstallLocation } }
        }
    }
    $null = Save-Csv ($apps | Sort-Object Nom) 'logiciels_installes.csv' '01_systeme'
    $null = Save-Csv (Get-HotFix | Select-Object HotFixID, Description, @{ n = 'InstalleLe'; e = { $_.InstalledOn } }) 'correctifs.csv' '01_systeme'
}

# ---------------------------------------------------------------------------
# ACCES DISTANTS : inventaire des outils + analyse des traces
# ---------------------------------------------------------------------------
function Mod-AccesDistant {
    $inv = New-Object System.Collections.Generic.List[object]
    $profiles = @(Get-UserProfiles)

    # Processus
    Get-CimInstance Win32_Process | ForEach-Object {
        $txt = '{0} {1}' -f $_.Name, $_.ExecutablePath
        if ($txt -match ('(?i)' + $script:OutilsRx)) {
            $tool = Get-OutilNom $txt
            $sig = Get-SignInfo $_.ExecutablePath
            $inv.Add([pscustomobject]@{ Outil = $tool; Source = 'Processus actif'; Nom = $_.Name; Etat = 'En cours'; Chemin = $_.ExecutablePath; Signature = $(if ($sig) { $sig.Statut } else { '' }); Detail = ('PID ' + $_.ProcessId) })
            $sev = 'MOYEN'
            if (Test-RiskPath $_.ExecutablePath) { $sev = 'ELEVE' }
            Add-Finding $sev 'Acces distant' ("{0} en cours d'execution ({1}, PID {2})" -f $tool, $_.Name, $_.ProcessId) $_.ExecutablePath 'A rapprocher de la liste des outils autorises de la pharmacie'
        }
    }
    # Services
    $svcs = @(Get-CimInstance Win32_Service | Where-Object { ('{0} {1} {2}' -f $_.Name, $_.DisplayName, $_.PathName) -match ('(?i)' + $script:OutilsRx) })
    foreach ($s in $svcs) {
        $tool = Get-OutilNom ('{0} {1} {2}' -f $s.Name, $s.DisplayName, $s.PathName)
        $exe = Get-ExePath $s.PathName
        $sig = Get-SignInfo $exe
        $inv.Add([pscustomobject]@{ Outil = $tool; Source = 'Service'; Nom = $s.Name; Etat = ('{0} / {1}' -f $s.State, $s.StartMode); Chemin = $exe; Signature = $(if ($sig) { $sig.Statut } else { '' }); Detail = $s.DisplayName })
        $sev = 'MOYEN'; if ($s.StartMode -ne 'Auto') { $sev = 'FAIBLE' }
        if (Test-RiskPath $exe) { $sev = 'ELEVE' }
        Add-Finding $sev 'Acces distant' ("Service {0} : {1} ({2}/{3})" -f $tool, $s.Name, $s.State, $s.StartMode) $exe 'A rapprocher de la liste des outils autorises de la pharmacie'
    }
    # Logiciels installes
    foreach ($u in 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall') {
        Get-ChildItem $u | ForEach-Object {
            $p = Get-ItemProperty -LiteralPath $_.PSPath
            if ($p.DisplayName -and ($p.DisplayName -match ('(?i)' + $script:OutilsRx))) {
                $inv.Add([pscustomobject]@{ Outil = (Get-OutilNom $p.DisplayName); Source = 'Logiciel installe'; Nom = $p.DisplayName; Etat = ('version ' + $p.DisplayVersion); Chemin = $p.InstallLocation; Signature = ''; Detail = ('Editeur : ' + $p.Publisher + ' ; installe le ' + $p.InstallDate) })
                Add-Finding 'FAIBLE' 'Acces distant' ("Logiciel installe : {0} {1}" -f $p.DisplayName, $p.DisplayVersion) $p.InstallLocation ('Installe le ' + $p.InstallDate)
            }
        }
    }
    # Fichiers et dossiers (niveau 1 ; niveau 3 pour Temp, Telechargements, Bureau)
    $bases = New-Object System.Collections.Generic.List[object]
    foreach ($b in 'C:\Program Files', 'C:\Program Files (x86)', 'C:\ProgramData') { $bases.Add(@{ P = $b; D = 0 }) }
    foreach ($pr in $profiles) {
        foreach ($sub in 'AppData\Roaming', 'AppData\Local', 'Documents') { $bases.Add(@{ P = (Join-Path $pr.FullName $sub); D = 0 }) }
        foreach ($sub in 'AppData\Local\Temp', 'Downloads', 'Desktop') { $bases.Add(@{ P = (Join-Path $pr.FullName $sub); D = 2 }) }
    }
    $bases.Add(@{ P = 'C:\Windows\Temp'; D = 2 }); $bases.Add(@{ P = 'C:\Users\Public'; D = 2 })
    foreach ($b in $bases) {
        if (-not (Test-Path -LiteralPath $b.P)) { continue }
        $items = if ($b.D -gt 0) { Get-ChildItem -LiteralPath $b.P -Force -Recurse -Depth $b.D -ErrorAction SilentlyContinue } else { Get-ChildItem -LiteralPath $b.P -Force -ErrorAction SilentlyContinue }
        foreach ($it in $items) {
            if (Test-OwnPath $it.FullName) { continue }
            if ($it.Name -match ('(?i)' + $script:OutilsRx)) {
                $tool = Get-OutilNom $it.Name
                $inv.Add([pscustomobject]@{ Outil = $tool; Source = $(if ($it.PSIsContainer) { 'Dossier' } else { 'Fichier' }); Nom = $it.Name; Etat = ('cree ' + (U $it.CreationTimeUtc) + ' ; modifie ' + (U $it.LastWriteTimeUtc)); Chemin = $it.FullName; Signature = ''; Detail = '' })
                $risky = Test-RiskPath $it.FullName
                if ($it.Extension -match '(?i)\.(docx?|xlsx?|pptx?|pdf|odt|md|lnk)$') {
                    # document ou raccourci dont le NOM contient un mot cle : sans interet
                } elseif ($risky -and -not $it.PSIsContainer -and $it.Extension -match '(?i)\.(exe|msi|zip)$') {
                    Add-Finding 'ELEVE' 'Acces distant' ("Programme d'acces distant ({0}) dans un dossier utilisateur ou temporaire" -f $tool) $it.FullName ('Cree le ' + (U $it.CreationTimeUtc))
                } elseif ($risky -and -not $it.PSIsContainer -and $it.Extension -match '(?i)\.(bat|ps1|vbs)$') {
                    Add-Finding 'MOYEN' 'Acces distant' ("Script mentionnant {0} dans un dossier utilisateur ou temporaire" -f $tool) $it.FullName ('Cree le ' + (U $it.CreationTimeUtc))
                } elseif ($it.FullName -match $script:UserDirRx -and -not $it.PSIsContainer) {
                    Add-Finding 'MOYEN' 'Acces distant' ("Fichier {0} dans un profil utilisateur" -f $tool) $it.FullName ('Cree le ' + (U $it.CreationTimeUtc))
                }
            }
        }
    }
    $null = Save-Csv ($inv | Sort-Object Outil, Source) 'inventaire_outils_acces_distant.csv' '02_acces_distant'
    Say ("   {0} elements d'acces distant recenses" -f $inv.Count)

    # ---------------- AnyDesk ----------------
    $adDirs = New-Object System.Collections.Generic.List[object]
    $adDirs.Add(@{ P = 'C:\ProgramData\AnyDesk'; Tag = 'ProgramData' })
    foreach ($pr in $profiles) {
        $adDirs.Add(@{ P = (Join-Path $pr.FullName 'AppData\Roaming\AnyDesk'); Tag = ('AppData_' + $pr.Name) })
    }
    $adConn = New-Object System.Collections.Generic.List[object]; $adEv = New-Object System.Collections.Generic.List[object]
    $adCT = New-Object System.Collections.Generic.List[object]; $adTr = New-Object System.Collections.Generic.List[object]
    foreach ($d in $adDirs) {
        if (-not (Test-Path -LiteralPath $d.P)) { continue }
        Add-CopyJob -Source $d.P -Dest ('anydesk\' + $d.Tag) -Filter @('*.trace', '*.txt', '*.cache')
        Add-CopyJob -Source $d.P -Dest ('anydesk\' + $d.Tag) -Filter @('*.conf') -Sensible
        Get-ChildItem -LiteralPath $d.P -Filter '*.trace' -File -Force | ForEach-Object {
            $r = ConvertFrom-AnyDeskTrace $_.FullName ($d.Tag + '\' + $_.Name)
            foreach ($c in $r.Connexions) { $adConn.Add($c) }
            foreach ($e in $r.Evenements) { $adEv.Add($e) }
        }
        $ct = Join-Path $d.P 'connection_trace.txt'
        if (Test-Path -LiteralPath $ct) { ConvertFrom-AnyDeskConnTrace $ct ($d.Tag + '\connection_trace.txt') | ForEach-Object { $adCT.Add($_) } }
        $ft = Join-Path $d.P 'file_transfer_trace.txt'
        if (Test-Path -LiteralPath $ft) { ConvertFrom-AnyDeskTransfer $ft ($d.Tag + '\file_transfer_trace.txt') | ForEach-Object { $adTr.Add($_) } }
    }
    # Dedoublonnage (la meme ligne peut figurer dans plusieurs traces tournantes)
    $adConn = @($adConn | Sort-Object DebutUtc, IdDistant -Unique)
    $null = Save-Csv ($adConn | Sort-Object DebutUtc) 'anydesk_connexions_entrantes.csv' '02_acces_distant'
    $null = Save-Csv ($adEv | Sort-Object TempsUtc, Message -Unique) 'anydesk_evenements_cles.csv' '02_acces_distant'
    $null = Save-Csv ($adCT | Sort-Object DateUtc) 'anydesk_connection_trace.csv' '02_acces_distant'
    $null = Save-Csv ($adTr | Sort-Object DateUtc) 'anydesk_transferts_fichiers.csv' '02_acces_distant'
    $nbIn = 0
    foreach ($c in $adConn) {
        Add-IocSeen 'AnyDesk ID distant' $c.IdDistant ('AnyDesk ' + $c.Origine) $c.DebutUtc $c.Resultat
        Add-IocSeen 'Adresse IP (AnyDesk)' $c.IpSource ('AnyDesk ' + $c.Origine) $c.DebutUtc ('ID ' + $c.IdDistant + ' ; relais ' + $c.Relais)
        Add-IocSeen 'Empreinte AnyDesk' $c.Empreinte ('AnyDesk ' + $c.Origine) $c.DebutUtc ('ID ' + $c.IdDistant)
        $dt = ParseUtc $c.DebutUtc
        if ($dt -and (InWindow $dt)) {
            $nbIn++
            Add-Finding 'MOYEN' 'AnyDesk' ("Connexion entrante {0} depuis ID {1}, IP {2} ({3})" -f $c.DebutUtc, $c.IdDistant, $c.IpSource, ($c.Resultat -replace '\s+', ' ')) $c.Origine 'Heures UTC. Verifier que cet ID est connu de la pharmacie'
        }
    }
    foreach ($c in $adCT) { Add-IocSeen 'AnyDesk ID distant' $c.IdDistant ('AnyDesk ' + $c.Origine) $c.DateUtc ($c.Sens + ' ' + $c.Authentification) }
    foreach ($t in $adTr) {
        $dt = ParseUtc $t.DateUtc
        if ($dt -and (InWindow $dt) -and $t.Etat -eq 'start') {
            $sev = 'MOYEN'; if ($t.Sens -eq 'upload') { $sev = 'ELEVE' }
            Add-Finding $sev 'AnyDesk' ("Transfert de fichier ({0}) le {1} : {2}" -f $t.Sens, $t.DateUtc, $t.Fichier) $t.Origine ($t.Detail)
        }
    }
    foreach ($e in $adEv) {
        if ($e.Message -match '--uninstall|--remove|The service has been uninstalled') {
            Add-Finding 'MOYEN' 'AnyDesk' ("Desinstallation d'AnyDesk tracee le {0}" -f $e.TempsUtc) $e.Origine $e.Message
        }
        if ($e.Message -match '^New user data\. Client-ID: (\d+)') { Add-IocSeen 'AnyDesk ID de ce poste' $Matches[1] ('AnyDesk ' + $e.Origine) $e.TempsUtc '' }
    }
    if ($adConn.Count -gt 0) {
        $ids = ($adConn | Group-Object IdDistant | ForEach-Object { '{0} ({1} connexions)' -f $_.Name, $_.Count }) -join ' ; '
        Add-Finding 'INFO' 'AnyDesk' ("{0} connexions entrantes tracees, ID distants : {1}" -f $adConn.Count, $ids)
    }

    # ---------------- TeamViewer ----------------
    $tvDirs = New-Object System.Collections.Generic.List[object]
    foreach ($b in 'C:\Program Files\TeamViewer', 'C:\Program Files (x86)\TeamViewer') { $tvDirs.Add(@{ P = $b; Tag = ('ProgramFiles_' + ($b -replace '[^A-Za-z0-9]', '')) }) }
    foreach ($pr in $profiles) { $tvDirs.Add(@{ P = (Join-Path $pr.FullName 'AppData\Roaming\TeamViewer'); Tag = ('AppData_' + $pr.Name) }) }
    $tv = New-Object System.Collections.Generic.List[object]
    foreach ($d in $tvDirs) {
        if (-not (Test-Path -LiteralPath $d.P)) { continue }
        Add-CopyJob -Source $d.P -Dest ('teamviewer\' + $d.Tag) -Filter @('Connections*.txt', '*Logfile*.log') -Max 50MB
        Get-ChildItem -LiteralPath $d.P -Filter 'Connections*.txt' -File -Force | ForEach-Object {
            ConvertFrom-TeamViewerConnections $_.FullName ($d.Tag + '\' + $_.Name) | ForEach-Object { $tv.Add($_) }
        }
    }
    $null = Save-Csv $tv 'teamviewer_connexions.csv' '02_acces_distant'
    foreach ($c in $tv) {
        Add-IocSeen 'TeamViewer ID distant' $c.IdDistant ('TeamViewer ' + $c.Origine) $c.Debut $c.Nom
        $dt = [datetime]::MinValue; $ok = [datetime]::TryParseExact([string]$c.Debut, 'dd-MM-yyyy HH:mm:ss', [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeLocal, [ref]$dt)
        if ($ok -and (InWindow $dt)) { Add-Finding 'MOYEN' 'TeamViewer' ("Connexion {0} de {1} ({2}) le {3}" -f $c.Type, $c.Nom, $c.IdDistant, $c.Debut) $c.Origine 'Heure locale du poste' }
    }

    # ---------------- Splashtop ----------------
    $sp = New-Object System.Collections.Generic.List[object]
    foreach ($d in 'C:\ProgramData\Splashtop\Splashtop Remote Server\log', 'C:\ProgramData\Splashtop\Splashtop Software Updater\log', 'C:\Program Files (x86)\Splashtop\Splashtop Remote Server\log') {
        if (-not (Test-Path -LiteralPath $d)) { continue }
        $tag = 'log_' + ($d -replace '[^A-Za-z0-9]', '').Substring(0, [Math]::Min(40, ($d -replace '[^A-Za-z0-9]', '').Length))
        Add-CopyJob -Source $d -Dest ('splashtop\' + $tag) -Filter @('SPLog*', 'agent_log*', '*.log', '*.txt') -Max 30MB -Recurse
        Get-ChildItem -LiteralPath $d -Filter 'SPLog*' -File -Force -Recurse | ForEach-Object {
            ConvertFrom-SplashtopLog $_.FullName $_.Name | ForEach-Object { $sp.Add($_) }
        }
    }
    $null = Save-Csv $sp 'splashtop_sessions_et_transferts.csv' '02_acces_distant'
    foreach ($s in $sp) {
        if ($s.Ip -and $s.Ip -notmatch '^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.)') { Add-IocSeen 'Adresse IP (Splashtop)' $s.Ip 'Splashtop' $s.Temps $s.Client }
        if ($s.Ligne -match 'UploadRequest') { Add-Finding 'ELEVE' 'Splashtop' ("Envoi de fichier (upload) via Splashtop : {0}" -f $s.Fichier) $s.Origine $s.Temps }
    }
    if ($sp.Count -gt 0) { Add-Finding 'INFO' 'Splashtop' ("{0} lignes de session/transfert extraites (voir splashtop_sessions_et_transferts.csv)" -f $sp.Count) }

    # ---------------- ScreenConnect / ConnectWise Control ----------------
    $sc = New-Object System.Collections.Generic.List[object]
    foreach ($s in ($svcs | Where-Object { $_.PathName -match '(?i)screenconnect' })) {
        $i = Get-ScreenConnectInfo $s.PathName
        $dir = Get-ChildItem 'C:\Program Files (x86)', 'C:\Program Files' -Directory -Filter 'ScreenConnect Client*' -ErrorAction SilentlyContinue | Select-Object -First 1
        $sc.Add([pscustomobject]@{ Service = $s.Name; Etat = $s.State; Demarrage = $s.StartMode; Hote = $i.Hote; Port = $i.Port; Instance = $i.Instance; Dossier = $(if ($dir) { $dir.FullName } else { '' }); InstalleUtc = $(if ($dir) { U $dir.CreationTimeUtc } else { '' }) })
        Add-IocSeen 'Relais ScreenConnect' $i.Hote 'Service ScreenConnect' $(if ($dir) { U $dir.CreationTimeUtc } else { '' }) ('instance ' + $i.Instance)
        Add-Finding 'MOYEN' 'ScreenConnect' ("Client ScreenConnect : instance {0}, relais {1}" -f $i.Instance, $i.Hote) '' ('A confirmer avec le prestataire proprietaire de cette instance ; installe le ' + $(if ($dir) { U $dir.CreationTimeUtc } else { '?' }))
    }
    $null = Save-Csv $sc 'screenconnect_instances.csv' '02_acces_distant'
    foreach ($d in (Get-ChildItem 'C:\ProgramData' -Directory -Filter 'ScreenConnect Client*' -ErrorAction SilentlyContinue)) {
        Add-CopyJob -Source $d.FullName -Dest ('screenconnect\' + ($d.Name -replace '[^A-Za-z0-9]', '_')) -Filter @('*.log', '*.txt') -Max 30MB
    }

    # Historique PowerShell des utilisateurs
    foreach ($pr in $profiles) {
        $h = Join-Path $pr.FullName 'AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'
        # l'historique contient souvent des mots de passe / jetons tapes en clair : jamais dans l'archive transmissible
        if (Test-Path -LiteralPath $h) { Add-CopyJob -Source $h -Dest ('powershell\' + $pr.Name) -Sensible }
    }
}

# ---------------------------------------------------------------------------
# PERSISTANCE
# ---------------------------------------------------------------------------
if (-not ('RegWalk' -as [type]) -and $env:OS -eq 'Windows_NT') {
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;
public static class RegWalk {
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
    static extern int RegQueryInfoKey(SafeRegistryHandle hKey, StringBuilder lpClass, IntPtr lpcbClass, IntPtr lpReserved,
        IntPtr lpcSubKeys, IntPtr lpcbMaxSubKeyLen, IntPtr lpcbMaxClassLen, IntPtr lpcValues, IntPtr lpcbMaxValueNameLen,
        IntPtr lpcbMaxValueLen, IntPtr lpcbSecurityDescriptor, out long lpftLastWriteTime);
    public static long LastWrite(RegistryKey k) {
        long ft;
        int r = RegQueryInfoKey(k.Handle, null, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero,
                                IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out ft);
        return r == 0 ? ft : 0;
    }
    public static void Walk(RegistryKey k, string path, long lo, long hi, List<string> res) {
        try {
            long ft = LastWrite(k);
            if (ft >= lo && ft <= hi) { res.Add(DateTime.FromFileTimeUtc(ft).ToString("s") + "\t" + path); }
            foreach (string n in k.GetSubKeyNames()) {
                try { using (RegistryKey s = k.OpenSubKey(n)) { if (s != null) { Walk(s, path + "\\" + n, lo, hi, res); } } } catch { }
            }
        } catch { }
    }
}
'@
}

function Mod-Persistance {
    # Cles Run / Winlogon
    $runKeys = New-Object System.Collections.Generic.List[string]
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run' | ForEach-Object { $runKeys.Add($_) }
    foreach ($sid in [Microsoft.Win32.Registry]::Users.GetSubKeyNames() | Where-Object { $_ -match $script:UserSidRx }) {
        foreach ($sub in 'Run', 'RunOnce') { $runKeys.Add("Registry::HKEY_USERS\$sid\Software\Microsoft\Windows\CurrentVersion\$sub") }
        $runKeys.Add("Registry::HKEY_USERS\$sid\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run")
    }
    $runOut = New-Object System.Collections.Generic.List[object]
    foreach ($rk in $runKeys) {
        $p = Get-ItemProperty -LiteralPath $rk
        if (-not $p) { continue }
        foreach ($np in ($p.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' })) {
            $val = [string]$np.Value
            $exe = Get-ExePath $val
            $sig = Get-SignInfo $exe
            $runOut.Add([pscustomobject]@{ Cle = ($rk -replace 'Registry::', ''); Nom = $np.Name; Valeur = $val; Signature = $(if ($sig) { $sig.Statut } else { '' }); Signataire = $(if ($sig) { $sig.Signataire } else { '' }) })
            $sev = 'INFO'; $why = @()
            if (Test-RiskPath $exe) { $sev = 'ELEVE'; $why += 'chemin a risque' }
            if ($val -match '(?i)(-enc\b|encodedcommand|powershell|mshta|wscript|cscript|cmd(\.exe)?\s+/c|https?://)') { $sev = 'ELEVE'; $why += 'commande suspecte' }
            if ($sig -and -not $sig.Valide -and $sev -eq 'INFO') { $sev = 'MOYEN'; $why += ('signature : ' + $sig.Statut) }
            if ($sev -ne 'INFO') { Add-Finding $sev 'Demarrage automatique' ("{0} : {1}" -f ($rk -replace 'Registry::HKEY_USERS\\S-[0-9-]+', 'HKU'), $np.Name) $exe (($val + ' | ' + ($why -join '; '))) }
        }
    }
    $null = Save-Csv $runOut 'cles_run.csv' '03_persistance'
    # profils dont la ruche n'est pas chargee (utilisateur non connecte) : leurs cles ne sont pas lisibles sans modifier
    # le poste (chargement de ruche) -> on le dit. Le mode VSS copie leurs NTUSER.DAT pour une analyse ulterieure.
    $unl = @(Get-CimInstance Win32_UserProfile | Where-Object { -not $_.Special -and -not $_.Loaded -and $_.SID -match $script:UserSidRx } | ForEach-Object { Split-Path -Leaf $_.LocalPath })
    if ($unl.Count -gt 0) { Add-Finding 'INFO' 'Couverture' ("Utilisateurs non connectes : demarrage automatique (Run), UserAssist et RunMRU non lus pour {0}" -f ($unl -join ', ')) '' 'Utiliser le mode VSS (copie des NTUSER.DAT) ou relancer la collecte avec ces utilisateurs connectes' }

    $wl = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    if ($wl) {
        if ($wl.Shell -and $wl.Shell -ne 'explorer.exe') { Add-Finding 'ELEVE' 'Winlogon' ('Shell modifie : ' + $wl.Shell) }
        if ($wl.Userinit -and $wl.Userinit -notmatch '^(?i)C:\\Windows\\system32\\userinit\.exe,?$') { Add-Finding 'ELEVE' 'Winlogon' ('Userinit modifie : ' + $wl.Userinit) }
    }
    Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' | ForEach-Object {
        $d = (Get-ItemProperty $_.PSPath).Debugger
        if ($d) { Add-Finding 'ELEVE' 'Detournement IFEO' ("Debugger sur {0}" -f $_.PSChildName) '' $d }
    }
    $ai = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows'
    if ($ai.AppInit_DLLs) { Add-Finding 'ELEVE' 'AppInit_DLLs' ([string]$ai.AppInit_DLLs) }

    # Dossiers Demarrage
    $startup = New-Object System.Collections.Generic.List[object]
    $dirs = @('C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp') + @(Get-UserProfiles | ForEach-Object { Join-Path $_.FullName 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup' })
    $wsh = $null; try { $wsh = New-Object -ComObject WScript.Shell } catch { }
    foreach ($d in $dirs) {
        Get-ChildItem -LiteralPath $d -File -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne 'desktop.ini' } | ForEach-Object {
            $target = ''
            if ($wsh -and $_.Extension -eq '.lnk') { try { $target = $wsh.CreateShortcut($_.FullName).TargetPath } catch { } }
            $startup.Add([pscustomobject]@{ Fichier = $_.FullName; Cible = $target; CreeUtc = (U $_.CreationTimeUtc); ModifieUtc = (U $_.LastWriteTimeUtc) })
            $sev = 'FAIBLE'; if (InWindow $_.CreationTimeUtc) { $sev = 'MOYEN' }
            if ($_.Extension -match '(?i)\.(bat|cmd|vbs|js|ps1|hta|exe)$') { $sev = 'MOYEN' }
            Add-Finding $sev 'Dossier Demarrage' $_.Name $_.FullName ('Cible : ' + $target + ' ; cree le ' + (U $_.CreationTimeUtc))
        }
    }
    $null = Save-Csv $startup 'dossiers_demarrage.csv' '03_persistance'

    # Taches planifiees
    $tasks = New-Object System.Collections.Generic.List[object]
    Get-ScheduledTask | ForEach-Object {
        $t = $_
        $info = $t | Get-ScheduledTaskInfo
        $act = ($t.Actions | ForEach-Object { ($_.Execute + ' ' + $_.Arguments).Trim() }) -join ' | '
        $tasks.Add([pscustomobject]@{ Tache = ($t.TaskPath + $t.TaskName); Etat = $t.State; Compte = $t.Principal.UserId; EnregistreeLe = [string]$t.Date; Auteur = $t.Author; Action = $act; DerniereExec = [string]$info.LastRunTime; Prochaine = [string]$info.NextRunTime })
        # les taches sous \Microsoft\ sont aussi examinees (cachette classique), mais seulement sur des criteres forts
        $isMs = ($t.TaskPath -match '^\\Microsoft\\')
        if ($true) {
            foreach ($a in $t.Actions) {
                if (-not $a.Execute) { continue }
                $exe = [Environment]::ExpandEnvironmentVariables($a.Execute).Trim('"')
                $full = ($exe + ' ' + $a.Arguments)
                if ($isMs) {
                    $whyMs = @()
                    if (Test-RiskPath $exe) { $whyMs += 'binaire dans un dossier a risque' }
                    if ($full -match '(?i)(-enc\b|encodedcommand|frombase64|downloadstring|\biex\b|mshta|https?://)') { $whyMs += 'arguments suspects' }
                    if ($whyMs.Count -gt 0) { Add-Finding 'ELEVE' 'Tache planifiee' ("{0}{1} [{2}] (dossier Microsoft)" -f $t.TaskPath, $t.TaskName, $t.State) $exe ((($a.Arguments) + ' | ' + ($whyMs -join '; ')).Trim(' |')) }
                    continue
                }
                $sig = Get-SignInfo $exe
                $sev = 'INFO'; $why = @()
                if (Test-RiskPath $exe) { $sev = 'ELEVE'; $why += 'binaire dans un dossier a risque' }
                if ($full -match '(?i)(-enc\b|encodedcommand|frombase64|downloadstring|\biex\b|-w(indowstyle)?\s+hidden|mshta|wscript|cscript|\.vbs|https?://)') { $sev = 'ELEVE'; $why += 'arguments suspects' }
                if ($sig -and -not $sig.Valide -and $sev -eq 'INFO') { $sev = 'MOYEN'; $why += ('signature : ' + $sig.Statut) }
                if ($t.Date -and $sev -eq 'INFO') { $dd = $null; try { $dd = [datetime]::Parse([string]$t.Date, [Globalization.CultureInfo]::InvariantCulture) } catch { }; if ($dd -and (InWindow $dd)) { $sev = 'MOYEN'; $why += 'creee dans la fenetre' } }
                if ($sev -ne 'INFO') { Add-Finding $sev 'Tache planifiee' ("{0}{1} [{2}]" -f $t.TaskPath, $t.TaskName, $t.State) $exe ((($a.Arguments) + ' | ' + ($why -join '; ')).Trim(' |')) }
            }
        }
    }
    $null = Save-Csv $tasks 'taches_planifiees.csv' '03_persistance'
    Add-CopyJob -Source 'C:\Windows\System32\Tasks' -Dest 'taches_xml' -Filter @('*') -Max 2MB -Recurse

    # Services (dates de modification de la cle = indice de creation)
    $svcRows = New-Object System.Collections.Generic.List[object]
    Get-CimInstance Win32_Service | ForEach-Object {
        $exe = Get-ExePath $_.PathName
        $sig = Get-SignInfo $exe
        $last = ''
        try { $k = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SYSTEM\CurrentControlSet\Services\' + $_.Name); if ($k) { $ft = [RegWalk]::LastWrite($k); if ($ft -gt 0) { $last = U ([DateTime]::FromFileTimeUtc($ft)) }; $k.Dispose() } } catch { }
        $svcRows.Add([pscustomobject]@{ Nom = $_.Name; Affichage = $_.DisplayName; Etat = $_.State; Demarrage = $_.StartMode; Compte = $_.StartName; Chemin = $_.PathName; Signature = $(if ($sig) { $sig.Statut } else { '' }); CleModifieeUtc = $last })
        $isStd = ($exe -match '^(?i)C:\\Windows\\(System32|SysWOW64)\\') -or ($exe -match '^(?i)C:\\Program Files')
        $sev = 'INFO'; $why = @()
        if (Test-RiskPath $exe) { $sev = 'ELEVE'; $why += 'chemin a risque' }
        elseif (-not $isStd -and $exe) { $sev = 'FAIBLE'; $why += 'hors Program Files / System32' }
        if ($sig -and -not $sig.Valide -and $exe) { if ($sev -ne 'ELEVE') { $sev = 'MOYEN' }; $why += ('signature : ' + $sig.Statut) }
        if ($_.PathName -match '(?i)(cmd(\.exe)?\s+/c|powershell|-enc\b|mshta|%comspec%)') { $sev = 'ELEVE'; $why += 'commande shell dans le service' }
        if ($last -and (InWindow ([datetime]::Parse($last + 'Z').ToUniversalTime())) -and $sev -in 'INFO', 'FAIBLE') { $sev = 'MOYEN'; $why += ('cle de service modifiee le ' + $last) }
        if ($sev -ne 'INFO') { Add-Finding $sev 'Service' ("{0} [{1}/{2}]" -f $_.Name, $_.State, $_.StartMode) $exe ($why -join '; ') }
    }
    $null = Save-Csv $svcRows 'services.csv' '03_persistance'

    # WMI, BITS, profils PowerShell
    $wmi = New-Object System.Collections.Generic.List[object]
    foreach ($cls in '__EventFilter', 'CommandLineEventConsumer', 'ActiveScriptEventConsumer', '__FilterToConsumerBinding') {
        Get-CimInstance -Namespace root\subscription -ClassName $cls | ForEach-Object {
            $wmi.Add([pscustomobject]@{ Classe = $cls; Detail = (($_ | Out-String).Trim() -replace '\s+', ' ') })
            # seuls les consommateurs qui executent quelque chose sont critiques ; la liaison "SCM Event Log"
            # est installee d'origine par Windows (elle ne doit pas declencher d'alerte sur un poste sain)
            if ($cls -in 'CommandLineEventConsumer', 'ActiveScriptEventConsumer') { Add-Finding 'ELEVE' 'Persistance WMI' ("{0} : {1}" -f $cls, $_.Name) '' (($_.CommandLineTemplate + $_.ScriptText)) }
            elseif ($cls -eq '__FilterToConsumerBinding' -and ($_ | Out-String) -notmatch 'SCM Event Log') { Add-Finding 'MOYEN' 'Persistance WMI' ('Liaison filtre/consommateur WMI non standard') '' ((($_ | Out-String).Trim() -replace '\s+', ' ')) }
        }
    }
    $null = Save-Csv $wmi 'wmi_abonnements.csv' '03_persistance'
    if (Get-Command Get-BitsTransfer -ErrorAction SilentlyContinue) {
        Get-BitsTransfer -AllUsers | ForEach-Object { Add-Finding 'ELEVE' 'Job BITS' $_.DisplayName '' (($_.FileList | ForEach-Object { $_.RemoteName }) -join ' ; ') }
    }
    $profs = @('C:\Windows\System32\WindowsPowerShell\v1.0\profile.ps1', 'C:\Windows\System32\WindowsPowerShell\v1.0\Microsoft.PowerShell_profile.ps1')
    foreach ($pr in (Get-UserProfiles)) { $profs += (Join-Path $pr.FullName 'Documents\WindowsPowerShell\profile.ps1'); $profs += (Join-Path $pr.FullName 'Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1') }
    foreach ($p in $profs) { if (Test-Path -LiteralPath $p) { Add-Finding 'MOYEN' 'Profil PowerShell' 'Un profil PowerShell existe (execute a chaque ouverture)' $p; Add-CopyJob -Source $p -Dest 'powershell\profils' } }
}
