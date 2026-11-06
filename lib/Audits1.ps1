# Audits1.ps1 - infrastructure des controles + durcissement Windows + correctifs

$script:Checks = New-Object System.Collections.Generic.List[object]

function Add-Check {
    # Ok = $true (conforme) / $false (ecart) / $null (non verifiable)
    param([string]$Cat, [string]$Ctrl, $Ok, [string]$Val = '', [string]$Reco = '', [ValidateSet('ELEVE', 'MOYEN', 'FAIBLE')][string]$Sev = 'MOYEN')
    $state = 'N/A'
    if ($Ok -eq $true) { $state = 'OK' } elseif ($Ok -eq $false) { $state = 'ECART' }
    $w = 2; if ($Sev -eq 'ELEVE') { $w = 3 } elseif ($Sev -eq 'FAIBLE') { $w = 1 }
    $script:Checks.Add([pscustomobject]@{ Categorie = $Cat; Controle = $Ctrl; Etat = $state; Valeur = $Val; Gravite = $Sev; Poids = $w; Recommandation = $Reco })
    if ($state -eq 'ECART') { Add-Finding $Sev $Cat ($Ctrl + ' : ' + $Val) '' $Reco }
}

function Get-RegVal {
    param([string]$Path, [string]$Name, $Default = $null)
    try {
        $p = Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop
        return $p.$Name
    } catch { return $Default }
}

function Get-InstalledSoftware {
    $list = New-Object System.Collections.Generic.List[object]
    foreach ($k in 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*') {
        Get-ItemProperty -Path $k -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName } | ForEach-Object {
            $list.Add([pscustomobject]@{ Nom = [string]$_.DisplayName; Version = [string]$_.DisplayVersion; Editeur = [string]$_.Publisher; InstalleLe = [string]$_.InstallDate })
        }
    }
    return $list
}

function Test-VersionLt {
    param([string]$Version, [string]$Min)
    try { return ([version]($Version -replace '[^0-9.].*$', '')) -lt ([version]$Min) } catch { return $false }
}

# ---------------------------------------------------------------------------
function Mod-Durcissement {
    $os = Get-CimInstance Win32_OperatingSystem
    $cap = [string]$os.Caption; $build = [int]$os.BuildNumber
    $sup = $true; $why = ('{0} (build {1})' -f $cap, $build)
    if ($cap -match 'Windows 10') { $sup = $false; $why += ' : fin de support le 14/10/2025 (sauf ESU)' }
    elseif ($cap -match 'Server 20(03|08|12)|Windows (7|8)|Vista') { $sup = $false; $why += ' : version non supportee' }
    Add-Check 'Systeme' 'Version de Windows encore supportee' $sup $why 'Migrer vers Windows 11 (ou souscrire aux mises a jour de securite etendues).' 'ELEVE'
    if ($cap -match 'Windows 11' -and $build -lt 26100) { Add-Check 'Systeme' 'Version de fonctionnalite Windows 11 recente' $false ('build ' + $build) 'Installer la derniere mise a jour de fonctionnalite (24H2 ou plus).' 'FAIBLE' }

    # SMB
    try {
        $c = Get-SmbServerConfiguration
        Add-Check 'Reseau' 'SMBv1 desactive' (-not $c.EnableSMB1Protocol) ('EnableSMB1Protocol=' + $c.EnableSMB1Protocol) 'Set-SmbServerConfiguration -EnableSMB1Protocol $false' 'ELEVE'
        Add-Check 'Reseau' 'Signature SMB exigee' ([bool]$c.RequireSecuritySignature) ('RequireSecuritySignature=' + $c.RequireSecuritySignature) 'Exiger la signature SMB (impact faible sur un petit reseau).' 'FAIBLE'
    } catch { Add-Check 'Reseau' 'SMBv1 desactive' $null 'non verifiable' }

    # RDP
    $deny = Get-RegVal 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections' 1
    Add-Check 'Acces distant' 'Bureau a distance (RDP) desactive' ($deny -ne 0) $(if ($deny -eq 0) { 'RDP active' } else { 'desactive' }) 'Desactiver RDP s''il n''est pas indispensable ; sinon NLA + pare-feu limite au reseau local + VPN.' 'MOYEN'
    if ($deny -eq 0) {
        $nla = Get-RegVal 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication' 0
        Add-Check 'Acces distant' 'RDP : authentification NLA exigee' ($nla -eq 1) ('UserAuthentication=' + $nla) 'Activer NLA.' 'ELEVE'
    }
    $ra = Get-RegVal 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' 'fAllowToGetHelp' 1
    Add-Check 'Acces distant' 'Assistance a distance Windows desactivee' ($ra -eq 0) ('fAllowToGetHelp=' + $ra) 'Desactiver l''assistance a distance si non utilisee.' 'FAIBLE'

    # Chiffrement, demarrage
    try {
        $bl = Get-BitLockerVolume -MountPoint $env:SystemDrive
        $on = ($bl.ProtectionStatus -eq 'On' -or [string]$bl.ProtectionStatus -eq '1')
        Add-Check 'Donnees' 'Disque systeme chiffre (BitLocker)' $on ('ProtectionStatus=' + $bl.ProtectionStatus) 'Activer BitLocker (surtout portables et postes exposes au public).' 'MOYEN'
    } catch { Add-Check 'Donnees' 'Disque systeme chiffre (BitLocker)' $null 'non verifiable' }
    try { $sb = Confirm-SecureBootUEFI; Add-Check 'Systeme' 'Secure Boot actif' ([bool]$sb) ([string]$sb) 'Activer Secure Boot dans le BIOS/UEFI.' 'FAIBLE' } catch { Add-Check 'Systeme' 'Secure Boot actif' $null 'non verifiable (BIOS ancien ?)' }
    try { $tpm = Get-Tpm; Add-Check 'Systeme' 'TPM present et pret' ([bool]($tpm.TpmPresent -and $tpm.TpmReady)) ('Present=' + $tpm.TpmPresent + ' Pret=' + $tpm.TpmReady) 'Activer le TPM dans le BIOS.' 'FAIBLE' } catch { }

    # Antivirus / Defender
    $avNames = @()
    try { $avNames = @(Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName AntiVirusProduct | ForEach-Object { $_.displayName }) } catch { }
    Add-Check 'Protection' 'Un antivirus est enregistre' ($avNames.Count -gt 0) ($avNames -join ', ') 'Installer/activer un antivirus.' 'ELEVE'
    try {
        $mp = Get-MpComputerStatus
        Add-Check 'Protection' 'Defender : protection temps reel active' ([bool]$mp.RealTimeProtectionEnabled) ('RealTimeProtectionEnabled=' + $mp.RealTimeProtectionEnabled) 'Reactiver la protection en temps reel (ou verifier l''antivirus tiers).' 'ELEVE'
        Add-Check 'Protection' 'Defender : signatures a jour (moins de 7 jours)' ($mp.AntivirusSignatureAge -le 7) ('age ' + $mp.AntivirusSignatureAge + ' jours') 'Forcer la mise a jour des signatures.' 'MOYEN'
        Add-Check 'Protection' 'Defender : protection contre la falsification' ([bool]$mp.IsTamperProtected) ('IsTamperProtected=' + $mp.IsTamperProtected) 'Activer la protection contre la falsification.' 'MOYEN'
        $pref = Get-MpPreference
        $ex = @($pref.ExclusionPath) + @($pref.ExclusionProcess) + @($pref.ExclusionExtension) | Where-Object { $_ }
        Add-Check 'Protection' 'Defender : aucune exclusion' ($ex.Count -eq 0) (($ex | Select-Object -First 10) -join ' ; ') 'Verifier chaque exclusion (les attaquants en ajoutent).' 'MOYEN'
    } catch { Add-Check 'Protection' 'Defender : etat' $null 'non verifiable (antivirus tiers ?)' }
    try {
        $prof = @(Get-NetFirewallProfile)
        $off = @($prof | Where-Object { -not $_.Enabled } | ForEach-Object { $_.Name })
        Add-Check 'Protection' 'Pare-feu Windows actif (tous profils)' ($off.Count -eq 0) ('desactive : ' + ($off -join ',')) 'Reactiver le pare-feu.' 'ELEVE'
    } catch { }
    $lua = Get-RegVal 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA' 1
    Add-Check 'Protection' 'UAC active' ($lua -eq 1) ('EnableLUA=' + $lua) 'Reactiver le controle de compte d''utilisateur.' 'ELEVE'

    # Durcissement des identifiants et protocoles
    $wd = Get-RegVal 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential' 0
    Add-Check 'Identifiants' 'WDigest : mots de passe non conserves en clair' ($wd -ne 1) ('UseLogonCredential=' + $wd) 'Mettre UseLogonCredential a 0.' 'ELEVE'
    $lm = Get-RegVal 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LmCompatibilityLevel' 3
    Add-Check 'Identifiants' 'NTLMv2 uniquement (LmCompatibilityLevel >= 5)' ($lm -ge 5) ('valeur ' + $lm) 'Passer LmCompatibilityLevel a 5 apres verification des applications anciennes.' 'FAIBLE'
    $rl = Get-RegVal 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RunAsPPL' 0
    Add-Check 'Identifiants' 'Protection du processus LSASS (RunAsPPL)' ($rl -ge 1) ('RunAsPPL=' + $rl) 'Activer RunAsPPL.' 'FAIBLE'
    $ll = Get-RegVal 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast' 1
    Add-Check 'Reseau' 'LLMNR desactive' ($ll -eq 0) ('EnableMulticast=' + $ll) 'Desactiver LLMNR par GPO.' 'FAIBLE'
    try {
        $v2 = Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root
        Add-Check 'Protection' 'PowerShell 2.0 desactive' ($v2.State -eq 'Disabled') ('etat ' + $v2.State) 'Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root' 'FAIBLE'
    } catch { }

    # Journalisation
    $sbl = Get-RegVal 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging' 0
    Add-Check 'Journalisation' 'Journal PowerShell (ScriptBlock) active' ($sbl -eq 1) ('valeur ' + $sbl) 'Outils\Activer-Journalisation.ps1' 'MOYEN'
    $ap = ''; try { $ap = (& auditpol.exe /get /subcategory:"{0CCE922B-69AE-11D9-BED3-505054503030}" /r 2>$null) -join ' ' } catch { }
    Add-Check 'Journalisation' 'Audit de creation de processus (4688)' ($ap -match '(?i)(Success|Succ|Reussite|Réussite)') $(if ($ap) { 'configure' } else { 'illisible' }) 'Outils\Activer-Journalisation.ps1' 'MOYEN'
    try {
        $sec = Get-WinEvent -ListLog Security
        $mo = [math]::Round($sec.MaximumSizeInBytes / 1MB)
        Add-Check 'Journalisation' 'Journal Securite : taille >= 100 Mo' ($mo -ge 100) ($mo.ToString() + ' Mo') 'wevtutil sl Security /ms:268435456' 'FAIBLE'
    } catch { }

    # Comptes
    try {
        $admins = @(Get-LocalGroupMember -Group (Get-LocalGroup -SID 'S-1-5-32-544').Name | ForEach-Object { $_.Name })
        Add-Check 'Comptes' 'Administrateurs locaux : 3 comptes ou moins' ($admins.Count -le 3) ($admins -join ' ; ') 'Retirer les comptes administrateurs inutiles.' 'MOYEN'
    } catch { }
    try {
        $users = @(Get-LocalUser)
        $b = $users | Where-Object { $_.SID -like '*-500' -and $_.Enabled }
        Add-Check 'Comptes' 'Compte Administrateur integre desactive' (-not $b) ($b | ForEach-Object { $_.Name }) 'Desactiver ou renommer le compte integre (ou gerer par LAPS).' 'MOYEN'
        $g = $users | Where-Object { $_.SID -like '*-501' -and $_.Enabled }
        Add-Check 'Comptes' 'Compte Invite desactive' (-not $g) ($g | ForEach-Object { $_.Name }) 'Desactiver le compte Invite.' 'ELEVE'
        $np = @($users | Where-Object { $_.Enabled -and -not $_.PasswordRequired } | ForEach-Object { $_.Name })
        Add-Check 'Comptes' 'Tous les comptes actifs exigent un mot de passe' ($np.Count -eq 0) ($np -join ' ; ') 'Definir un mot de passe.' 'ELEVE'
        $old = @($users | Where-Object { $_.Enabled -and $_.LastLogon -and $_.LastLogon -lt (Get-Date).AddDays(-90) } | ForEach-Object { $_.Name })
        Add-Check 'Comptes' 'Aucun compte actif inutilise depuis 90 jours' ($old.Count -eq 0) ($old -join ' ; ') 'Desactiver les comptes inutilises.' 'FAIBLE'
    } catch { }
    $laps = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Policies\Windows\LAPS') -or (Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd') -or (Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LAPS')
    Add-Check 'Comptes' 'Mot de passe administrateur local gere (LAPS)' $laps $(if ($laps) { 'politique LAPS presente' } else { 'aucune politique LAPS' }) 'Deployer Windows LAPS (Intune ou GPO).' 'FAIBLE'

    # Outils d'acces distant installes et non autorises
    $sw = Get-InstalledSoftware
    $tools = @($sw | Where-Object { Get-OutilNom $_.Nom } | ForEach-Object { '{0} {1}' -f $_.Nom, $_.Version })
    $unauth = @($tools | Where-Object { $t = $_; -not ($script:Allow | Where-Object { $t -match $_ }) })
    Add-Check 'Acces distant' 'Outils d''acces distant installes : tous declares (config\autorises.txt)' ($unauth.Count -eq 0) ($unauth -join ' ; ') 'Desinstaller les outils inutiles ou les declarer dans config\autorises.txt.' 'MOYEN'
    $null = Save-Csv $sw 'logiciels_installes.csv' '01_durcissement'
}

# ---------------------------------------------------------------------------
function Mod-Correctifs {
    try {
        $hf = @(Get-HotFix | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending)
        if ($hf.Count -gt 0) {
            $age = [int]((Get-Date) - $hf[0].InstalledOn).TotalDays
            Add-Check 'Correctifs' 'Dernier correctif installe : moins de 45 jours' ($age -le 45) ('{0} ({1} jours, {2})' -f $hf[0].InstalledOn.ToString('yyyy-MM-dd'), $age, $hf[0].HotFixID) 'Lancer Windows Update et installer les mises a jour de securite.' 'ELEVE'
        }
        $null = Save-Csv ($hf | Select-Object HotFixID, Description, InstalledOn) 'correctifs.csv' '02_correctifs'
    } catch { }
    $svc = Get-Service wuauserv
    if ($svc) { Add-Check 'Correctifs' 'Service Windows Update non desactive' ($svc.StartType -ne 'Disabled') ([string]$svc.StartType) 'Remettre le service en demarrage manuel.' 'ELEVE' }
    $nau = Get-RegVal 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' 'NoAutoUpdate' 0
    Add-Check 'Correctifs' 'Mises a jour automatiques non bloquees' ($nau -ne 1) ('NoAutoUpdate=' + $nau) 'Supprimer la strategie qui bloque les mises a jour.' 'ELEVE'
    $reboot = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') -or (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')
    Add-Check 'Correctifs' 'Aucun redemarrage en attente' (-not $reboot) $(if ($reboot) { 'redemarrage en attente' } else { '' }) 'Redemarrer le poste.' 'FAIBLE'

    if (-not $script:Rapide) {
        Say '   Recherche des mises a jour en attente (1 a 3 minutes)...'
        try {
            $ses = New-Object -ComObject Microsoft.Update.Session
            $res = $ses.CreateUpdateSearcher().Search("IsInstalled=0 and Type='Software'")
            $rows = @(); $crit = 0
            foreach ($u in $res.Updates) {
                $sev = [string]$u.MsrcSeverity; if ($sev -match 'Critical|Important') { $crit++ }
                $rows += [pscustomobject]@{ Titre = $u.Title; Gravite = $sev; Taille = $u.MaxDownloadSize }
            }
            $null = Save-Csv $rows 'mises_a_jour_en_attente.csv' '02_correctifs'
            Add-Check 'Correctifs' 'Aucune mise a jour critique/importante en attente' ($crit -eq 0) ('{0} en attente dont {1} critiques/importantes' -f $res.Updates.Count, $crit) 'Installer les mises a jour.' 'ELEVE'
        } catch { Add-Check 'Correctifs' 'Mises a jour en attente' $null 'non verifiable (hors ligne ?)' }
    }

    # Logiciels obsoletes ou connus pour etre exploites
    $sw = Get-InstalledSoftware
    foreach ($s in $sw) {
        $n = $s.Nom; $v = $s.Version
        if ($n -match '(?i)Adobe Flash|Shockwave|Silverlight|QuickTime') { Add-Check 'Logiciels' ('Logiciel en fin de vie : ' + $n) $false $v 'Desinstaller.' 'ELEVE' }
        elseif ($n -match '(?i)^Java(\(TM\))? (6|7)\b|Java 6|Java 7') { Add-Check 'Logiciels' ('Java obsolete : ' + $n) $false $v 'Desinstaller ou mettre a jour.' 'ELEVE' }
        elseif ($n -match '(?i)^Java(\(TM\))? ?(SE|\d|Runtime)|Java 8|Java Runtime') { Add-Check 'Logiciels' ('Java present : ' + $n) $false $v 'Verifier si Java est necessaire (logiciel d''officine) et le tenir a jour.' 'FAIBLE' }
        elseif ($n -match '(?i)Microsoft Office.*(2007|2010|2013|2016)|Office (2007|2010|2013|2016)') { Add-Check 'Logiciels' ('Office hors support : ' + $n) $false $v 'Migrer vers Microsoft 365 / Office 2021+.' 'MOYEN' }
        elseif ($n -match '(?i)SQL Server (2005|2008|2012|2014)') { Add-Check 'Logiciels' ('SQL Server hors support : ' + $n) $false $v 'Migrer SQL Server.' 'MOYEN' }
        elseif ($n -match '(?i)^WinRAR' -and (Test-VersionLt $v '7.13')) { Add-Check 'Logiciels' ('WinRAR vulnerable : ' + $n) $false $v 'Mettre a jour WinRAR (>= 7.13).' 'ELEVE' }
        elseif ($n -match '(?i)^7-Zip' -and (Test-VersionLt $v '25.00')) { Add-Check 'Logiciels' ('7-Zip a mettre a jour : ' + $n) $false $v 'Mettre a jour 7-Zip (>= 25.00).' 'MOYEN' }
        elseif ($n -match '(?i)UltraVNC|TightVNC' -and (Test-VersionLt $v '1.3')) { Add-Check 'Logiciels' ('VNC ancien : ' + $n) $false $v 'Desinstaller ou mettre a jour.' 'MOYEN' }
    }
    $br = @(
        @{ N = 'Google Chrome'; P = "$env:ProgramFiles\Google\Chrome\Application\chrome.exe" },
        @{ N = 'Google Chrome'; P = "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe" },
        @{ N = 'Microsoft Edge'; P = "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe" },
        @{ N = 'Mozilla Firefox'; P = "$env:ProgramFiles\Mozilla Firefox\firefox.exe" }
    )
    foreach ($b in $br) {
        if (Test-Path -LiteralPath $b.P) {
            $f = Get-Item -LiteralPath $b.P
            $age = [int]((Get-Date) - $f.LastWriteTime).TotalDays
            Add-Check 'Logiciels' ($b.N + ' mis a jour depuis moins de 90 jours') ($age -le 90) ('version ' + $f.VersionInfo.ProductVersion + ', binaire date de ' + $age + ' jours') 'Mettre a jour le navigateur.' 'MOYEN'
        }
    }
    try {
        $bios = Get-CimInstance Win32_BIOS
        if ($bios.ReleaseDate) {
            $ya = [int](((Get-Date) - $bios.ReleaseDate).TotalDays / 365)
            Add-Check 'Systeme' 'BIOS/UEFI de moins de 4 ans' ($ya -lt 4) ('version ' + $bios.SMBIOSBIOSVersion + ' de ' + $bios.ReleaseDate.ToString('yyyy-MM')) 'Verifier les mises a jour du constructeur.' 'FAIBLE'
        }
    } catch { }
}
