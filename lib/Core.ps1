# Core.ps1 - etat global, journalisation, resultats, copie de preuves (empreintes + dates d'origine)

$script:KitVersion = '1.3.0'
$script:Findings   = New-Object System.Collections.Generic.List[object]
$script:Errors     = New-Object System.Collections.Generic.List[string]
$script:Manifest   = New-Object System.Collections.Generic.List[object]
$script:Allow      = @()
$script:SigCache   = @{}
$script:Timings    = New-Object System.Collections.Generic.List[object]
$script:Delim      = ';'
$script:NonAutorisables = '^(Indicateur connu|Note de rancon probable|Persistance WMI|Winlogon|Detournement IFEO|AppInit_DLLs|Connexion RDP)$'

# Dossiers ou un executable d'acces distant n'a rien a faire
$script:RiskDirRx = '(?i)\\(temp|tmp)\\|\\appdata\\local\\temp|\\users\\public\\|\\downloads\\|\\desktop\\|\\documents\\|\\\$recycle|\\windows\\tasks|\\windows\\temp'
$script:UserDirRx = '(?i)\\users\\[^\\]+\\(appdata|downloads|desktop|documents)|\\programdata\\[^\\]+\\|\\users\\public\\'

function Say {
    param([string]$Message, [string]$Color = 'Cyan')
    $line = '[{0:HH:mm:ss}] {1}' -f (Get-Date), $Message
    Write-Host $line -ForegroundColor $Color
    if ($script:LogFile) { try { Add-Content -LiteralPath $script:LogFile -Value $line -Encoding UTF8 } catch { } }
}

function U {
    # date -> texte UTC lisible ; vide si date invalide
    param($Date)
    if ($null -eq $Date) { return '' }
    try {
        $d = [datetime]$Date
        if ($d.Year -lt 1700) { return '' }
        return $d.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
    } catch { return '' }
}

function InWindow {
    param($Date)
    if ($null -eq $Date) { return $false }
    try { $d = ([datetime]$Date).ToUniversalTime(); return ($d -ge $script:WinS -and $d -le $script:WinE) } catch { return $false }
}

function Add-Finding {
    param(
        [ValidateSet('INFO', 'FAIBLE', 'MOYEN', 'ELEVE')][string]$Severite,
        [string]$Categorie, [string]$Detail, [string]$Chemin = '', [string]$Info = ''
    )
    $sev = $Severite
    $hay = '{0} {1} {2} {3}' -f $Categorie, $Detail, $Chemin, $Info
    # constats critiques : jamais masques par config\autorises.txt
    $allowList = $script:Allow
    if ($Categorie -match $script:NonAutorisables) { $allowList = @() }
    foreach ($rx in $allowList) {
        try { if ($hay -match $rx) { $sev = 'INFO'; $Info = ($Info + ' [AUTORISE: ' + $rx + ']').Trim(); break } } catch { }
    }
    $script:Findings.Add([pscustomobject]@{ Severite = $sev; Categorie = $Categorie; Detail = $Detail; Chemin = $Chemin; Info = $Info })
}

function Save-Csv {
    param($Data, [string]$Name, [string]$Sub = '')
    $dir = $script:Out
    if ($Sub) { $dir = Join-Path $script:Out $Sub }
    if (-not (Test-Path -LiteralPath $dir)) { $null = New-Item -ItemType Directory -Path $dir -Force }
    $p = Join-Path $dir $Name
    $arr = @($Data | Where-Object { $null -ne $_ })
    if ($arr.Count -gt 0) {
        $arr | Export-Csv -LiteralPath $p -NoTypeInformation -Encoding UTF8 -Delimiter $script:Delim
    } else {
        Set-Content -LiteralPath $p -Value '(aucun resultat)' -Encoding UTF8
    }
    return $arr.Count
}

function Save-Text {
    param([string[]]$Lines, [string]$Name, [string]$Sub = '')
    $dir = $script:Out
    if ($Sub) { $dir = Join-Path $script:Out $Sub }
    if (-not (Test-Path -LiteralPath $dir)) { $null = New-Item -ItemType Directory -Path $dir -Force }
    Set-Content -LiteralPath (Join-Path $dir $Name) -Value $Lines -Encoding UTF8
}

function Invoke-Module {
    param([string]$Name, [scriptblock]$Script)
    Say ("== {0}" -f $Name) 'Green'
    $sw = [Diagnostics.Stopwatch]::StartNew()
    try { & $Script } catch {
        $msg = '{0} : {1} (ligne {2})' -f $Name, $_.Exception.Message, $_.InvocationInfo.ScriptLineNumber
        $script:Errors.Add($msg)
        Say ('   ERREUR (le module est ignore, la collecte continue) : ' + $_.Exception.Message) 'Yellow'
    }
    $script:Timings.Add([pscustomobject]@{ Module = $Name; Secondes = [int]$sw.Elapsed.TotalSeconds })
}

function Get-SignInfo {
    param([string]$File)
    if ([string]::IsNullOrWhiteSpace($File)) { return $null }
    if ($script:SigCache.ContainsKey($File)) { return $script:SigCache[$File] }
    $r = $null
    if (Test-Path -LiteralPath $File -PathType Leaf) {
        $sig = Get-AuthenticodeSignature -LiteralPath $File -ErrorAction SilentlyContinue
        if ($sig) {
            $r = [pscustomobject]@{
                Statut = [string]$sig.Status
                Signataire = $(if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { '' })
                Valide = ($sig.Status -eq 'Valid')
            }
        }
    }
    $script:SigCache[$File] = $r
    return $r
}

function Get-ExePath {
    # extrait le chemin de l'executable d'une ligne de commande (services, cles Run)
    param([string]$Cmd)
    if ([string]::IsNullOrWhiteSpace($Cmd)) { return '' }
    $c = $Cmd.Trim()
    if ($c.StartsWith('"')) {
        $e = $c.IndexOf('"', 1)
        if ($e -gt 1) { return [Environment]::ExpandEnvironmentVariables($c.Substring(1, $e - 1)) }
    }
    $m = [regex]::Match($c, '^[A-Za-z]:\\.*?\.(exe|dll|bat|cmd|ps1|vbs|js|com|scr|msi)', 'IgnoreCase')
    if ($m.Success) { return [Environment]::ExpandEnvironmentVariables($m.Value) }
    return [Environment]::ExpandEnvironmentVariables(($c -split '\s+')[0])
}

function Test-RiskPath {
    param([string]$Path)
    if (-not $Path) { return $false }
    return ($Path -match $script:RiskDirRx)
}

# comptes locaux/domaine (S-1-5-21) et comptes Entra ID / Azure AD (S-1-12-1)
$script:UserSidRx = '^S-1-(5-21|12-1)-[0-9-]+$'

function Get-UserProfiles {
    Get-ChildItem 'C:\Users' -Directory -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -notin 'Default', 'Default User', 'All Users', 'Public' }
}

# ---------------------------------------------------------------------------
# Copie de preuves : flux unique, SHA256 a la volee, dates d'origine conservees,
# partage lecture/ecriture pour les journaux verrouilles, manifeste CSV.
# ---------------------------------------------------------------------------
function Copy-OneFile {
    param([string]$Src, [string]$Dst)
    $dir = Split-Path -Parent $Dst
    if (-not (Test-Path -LiteralPath $dir)) { $null = New-Item -ItemType Directory -Path $dir -Force }
    $in = $null; $out = $null; $hash = ''
    try {
        $in = New-Object IO.FileStream($Src, [IO.FileMode]::Open, [IO.FileAccess]::Read, ([IO.FileShare]'ReadWrite,Delete'))
        $out = New-Object IO.FileStream($Dst, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::None)
        $sha = [Security.Cryptography.SHA256]::Create()
        $buf = New-Object byte[] 1048576
        while (($n = $in.Read($buf, 0, $buf.Length)) -gt 0) {
            $out.Write($buf, 0, $n)
            $null = $sha.TransformBlock($buf, 0, $n, $null, 0)
        }
        $null = $sha.TransformFinalBlock($buf, 0, 0)
        $hash = ([BitConverter]::ToString($sha.Hash)) -replace '-', ''
    } finally {
        if ($out) { $out.Dispose() }
        if ($in) { $in.Dispose() }
    }
    return $hash
}

function Copy-Evidence {
    param(
        [Parameter(Mandatory)][string]$Source,   # fichier, dossier, ou motif avec *
        [Parameter(Mandatory)][string]$Dest,     # sous-dossier dans raw\ (ou raw_SENSIBLE\)
        [switch]$Sensible,
        [string[]]$Filter = @('*'),
        [int64]$MaxFileBytes = 150MB,
        [switch]$Recurse
    )
    $root = $script:Raw
    if ($Sensible) { $root = $script:RawSens }
    $items = @()
    if (Test-Path -LiteralPath $Source -PathType Container) {
        $base = (Get-Item -LiteralPath $Source -Force).FullName.TrimEnd('\')
        foreach ($flt in $Filter) {
            if ($Recurse) { $items += Get-ChildItem -LiteralPath $Source -Filter $flt -File -Force -Recurse -ErrorAction SilentlyContinue }
            else { $items += Get-ChildItem -LiteralPath $Source -Filter $flt -File -Force -ErrorAction SilentlyContinue }
        }
    } else {
        $base = $null
        # fichier unique : chemin litteral (un nom contenant [ ] serait sinon pris pour un motif et ignore)
        if (Test-Path -LiteralPath $Source -PathType Leaf) { $items = @(Get-Item -LiteralPath $Source -Force) }
        else { $items = @(Get-ChildItem -Path $Source -File -Force -ErrorAction SilentlyContinue) }
    }
    $nb = 0
    foreach ($f in ($items | Sort-Object FullName -Unique)) {
        $row = [ordered]@{
            Source = $f.FullName; Copie = ''; TailleOctets = $f.Length; CreeUtc = (U $f.CreationTimeUtc)
            ModifieUtc = (U $f.LastWriteTimeUtc); AccedeUtc = (U $f.LastAccessTimeUtc); SHA256 = ''; Statut = ''
        }
        if ($f.Length -gt $MaxFileBytes) {
            $row.Statut = 'IGNORE (trop gros)'; $script:Manifest.Add([pscustomobject]$row); continue
        }
        if ($base) { $rel = $f.FullName.Substring($base.Length).TrimStart('\') }
        else {
            $pre = ''
            if ($f.Directory) { $pre = $f.Directory.Name; if ($f.Directory.Parent) { $pre = $f.Directory.Parent.Name + '_' + $pre } }
            $rel = (($pre -replace '[^A-Za-z0-9_.-]', '_') + '__' + $f.Name)
        }
        $dst = Join-Path (Join-Path $root $Dest) $rel
        try {
            $row.SHA256 = Copy-OneFile $f.FullName $dst
            $d = Get-Item -LiteralPath $dst -Force
            $d.CreationTimeUtc = $f.CreationTimeUtc
            $d.LastWriteTimeUtc = $f.LastWriteTimeUtc
            $row.Copie = $dst.Substring($script:Out.Length).TrimStart('\', '/')
            $row.Statut = 'OK'; $nb++
        } catch { $row.Statut = 'ECHEC : ' + $_.Exception.Message }
        $script:Manifest.Add([pscustomobject]$row)
    }
    return $nb
}

# ---------------------------------------------------------------------------
# Protection des donnees sensibles : seuls SYSTEM et les administrateurs y accedent
# ---------------------------------------------------------------------------
function Test-AdminOnlyAcl {
    # vrai si AUCUN droit "autoriser" n'est accorde a un autre compte que SYSTEM ou Administrateurs
    param([string]$Path)
    try {
        $rules = (Get-Acl -LiteralPath $Path -ErrorAction Stop).GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])
        foreach ($r in $rules) {
            if ($r.AccessControlType -eq 'Allow' -and $r.IdentityReference.Value -notin 'S-1-5-18', 'S-1-5-32-544') { return $false }
        }
        return $true
    } catch { return $false }
}

function Set-AdminOnlyAcl {
    # Reserve un dossier (et tout son contenu) a SYSTEM et aux Administrateurs, puis le VERIFIE.
    #  0) refus des liens/jonctions (redirection vers un dossier controle par un tiers)
    #  1) proprietaire = Administrateurs ; /reset efface tout droit explicite pose par un tiers
    #  2) la RACINE seule recoit SYSTEM + Administrateurs (heritables), sans heritage du parent.
    #     Jamais /grant avec /T : applique aux fichiers, il leur laisse une liste de droits vide
    #     (fichiers illisibles meme pour un administrateur - bug de la 1.2.1).
    #  3) le CONTENU est remis a l'heritage pur (/reset /T) : exactement les droits de la racine.
    #  4) controle : aucun autre compte n'a de droit, et chaque fichier reste lisible par un administrateur.
    # SID plutot que noms : fonctionne sur un Windows en francais.
    param([string]$Full)
    $it = Get-Item -LiteralPath $Full -Force
    $rp = @(Get-ChildItem -LiteralPath $Full -Recurse -Force -Attributes ReparsePoint -ErrorAction SilentlyContinue)
    if (($it.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $rp.Count -gt 0) {
        Say ('ATTENTION : lien ou jonction dans ' + $Full + ' : protection refusee.') 'Red'; return $false
    }
    $null = & icacls.exe $Full /setowner '*S-1-5-32-544' /T /C /Q 2>&1
    $null = & icacls.exe $Full /reset /C /Q 2>&1
    $null = & icacls.exe $Full /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' /C /Q 2>&1
    if ($LASTEXITCODE -ne 0) { Say ('ATTENTION : droits non appliques sur ' + $Full) 'Yellow'; return $false }
    if (@(Get-ChildItem -LiteralPath $Full -Force -ErrorAction SilentlyContinue).Count -gt 0) {
        $null = & icacls.exe (Join-Path $Full '*') /reset /T /C /Q 2>&1
    }
    $foreign = 0; $unread = 0
    foreach ($i in (@($it) + @(Get-ChildItem -LiteralPath $Full -Recurse -Force -ErrorAction SilentlyContinue))) {
        if (-not (Test-AdminOnlyAcl $i.FullName)) { $foreign++ }
        if (-not $i.PSIsContainer) { try { $fs = [IO.File]::Open($i.FullName, 'Open', 'Read', 'ReadWrite'); $fs.Dispose() } catch { $unread++ } }
    }
    if ($foreign -gt 0) { Say ('ATTENTION : ' + $foreign + ' element(s) de ' + $Full + ' restent accessibles a d''autres comptes.') 'Red'; return $false }
    if ($unread -gt 0) { Say ('ATTENTION : ' + $unread + ' fichier(s) illisible(s) dans ' + $Full) 'Yellow'; return $false }
    return $true
}

function Test-OwnPath {
    # vrai si le chemin appartient a l'outil ou a ses resultats (a ne pas analyser comme une trace du poste)
    param([string]$Path)
    if (-not $Path) { return $false }
    foreach ($r in @($script:KitRoot, $script:Out)) {
        if ($r -and $r.TrimEnd('\').Length -gt 3 -and $Path.StartsWith($r.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) { return $true }
    }
    return $false
}

function Get-GroupMemberNames {
    # membres d'un groupe local par SID ; repli ADSI si Get-LocalGroupMember echoue (compte orphelin, poste Entra)
    param([string]$Sid)
    # virgule : un groupe vide renvoie un tableau vide (et non $null, reserve a l'echec)
    try { return ,@(Get-LocalGroupMember -SID $Sid -ErrorAction Stop | ForEach-Object { [string]$_.Name }) } catch { }
    try {
        $gn = (New-Object Security.Principal.SecurityIdentifier($Sid)).Translate([Security.Principal.NTAccount]).Value.Split('\')[-1]
        $g = [ADSI]('WinNT://./' + $gn + ',group')
        return ,@($g.Invoke('Members') | ForEach-Object {
            $p = [string]$_.GetType().InvokeMember('ADsPath', 'GetProperty', $null, $_, $null)
            ($p -replace '^WinNT://', '') -replace '/', '\'
        })
    } catch { return $null }
}

function Protect-Folder {
    param([string]$Path)
    try {
        $full = (Get-Item -LiteralPath $Path -Force).FullName
        $root = [IO.Path]::GetPathRoot($full)
        if ($root -like '\\*' -or ([IO.DriveInfo]$root).DriveType -eq 'Network') { Say ('ATTENTION : ' + $full + ' est sur un partage reseau, droits non verifiables.') 'Yellow'; return $false }
        $fmt = ([IO.DriveInfo]$root).DriveFormat
        if ($fmt -notin 'NTFS', 'ReFS') {
            Say ('ATTENTION : le support ' + $root + ' est en ' + $fmt + ' (pas de droits d''acces) : raw_SENSIBLE est lisible par quiconque a la cle. Gardez-la sous clef.') 'Yellow'
            return $false
        }
        return (Set-AdminOnlyAcl $full)
    } catch {
        Say ('ATTENTION : protection impossible de ' + $Path + ' : ' + $_.Exception.Message) 'Yellow'
        return $false
    }
}

# ---------------------------------------------------------------------------
# En fin d'analyse : proposer d'enregistrer les resultats AVANT d'ouvrir le rapport
# ---------------------------------------------------------------------------
function Save-Resultats {
    param([Parameter(Mandatory)][string]$Rapport)
    $src = $script:Out.TrimEnd('\', '/')
    $zip = $src + '_SANS_SENSIBLE.zip'
    $hasZip = Test-Path -LiteralPath $zip
    $sens = Join-Path $src 'raw_SENSIBLE'
    $hasSens = (Test-Path -LiteralPath $sens) -and @(Get-ChildItem -LiteralPath $sens -Recurse -File -Force -ErrorAction SilentlyContinue).Count -gt 0
    $stampName = Split-Path -Leaf $src

    while ($true) {
        Write-Host ''
        Write-Host ' Le rapport est pret. Enregistrer une copie avant de l''ouvrir ?' -ForegroundColor Cyan
        if ($hasZip) { Write-Host ' 1) Archive transmissible (.zip, sans les donnees sensibles)' }
        if ($hasSens) { Write-Host ' 2) Dossier complet (AVEC raw_SENSIBLE : cles AnyDesk, historiques)' }
        else { Write-Host ' 2) Dossier complet des resultats' }
        Write-Host ' Entree) Ne pas enregistrer, ouvrir le rapport'
        $c = Read-Host ' Choix'
        if (-not $c) { return }
        if (($c -eq '1' -and $hasZip) -or $c -eq '2') { break }
        Write-Host ' Choix invalide.' -ForegroundColor Yellow
    }

    $owner = $null
    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
        $owner = New-Object System.Windows.Forms.Form -Property @{ TopMost = $true; ShowInTaskbar = $false }
    } catch { }
    try {
        if ($c -eq '1') {
            $dest = $null
            if ($owner) {
                $dlg = New-Object System.Windows.Forms.SaveFileDialog
                $dlg.Title = 'Enregistrer l''archive des resultats'
                $dlg.Filter = 'Archive ZIP (*.zip)|*.zip'
                $dlg.FileName = Split-Path -Leaf $zip
                $dlg.OverwritePrompt = $true
                if ($dlg.ShowDialog($owner) -eq [System.Windows.Forms.DialogResult]::OK) { $dest = $dlg.FileName }
            } else { $dest = Read-Host ' Chemin complet du fichier .zip de destination' }
            if (-not $dest) { Say 'Enregistrement annule.' 'Yellow'; return }
            Copy-Item -LiteralPath $zip -Destination $dest -Force -ErrorAction Stop
            if ((Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash -eq (Get-FileHash -LiteralPath $dest -Algorithm SHA256).Hash) {
                Say ('Archive enregistree, empreinte SHA256 verifiee : ' + $dest) 'Green'
            } else { Say ('ERREUR : la copie differe de l''original : ' + $dest) 'Red' }
        } else {
            $parent = $null
            if ($owner) {
                $dlg = New-Object System.Windows.Forms.FolderBrowserDialog
                $dlg.Description = 'Dossier ou enregistrer ' + $stampName
                $dlg.ShowNewFolderButton = $true
                if ($dlg.ShowDialog($owner) -eq [System.Windows.Forms.DialogResult]::OK) { $parent = $dlg.SelectedPath }
            } else { $parent = Read-Host ' Dossier de destination' }
            if (-not $parent) { Say 'Enregistrement annule.' 'Yellow'; return }
            $dest = Join-Path $parent $stampName
            if ($dest.TrimEnd('\') -eq $src -or $dest.StartsWith($src + '\', [StringComparison]::OrdinalIgnoreCase)) { Say 'Destination invalide (dossier des resultats lui-meme).' 'Red'; return }
            if (Test-Path -LiteralPath $dest) { Say ('Destination deja existante, rien n''est ecrase : ' + $dest) 'Red'; return }
            # 1) arborescence ; raw_SENSIBLE est protege AVANT d'y copier quoi que ce soit :
            #    les fichiers copies heritent des droits, aucun droit n'est modifie apres coup.
            # sans -Force : echoue si un tiers a cree le dossier entre-temps (il en controlerait les droits)
            $null = New-Item -ItemType Directory -Path $dest -ErrorAction Stop
            $skipSens = $false
            if ($hasSens) {
                $ds = Join-Path $dest 'raw_SENSIBLE'
                $null = New-Item -ItemType Directory -Path $ds -ErrorAction Stop
                if (-not (Protect-Folder $ds)) {
                    Write-Host ' raw_SENSIBLE ne peut pas etre protege a cet endroit (voir ci-dessus).' -ForegroundColor Yellow
                    if ((Read-Host ' Copier quand meme les donnees sensibles SANS protection ? Taper OUI') -cne 'OUI') {
                        $skipSens = $true; Say 'Donnees sensibles NON copiees (raw_SENSIBLE reste vide).' 'Yellow'
                    }
                }
            }
            foreach ($d in (Get-ChildItem -LiteralPath $src -Recurse -Directory -Force)) {
                $null = New-Item -ItemType Directory -Path (Join-Path $dest $d.FullName.Substring($src.Length).TrimStart('\')) -Force
            }
            # 2) copie en flux + verification immediate : empreinte de l'original (lue pendant la copie)
            #    comparee a l'empreinte de la copie relue sur le disque ; 2 tentatives par fichier.
            #    Le journal (encore ouvert en ecriture) est copie mais ne peut pas etre compare.
            $bad = New-Object System.Collections.Generic.List[string]; $n = 0
            foreach ($f in (Get-ChildItem -LiteralPath $src -Recurse -File -Force)) {
                $rel = $f.FullName.Substring($src.Length).TrimStart('\')
                if ($skipSens -and $rel -like 'raw_SENSIBLE\*') { continue }
                $g = Join-Path $dest $rel
                $isLog = ($f.Name -eq 'collecte.log' -or $f.Name -eq 'audit.log')
                $why = 'non copie'
                for ($try = 1; $try -le 2 -and $why; $try++) {
                    try {
                        $h1 = Copy-OneFile $f.FullName $g
                        try { $o = Get-Item -LiteralPath $g -Force; $o.CreationTimeUtc = $f.CreationTimeUtc; $o.LastWriteTimeUtc = $f.LastWriteTimeUtc } catch { }
                        if ($isLog) { $why = '' }
                        else {
                            $h2 = (Get-FileHash -LiteralPath $g -Algorithm SHA256 -ErrorAction Stop).Hash
                            if ($h1 -eq $h2) { $why = '' } else { $why = 'empreinte differente' }
                        }
                    } catch { $why = $_.Exception.Message }
                }
                if (-not $isLog) { $n++ }
                if ($why) { $bad.Add(($rel + '  [' + $why + ']')) }
            }
            if ($hasZip) {
                try { Copy-Item -LiteralPath $zip -Destination $parent -Force -ErrorAction Stop }
                catch { $bad.Add(((Split-Path -Leaf $zip) + '  [' + $_.Exception.Message + ']')) }
            }
            if ($bad.Count -eq 0) { Say ('Resultats enregistres et verifies (' + $n + ' fichiers) : ' + $dest) 'Green' }
            else {
                Say ('ERREUR : ' + $bad.Count + ' fichier(s) sur ' + $n + ' manquants ou differents dans ' + $dest) 'Red'
                foreach ($b in ($bad | Select-Object -First 10)) { Say ('   - ' + $b) 'Red' }
                try { Set-Content -LiteralPath (Join-Path $parent ($stampName + '_verification_copie.txt')) -Value $bad -Encoding UTF8 } catch { }
            }
            if ($hasSens -and -not $skipSens) { Say 'Cette copie contient raw_SENSIBLE : ne la transmettez a personne.' 'Yellow' }
        }
    } catch {
        Say ('ERREUR d''enregistrement : ' + $_.Exception.Message) 'Red'
    } finally { if ($owner) { $owner.Dispose() } }
}

function Open-Rapport {
    # enregistrement propose, puis ouverture du rapport
    param([Parameter(Mandatory)][string]$Rapport)
    $p = Join-Path $script:Out $Rapport
    if (-not (Test-Path -LiteralPath $p)) { Say ('ERREUR : rapport introuvable : ' + $p) 'Red'; return }
    Save-Resultats -Rapport $Rapport
    # ouverture par l'Explorateur deja lance (droits utilisateur) : pas de navigateur avec les droits administrateur
    try { Start-Process -FilePath 'explorer.exe' -ArgumentList ('"' + $p + '"') -ErrorAction Stop }
    catch { try { Start-Process -FilePath $p } catch { Say ('Ouvrez le rapport manuellement : ' + $p) 'Yellow' } }
}
