# Core.ps1 - etat global, journalisation, resultats, copie de preuves (empreintes + dates d'origine)

$script:KitVersion = '1.0.0'
$script:Findings   = New-Object System.Collections.Generic.List[object]
$script:Errors     = New-Object System.Collections.Generic.List[string]
$script:Manifest   = New-Object System.Collections.Generic.List[object]
$script:Allow      = @()
$script:SigCache   = @{}
$script:Timings    = New-Object System.Collections.Generic.List[object]
$script:Delim      = ';'

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
    foreach ($rx in $script:Allow) {
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
        $items = @(Get-ChildItem -Path $Source -File -Force -ErrorAction SilentlyContinue)
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
