# Parsers.ps1 - fonctions d'analyse pures (aucun acces systeme, testables hors Windows).
# Compatible Windows PowerShell 5.1 (C# 5 pour Add-Type).

# ---------------------------------------------------------------------------
# Lecture de texte tolerante : UTF-8, UTF-16 avec ou sans BOM (traces AnyDesk)
# ---------------------------------------------------------------------------
function Read-TextSmart {
    param([Parameter(Mandatory)][string]$Path, [int64]$MaxBytes = 200MB)
    $fs = [IO.File]::Open($Path, 'Open', 'Read', 'ReadWrite')
    try {
        $len = [int][Math]::Min($fs.Length, $MaxBytes)
        $b = New-Object byte[] $len
        $got = 0
        while ($got -lt $len) {
            $n = $fs.Read($b, $got, $len - $got)
            if ($n -le 0) { break }
            $got += $n
        }
    } finally { $fs.Dispose() }
    if ($got -lt 2) { return @() }
    if ($b[0] -eq 0xFF -and $b[1] -eq 0xFE) { $t = [Text.Encoding]::Unicode.GetString($b, 2, $got - 2) }
    elseif ($b[0] -eq 0xFE -and $b[1] -eq 0xFF) { $t = [Text.Encoding]::BigEndianUnicode.GetString($b, 2, $got - 2) }
    elseif ($got -ge 3 -and $b[0] -eq 0xEF -and $b[1] -eq 0xBB -and $b[2] -eq 0xBF) { $t = [Text.Encoding]::UTF8.GetString($b, 3, $got - 3) }
    else {
        $nul = 0; $lim = [Math]::Min($got, 4096)
        for ($i = 0; $i -lt $lim; $i++) { if ($b[$i] -eq 0) { $nul++ } }
        if ($nul -gt ($lim / 4)) { $t = [Text.Encoding]::Unicode.GetString($b, 0, $got) }
        else { $t = [Text.Encoding]::UTF8.GetString($b, 0, $got) }
    }
    return ,@($t -split "\r?\n")
}

# ---------------------------------------------------------------------------
# Decompression XPRESS-Huffman (format MAM des fichiers Prefetch Windows 10/11)
# Implementation geree : ne depend d'aucune API Windows.
# ---------------------------------------------------------------------------
if (-not ('XpressHuff' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
public class XpressHuff {
    byte[] src; int pos; int end; uint mask; int bits;
    int[] cnt = new int[17]; int[] first = new int[17]; int[] offs = new int[17]; int[] sorted = new int[512];

    int R16() {
        int v = 0;
        if (pos + 1 < end) { v = src[pos] | (src[pos + 1] << 8); }
        else if (pos < end) { v = src[pos] << 8; }
        pos += 2;
        return v;
    }
    int RB() { int v = 0; if (pos < end) { v = src[pos]; } pos += 1; return v; }
    void Skip(int n) {
        mask = mask << n;
        bits -= n;
        if (bits < 16) { mask += ((uint)R16()) << (16 - bits); bits += 16; }
    }
    uint Lookup(int n) { if (n == 0) { return 0; } return mask >> (32 - n); }
    void Build(int p) {
        int[] len = new int[512];
        for (int i = 0; i < 256; i++) { int b = src[p + i]; len[2 * i] = b & 15; len[2 * i + 1] = b >> 4; }
        for (int l = 0; l < 17; l++) { cnt[l] = 0; }
        for (int s = 0; s < 512; s++) { cnt[len[s]]++; }
        cnt[0] = 0;
        int[] o = new int[18];
        o[1] = 0;
        for (int l = 1; l < 16; l++) { o[l + 1] = o[l] + cnt[l]; }
        int[] fill = new int[18];
        Array.Copy(o, fill, 18);
        for (int s = 0; s < 512; s++) { int l = len[s]; if (l > 0) { sorted[fill[l]] = s; fill[l]++; } }
        int code = 0;
        for (int l = 1; l < 16; l++) { first[l] = code; offs[l] = o[l]; code = (code + cnt[l]) << 1; }
    }
    int DecodeSym() {
        int code = 0;
        for (int l = 1; l <= 15; l++) {
            int bit = (int)(mask >> 31);
            Skip(1);
            code = (code << 1) | bit;
            int idx = code - first[l];
            if (cnt[l] > 0 && idx >= 0 && idx < cnt[l]) { return sorted[offs[l] + idx]; }
        }
        throw new InvalidOperationException("code Huffman invalide");
    }
    public static byte[] Decompress(byte[] data, int offset, int length, int outSize) {
        XpressHuff d = new XpressHuff();
        d.src = data; d.pos = offset; d.end = offset + length;
        byte[] dst = new byte[outSize];
        int di = 0;
        while (d.pos < d.end) {
            if (d.pos + 256 > d.end) { break; }
            d.Build(d.pos);
            d.pos += 256;
            int hi = d.R16();
            int lo = d.R16();
            d.mask = (((uint)hi) << 16) + (uint)lo;
            d.bits = 32;
            int chunk = 0;
            while (chunk < 65536 && d.pos < d.end) {
                int sym = d.DecodeSym();
                if (sym < 256) {
                    if (di < outSize) { dst[di] = (byte)sym; }
                    di++; chunk++;
                } else {
                    sym -= 256;
                    int mlen = sym & 15;
                    sym >>= 4;
                    int off = (1 << sym) + (int)d.Lookup(sym);
                    if (mlen == 15) {
                        mlen = d.RB() + 15;
                        if (mlen == 270) { mlen = d.R16(); }
                    }
                    d.Skip(sym);
                    mlen += 3;
                    for (int k = 0; k < mlen; k++) {
                        if (di - off >= 0 && di < outSize) { dst[di] = dst[di - off]; }
                        di++;
                    }
                    chunk += mlen;
                }
            }
        }
        return dst;
    }
}
'@
}

function ConvertFrom-FileTimeSafe {
    param([uint64]$Ft)
    if ($Ft -eq 0 -or $Ft -gt 2650467743999999999) { return $null }
    try { return [DateTime]::FromFileTimeUtc([int64]$Ft) } catch { return $null }
}

# Lit un fichier Prefetch (.pf) : nom, nombre d'executions, 8 dernieres dates (UTC)
function Read-Prefetch {
    param([Parameter(Mandatory)][string]$Path)
    $b = [IO.File]::ReadAllBytes($Path)
    if ($b.Length -lt 100) { return $null }
    if ($b[0] -eq 0x4D -and $b[1] -eq 0x41 -and $b[2] -eq 0x4D) {
        $size = [BitConverter]::ToUInt32($b, 4)
        if ($size -lt 100 -or $size -gt 64MB) { return $null }
        $b = [XpressHuff]::Decompress($b, 8, $b.Length - 8, [int]$size)
    }
    if ([Text.Encoding]::ASCII.GetString($b, 4, 4) -ne 'SCCA') { return $null }
    $ver = [BitConverter]::ToUInt32($b, 0)
    $name = ([Text.Encoding]::Unicode.GetString($b, 16, 60)).Split([char]0)[0]
    $runs = New-Object System.Collections.Generic.List[datetime]
    $count = 0
    switch ($ver) {
        { $_ -eq 30 -or $_ -eq 31 } {
            for ($i = 0; $i -lt 8; $i++) { $d = ConvertFrom-FileTimeSafe ([BitConverter]::ToUInt64($b, 0x80 + 8 * $i)); if ($d) { $runs.Add($d) } }
            $count = [BitConverter]::ToUInt32($b, 0xC8)
        }
        26 {
            for ($i = 0; $i -lt 8; $i++) { $d = ConvertFrom-FileTimeSafe ([BitConverter]::ToUInt64($b, 0x80 + 8 * $i)); if ($d) { $runs.Add($d) } }
            $count = [BitConverter]::ToUInt32($b, 0xD0)
        }
        23 {
            $d = ConvertFrom-FileTimeSafe ([BitConverter]::ToUInt64($b, 0x80)); if ($d) { $runs.Add($d) }
            $count = [BitConverter]::ToUInt32($b, 0x98)
        }
        default { return $null }
    }
    [pscustomobject]@{ Nom = $name; Version = $ver; NbExecutions = $count; Executions = $runs.ToArray() }
}

# ---------------------------------------------------------------------------
# AnyDesk : ad.trace / ad_svc.trace (heures UTC), connection_trace, file_transfer_trace
# ---------------------------------------------------------------------------
$script:RxAdLine = [regex]'^\s*(?<lvl>\w+)\s+(?<d>\d{4}-\d\d-\d\d)\s+(?<t>\d\d:\d\d:\d\d)\.\d+\s+.*?(?<mod>[A-Za-z_][\w\.]*)\s+-\s+(?<msg>.*)$'
$script:RxAdInteresting = [regex]'(?i)Accepting from|Client-ID|Logged in from|Incoming session request|Remote OS|Authenticat|passphrase|Session closed|desk_rt_|Command Line params|uninstall|--install|--remove|New user data|Install status|Session count|Custom Client|Connect request|reject|denied|clipboard|file transfer|unattended|elevat'

function ConvertFrom-AnyDeskTrace {
    param([Parameter(Mandatory)][string]$Path, [string]$Origine = '')
    $conns = New-Object System.Collections.Generic.List[object]
    $events = New-Object System.Collections.Generic.List[object]
    $cur = $null
    foreach ($line in (Read-TextSmart $Path)) {
        $m = $script:RxAdLine.Match($line)
        if (-not $m.Success) { continue }
        $ts = '{0} {1}' -f $m.Groups['d'].Value, $m.Groups['t'].Value
        $msg = $m.Groups['msg'].Value.Trim()
        if (-not $script:RxAdInteresting.IsMatch($msg)) { continue }
        $events.Add([pscustomobject]@{ Origine = $Origine; TempsUtc = $ts; Module = $m.Groups['mod'].Value; Message = $msg })
        $a = [regex]::Match($msg, '^Accepting from (?<id>\d+)')
        if ($a.Success) {
            $cur = [pscustomobject]@{ Origine = $Origine; DebutUtc = $ts; FinUtc = $ts; IdDistant = $a.Groups['id'].Value; Empreinte = ''; IpSource = ''; Port = ''; Relais = ''; Resultat = '' }
            $conns.Add($cur)
            continue
        }
        if ($null -eq $cur) { continue }
        $cur.FinUtc = $ts
        $c = [regex]::Match($msg, 'Client-ID: (?<id>\d+) \(FPR: (?<f>\w+)\)')
        if ($c.Success) { $cur.Empreinte = $c.Groups['f'].Value; continue }
        $l = [regex]::Match($msg, 'Logged in from (?<ip>[\d\.]+):(?<p>\d+) on relay (?<r>\w+)')
        if ($l.Success) { $cur.IpSource = $l.Groups['ip'].Value; $cur.Port = $l.Groups['p'].Value; $cur.Relais = $l.Groups['r'].Value; continue }
        if ($msg -match 'Session closed|desk_rt_|Authentication|passphrase|reject|denied|Connect request') {
            if ($cur.Resultat) { $cur.Resultat += ' | ' }
            $cur.Resultat += $msg
        }
    }
    [pscustomobject]@{ Connexions = $conns.ToArray(); Evenements = $events.ToArray() }
}

function ConvertFrom-AnyDeskConnTrace {
    param([Parameter(Mandatory)][string]$Path, [string]$Origine = '')
    foreach ($l in (Read-TextSmart $Path)) {
        $m = [regex]::Match($l, '^(?<dir>Incoming|Outgoing)\s+(?<d>\d{4}-\d\d-\d\d),\s+(?<t>\d\d:\d\d)\s+(?<rest>.*)$')
        if (-not $m.Success) { continue }
        $tok = @($m.Groups['rest'].Value -split '\s+' | Where-Object { $_ })
        $ids = @($tok | Where-Object { $_ -match '^\d{6,}$' })
        $usr = @($tok | Where-Object { $_ -match '@' })
        [pscustomobject]@{
            Origine = $Origine; Sens = $m.Groups['dir'].Value; DateUtc = ('{0} {1}' -f $m.Groups['d'].Value, $m.Groups['t'].Value)
            Authentification = $(if ($tok.Count -gt 0) { $tok[0] } else { '' })
            IdDistant = $(if ($ids.Count -gt 0) { $ids[0] } else { '' })
            Utilisateur = ($usr -join ' ')
        }
    }
}

function ConvertFrom-AnyDeskTransfer {
    param([Parameter(Mandatory)][string]$Path, [string]$Origine = '')
    foreach ($l in (Read-TextSmart $Path)) {
        $m = [regex]::Match($l, "^File Manager\s+(?<d>\d{4}-\d\d-\d\d),\s+(?<t>\d\d:\d\d)\s+(?<st>\w+)\s+(?<dir>\w+)\s+'(?<f>.*?)'\s*(?<rest>.*)$")
        if (-not $m.Success) { continue }
        [pscustomobject]@{
            Origine = $Origine; DateUtc = ('{0} {1}' -f $m.Groups['d'].Value, $m.Groups['t'].Value)
            Etat = $m.Groups['st'].Value; Sens = $m.Groups['dir'].Value; Fichier = $m.Groups['f'].Value; Detail = $m.Groups['rest'].Value.Trim()
        }
    }
}

# ---------------------------------------------------------------------------
# TeamViewer : Connections_incoming.txt / Connections.txt (colonnes separees par tabulation)
# ---------------------------------------------------------------------------
function ConvertFrom-TeamViewerConnections {
    param([Parameter(Mandatory)][string]$Path, [string]$Origine = '')
    foreach ($l in (Read-TextSmart $Path)) {
        if (-not $l.Trim()) { continue }
        $c = $l -split "`t"
        if ($c.Count -lt 3) { continue }
        [pscustomobject]@{
            Origine = $Origine; IdDistant = $c[0].Trim(); Nom = $c[1].Trim(); Debut = $c[2].Trim()
            Fin = $(if ($c.Count -gt 3) { $c[3].Trim() } else { '' })
            Utilisateur = $(if ($c.Count -gt 4) { $c[4].Trim() } else { '' })
            Type = $(if ($c.Count -gt 5) { $c[5].Trim() } else { '' })
        }
    }
}

# ---------------------------------------------------------------------------
# Splashtop : lignes utiles des SPLog (debut de session distante, client, IP, transferts)
# ---------------------------------------------------------------------------
function ConvertFrom-SplashtopLog {
    param([Parameter(Mandatory)][string]$Path, [string]$Origine = '')
    $rx = [regex]'channel remote begin|Auth-L\] ok, client|peer public addr|DownloadRequest|UploadRequest|filePath\['
    foreach ($l in (Read-TextSmart $Path)) {
        if (-not $rx.IsMatch($l)) { continue }
        $ts = [regex]::Match($l, '(?<ts>\d{4}[-/]\d\d[-/]\d\d[ T]\d\d:\d\d:\d\d)')
        $cl = [regex]::Match($l, 'client \((?<c>[^)]*)\)')
        $ip = [regex]::Match($l, '(?<ip>\d{1,3}(\.\d{1,3}){3})')
        $fp = [regex]::Match($l, 'filePath\[(?<p>[^\]]*)\]')
        $brut = $l.Trim(); if ($brut.Length -gt 300) { $brut = $brut.Substring(0, 300) }
        [pscustomobject]@{
            Origine = $Origine; Temps = $ts.Groups['ts'].Value; Client = $cl.Groups['c'].Value
            Ip = $ip.Groups['ip'].Value; Fichier = $fp.Groups['p'].Value; Ligne = $brut
        }
    }
}

# ---------------------------------------------------------------------------
# ScreenConnect : parametres du service (hote relais, instance). La cle k= n'est JAMAIS extraite.
# ---------------------------------------------------------------------------
function Get-ScreenConnectInfo {
    param([string]$ImagePath)
    $h = [regex]::Match($ImagePath, '(?i)[?&]h=(?<v>[^&\s"]+)')
    $p = [regex]::Match($ImagePath, '(?i)[?&]p=(?<v>\d+)')
    $s = [regex]::Match($ImagePath, '(?i)[?&]s=(?<v>[0-9a-f\-]{8,})')
    $i = [regex]::Match($ImagePath, '(?i)instance-(?<v>[a-z0-9]+)')
    [pscustomobject]@{ Hote = $h.Groups['v'].Value; Port = $p.Groups['v'].Value; Session = $s.Groups['v'].Value; Instance = $i.Groups['v'].Value }
}

# ---------------------------------------------------------------------------
# Listes de configuration (IOC, autorisations) : une valeur par ligne, # commentaire
# ---------------------------------------------------------------------------
function Read-ConfigList {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return @() }
    foreach ($l in (Read-TextSmart $Path)) {
        $t = $l.Trim()
        if (-not $t -or $t.StartsWith('#')) { continue }
        $v = $t; $c = ''
        $ix = $t.IndexOf(' #')
        if ($ix -gt 0) { $v = $t.Substring(0, $ix).Trim(); $c = $t.Substring($ix + 2).Trim() }
        [pscustomobject]@{ Valeur = $v; Commentaire = $c }
    }
}

# Recherche de chaines (IOC) dans des fichiers texte / CSV / traces
function Find-IocInFiles {
    param([string[]]$Iocs, [string[]]$Files, [int]$MaxHitsPerIoc = 50)
    $hitCount = @{}
    foreach ($f in $Files) {
        try { $lines = Read-TextSmart $f -MaxBytes 100MB } catch { continue }
        for ($n = 0; $n -lt $lines.Count; $n++) {
            $ln = $lines[$n]
            if ($ln.Length -lt 4) { continue }
            foreach ($ioc in $Iocs) {
                if ($ln.IndexOf($ioc, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
                    $k = $f + '|' + $ioc
                    if (-not $hitCount.ContainsKey($k)) { $hitCount[$k] = 0 }
                    $hitCount[$k]++
                    if ($hitCount[$k] -le $MaxHitsPerIoc) {
                        $show = $ln.Trim(); if ($show.Length -gt 260) { $show = $show.Substring(0, 260) }
                        [pscustomobject]@{ Ioc = $ioc; Fichier = $f; Ligne = ($n + 1); Extrait = $show }
                    }
                }
            }
        }
    }
}
