<#
 BLL IR-Kit - collecte de preuves portable (lecture seule sur le poste)
 Usage : Lancer.bat (menu) ou  powershell -ExecutionPolicy Bypass -File IR-Kit.ps1 -Mode Complet
#>
[CmdletBinding()]
param(
    [ValidateSet('Rapide', 'Complet')][string]$Mode = 'Complet',
    [string]$DebutUtc,          # ex. "2026-10-31 14:00"
    [string]$FinUtc,            # ex. "2026-10-31 15:00"
    [int]$Jours = 30,           # fenetre par defaut : N derniers jours
    [string]$Sortie,            # dossier de sortie (defaut : <kit>\Resultats)
    [switch]$Vss,               # copie via instantane VSS (fichiers verrouilles)
    [switch]$SansMenu
)
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
$script:StartTime = Get-Date
$script:KitRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$script:Mode = $Mode
$script:UseVss = [bool]$Vss

$id = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $id.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host 'ERREUR : lancez en administrateur (utilisez Lancer.bat, clic droit > Executer en tant qu administrateur).' -ForegroundColor Red
    exit 1
}

. (Join-Path $script:KitRoot 'lib\Parsers.ps1')
. (Join-Path $script:KitRoot 'lib\Core.ps1')
. (Join-Path $script:KitRoot 'lib\Collecte1.ps1')
. (Join-Path $script:KitRoot 'lib\Collecte2.ps1')
. (Join-Path $script:KitRoot 'lib\Rapport.ps1')

$script:WinDefault = (-not $DebutUtc)
function Parse-UtcDate {
    param([string]$Text)
    $ci = [Globalization.CultureInfo]::InvariantCulture
    $st = [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal
    return [datetime]::Parse($Text, $ci, $st)
}
if (-not $DebutUtc -and $Jours -lt 1) {
    Write-Host 'ERREUR : Jours doit etre superieur ou egal a 1.' -ForegroundColor Red
    exit 2
}
try {
    if ($DebutUtc) { $script:WinS = Parse-UtcDate $DebutUtc } else { $script:WinS = (Get-Date).ToUniversalTime().AddDays(-$Jours) }
    if ($FinUtc) { $script:WinE = Parse-UtcDate $FinUtc } else { $script:WinE = (Get-Date).ToUniversalTime().AddHours(1) }
} catch {
    Write-Host ('ERREUR : date UTC invalide. Utilisez le format aaaa-mm-jj hh:mm. ' + $_.Exception.Message) -ForegroundColor Red
    exit 2
}

if (-not $SansMenu -and -not $PSBoundParameters.ContainsKey('Mode')) {
    Write-Host ''
    Write-Host ' BLL IR-Kit - collecte de preuves' -ForegroundColor Cyan
    Write-Host ' 1) Rapide    : acces distants, persistance, traces d''execution, reseau (2-5 min)'
    Write-Host ' 2) Complet   : + parcours des disques, registre, journaux (10-40 min)'
    Write-Host ' 3) Complet + VSS (copie des fichiers verrouilles via instantane)'
    Write-Host ' 4) Fenetre horaire precise (incident connu) + Complet'
    $c = Read-Host ' Choix [2]'
    switch ($c) {
        '1' { $script:Mode = 'Rapide' }
        '3' { $script:UseVss = $true }
        '4' {
            $d = Read-Host ' Debut UTC (aaaa-mm-jj hh:mm)'; $e = Read-Host ' Fin UTC   (aaaa-mm-jj hh:mm)'
            try {
                if ($d) { $script:WinS = Parse-UtcDate $d; $script:WinDefault = $false }
                if ($e) { $script:WinE = Parse-UtcDate $e }
            } catch {
                Write-Host ('ERREUR : date UTC invalide. Utilisez le format aaaa-mm-jj hh:mm. ' + $_.Exception.Message) -ForegroundColor Red
                exit 2
            }
        }
    }
}
if ($script:WinS -gt $script:WinE) {
    Write-Host 'ERREUR : le debut de la fenetre doit preceder sa fin.' -ForegroundColor Red
    exit 2
}

# Dossier de sortie : a cote de l'outil (cle USB), jamais sur un partage reseau
$base = $Sortie; if (-not $base) { $base = Join-Path $script:KitRoot 'Resultats' }
$stamp = '{0}_{1:yyyyMMdd_HHmmss}' -f $env:COMPUTERNAME, (Get-Date)
$script:Out = Join-Path $base $stamp
$script:Raw = Join-Path $script:Out 'raw'
$script:RawSens = Join-Path $script:Out 'raw_SENSIBLE'
foreach ($d in $script:Out, $script:Raw, $script:RawSens) { $null = New-Item -ItemType Directory -Path $d -Force }
$script:LogFile = Join-Path $script:Out 'collecte.log'

Say ('BLL IR-Kit v{0} - poste {1} - mode {2}' -f $script:KitVersion, $env:COMPUTERNAME, $script:Mode) 'Green'
Say ('Fenetre analysee : {0} -> {1} UTC' -f (U $script:WinS), (U $script:WinE))
Say ('Sortie : ' + $script:Out)
$drv = (Get-Item -LiteralPath $script:Out).PSDrive
if ($drv -and $drv.Free -lt 2GB) { Say ('ATTENTION : moins de 2 Go libres sur ' + $drv.Name + ':') 'Yellow' }

# Configuration
$script:IocList = @(Read-ConfigList (Join-Path $script:KitRoot 'config\ioc.txt'))
$script:Allow = @(Read-ConfigList (Join-Path $script:KitRoot 'config\autorises.txt') | ForEach-Object { $_.Valeur })
Say ('{0} indicateur(s) connus, {1} regle(s) d''autorisation' -f $script:IocList.Count, $script:Allow.Count)

Invoke-Module 'Systeme'          { Mod-Systeme }
Invoke-Module 'Acces distants'   { Mod-AccesDistant }
Invoke-Module 'Persistance'      { Mod-Persistance }
Invoke-Module 'Traces d''execution' { Mod-Execution }
Invoke-Module 'Reseau'           { Mod-Reseau }
Invoke-Module 'Journaux'         { Mod-Journaux }
if ($script:Mode -eq 'Complet') { Invoke-Module 'Fichiers' { Mod-Fichiers } }
Invoke-Module 'Copie des preuves' { Mod-Preuves }
Invoke-Module 'Indicateurs connus' { Mod-IOC }
Invoke-Module 'Rapport'          { Build-Rapport }
Say '== Empreintes et archive' 'Green'
try { Close-Collecte } catch { Say ('Erreur de cloture : ' + $_.Exception.Message) 'Yellow' }

$nE = @($script:Findings | Where-Object { $_.Severite -eq 'ELEVE' }).Count
$nM = @($script:Findings | Where-Object { $_.Severite -eq 'MOYEN' }).Count
Say ''
Say ('TERMINE en {0} min : {1} constats eleves, {2} moyens.' -f [int]((Get-Date) - $script:StartTime).TotalMinutes, $nE, $nM) 'Green'
Say ('Ouvrez : ' + (Join-Path $script:Out 'rapport.html'))
Say 'ATTENTION : le dossier raw_SENSIBLE contient des cles/historiques : ne le transmettez a personne sans raison.' 'Yellow'
if (-not $SansMenu) { try { Start-Process (Join-Path $script:Out 'rapport.html') } catch { }; Read-Host 'Entree pour fermer' | Out-Null }
