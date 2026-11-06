<#
 BLL Audit-Kit - audit de securite d'un poste (lecture seule), avec score et recommandations.
 Usage : Lancer-Audit.bat   ou   powershell -ExecutionPolicy Bypass -File Audit-Kit.ps1 [-Modules Durcissement,Sauvegardes] [-Rapide]
#>
[CmdletBinding()]
param(
    [ValidateSet('Durcissement', 'Correctifs', 'Sauvegardes', 'Partages', 'Reseau', 'Tout')][string[]]$Modules = @('Tout'),
    [switch]$Rapide,            # saute la recherche de mises a jour Windows (lente)
    [string]$Sortie,
    [switch]$SansMenu
)
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
$script:StartTime = Get-Date
$script:KitRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$script:Rapide = [bool]$Rapide
$script:Mode = 'Audit'

$id = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $id.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host 'ERREUR : lancez en administrateur (Lancer-Audit.bat).' -ForegroundColor Red; exit 1
}
. (Join-Path $script:KitRoot 'lib\Parsers.ps1')
. (Join-Path $script:KitRoot 'lib\Core.ps1')
. (Join-Path $script:KitRoot 'lib\Collecte1.ps1')
. (Join-Path $script:KitRoot 'lib\Audits1.ps1')
. (Join-Path $script:KitRoot 'lib\Audits2.ps1')

$script:WinS = (Get-Date).ToUniversalTime().AddDays(-30); $script:WinE = (Get-Date).ToUniversalTime().AddHours(1)
$base = $Sortie; if (-not $base) { $base = Join-Path $script:KitRoot 'Resultats' }
$script:Out = Join-Path $base ('AUDIT_{0}_{1:yyyyMMdd_HHmmss}' -f $env:COMPUTERNAME, (Get-Date))
$script:Raw = Join-Path $script:Out 'raw'; $script:RawSens = Join-Path $script:Out 'raw_SENSIBLE'
$null = New-Item -ItemType Directory -Path $script:Out -Force
$script:LogFile = Join-Path $script:Out 'audit.log'
$script:Allow = @(Read-ConfigList (Join-Path $script:KitRoot 'config\autorises.txt') | ForEach-Object { $_.Valeur })

$sel = $Modules
if (-not $SansMenu -and -not $PSBoundParameters.ContainsKey('Modules')) {
    Write-Host ''; Write-Host ' BLL Audit-Kit - audit de securite (lecture seule)' -ForegroundColor Cyan
    Write-Host ' 1) Complet (poste + sauvegardes + partages + reseau local)'
    Write-Host ' 2) Poste seul (durcissement + correctifs)'
    Write-Host ' 3) Sauvegardes seules'
    Write-Host ' 4) Reseau local seul (a lancer depuis un poste de l''officine)'
    $c = Read-Host ' Choix [1]'
    switch ($c) { '2' { $sel = @('Durcissement', 'Correctifs') } '3' { $sel = @('Sauvegardes') } '4' { $sel = @('Reseau') } default { $sel = @('Tout') } }
}
function Want { param([string]$m) return (($sel -contains 'Tout') -or ($sel -contains $m)) }

Say ('BLL Audit-Kit v{0} - poste {1}' -f $script:KitVersion, $env:COMPUTERNAME) 'Green'
Say ('Sortie : ' + $script:Out)
if (Want 'Durcissement') { Invoke-Module 'Durcissement Windows' { Mod-Durcissement } }
if (Want 'Correctifs')   { Invoke-Module 'Correctifs et logiciels' { Mod-Correctifs } }
if (Want 'Sauvegardes')  { Invoke-Module 'Sauvegardes' { Mod-Sauvegardes } }
if (Want 'Partages')     { Invoke-Module 'Partages et donnees' { Mod-Partages } }
if (Want 'Reseau')       { Invoke-Module 'Reseau local' { Mod-ReseauLan } }
Invoke-Module 'Rapport' { Build-RapportAudit }
Say ''
Say ('TERMINE : score {0}/100 (note {1}) - {2} ecarts.' -f $script:Score, $script:Note, @($script:Checks | Where-Object { $_.Etat -eq 'ECART' }).Count) 'Green'
Say ('Rapport : ' + (Join-Path $script:Out 'rapport_audit.html'))
if (-not $SansMenu) { try { Start-Process (Join-Path $script:Out 'rapport_audit.html') } catch { }; Read-Host 'Entree pour fermer' | Out-Null }
