<#
 Active une meilleure journalisation (MODIFIE le poste - a lancer APRES la collecte, avec accord du titulaire).
 - Audit creation de processus (4688) + ligne de commande
 - Journal PowerShell ScriptBlock (4104)
 - Taille des journaux Securite / PowerShell portee a 256 Mo
#>
$id = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $id.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { Write-Host 'Lancez en administrateur.' -ForegroundColor Red; exit 1 }
Write-Host 'Ce script modifie la configuration d''audit de ce poste.' -ForegroundColor Yellow
if ((Read-Host 'Taper OUI pour continuer') -ne 'OUI') { exit 0 }
# GUID des sous-categories : les noms ("Process Creation", "Logon") sont traduits sur un Windows en francais
auditpol /set /subcategory:'{0CCE922B-69AE-11D9-BED3-505054503030}' /success:enable | Out-Null
if ($LASTEXITCODE -ne 0) { Write-Host 'ERREUR : audit de creation de processus non active.' -ForegroundColor Red }
auditpol /set /subcategory:'{0CCE9215-69AE-11D9-BED3-505054503030}' /success:enable /failure:enable | Out-Null
if ($LASTEXITCODE -ne 0) { Write-Host 'ERREUR : audit des ouvertures de session non active.' -ForegroundColor Red }
$k = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
New-Item -Path $k -Force | Out-Null
Set-ItemProperty -Path $k -Name ProcessCreationIncludeCmdLine_Enabled -Value 1 -Type DWord
$k2 = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
New-Item -Path $k2 -Force | Out-Null
Set-ItemProperty -Path $k2 -Name EnableScriptBlockLogging -Value 1 -Type DWord
# taille portee a 256 Mo seulement si elle est inferieure (ne jamais reduire un journal deja plus grand)
foreach ($ln in 'Security', 'Microsoft-Windows-PowerShell/Operational') {
    $cur = 0; try { $cur = (Get-WinEvent -ListLog $ln -ErrorAction Stop).MaximumSizeInBytes } catch { }
    if ($cur -lt 268435456) { wevtutil sl "$ln" /ms:268435456 }
}
Write-Host 'Journalisation renforcee. Fait le' (Get-Date -Format 'yyyy-MM-dd HH:mm') -ForegroundColor Green
Read-Host 'Entree pour fermer' | Out-Null
