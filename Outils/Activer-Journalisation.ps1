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
auditpol /set /subcategory:"Process Creation" /success:enable | Out-Null
auditpol /set /subcategory:"Logon" /success:enable /failure:enable | Out-Null
$k = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
New-Item -Path $k -Force | Out-Null
Set-ItemProperty -Path $k -Name ProcessCreationIncludeCmdLine_Enabled -Value 1 -Type DWord
$k2 = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
New-Item -Path $k2 -Force | Out-Null
Set-ItemProperty -Path $k2 -Name EnableScriptBlockLogging -Value 1 -Type DWord
wevtutil sl Security /ms:268435456
wevtutil sl "Microsoft-Windows-PowerShell/Operational" /ms:268435456
Write-Host 'Journalisation renforcee. Fait le' (Get-Date -Format 'yyyy-MM-dd HH:mm') -ForegroundColor Green
Read-Host 'Entree pour fermer' | Out-Null
