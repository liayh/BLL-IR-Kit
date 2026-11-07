<#
 BLL Audit Microsoft 365 - audit en LECTURE SEULE d'un tenant (a lancer depuis votre poste, pas depuis la pharmacie).
 Prerequis : compte administrateur general ou lecteur de securite du tenant. Le module Microsoft.Graph.Authentication
 (et ExchangeOnlineManagement pour la partie messagerie) est installe pour l'utilisateur courant si absent.
 Note : a la premiere connexion, Microsoft demande de consentir a l'application "Microsoft Graph Command Line Tools"
 (enregistrement de cette application dans le tenant). L'audit lui-meme ne modifie rien.
 Usage : Lancer-M365.bat   ou   powershell -ExecutionPolicy Bypass -File Audits\Audit-M365.ps1 [-SansExchange] [-Pays FR,BE]
#>
[CmdletBinding()]
param([switch]$SansExchange, [string[]]$Pays = @('FR'), [string]$Sortie, [switch]$Menu)
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
$script:KitRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$script:Mode = 'M365'
. (Join-Path $script:KitRoot 'lib\Parsers.ps1')
. (Join-Path $script:KitRoot 'lib\Core.ps1')
. (Join-Path $script:KitRoot 'lib\Audits1.ps1')
. (Join-Path $script:KitRoot 'lib\Audits2.ps1')
$script:WinS = (Get-Date).ToUniversalTime().AddDays(-30); $script:WinE = (Get-Date).ToUniversalTime().AddHours(1)

function Need-Module { param([string]$n) if (-not (Get-Module -ListAvailable -Name $n)) { Write-Host "Installation du module $n (utilisateur courant)..." -ForegroundColor Yellow; Install-Module $n -Scope CurrentUser -Force -AllowClobber } ; Import-Module $n -ErrorAction Stop }
try { Need-Module 'Microsoft.Graph.Authentication' } catch { Write-Host ('Impossible de charger Microsoft.Graph.Authentication : ' + $_.Exception.Message) -ForegroundColor Red; Read-Host 'Entree'; exit 1 }
$scopes = 'Policy.Read.All', 'Directory.Read.All', 'User.Read.All', 'AuditLog.Read.All', 'Reports.Read.All', 'RoleManagement.Read.Directory', 'Application.Read.All', 'DelegatedPermissionGrant.Read.All'
Write-Host 'Connexion a Microsoft 365 (une fenetre de connexion va s''ouvrir)...' -ForegroundColor Cyan
Connect-MgGraph -Scopes $scopes -NoWelcome | Out-Null
$ctx = Get-MgContext
if (-not $ctx) { Write-Host 'Connexion impossible.' -ForegroundColor Red; Read-Host 'Entree'; exit 1 }

function GraphGet {
    param([string]$Uri)
    $res = New-Object System.Collections.Generic.List[object]
    while ($Uri) {
        $r = Invoke-MgGraphRequest -Method GET -Uri $Uri -Headers @{ ConsistencyLevel = 'eventual' } -ErrorAction Stop
        foreach ($v in $r['value']) { $res.Add($v) }
        $Uri = $r['@odata.nextLink']
    }
    return $res
}

$org = $null; try { $org = (GraphGet 'https://graph.microsoft.com/v1.0/organization')[0] } catch { }
$tenant = 'tenant'; if ($org) { $tenant = ([string]$org['displayName'] -replace '[^A-Za-z0-9_-]', '_') }
$base = $Sortie; if (-not $base) { $base = Join-Path $script:KitRoot 'Resultats' }
$script:Out = Join-Path $base ('AUDIT_M365_{0}_{1:yyyyMMdd_HHmmss}' -f $tenant, (Get-Date))
$null = New-Item -ItemType Directory -Path $script:Out -Force
$script:LogFile = Join-Path $script:Out 'audit.log'
$script:Allow = @(Read-ConfigList (Join-Path $script:KitRoot 'config\autorises.txt') | ForEach-Object { $_.Valeur })
$env:COMPUTERNAME = $tenant

Invoke-Module 'Microsoft 365 : identites et acces' {
    $c = 'Microsoft 365'
    # Security defaults / acces conditionnel
    $sd = $null; try { $sd = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy' -ErrorAction Stop } catch { }
    $ca = @(); try { $ca = @(GraphGet 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies' | Where-Object { $_['state'] -eq 'enabled' }) } catch { }
    $caMfa = @($ca | Where-Object { @($_['grantControls']['builtInControls']) -contains 'mfa' -or $_['grantControls']['authenticationStrength'] })
    $sdOn = ($sd -and $sd['isEnabled'])
    Add-Check $c 'MFA impose par Security Defaults ou une strategie d''acces conditionnel' ($sdOn -or $caMfa.Count -gt 0) ('Security Defaults=' + $sdOn + ' ; strategies CA actives=' + $ca.Count + ' dont MFA=' + $caMfa.Count) 'Activer Security Defaults (petit tenant) ou une strategie d''acces conditionnel exigeant le MFA pour tous.' 'ELEVE'
    # strategie de blocage du legacy : clients "other" (IMAP/POP/SMTP...) ou ActiveSync, appliquee a TOUS les utilisateurs
    $legacy = @($ca | Where-Object { $ty = @($_['conditions']['clientAppTypes']); ($ty -contains 'other' -or $ty -contains 'exchangeActiveSync') -and @($_['grantControls']['builtInControls']) -contains 'block' -and @($_['conditions']['users']['includeUsers']) -contains 'All' })
    if ($ca.Count -gt 0) { Add-Check $c 'Authentification heritee bloquee (acces conditionnel)' ($legacy.Count -gt 0) ('strategies bloquant le legacy : ' + $legacy.Count) 'Bloquer les protocoles d''authentification herites.' 'MOYEN' }

    # Utilisateurs (sans signInActivity, qui exige une licence Entra ID P1 : lu a part plus bas)
    $usersBasic = @(); $uById = @{}
    try {
        $usersBasic = @(GraphGet 'https://graph.microsoft.com/v1.0/users?$select=id,displayName,userPrincipalName,accountEnabled,userType,createdDateTime&$top=999')
        foreach ($u in $usersBasic) { $uById[[string]$u['id']] = $u }
    } catch { }

    # MFA par utilisateur : comptes actifs internes seulement (boites partagees et comptes desactives exclus)
    try {
        $reg = GraphGet 'https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails?$top=999'
        $rows = @($reg | ForEach-Object {
            $u = $uById[[string]$_['id']]
            $actif = $true; if ($u) { $actif = [bool]$u['accountEnabled'] }
            [pscustomobject]@{ Utilisateur = $_['userPrincipalName']; Actif = $actif; Type = [string]$_['userType']; Admin = $_['isAdmin']; MfaEnregistre = $_['isMfaRegistered']; MfaCapable = $_['isMfaCapable']; Methodes = (@($_['methodsRegistered']) -join ',') }
        })
        $null = Save-Csv $rows 'm365_mfa_par_utilisateur.csv' ''
        $rows = @($rows | Where-Object { $_.Actif -and $_.Type -ne 'guest' })
        $noMfa = @($rows | Where-Object { -not $_.MfaEnregistre })
        $adm = @($rows | Where-Object { $_.Admin -and -not $_.MfaEnregistre })
        Add-Check $c 'Tous les administrateurs ont enregistre le MFA' ($adm.Count -eq 0) (($adm | ForEach-Object { $_.Utilisateur }) -join ' ; ') 'Enregistrer le MFA pour chaque compte administrateur immediatement.' 'ELEVE'
        Add-Check $c 'Tous les utilisateurs ont enregistre le MFA' ($noMfa.Count -eq 0) ([string]$noMfa.Count + ' sur ' + $rows.Count + ' : ' + (($noMfa | Select-Object -First 10 | ForEach-Object { $_.Utilisateur }) -join ' ; ')) 'Faire enregistrer le MFA a chaque utilisateur.' 'ELEVE'
        $sms = @($rows | Where-Object { $_.Methodes -match 'mobilePhone|voice' -and $_.Methodes -notmatch '(?i)microsoftAuthenticator|fido2|windowsHello|softwareOneTimePasscode|hardwareOneTimePasscode|passKey' })
        Add-Check $c 'MFA autre que SMS/voix seul' ($sms.Count -eq 0) ([string]$sms.Count + ' utilisateur(s) en SMS/voix uniquement') 'Passer a Microsoft Authenticator.' 'FAIBLE'
    } catch { Add-Check $c 'MFA par utilisateur' $null ('non verifiable : ' + $_.Exception.Message) }

    # Administrateurs generaux
    try {
        $roles = GraphGet 'https://graph.microsoft.com/v1.0/directoryRoles'
        $ga = $roles | Where-Object { $_['roleTemplateId'] -eq '62e90394-69f5-4237-9190-012177145e10' } | Select-Object -First 1
        if ($ga) {
            $mem = @(GraphGet ('https://graph.microsoft.com/v1.0/directoryRoles/' + $ga['id'] + '/members'))
            $null = Save-Csv ($mem | ForEach-Object { [pscustomobject]@{ Nom = $_['displayName']; Upn = $_['userPrincipalName'] } }) 'm365_administrateurs_generaux.csv' ''
            Add-Check $c 'Entre 2 et 4 administrateurs generaux' ($mem.Count -ge 2 -and $mem.Count -le 4) ([string]$mem.Count + ' : ' + (($mem | ForEach-Object { $_['userPrincipalName'] }) -join ' ; ')) 'Limiter les administrateurs generaux (au moins 2 pour le secours, pas plus de 4).' 'MOYEN'
        }
    } catch { }

    # Comptes invites (sans licence particuliere)
    if ($usersBasic.Count -gt 0) {
        $guests = @($usersBasic | Where-Object { $_['userType'] -eq 'Guest' })
        Add-Check $c 'Aucun compte invite (externe) non justifie' ($guests.Count -eq 0) ([string]$guests.Count + ' invite(s) : ' + (($guests | Select-Object -First 8 | ForEach-Object { $_['userPrincipalName'] }) -join ' ; ')) 'Verifier chaque compte invite.' 'FAIBLE'
    } else { Add-Check $c 'Comptes invites' $null 'non verifiable (liste des utilisateurs illisible)' }
    # Derniere connexion (licence Entra ID P1) : comptes actifs sans connexion depuis 90 jours, ou jamais connectes et crees il y a plus de 90 jours
    $lastSi = @{}
    try {
        foreach ($u in (GraphGet 'https://graph.microsoft.com/v1.0/users?$select=id,signInActivity&$top=999')) {
            if ($u['signInActivity']) { $lastSi[[string]$u['id']] = $u['signInActivity']['lastSuccessfulSignInDateTime'] }
        }
        $lim = (Get-Date).AddDays(-90)
        $inact = @($usersBasic | Where-Object {
            $l = $lastSi[[string]$_['id']]
            $_['accountEnabled'] -and $_['userType'] -ne 'Guest' -and (($l -and ([datetime]$l) -lt $lim) -or (-not $l -and $_['createdDateTime'] -and ([datetime]$_['createdDateTime']) -lt $lim))
        })
        Add-Check $c 'Aucun compte actif sans connexion depuis 90 jours' ($inact.Count -eq 0) (($inact | Select-Object -First 8 | ForEach-Object { $_['userPrincipalName'] }) -join ' ; ') 'Desactiver les comptes inutilises (les boites partagees doivent etre des comptes desactives).' 'MOYEN'
    } catch { Add-Check $c 'Comptes inactifs' $null 'non verifiable (licence Entra ID P1 requise pour la date de derniere connexion)' }
    $null = Save-Csv ($usersBasic | ForEach-Object { [pscustomobject]@{ Nom = $_['displayName']; Upn = $_['userPrincipalName']; Actif = $_['accountEnabled']; Type = $_['userType']; Cree = $_['createdDateTime']; DerniereConnexion = $lastSi[[string]$_['id']] } }) 'm365_utilisateurs.csv' ''

    # Consentements d'applications
    try {
        $grants = GraphGet 'https://graph.microsoft.com/v1.0/oauth2PermissionGrants?$top=999'
        $riskRx = '(?i)Mail\.(Read|ReadWrite|Send)|Files\.ReadWrite\.All|Files\.Read\.All|MailboxSettings\.ReadWrite|full_access_as_app|Directory\.ReadWrite|Contacts\.Read|Chat\.Read'
        $sp = @{}
        $list = foreach ($g in $grants) {
            if (-not $sp.ContainsKey($g['clientId'])) { try { $sp[$g['clientId']] = (Invoke-MgGraphRequest -Method GET -Uri ('https://graph.microsoft.com/v1.0/servicePrincipals/' + $g['clientId'] + '?$select=displayName,publisherName,verifiedPublisher') -ErrorAction Stop) } catch { $sp[$g['clientId']] = @{ displayName = $g['clientId'] } } }
            [pscustomobject]@{ Application = $sp[$g['clientId']]['displayName']; Editeur = $sp[$g['clientId']]['publisherName']; Type = $g['consentType']; Droits = $g['scope']; Risque = [bool]($g['scope'] -match $riskRx) }
        }
        $null = Save-Csv $list 'm365_consentements_applications.csv' ''
        $risky = @($list | Where-Object { $_.Risque -and $_.Type -eq 'Principal' })
        Add-Check $c 'Aucune application tierce avec acces large (messagerie/fichiers) consenti par un utilisateur' ($risky.Count -eq 0) (($risky | Select-Object -First 8 | ForEach-Object { $_.Application + ' [' + $_.Droits.Trim() + ']' }) -join ' ; ') 'Revoquer les consentements inconnus ; desactiver le consentement utilisateur.' 'ELEVE'
    } catch { Add-Check $c 'Consentements d''applications' $null 'non verifiable' }

    # Connexions depuis l'etranger (7 jours)
    try {
        $since = (Get-Date).ToUniversalTime().AddDays(-7).ToString('yyyy-MM-ddTHH:mm:ssZ')
        $si = GraphGet ('https://graph.microsoft.com/v1.0/auditLogs/signIns?$filter=createdDateTime ge ' + $since + '&$top=500')
        $ok = @($si | Where-Object { $_['status']['errorCode'] -eq 0 })
        $foreign = @($ok | Where-Object { $_['location'] -and $_['location']['countryOrRegion'] -and ($Pays -notcontains $_['location']['countryOrRegion']) })
        $null = Save-Csv ($foreign | ForEach-Object { [pscustomobject]@{ Date = $_['createdDateTime']; Utilisateur = $_['userPrincipalName']; Pays = $_['location']['countryOrRegion']; Ip = $_['ipAddress']; Application = $_['appDisplayName']; Client = $_['clientAppUsed'] } }) 'm365_connexions_hors_pays.csv' ''
        Add-Check $c ('Aucune connexion reussie hors de : ' + ($Pays -join ',') + ' (7 jours, 500 dernieres)') ($foreign.Count -eq 0) ([string]$foreign.Count + ' connexion(s) ; pays : ' + ((($foreign | ForEach-Object { $_['location']['countryOrRegion'] }) | Sort-Object -Unique) -join ',')) 'Verifier chaque connexion ; bloquer les pays inutiles par acces conditionnel.' 'ELEVE'
        $leg = @($ok | Where-Object { $_['clientAppUsed'] -match 'IMAP|POP|SMTP|Exchange ActiveSync|Other clients' })
        Add-Check $c 'Aucune connexion par protocole herite (IMAP/POP/SMTP) en 7 jours' ($leg.Count -eq 0) ([string]$leg.Count + ' connexion(s)') 'Bloquer l''authentification heritee.' 'MOYEN'
    } catch { Add-Check $c 'Journal des connexions' $null 'non verifiable (licence Entra ID P1 requise ?)' }
}

if (-not $SansExchange) {
    Invoke-Module 'Microsoft 365 : messagerie Exchange Online' {
        $c = 'Exchange Online'
        Need-Module 'ExchangeOnlineManagement'
        Write-Host 'Connexion a Exchange Online...' -ForegroundColor Cyan
        Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
        $mbx = @(Get-Mailbox -ResultSize Unlimited)
        # Redirections au niveau de la boite
        $fw = @($mbx | Where-Object { $_.ForwardingSmtpAddress -or $_.ForwardingAddress })
        Add-Check $c 'Aucune boite avec redirection automatique' ($fw.Count -eq 0) (($fw | ForEach-Object { $_.UserPrincipalName + ' -> ' + $_.ForwardingSmtpAddress + $_.ForwardingAddress }) -join ' ; ') 'Supprimer les redirections non justifiees (technique classique de compromission).' 'ELEVE'
        # Regles de boite de reception suspectes
        $susp = New-Object System.Collections.Generic.List[object]
        foreach ($m in $mbx) {
            foreach ($r in @(Get-InboxRule -Mailbox $m.UserPrincipalName -ErrorAction SilentlyContinue)) {
                if ($r.ForwardTo -or $r.ForwardAsAttachmentTo -or $r.RedirectTo -or $r.DeleteMessage -or ($r.MoveToFolder -match '(?i)RSS|Archive|Conversation History|Historique des conversations')) {
                    # proprietes vides exclues avant la jointure (sinon ";;" serait compte comme une redirection)
                    $redir = (@($r.ForwardTo, $r.RedirectTo, $r.ForwardAsAttachmentTo) | ForEach-Object { $_ } | Where-Object { $_ }) -join ';'
                    $susp.Add([pscustomobject]@{ Boite = $m.UserPrincipalName; Regle = $r.Name; Activee = $r.Enabled; Redirige = $redir; Supprime = [bool]$r.DeleteMessage; Dossier = $r.MoveToFolder })
                }
            }
        }
        $null = Save-Csv $susp 'm365_regles_boite_suspectes.csv' ''
        $bad = @($susp | Where-Object { $_.Redirige -or $_.Supprime })
        Add-Check $c 'Aucune regle de boite qui redirige ou supprime des messages' ($bad.Count -eq 0) (($bad | Select-Object -First 6 | ForEach-Object { $_.Boite + ' : ' + $_.Regle }) -join ' ; ') 'Examiner et supprimer les regles inconnues.' 'ELEVE'
        $tr = @(Get-TransportRule | Where-Object { $_.RedirectMessageTo -or $_.BlindCopyTo -or $_.CopyTo })
        Add-Check $c 'Aucune regle de transport qui copie/redirige les messages' ($tr.Count -eq 0) (($tr | ForEach-Object { $_.Name }) -join ' ; ') 'Verifier les regles de flux de messagerie.' 'ELEVE'
        $oc = Get-OrganizationConfig
        Add-Check $c 'Audit des boites aux lettres active' (-not $oc.AuditDisabled) ('AuditDisabled=' + $oc.AuditDisabled) 'Set-OrganizationConfig -AuditDisabled $false' 'MOYEN'
        $tc = Get-TransportConfig
        Add-Check $c 'SMTP AUTH desactive au niveau du tenant' ([bool]$tc.SmtpClientAuthenticationDisabled) ('SmtpClientAuthenticationDisabled=' + $tc.SmtpClientAuthenticationDisabled) 'Desactiver SMTP AUTH sauf besoin (imprimante/scanner : compte dedie).' 'MOYEN'
        $cas = @(Get-CASMailbox -ResultSize Unlimited | Where-Object { $_.PopEnabled -or $_.ImapEnabled })
        $null = Save-Csv ($cas | ForEach-Object { [pscustomobject]@{ Boite = $_.PrimarySmtpAddress; Pop = $_.PopEnabled; Imap = $_.ImapEnabled } }) 'm365_pop_imap_actifs.csv' ''
        Add-Check $c 'POP/IMAP desactives sur les boites' ($cas.Count -eq 0) ([string]$cas.Count + ' boite(s) avec POP/IMAP actif') 'Desactiver POP/IMAP par boite si non utilise.' 'MOYEN'
        Disconnect-ExchangeOnline -Confirm:$false | Out-Null
    }
}
Invoke-Module 'Rapport' { Build-RapportAudit }
Disconnect-MgGraph | Out-Null
Write-Host ''
Write-Host ('TERMINE : score {0}/100 (note {1}). Rapport : {2}' -f $script:Score, $script:Note, (Join-Path $script:Out 'rapport_audit.html')) -ForegroundColor Green
Write-Host ('Rapport detaille : donner ' + (Join-Path $script:Out 'DOSSIER_POUR_IA.md') + ' a Claude Code.') -ForegroundColor Cyan
Open-Rapport 'rapport_audit.html'
Wait-Fin -Menu:$Menu
