# Rapport.ps1 - recherche d'IOC, rapport HTML, resume, chaine de possession, archive

function Mod-IOC {
    $iocs = @($script:IocList | ForEach-Object { $_.Valeur })
    if ($iocs.Count -eq 0) { Say '   Aucun indicateur dans config\ioc.txt'; return }
    $files = New-Object System.Collections.Generic.List[string]
    foreach ($root in $script:Raw, $script:Out) {
        if (-not (Test-Path -LiteralPath $root)) { continue }
        Get-ChildItem -LiteralPath $root -Recurse -File -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension -in '.trace', '.txt', '.log', '.csv', '.ini', '.xml' -and $_.Length -lt 100MB -and $_.FullName -notmatch 'ioc_correspondances|IOC_observes|RESUME|LISEZMOI|SHA256SUMS' } |
            ForEach-Object { if (-not $files.Contains($_.FullName)) { $files.Add($_.FullName) } }
    }
    Say ("   Recherche de {0} indicateur(s) dans {1} fichiers collectes" -f $iocs.Count, $files.Count)
    $hits = @(Find-IocInFiles -Iocs $iocs -Files $files.ToArray() -MaxHitsPerIoc 50)
    $null = Save-Csv $hits 'ioc_correspondances.csv' '08_synthese'
    $null = Save-Csv $script:IocSeen 'IOC_observes_sur_ce_poste.csv' '08_synthese'
    $byIoc = $hits | Group-Object Ioc
    foreach ($g in $byIoc) {
        $first = $g.Group | Select-Object -First 1
        Add-Finding 'ELEVE' 'Indicateur connu' ("L'indicateur '{0}' apparait {1} fois dans les donnees collectees" -f $g.Name, $g.Count) $first.Fichier ('Exemple : ' + $first.Extrait)
    }
    if (-not $hits) { Say '   Aucun indicateur connu retrouve' }
}

function HtmlEnc { param($t) return [System.Net.WebUtility]::HtmlEncode([string]$t) }

function Build-Rapport {
    $order = @{ 'ELEVE' = 0; 'MOYEN' = 1; 'FAIBLE' = 2; 'INFO' = 3 }
    $f = @($script:Findings | Sort-Object @{ Expression = { $order[$_.Severite] } }, Categorie, Detail)
    $nE = @($f | Where-Object { $_.Severite -eq 'ELEVE' }).Count
    $nM = @($f | Where-Object { $_.Severite -eq 'MOYEN' }).Count
    $nF = @($f | Where-Object { $_.Severite -eq 'FAIBLE' }).Count
    $nI = @($f | Where-Object { $_.Severite -eq 'INFO' }).Count

    # RESUME.txt
    $r = New-Object System.Collections.Generic.List[string]
    $r.Add('BLL IR-Kit v' + $script:KitVersion + ' - RESUME'); $r.Add('=' * 60)
    $r.Add('Poste            : ' + $env:COMPUTERNAME)
    $r.Add('Collecte         : ' + (U (Get-Date)) + ' UTC (mode ' + $script:Mode + ')')
    $r.Add('Fenetre analysee : ' + (U $script:WinS) + ' -> ' + (U $script:WinE) + ' UTC')
    $r.Add(('Constats         : {0} eleves, {1} moyens, {2} faibles, {3} informatifs' -f $nE, $nM, $nF, $nI)); $r.Add('')
    foreach ($x in ($f | Where-Object { $_.Severite -in 'ELEVE', 'MOYEN' } | Select-Object -First 80)) {
        $r.Add(('[{0}] {1} - {2}' -f $x.Severite, $x.Categorie, $x.Detail))
        if ($x.Chemin) { $r.Add('       ' + $x.Chemin) }
        if ($x.Info) { $r.Add('       ' + $x.Info) }
    }
    if ($script:Errors.Count -gt 0) { $r.Add(''); $r.Add('MODULES EN ERREUR (resultats partiels) :'); foreach ($e in $script:Errors) { $r.Add(' - ' + $e) } }
    $r.Add(''); $r.Add('Rapport detaille : rapport.html - Tableaux : dossiers 01 a 08 - Preuves : raw\ et raw_SENSIBLE\')
    Save-Text $r.ToArray() 'RESUME.txt' ''
    $null = Save-Csv $f 'constats.csv' '08_synthese'

    # rapport.html
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8"><title>Rapport IR - ' + (HtmlEnc $env:COMPUTERNAME) + '</title><style>')
    [void]$sb.Append('body{font-family:Segoe UI,Arial,sans-serif;margin:24px;color:#222}h1{font-size:22px}h2{font-size:17px;margin-top:28px;border-bottom:1px solid #ccc;padding-bottom:4px}')
    [void]$sb.Append('table{border-collapse:collapse;width:100%;font-size:12.5px}th,td{border:1px solid #ddd;padding:4px 6px;text-align:left;vertical-align:top;word-break:break-word}th{background:#f3f3f3}')
    [void]$sb.Append('.ELEVE{background:#fde2e2}.MOYEN{background:#fff0d6}.FAIBLE{background:#fffbe0}.INFO{background:#f4f4f4}.k{display:inline-block;margin-right:14px;padding:6px 12px;border-radius:4px;font-weight:600}</style></head><body>')
    [void]$sb.Append('<h1>Rapport de collecte - ' + (HtmlEnc $env:COMPUTERNAME) + '</h1>')
    [void]$sb.Append('<p>Collecte du ' + (U (Get-Date)) + ' UTC - fenetre analysee : ' + (U $script:WinS) + ' &rarr; ' + (U $script:WinE) + ' UTC - BLL IR-Kit v' + $script:KitVersion + ' (mode ' + $script:Mode + ')</p>')
    [void]$sb.Append('<p><span class="k ELEVE">' + $nE + ' eleves</span><span class="k MOYEN">' + $nM + ' moyens</span><span class="k FAIBLE">' + $nF + ' faibles</span><span class="k INFO">' + $nI + ' informatifs</span></p>')
    [void]$sb.Append('<p><em>Ce rapport signale des elements a verifier ; il ne conclut pas seul a une compromission. Une absence de trace ne prouve pas une absence d''activite (journaux limites, effacements, retention).</em></p>')
    [void]$sb.Append('<h2>Constats</h2><table><tr><th>Gravite</th><th>Categorie</th><th>Detail</th><th>Chemin</th><th>Info</th></tr>')
    foreach ($x in $f) { [void]$sb.Append('<tr class="' + $x.Severite + '"><td>' + $x.Severite + '</td><td>' + (HtmlEnc $x.Categorie) + '</td><td>' + (HtmlEnc $x.Detail) + '</td><td>' + (HtmlEnc $x.Chemin) + '</td><td>' + (HtmlEnc $x.Info) + '</td></tr>') }
    [void]$sb.Append('</table>')
    # sessions AnyDesk etc. (reprises des CSV produits)
    foreach ($csv in @(@('02_acces_distant\anydesk_connexions_entrantes.csv', 'Connexions AnyDesk reconstituees (heures UTC)'), @('02_acces_distant\anydesk_transferts_fichiers.csv', 'Transferts de fichiers AnyDesk'), @('02_acces_distant\teamviewer_connexions.csv', 'Connexions TeamViewer'), @('08_synthese\ioc_correspondances.csv', 'Correspondances avec les indicateurs connus'), @('06_journaux\couverture_des_journaux.csv', 'Couverture des journaux d''evenements'))) {
        $p = Join-Path $script:Out $csv[0]
        if (-not (Test-Path -LiteralPath $p)) { continue }
        $rows = @(Import-Csv -LiteralPath $p -Delimiter $script:Delim -ErrorAction SilentlyContinue)
        if ($rows.Count -eq 0 -or -not $rows[0].PSObject.Properties) { continue }
        $cols = @($rows[0].PSObject.Properties.Name)
        [void]$sb.Append('<h2>' + (HtmlEnc $csv[1]) + '</h2><table><tr>')
        foreach ($c in $cols) { [void]$sb.Append('<th>' + (HtmlEnc $c) + '</th>') }
        [void]$sb.Append('</tr>')
        foreach ($row in ($rows | Select-Object -First 200)) { [void]$sb.Append('<tr>'); foreach ($c in $cols) { [void]$sb.Append('<td>' + (HtmlEnc $row.$c) + '</td>') }; [void]$sb.Append('</tr>') }
        [void]$sb.Append('</table>')
        if ($rows.Count -gt 200) { [void]$sb.Append('<p>... ' + ($rows.Count - 200) + ' lignes de plus dans le fichier CSV.</p>') }
    }
    if ($script:Errors.Count -gt 0) { [void]$sb.Append('<h2>Modules en erreur</h2><ul>'); foreach ($e in $script:Errors) { [void]$sb.Append('<li>' + (HtmlEnc $e) + '</li>') }; [void]$sb.Append('</ul>') }
    [void]$sb.Append('<h2>Duree des modules</h2><table><tr><th>Module</th><th>Secondes</th></tr>')
    foreach ($t in $script:Timings) { [void]$sb.Append('<tr><td>' + (HtmlEnc $t.Module) + '</td><td>' + $t.Secondes + '</td></tr>') }
    [void]$sb.Append('</table></body></html>')
    [System.IO.File]::WriteAllText((Join-Path $script:Out 'rapport.html'), $sb.ToString(), (New-Object System.Text.UTF8Encoding($true)))
}

function Close-Collecte {
    # chaine de possession + empreintes + archive (hors raw_SENSIBLE)
    $cust = New-Object System.Collections.Generic.List[string]
    $cust.Add('FICHE DE COLLECTE (chaine de possession)'); $cust.Add('=' * 60)
    $cust.Add('Outil            : BLL IR-Kit v' + $script:KitVersion)
    $cust.Add('Poste            : ' + $env:COMPUTERNAME + ' (utilisateur ' + $env:USERNAME + ')')
    $cust.Add('Debut collecte   : ' + (U $script:StartTime) + ' UTC')
    $cust.Add('Fin collecte     : ' + (U (Get-Date)) + ' UTC')
    $cust.Add('Mode / fenetre   : ' + $script:Mode + ' / ' + (U $script:WinS) + ' -> ' + (U $script:WinE) + ' UTC')
    $cust.Add('Dossier de sortie: ' + $script:Out)
    $cust.Add(''); $cust.Add('Empreintes SHA256 des fichiers de l''outil :')
    Get-ChildItem -LiteralPath $script:KitRoot -Recurse -File -Force -ErrorAction SilentlyContinue | Where-Object { $_.FullName -notlike ($script:KitRoot + '*\Resultats\*') } | ForEach-Object {
        $h = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash
        $cust.Add(('  {0}  {1}' -f $h, $_.FullName.Substring($script:KitRoot.Length).TrimStart('\', '/')))
    }
    $cust.Add(''); $cust.Add('Les empreintes des preuves copiees sont dans manifeste_des_copies.csv et SHA256SUMS.txt.')
    $cust.Add('Aucune preuve n''a ete modifiee sur le poste ; les copies conservent les dates d''origine.')
    Save-Text $cust.ToArray() 'FICHE_DE_COLLECTE.txt' ''

    $sums = New-Object System.Collections.Generic.List[string]
    Get-ChildItem -LiteralPath $script:Out -Recurse -File -Force | Where-Object { $_.Name -ne 'SHA256SUMS.txt' -and $_.Name -ne 'collecte.log' } | ForEach-Object {
        $sums.Add(('{0}  {1}' -f (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash, $_.FullName.Substring($script:Out.Length).TrimStart('\', '/')))
    }
    Set-Content -LiteralPath (Join-Path $script:Out 'SHA256SUMS.txt') -Value $sums -Encoding UTF8

    # archive sans raw_SENSIBLE (cles AnyDesk, historiques navigateurs)
    $zip = $script:Out.TrimEnd('\', '/') + '_SANS_SENSIBLE.zip'
    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        if (Test-Path -LiteralPath $zip) { Remove-Item -LiteralPath $zip -Force }
        $za = [System.IO.Compression.ZipFile]::Open($zip, 'Create')
        $baseLen = $script:Out.TrimEnd('\', '/').Length + 1
        Get-ChildItem -LiteralPath $script:Out -Recurse -File -Force | Where-Object { $_.FullName -notmatch '[\\/]raw_SENSIBLE[\\/]' -and $_.Name -ne 'collecte.log' } | ForEach-Object {
            try {
                $entry = $_.FullName.Substring($baseLen) -replace '\\', '/'
                $in = New-Object IO.FileStream($_.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, ([IO.FileShare]'ReadWrite,Delete'))
                $e = $za.CreateEntry($entry, [System.IO.Compression.CompressionLevel]::Optimal)
                $e.LastWriteTime = $_.LastWriteTime
                $o = $e.Open(); $in.CopyTo($o); $o.Dispose(); $in.Dispose()
            } catch { }
        }
        $za.Dispose()
        Say ('   Archive : ' + $zip)
    } catch { Say ('   Archive non creee : ' + $_.Exception.Message) 'Yellow' }
}
