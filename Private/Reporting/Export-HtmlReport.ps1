function Export-HtmlReport {
    <#
    .SYNOPSIS
        Generates a self-contained HTML report from scan findings.
    .DESCRIPTION
        Produces a professional dark-themed HTML report with an executive summary,
        severity chart, sortable findings table with expandable details, timeline
        section, and scan metadata footer. All CSS is inline with no external dependencies.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [PSCustomObject[]]$Findings,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [PSCustomObject[]]$Timeline,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$OutputPath,

        [Parameter()]
        [PSCustomObject]$ScanMetadata
    )

    try {
        # Ensure output directory exists
        $outputDir = Split-Path -Path $OutputPath -Parent
        if ($outputDir -and -not (Test-Path $outputDir)) {
            New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
        }

        # Severity configuration
        $severityColors = @{
            'Critical'      = '#e74c3c'
            'High'          = '#c0392b'
            'Medium'        = '#f39c12'
            'Low'           = '#00bcd4'
            'Informational' = '#95a5a6'
        }
        $severityOrder = @('Critical', 'High', 'Medium', 'Low', 'Informational')

        # Count by severity
        $severityCounts = [ordered]@{}
        foreach ($sev in $severityOrder) {
            $severityCounts[$sev] = @($Findings | Where-Object { $_.Severity -eq $sev }).Count
        }
        $totalFindings = $Findings.Count

        # Build severity bar chart segments (pure CSS)
        $chartBars = [System.Text.StringBuilder]::new()
        foreach ($sev in $severityOrder) {
            $count = $severityCounts[$sev]
            if ($count -eq 0) { continue }
            $pct = if ($totalFindings -gt 0) { [Math]::Round(($count / $totalFindings) * 100, 1) } else { 0 }
            $color = $severityColors[$sev]
            [void]$chartBars.AppendLine("                <div class=`"bar-segment`" style=`"width:${pct}%;background:${color};`" title=`"${sev}: ${count} (${pct}%)`">")
            [void]$chartBars.AppendLine("                    <span class=`"bar-label`">${sev}: ${count}</span>")
            [void]$chartBars.AppendLine("                </div>")
        }

        # Build donut chart segments (pure CSS conic-gradient)
        $gradientStops = [System.Collections.Generic.List[string]]::new()
        $cumulative = 0
        foreach ($sev in $severityOrder) {
            $count = $severityCounts[$sev]
            if ($count -eq 0) { continue }
            $pct = if ($totalFindings -gt 0) { [Math]::Round(($count / $totalFindings) * 100, 2) } else { 0 }
            $color = $severityColors[$sev]
            $startPct = $cumulative
            $cumulative += $pct
            $endPct = $cumulative
            $gradientStops.Add("${color} ${startPct}% ${endPct}%")
        }
        $conicGradient = if ($gradientStops.Count -gt 0) {
            "conic-gradient($($gradientStops -join ', '))"
        } else {
            'conic-gradient(#333 0% 100%)'
        }

        # Build severity summary cards
        $summaryCards = [System.Text.StringBuilder]::new()
        foreach ($sev in $severityOrder) {
            $count = $severityCounts[$sev]
            $color = $severityColors[$sev]
            [void]$summaryCards.AppendLine("                <div class=`"summary-card`" style=`"border-left:4px solid ${color};`">")
            [void]$summaryCards.AppendLine("                    <div class=`"card-count`" style=`"color:${color};`">${count}</div>")
            [void]$summaryCards.AppendLine("                    <div class=`"card-label`">${sev}</div>")
            [void]$summaryCards.AppendLine("                </div>")
        }

        # Build findings table rows
        $findingsRows = [System.Text.StringBuilder]::new()
        $rowIndex = 0
        $sortedFindings = $Findings | Sort-Object {
            switch ($_.Severity) {
                'Critical'      { 0 }
                'High'          { 1 }
                'Medium'        { 2 }
                'Low'           { 3 }
                'Informational' { 4 }
                default         { 5 }
            }
        }

        foreach ($f in $sortedFindings) {
            $rowIndex++
            $color = $severityColors[$f.Severity]
            $escapedTitle = [System.Net.WebUtility]::HtmlEncode($f.Title)
            $escapedDesc = [System.Net.WebUtility]::HtmlEncode($f.Description)
            $escapedRec = [System.Net.WebUtility]::HtmlEncode($f.Recommendation)
            $escapedId = [System.Net.WebUtility]::HtmlEncode($f.Id)
            $escapedCat = [System.Net.WebUtility]::HtmlEncode($f.Category)
            $escapedMitre = [System.Net.WebUtility]::HtmlEncode($f.MITRE)
            $escapedCvss = [System.Net.WebUtility]::HtmlEncode($f.CVSSv3Score)
            $escapedImpact = [System.Net.WebUtility]::HtmlEncode($f.TechnicalImpact)

            # CVSSv3 display with color coding
            $cvssDisplay = 'N/A'
            $cvssClass = 'cvss-na'
            if (-not [string]::IsNullOrWhiteSpace($f.CVSSv3Score)) {
                $cvssDisplay = $escapedCvss
                $cvssNum = 0.0
                if ([double]::TryParse(($f.CVSSv3Score -replace '[^0-9.]',''), [ref]$cvssNum)) {
                    if ($cvssNum -ge 9.0) { $cvssClass = 'cvss-critical' }
                    elseif ($cvssNum -ge 7.0) { $cvssClass = 'cvss-high' }
                    elseif ($cvssNum -ge 4.0) { $cvssClass = 'cvss-medium' }
                    else { $cvssClass = 'cvss-low' }
                }
            }

            # Evidence section
            $evidenceHtml = ''
            if ($f.Evidence -and $f.Evidence.Count -gt 0) {
                $escapedEvidence = ($f.Evidence | ForEach-Object { [System.Net.WebUtility]::HtmlEncode($_) }) -join "`n"
                $evidenceHtml = "<div class=`"detail-section`"><strong>Related Evidence:</strong><pre class=`"evidence-block`">${escapedEvidence}</pre></div>"
            }

            # Artifact path as related file
            $artifactHtml = ''
            if (-not [string]::IsNullOrWhiteSpace($f.ArtifactPath)) {
                $escapedArtifact = [System.Net.WebUtility]::HtmlEncode($f.ArtifactPath)
                $artifactHtml = "<div class=`"detail-section`"><strong>Source File:</strong> <code class=`"file-path`">${escapedArtifact}</code></div>"
            }

            # MITRE tag
            $mitreHtml = ''
            if (-not [string]::IsNullOrWhiteSpace($f.MITRE)) {
                $mitreHtml = "<div class=`"detail-section`"><strong>MITRE ATT&amp;CK:</strong> <span class=`"mitre-tag`">${escapedMitre}</span></div>"
            }

            # Technical Impact
            $impactHtml = ''
            if (-not [string]::IsNullOrWhiteSpace($f.TechnicalImpact)) {
                $impactHtml = "<div class=`"detail-section`"><strong>Technical Impact:</strong> ${escapedImpact}</div>"
            }

            # Suggested Mitigation
            $mitigationHtml = ''
            if (-not [string]::IsNullOrWhiteSpace($f.Recommendation)) {
                $mitigationHtml = "<div class=`"detail-section`"><strong>Suggested Mitigation:</strong> ${escapedRec}</div>"
            }

            # Table row (summary)
            [void]$findingsRows.AppendLine("            <tr class=`"finding-row`" onclick=`"toggleDetail('detail-${rowIndex}')`">")
            [void]$findingsRows.AppendLine("                <td>${escapedId}</td>")
            [void]$findingsRows.AppendLine("                <td><span class=`"severity-badge`" style=`"background:${color};`">$($f.Severity)</span></td>")
            [void]$findingsRows.AppendLine("                <td><span class=`"${cvssClass}`">${cvssDisplay}</span></td>")
            [void]$findingsRows.AppendLine("                <td>${escapedCat}</td>")
            [void]$findingsRows.AppendLine("                <td>${escapedTitle}</td>")
            [void]$findingsRows.AppendLine("            </tr>")

            # Detail row (expanded)
            [void]$findingsRows.AppendLine("            <tr class=`"detail-row`" id=`"detail-${rowIndex}`">")
            [void]$findingsRows.AppendLine("                <td colspan=`"5`">")
            [void]$findingsRows.AppendLine("                    <div class=`"detail-grid`">")
            [void]$findingsRows.AppendLine("                        <div class=`"detail-main`">")
            [void]$findingsRows.AppendLine("                            <div class=`"detail-section`"><strong>Description:</strong> ${escapedDesc}</div>")
            [void]$findingsRows.AppendLine("                            ${impactHtml}")
            [void]$findingsRows.AppendLine("                            ${mitigationHtml}")
            [void]$findingsRows.AppendLine("                            ${evidenceHtml}")
            [void]$findingsRows.AppendLine("                        </div>")
            [void]$findingsRows.AppendLine("                        <div class=`"detail-sidebar`">")
            [void]$findingsRows.AppendLine("                            ${artifactHtml}")
            [void]$findingsRows.AppendLine("                            ${mitreHtml}")

            # CVSSv3 in sidebar if present
            if (-not [string]::IsNullOrWhiteSpace($f.CVSSv3Score)) {
                [void]$findingsRows.AppendLine("                            <div class=`"detail-section`"><strong>CVSSv3 Score:</strong> <span class=`"${cvssClass}`">${cvssDisplay}</span></div>")
            }

            [void]$findingsRows.AppendLine("                        </div>")
            [void]$findingsRows.AppendLine("                    </div>")
            [void]$findingsRows.AppendLine("                </td>")
            [void]$findingsRows.AppendLine("            </tr>")
        }

        # Build timeline rows
        $timelineRows = [System.Text.StringBuilder]::new()
        foreach ($entry in $Timeline) {
            $color = $severityColors[$entry.Severity]
            $ts = if ($null -ne $entry.Timestamp) { $entry.Timestamp.ToString('yyyy-MM-dd HH:mm:ss') } else { 'N/A' }
            $escapedTlTitle = [System.Net.WebUtility]::HtmlEncode($entry.Title)
            $escapedTlDesc = [System.Net.WebUtility]::HtmlEncode($entry.Description)
            $escapedTlId = [System.Net.WebUtility]::HtmlEncode($entry.FindingId)
            [void]$timelineRows.AppendLine("            <tr>")
            [void]$timelineRows.AppendLine("                <td>${ts}</td>")
            [void]$timelineRows.AppendLine("                <td><span class=`"severity-badge`" style=`"background:${color};`">$($entry.Severity)</span></td>")
            [void]$timelineRows.AppendLine("                <td>${escapedTlTitle}</td>")
            [void]$timelineRows.AppendLine("                <td>${escapedTlDesc}</td>")
            [void]$timelineRows.AppendLine("                <td>${escapedTlId}</td>")
            [void]$timelineRows.AppendLine("            </tr>")
        }

        # Build metadata footer
        $metadataHtml = ''
        if ($null -ne $ScanMetadata) {
            $metaEntries = [System.Text.StringBuilder]::new()
            foreach ($prop in $ScanMetadata.PSObject.Properties) {
                $escapedName = [System.Net.WebUtility]::HtmlEncode($prop.Name)
                $escapedValue = [System.Net.WebUtility]::HtmlEncode([string]$prop.Value)
                [void]$metaEntries.AppendLine("                <div class=`"meta-item`"><strong>${escapedName}:</strong> ${escapedValue}</div>")
            }
            $metadataHtml = @"
        <section class="metadata-section">
            <h2>Scan Metadata</h2>
            <div class="meta-grid">
$($metaEntries.ToString())
            </div>
        </section>
"@
        }

        $reportDate = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')

        # Assemble the full HTML document
        $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PWSPostProcessingSuite - Scan Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #1a1a2e; color: #e0e0e0; line-height: 1.6;
        }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        header {
            background: linear-gradient(135deg, #16213e, #0f3460);
            padding: 30px; border-radius: 8px; margin-bottom: 24px;
            border-left: 5px solid #e74c3c;
        }
        header h1 { font-size: 1.8em; color: #fff; margin-bottom: 4px; }
        header .subtitle { color: #a0a0c0; font-size: 0.95em; }
        section { background: #16213e; border-radius: 8px; padding: 24px; margin-bottom: 24px; }
        h2 { color: #fff; font-size: 1.3em; margin-bottom: 16px; border-bottom: 1px solid #2a2a4a; padding-bottom: 8px; }

        /* Summary cards */
        .summary-cards { display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 20px; }
        .summary-card {
            background: #1a1a2e; padding: 16px 20px; border-radius: 6px; min-width: 120px;
            text-align: center; flex: 1;
        }
        .card-count { font-size: 2em; font-weight: 700; }
        .card-label { font-size: 0.85em; color: #a0a0c0; margin-top: 4px; }

        /* Charts */
        .chart-container { display: flex; gap: 24px; align-items: center; flex-wrap: wrap; }
        .donut-chart {
            width: 160px; height: 160px; border-radius: 50%;
            background: ${conicGradient};
            position: relative; flex-shrink: 0;
        }
        .donut-chart::after {
            content: '${totalFindings}'; position: absolute;
            top: 50%; left: 50%; transform: translate(-50%, -50%);
            width: 90px; height: 90px; background: #16213e;
            border-radius: 50%; display: flex; align-items: center;
            justify-content: center; font-size: 1.6em; font-weight: 700; color: #fff;
        }
        .bar-chart { flex: 1; min-width: 300px; }
        .bar-segment {
            display: inline-block; height: 32px; line-height: 32px;
            text-align: center; min-width: 2px; transition: opacity 0.2s;
        }
        .bar-segment:hover { opacity: 0.8; }
        .bar-label { font-size: 0.75em; color: #fff; padding: 0 6px; white-space: nowrap; overflow: hidden; }
        .stacked-bar { display: flex; border-radius: 4px; overflow: hidden; margin-top: 8px; }

        /* Findings table */
        table { width: 100%; border-collapse: collapse; }
        th { background: #0f3460; color: #fff; padding: 12px; text-align: left; cursor: pointer; user-select: none; }
        th:hover { background: #1a4a7a; }
        td { padding: 10px 12px; border-bottom: 1px solid #2a2a4a; }
        .finding-row { cursor: pointer; transition: background 0.2s; }
        .finding-row:hover { background: #1e2a4a; }
        .detail-row { display: none; }
        .detail-row.visible { display: table-row; }
        .detail-row td { background: #0d1a30; padding: 16px 20px; }
        .detail-section { margin-bottom: 10px; }
        .severity-badge {
            display: inline-block; padding: 3px 10px; border-radius: 12px;
            font-size: 0.8em; font-weight: 600; color: #fff;
        }
        .evidence-block {
            background: #0a0f1f; border: 1px solid #2a2a4a; border-radius: 4px;
            padding: 12px; margin-top: 6px; font-family: 'Consolas', 'Courier New', monospace;
            font-size: 0.85em; overflow-x: auto; white-space: pre-wrap; color: #b0c4de;
        }
        .mitre-tag {
            display: inline-block; background: #2a2a4a; padding: 2px 8px;
            border-radius: 4px; font-size: 0.85em; color: #7ec8e3;
        }
        .file-path {
            background: #0a0f1f; border: 1px solid #2a2a4a; border-radius: 3px;
            padding: 2px 6px; font-family: 'Consolas', 'Courier New', monospace;
            font-size: 0.85em; color: #b0c4de;
        }
        .detail-grid { display: flex; gap: 20px; }
        .detail-main { flex: 3; }
        .detail-sidebar { flex: 1; min-width: 180px; border-left: 1px solid #2a2a4a; padding-left: 16px; }
        .cvss-critical { color: #e74c3c; font-weight: 700; }
        .cvss-high { color: #c0392b; font-weight: 700; }
        .cvss-medium { color: #f39c12; font-weight: 600; }
        .cvss-low { color: #00bcd4; font-weight: 600; }
        .cvss-na { color: #666; font-style: italic; }

        /* Timeline */
        .timeline-table td { font-size: 0.9em; }

        /* Metadata */
        .metadata-section { background: #0f1a2e; }
        .meta-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 8px; }
        .meta-item { padding: 6px 0; font-size: 0.9em; }
        .meta-item strong { color: #a0a0c0; }

        footer { text-align: center; padding: 16px; color: #555; font-size: 0.8em; }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>PWSPostProcessingSuite - Scan Report</h1>
            <div class="subtitle">Generated: ${reportDate}</div>
        </header>

        <section>
            <h2>Executive Summary</h2>
            <div class="summary-cards">
$($summaryCards.ToString())
            </div>
            <div class="chart-container">
                <div class="donut-chart"></div>
                <div class="bar-chart">
                    <div class="stacked-bar">
$($chartBars.ToString())
                    </div>
                </div>
            </div>
        </section>

        <section>
            <h2>Findings ($totalFindings)</h2>
            <table>
                <thead>
                    <tr>
                        <th onclick="sortTable(0)">ID</th>
                        <th onclick="sortTable(1)">Severity</th>
                        <th onclick="sortTable(2)">CVSSv3</th>
                        <th onclick="sortTable(3)">Category</th>
                        <th onclick="sortTable(4)">Title</th>
                    </tr>
                </thead>
                <tbody>
$($findingsRows.ToString())
                </tbody>
            </table>
        </section>

        <section>
            <h2>Timeline ($($Timeline.Count) events)</h2>
            <table class="timeline-table">
                <thead>
                    <tr>
                        <th>Timestamp</th>
                        <th>Severity</th>
                        <th>Title</th>
                        <th>Description</th>
                        <th>Finding ID</th>
                    </tr>
                </thead>
                <tbody>
$($timelineRows.ToString())
                </tbody>
            </table>
        </section>

${metadataHtml}

        <footer>
            PWSPostProcessingSuite &mdash; Report generated ${reportDate}
        </footer>
    </div>

    <script>
        function toggleDetail(id) {
            var row = document.getElementById(id);
            if (row) { row.classList.toggle('visible'); }
        }

        function sortTable(colIndex) {
            var table = document.querySelector('section:nth-of-type(2) table');
            var tbody = table.querySelector('tbody');
            var rows = Array.from(tbody.querySelectorAll('tr.finding-row'));
            var sevOrder = { 'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'Informational': 4 };
            var ascending = table.getAttribute('data-sort-col') == colIndex &&
                            table.getAttribute('data-sort-dir') !== 'asc';
            table.setAttribute('data-sort-col', colIndex);
            table.setAttribute('data-sort-dir', ascending ? 'asc' : 'desc');
            rows.sort(function(a, b) {
                var aVal = a.cells[colIndex].textContent.trim();
                var bVal = b.cells[colIndex].textContent.trim();
                if (colIndex === 1) {
                    aVal = sevOrder[aVal] !== undefined ? sevOrder[aVal] : 99;
                    bVal = sevOrder[bVal] !== undefined ? sevOrder[bVal] : 99;
                    return ascending ? aVal - bVal : bVal - aVal;
                }
                if (colIndex === 2) {
                    var aNum = parseFloat(aVal) || 0;
                    var bNum = parseFloat(bVal) || 0;
                    return ascending ? aNum - bNum : bNum - aNum;
                }
                return ascending ? aVal.localeCompare(bVal) : bVal.localeCompare(aVal);
            });
            rows.forEach(function(row) {
                var detailId = row.getAttribute('onclick').match(/'([^']+)'/)[1];
                var detail = document.getElementById(detailId);
                tbody.appendChild(row);
                if (detail) { tbody.appendChild(detail); }
            });
        }
    </script>
</body>
</html>
"@

        $html | Out-File -FilePath $OutputPath -Encoding utf8 -Force
        Write-Verbose "HTML report written to: $OutputPath"
    }
    catch {
        Write-Error "Failed to export HTML report to '${OutputPath}': $_"
    }
}
