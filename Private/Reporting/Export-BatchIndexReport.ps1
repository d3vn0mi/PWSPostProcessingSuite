function Export-BatchIndexReport {
    <#
    .SYNOPSIS
        Generates an HTML index page summarizing batch scan results across all hosts.
    .DESCRIPTION
        Creates a self-contained HTML dashboard linking to individual per-host reports
        with severity summaries, status indicators, and aggregate statistics.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [PSCustomObject[]]$HostResults,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$OutputPath,

        [Parameter()]
        [string]$OutputDirectory
    )

    try {
        $outputDir = Split-Path -Path $OutputPath -Parent
        if ($outputDir -and -not (Test-Path $outputDir)) {
            New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
        }

        $severityColors = @{
            'Critical'      = '#e74c3c'
            'High'          = '#c0392b'
            'Medium'        = '#f39c12'
            'Low'           = '#00bcd4'
            'Informational' = '#95a5a6'
        }

        # Aggregate totals
        $totalFindings = 0
        $totalCritical = 0
        $totalHigh = 0
        $totalMedium = 0
        $totalLow = 0
        $totalInfo = 0
        $hostsCompleted = 0
        $hostsErrored = 0

        foreach ($hr in $HostResults) {
            $totalFindings += $hr.TotalFindings
            $totalCritical += $hr.BySeverity.Critical
            $totalHigh += $hr.BySeverity.High
            $totalMedium += $hr.BySeverity.Medium
            $totalLow += $hr.BySeverity.Low
            $totalInfo += $hr.BySeverity.Informational
            if ($hr.Status -eq 'Completed') { $hostsCompleted++ } else { $hostsErrored++ }
        }

        # Build host table rows
        $hostRows = [System.Text.StringBuilder]::new()
        foreach ($hr in ($HostResults | Sort-Object { $_.BySeverity.Critical + $_.BySeverity.High } -Descending)) {
            $escapedName = [System.Net.WebUtility]::HtmlEncode($hr.HostName)
            $statusClass = if ($hr.Status -eq 'Completed') { 'status-ok' } else { 'status-error' }
            $statusText = if ($hr.Status -eq 'Completed') { 'OK' } else { 'ERROR' }

            # Build link to per-host HTML report (relative path)
            $reportLink = ''
            if ($hr.ReportPaths -and $hr.ReportPaths['HTML']) {
                $htmlReportPath = $hr.ReportPaths['HTML']
                if ($OutputDirectory) {
                    $relativePath = $htmlReportPath.Replace($OutputDirectory, '').TrimStart('/').TrimStart('\')
                }
                else {
                    $relativePath = Split-Path $htmlReportPath -Leaf
                }
                $escapedLink = [System.Net.WebUtility]::HtmlEncode($relativePath)
                $reportLink = "<a href=`"${escapedLink}`" class=`"report-link`">View Report</a>"
            }

            # Severity mini-bars
            $critCount = $hr.BySeverity.Critical
            $highCount = $hr.BySeverity.High
            $medCount = $hr.BySeverity.Medium
            $lowCount = $hr.BySeverity.Low
            $infoCount = $hr.BySeverity.Informational

            $severityBadges = [System.Text.StringBuilder]::new()
            if ($critCount -gt 0) {
                [void]$severityBadges.Append("<span class=`"sev-badge`" style=`"background:$($severityColors.Critical);`">${critCount}</span> ")
            }
            if ($highCount -gt 0) {
                [void]$severityBadges.Append("<span class=`"sev-badge`" style=`"background:$($severityColors.High);`">${highCount}</span> ")
            }
            if ($medCount -gt 0) {
                [void]$severityBadges.Append("<span class=`"sev-badge`" style=`"background:$($severityColors.Medium);`">${medCount}</span> ")
            }
            if ($lowCount -gt 0) {
                [void]$severityBadges.Append("<span class=`"sev-badge`" style=`"background:$($severityColors.Low);`">${lowCount}</span> ")
            }
            if ($infoCount -gt 0) {
                [void]$severityBadges.Append("<span class=`"sev-badge`" style=`"background:$($severityColors.Informational);`">${infoCount}</span>")
            }

            $errorInfo = ''
            if ($hr.Error) {
                $escapedError = [System.Net.WebUtility]::HtmlEncode($hr.Error)
                $errorInfo = "<div class=`"error-info`">${escapedError}</div>"
            }

            [void]$hostRows.AppendLine("            <tr>")
            [void]$hostRows.AppendLine("                <td class=`"host-name`">${escapedName}</td>")
            [void]$hostRows.AppendLine("                <td><span class=`"status-badge ${statusClass}`">${statusText}</span></td>")
            [void]$hostRows.AppendLine("                <td class=`"findings-count`">$($hr.TotalFindings)</td>")
            [void]$hostRows.AppendLine("                <td class=`"severity-breakdown`">$($severityBadges.ToString())</td>")
            [void]$hostRows.AppendLine("                <td>${reportLink}${errorInfo}</td>")
            [void]$hostRows.AppendLine("            </tr>")
        }

        $reportDate = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')

        $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PWSPostProcessingSuite - Batch Scan Index</title>
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

        /* Aggregate summary */
        .agg-cards { display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 20px; }
        .agg-card {
            background: #1a1a2e; padding: 16px 20px; border-radius: 6px; min-width: 130px;
            text-align: center; flex: 1;
        }
        .agg-count { font-size: 2em; font-weight: 700; }
        .agg-label { font-size: 0.85em; color: #a0a0c0; margin-top: 4px; }

        /* Host table */
        table { width: 100%; border-collapse: collapse; }
        th { background: #0f3460; color: #fff; padding: 12px; text-align: left; cursor: pointer; user-select: none; }
        th:hover { background: #1a4a7a; }
        td { padding: 10px 12px; border-bottom: 1px solid #2a2a4a; }
        tr:hover { background: #1e2a4a; }
        .host-name { font-weight: 600; color: #fff; }
        .findings-count { font-weight: 700; font-size: 1.1em; }
        .status-badge {
            display: inline-block; padding: 3px 10px; border-radius: 12px;
            font-size: 0.8em; font-weight: 600; color: #fff;
        }
        .status-ok { background: #27ae60; }
        .status-error { background: #e74c3c; }
        .sev-badge {
            display: inline-block; padding: 2px 8px; border-radius: 10px;
            font-size: 0.8em; font-weight: 600; color: #fff; min-width: 28px;
            text-align: center;
        }
        .severity-breakdown { white-space: nowrap; }
        .report-link {
            color: #7ec8e3; text-decoration: none; font-weight: 600;
            padding: 4px 12px; border: 1px solid #7ec8e3; border-radius: 4px;
            transition: all 0.2s;
        }
        .report-link:hover { background: #7ec8e3; color: #1a1a2e; }
        .error-info { color: #e74c3c; font-size: 0.85em; margin-top: 4px; }

        footer { text-align: center; padding: 16px; color: #555; font-size: 0.8em; }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>PWSPostProcessingSuite - Batch Scan Index</h1>
            <div class="subtitle">Generated: ${reportDate} &mdash; $($HostResults.Count) hosts scanned</div>
        </header>

        <section>
            <h2>Aggregate Summary</h2>
            <div class="agg-cards">
                <div class="agg-card" style="border-left:4px solid #fff;">
                    <div class="agg-count" style="color:#fff;">$($HostResults.Count)</div>
                    <div class="agg-label">Hosts</div>
                </div>
                <div class="agg-card" style="border-left:4px solid #27ae60;">
                    <div class="agg-count" style="color:#27ae60;">${hostsCompleted}</div>
                    <div class="agg-label">Completed</div>
                </div>
                <div class="agg-card" style="border-left:4px solid $($severityColors.Critical);">
                    <div class="agg-count" style="color:$($severityColors.Critical);">${totalCritical}</div>
                    <div class="agg-label">Critical</div>
                </div>
                <div class="agg-card" style="border-left:4px solid $($severityColors.High);">
                    <div class="agg-count" style="color:$($severityColors.High);">${totalHigh}</div>
                    <div class="agg-label">High</div>
                </div>
                <div class="agg-card" style="border-left:4px solid $($severityColors.Medium);">
                    <div class="agg-count" style="color:$($severityColors.Medium);">${totalMedium}</div>
                    <div class="agg-label">Medium</div>
                </div>
                <div class="agg-card" style="border-left:4px solid $($severityColors.Low);">
                    <div class="agg-count" style="color:$($severityColors.Low);">${totalLow}</div>
                    <div class="agg-label">Low</div>
                </div>
                <div class="agg-card" style="border-left:4px solid $($severityColors.Informational);">
                    <div class="agg-count" style="color:$($severityColors.Informational);">${totalInfo}</div>
                    <div class="agg-label">Informational</div>
                </div>
                <div class="agg-card" style="border-left:4px solid #fff;">
                    <div class="agg-count" style="color:#fff;">${totalFindings}</div>
                    <div class="agg-label">Total Findings</div>
                </div>
            </div>
        </section>

        <section>
            <h2>Host Results</h2>
            <table>
                <thead>
                    <tr>
                        <th onclick="sortTable(0)">Host</th>
                        <th onclick="sortTable(1)">Status</th>
                        <th onclick="sortTable(2)">Findings</th>
                        <th>Severity Breakdown</th>
                        <th>Report</th>
                    </tr>
                </thead>
                <tbody>
$($hostRows.ToString())
                </tbody>
            </table>
        </section>

        <footer>
            PWSPostProcessingSuite &mdash; Batch scan report generated ${reportDate}
        </footer>
    </div>

    <script>
        function sortTable(colIndex) {
            var table = document.querySelector('section:nth-of-type(2) table');
            var tbody = table.querySelector('tbody');
            var rows = Array.from(tbody.querySelectorAll('tr'));
            var ascending = table.getAttribute('data-sort-col') == colIndex &&
                            table.getAttribute('data-sort-dir') !== 'asc';
            table.setAttribute('data-sort-col', colIndex);
            table.setAttribute('data-sort-dir', ascending ? 'asc' : 'desc');
            rows.sort(function(a, b) {
                var aVal = a.cells[colIndex].textContent.trim();
                var bVal = b.cells[colIndex].textContent.trim();
                if (colIndex === 2) {
                    return ascending ? parseInt(aVal) - parseInt(bVal) : parseInt(bVal) - parseInt(aVal);
                }
                return ascending ? aVal.localeCompare(bVal) : bVal.localeCompare(aVal);
            });
            rows.forEach(function(row) { tbody.appendChild(row); });
        }
    </script>
</body>
</html>
"@

        $html | Out-File -FilePath $OutputPath -Encoding utf8 -Force
        Write-Verbose "Batch index report written to: $OutputPath"
    }
    catch {
        Write-Error "Failed to export batch index report to '${OutputPath}': $_"
    }
}
