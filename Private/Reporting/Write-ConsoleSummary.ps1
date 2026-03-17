function Write-ConsoleSummary {
    <#
    .SYNOPSIS
        Displays a formatted summary of scan findings to the console.
    .DESCRIPTION
        Renders a color-coded summary banner with severity counts, top critical/high
        findings, and a category breakdown to the host console.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [PSCustomObject[]]$Findings,

        [Parameter(Mandatory)]
        [hashtable]$BySeverity
    )

    try {
        $severityColors = @{
            'Critical'      = 'Red'
            'High'          = 'DarkRed'
            'Medium'        = 'Yellow'
            'Low'           = 'Cyan'
            'Informational' = 'Gray'
        }

        $severityOrder = @('Critical', 'High', 'Medium', 'Low', 'Informational')

        # Banner
        $bannerWidth = 72
        $bannerLine = '=' * $bannerWidth
        Write-Host ''
        Write-Host $bannerLine -ForegroundColor White
        Write-Host '  PWSPostProcessingSuite - Scan Results Summary' -ForegroundColor White
        Write-Host $bannerLine -ForegroundColor White
        Write-Host ''

        # Total findings count
        $totalCount = $Findings.Count
        Write-Host "  Total Findings: $totalCount" -ForegroundColor White
        Write-Host ''

        # Severity counts with colored output
        Write-Host '  Severity Breakdown:' -ForegroundColor White
        Write-Host ('  ' + ('-' * 40)) -ForegroundColor DarkGray

        foreach ($sev in $severityOrder) {
            $count = 0
            if ($BySeverity.ContainsKey($sev)) {
                $count = @($BySeverity[$sev]).Count
            }
            $color = $severityColors[$sev]
            $label = $sev.PadRight(16)
            $bar = '#' * [Math]::Min($count, 30)
            Write-Host "    $label $($count.ToString().PadLeft(5))  " -ForegroundColor $color -NoNewline
            Write-Host $bar -ForegroundColor $color
        }

        Write-Host ''

        # Top 10 critical/high findings
        $topFindings = $Findings |
            Where-Object { $_.Severity -eq 'Critical' -or $_.Severity -eq 'High' } |
            Select-Object -First 10

        if ($topFindings.Count -gt 0) {
            Write-Host '  Top Critical/High Findings:' -ForegroundColor White
            Write-Host ('  ' + ('-' * 40)) -ForegroundColor DarkGray

            $index = 0
            foreach ($finding in $topFindings) {
                $index++
                $color = $severityColors[$finding.Severity]
                $sevTag = "[$($finding.Severity)]"
                Write-Host "    $index. " -ForegroundColor White -NoNewline
                Write-Host $sevTag.PadRight(14) -ForegroundColor $color -NoNewline
                Write-Host "$($finding.Id): $($finding.Title)" -ForegroundColor White

                if (-not [string]::IsNullOrWhiteSpace($finding.Category)) {
                    Write-Host "       Category: $($finding.Category)" -ForegroundColor DarkGray
                }

                if (-not [string]::IsNullOrWhiteSpace($finding.MITRE)) {
                    Write-Host "       MITRE: $($finding.MITRE)" -ForegroundColor DarkGray
                }
            }

            Write-Host ''
        }

        # Category breakdown
        $categoryGroups = $Findings | Group-Object -Property Category | Sort-Object Count -Descending

        if ($categoryGroups.Count -gt 0) {
            Write-Host '  Category Breakdown:' -ForegroundColor White
            Write-Host ('  ' + ('-' * 40)) -ForegroundColor DarkGray

            foreach ($group in $categoryGroups) {
                $catName = if ([string]::IsNullOrWhiteSpace($group.Name)) { '(Uncategorized)' } else { $group.Name }
                $catLabel = $catName.PadRight(30)
                Write-Host "    $catLabel $($group.Count.ToString().PadLeft(5))" -ForegroundColor White
            }

            Write-Host ''
        }

        Write-Host $bannerLine -ForegroundColor White
        Write-Host ''
    }
    catch {
        Write-Error "Failed to write console summary: $_"
    }
}
