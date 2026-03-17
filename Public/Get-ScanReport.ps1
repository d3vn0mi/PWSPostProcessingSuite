function Get-ScanReport {
    <#
    .SYNOPSIS
        Re-generates reports from a previously returned scan result object.
    .DESCRIPTION
        Takes a scan result from Invoke-LinuxArtifactScan and generates
        reports in the specified formats.
    .PARAMETER ScanResult
        The scan result object returned by Invoke-LinuxArtifactScan.
    .PARAMETER Format
        Output formats to generate: HTML, CSV, Console, Timeline.
    .PARAMETER OutputDirectory
        Directory where report files will be written.
    .EXAMPLE
        $result | Get-ScanReport -Format HTML, CSV
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [PSCustomObject]$ScanResult,

        [ValidateSet('HTML', 'CSV', 'Console', 'Timeline')]
        [string[]]$Format = @('HTML', 'Console'),

        [string]$OutputDirectory = '.'
    )

    process {
        if (-not (Test-Path $OutputDirectory)) {
            New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
        }

        $reportPaths = @{}
        $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'

        foreach ($fmt in $Format) {
            switch ($fmt) {
                'Console' {
                    Write-ConsoleSummary -Findings $ScanResult.Findings -BySeverity $ScanResult.BySeverity
                }
                'HTML' {
                    $htmlPath = Join-Path $OutputDirectory "LinuxArtifactScan_${timestamp}.html"
                    Export-HtmlReport -Findings $ScanResult.Findings -Timeline $ScanResult.Timeline -OutputPath $htmlPath -ScanMetadata $ScanResult.Metadata
                    $reportPaths['HTML'] = $htmlPath
                    Write-Host "[+] HTML report: $htmlPath" -ForegroundColor Green
                }
                'CSV' {
                    $csvPath = Join-Path $OutputDirectory "LinuxArtifactScan_${timestamp}.csv"
                    Export-CsvReport -Findings $ScanResult.Findings -OutputPath $csvPath
                    $reportPaths['CSV'] = $csvPath
                    Write-Host "[+] CSV report: $csvPath" -ForegroundColor Green
                }
                'Timeline' {
                    $timelinePath = Join-Path $OutputDirectory "LinuxArtifactScan_Timeline_${timestamp}.csv"
                    Export-TimelineReport -Timeline $ScanResult.Timeline -OutputPath $timelinePath
                    $reportPaths['Timeline'] = $timelinePath
                    Write-Host "[+] Timeline report: $timelinePath" -ForegroundColor Green
                }
            }
        }

        $reportPaths
    }
}
