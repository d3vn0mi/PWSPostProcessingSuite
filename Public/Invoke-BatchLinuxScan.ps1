function Invoke-BatchLinuxScan {
    <#
    .SYNOPSIS
        Scans multiple host evidence folders and produces per-host HTML reports.
    .DESCRIPTION
        Iterates over subdirectories in a parent evidence folder (one folder per host),
        runs Invoke-LinuxArtifactScan on each, and generates individual HTML/CSV reports.
        Optionally produces an index HTML page linking all host reports with a summary.
    .PARAMETER EvidencePath
        Parent folder containing one subdirectory per host.
    .PARAMETER OutputDirectory
        Base directory for report output. Per-host reports are placed in subdirectories.
        Defaults to current directory.
    .PARAMETER IncludeAnalyzers
        Run only these specific analyzers (passed to each per-host scan).
    .PARAMETER ExcludeAnalyzers
        Skip these specific analyzers (passed to each per-host scan).
    .PARAMETER CustomRulesPath
        Path to a custom YAML rules file (passed to each per-host scan).
    .PARAMETER MinimumSeverity
        Minimum severity level to include. Default: Informational.
    .PARAMETER SkipHtmlReport
        Skip per-host HTML report generation.
    .PARAMETER SkipCsvReport
        Skip per-host CSV report generation.
    .PARAMETER SkipIndexReport
        Skip the combined index HTML page.
    .PARAMETER HostFilter
        Only process host folders matching these names (supports wildcards).
    .EXAMPLE
        Invoke-BatchLinuxScan -EvidencePath '/cases/incident1/hosts'
    .EXAMPLE
        Invoke-BatchLinuxScan -EvidencePath './evidence' -OutputDirectory './reports' -MinimumSeverity High
    .EXAMPLE
        Invoke-BatchLinuxScan -EvidencePath './evidence' -HostFilter 'web*','db*'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [ValidateScript({ Test-Path $_ -PathType Container })]
        [string]$EvidencePath,

        [string]$OutputDirectory = '.',

        [string[]]$IncludeAnalyzers,

        [string[]]$ExcludeAnalyzers,

        [string]$CustomRulesPath,

        [ValidateSet('All', 'Critical', 'High', 'Medium', 'Low', 'Informational')]
        [string]$MinimumSeverity = 'Informational',

        [switch]$SkipHtmlReport,

        [switch]$SkipCsvReport,

        [switch]$SkipIndexReport,

        [string[]]$HostFilter
    )

    $batchStart = Get-Date
    $EvidencePath = (Resolve-Path $EvidencePath).Path

    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "  PWSPostProcessingSuite - Batch Linux Artifact Scanner" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "[*] Evidence root: $EvidencePath" -ForegroundColor White
    Write-Host ""

    # Discover host folders
    $hostFolders = Get-ChildItem -Path $EvidencePath -Directory | Sort-Object Name

    if ($HostFilter) {
        $hostFolders = $hostFolders | Where-Object {
            $name = $_.Name
            $HostFilter | Where-Object { $name -like $_ } | Select-Object -First 1
        }
    }

    if ($hostFolders.Count -eq 0) {
        Write-Warning "No host subdirectories found in: $EvidencePath"
        return
    }

    Write-Host "[*] Found $($hostFolders.Count) host folder(s):" -ForegroundColor White
    foreach ($folder in $hostFolders) {
        Write-Host "    - $($folder.Name)" -ForegroundColor DarkGray
    }
    Write-Host ""

    # Ensure output directory exists
    if (-not (Test-Path $OutputDirectory)) {
        New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
    }
    $OutputDirectory = (Resolve-Path $OutputDirectory).Path

    # Process each host
    $hostResults = [System.Collections.Generic.List[PSCustomObject]]::new()
    $hostIndex = 0

    foreach ($folder in $hostFolders) {
        $hostIndex++
        $hostName = $folder.Name
        $hostOutputDir = Join-Path $OutputDirectory $hostName

        Write-Host "------------------------------------------------------------" -ForegroundColor DarkGray
        Write-Host "[${hostIndex}/$($hostFolders.Count)] Scanning host: $hostName" -ForegroundColor Cyan
        Write-Host "------------------------------------------------------------" -ForegroundColor DarkGray

        # Build parameters for per-host scan
        $scanParams = @{
            EvidencePath    = $folder.FullName
            OutputDirectory = $hostOutputDir
            MinimumSeverity = $MinimumSeverity
        }
        if ($IncludeAnalyzers)  { $scanParams['IncludeAnalyzers'] = $IncludeAnalyzers }
        if ($ExcludeAnalyzers)  { $scanParams['ExcludeAnalyzers'] = $ExcludeAnalyzers }
        if ($CustomRulesPath)   { $scanParams['CustomRulesPath']  = $CustomRulesPath }
        if ($SkipHtmlReport)    { $scanParams['SkipHtmlReport']   = $true }
        if ($SkipCsvReport)     { $scanParams['SkipCsvReport']    = $true }

        try {
            $result = Invoke-LinuxArtifactScan @scanParams

            $hostResults.Add([PSCustomObject]@{
                HostName      = $hostName
                Status        = 'Completed'
                TotalFindings = $result.TotalFindings
                BySeverity    = $result.BySeverity
                ReportPaths   = $result.ReportPaths
                ScanResult    = $result
                Error         = $null
            })
        }
        catch {
            Write-Host "[!] ERROR scanning ${hostName}: $_" -ForegroundColor Red
            $hostResults.Add([PSCustomObject]@{
                HostName      = $hostName
                Status        = 'Error'
                TotalFindings = 0
                BySeverity    = @{ Critical = 0; High = 0; Medium = 0; Low = 0; Informational = 0 }
                ReportPaths   = @{}
                ScanResult    = $null
                Error         = $_.ToString()
            })
        }

        Write-Host ""
    }

    # Generate index report
    if (-not $SkipIndexReport -and -not $SkipHtmlReport) {
        $indexPath = Join-Path $OutputDirectory "BatchScanIndex.html"
        Export-BatchIndexReport -HostResults $hostResults -OutputPath $indexPath -OutputDirectory $OutputDirectory
        Write-Host "[+] Batch index report saved: $indexPath" -ForegroundColor Green
    }

    $batchEnd = Get-Date
    $batchDuration = $batchEnd - $batchStart

    # Print batch summary
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "  Batch Scan Summary" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host ""

    $totalAllFindings = 0
    $totalCritical = 0
    $totalHigh = 0
    foreach ($hr in $hostResults) {
        $status = if ($hr.Status -eq 'Completed') { 'OK' } else { 'ERROR' }
        $statusColor = if ($hr.Status -eq 'Completed') { 'Green' } else { 'Red' }
        $critHigh = $hr.BySeverity.Critical + $hr.BySeverity.High
        $findingColor = if ($hr.BySeverity.Critical -gt 0) { 'Red' } elseif ($hr.BySeverity.High -gt 0) { 'DarkRed' } elseif ($hr.TotalFindings -gt 0) { 'Yellow' } else { 'Green' }

        Write-Host "  $($hr.HostName.PadRight(30))" -NoNewline -ForegroundColor White
        Write-Host "[$status] " -NoNewline -ForegroundColor $statusColor
        Write-Host "$($hr.TotalFindings) findings " -NoNewline -ForegroundColor $findingColor
        if ($critHigh -gt 0) {
            Write-Host "($($hr.BySeverity.Critical)C/$($hr.BySeverity.High)H)" -ForegroundColor Red
        }
        else {
            Write-Host ""
        }

        $totalAllFindings += $hr.TotalFindings
        $totalCritical += $hr.BySeverity.Critical
        $totalHigh += $hr.BySeverity.High
    }

    Write-Host ""
    Write-Host "  Total: $totalAllFindings findings across $($hostResults.Count) hosts ($totalCritical critical, $totalHigh high)" -ForegroundColor White
    Write-Host "  Completed in $($batchDuration.TotalSeconds.ToString('F1'))s" -ForegroundColor Cyan
    Write-Host ""

    # Return batch result object
    $batchResult = [PSCustomObject]@{
        PSTypeName     = 'PWSPostProcessingSuite.BatchScanResult'
        HostCount      = $hostResults.Count
        TotalFindings  = $totalAllFindings
        HostResults    = $hostResults
        BatchStart     = $batchStart
        BatchEnd       = $batchEnd
        BatchDuration  = $batchDuration
        IndexReportPath = if (-not $SkipIndexReport -and -not $SkipHtmlReport) { $indexPath } else { $null }
    }

    return $batchResult
}
