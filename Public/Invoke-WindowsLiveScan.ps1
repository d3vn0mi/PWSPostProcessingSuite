function Invoke-WindowsLiveScan {
    <#
    .SYNOPSIS
        Active mode: Collects evidence from the live Windows system and runs all analyzers.
    .DESCRIPTION
        Two-phase operation:
          Phase 1 - Collection: Gathers registry keys, event logs, service configs,
                    scheduled tasks, firewall rules, and command outputs from the
                    running Windows system into a structured evidence directory.
          Phase 2 - Analysis:   Runs Invoke-WindowsArtifactScan against the
                    collected evidence using all 15 Windows analyzers.
    .PARAMETER OutputDirectory
        Directory where evidence and reports will be stored.
    .PARAMETER EvidencePath
        Explicit path to store collected evidence. If omitted, a timestamped
        subdirectory is created under OutputDirectory.
    .PARAMETER IncludeAnalyzers
        Run only these specific analyzers during the analysis phase.
    .PARAMETER ExcludeAnalyzers
        Skip these analyzers during the analysis phase.
    .PARAMETER IncludeCategories
        Collect only these artifact categories. Default: all categories.
    .PARAMETER ExcludeCategories
        Skip these artifact categories during collection.
    .PARAMETER CustomRulesPath
        Path to a custom YAML rules file.
    .PARAMETER MinimumSeverity
        Minimum severity level to include. Default: Informational.
    .PARAMETER SkipCollection
        Skip collection and use existing EvidencePath.
    .PARAMETER SkipAnalysis
        Skip analysis. Only collect artifacts.
    .PARAMETER SkipCommands
        During collection, skip running live commands (only export configs).
    .PARAMETER MaxEventLogEntries
        Maximum event log entries to collect. Default: 5000.
    .PARAMETER CollectUserProfiles
        Include user profile artifacts (PSReadLine history, etc.).
    .PARAMETER SkipHtmlReport
        Skip HTML report generation.
    .PARAMETER SkipCsvReport
        Skip CSV report generation.
    .EXAMPLE
        Invoke-WindowsLiveScan -OutputDirectory 'C:\Cases\incident1'

        Full active scan on the local Windows system.
    .EXAMPLE
        Invoke-WindowsLiveScan -OutputDirectory '.\output' -MinimumSeverity High

        Active scan showing only High and Critical findings.
    .EXAMPLE
        Invoke-WindowsLiveScan -OutputDirectory '.\output' -SkipAnalysis

        Collection only mode.
    .EXAMPLE
        Invoke-WindowsLiveScan -OutputDirectory '.\output' -SkipCollection -EvidencePath '.\previous\evidence'

        Re-analyze previously collected evidence.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)]
        [string]$OutputDirectory = '.',

        [string]$EvidencePath,

        [string[]]$IncludeAnalyzers,

        [string[]]$ExcludeAnalyzers,

        [string[]]$IncludeCategories,

        [string[]]$ExcludeCategories,

        [string]$CustomRulesPath,

        [ValidateSet('All', 'Critical', 'High', 'Medium', 'Low', 'Informational')]
        [string]$MinimumSeverity = 'Informational',

        [switch]$SkipCollection,

        [switch]$SkipAnalysis,

        [switch]$SkipCommands,

        [int]$MaxEventLogEntries = 5000,

        [switch]$CollectUserProfiles,

        [switch]$SkipHtmlReport,

        [switch]$SkipCsvReport
    )

    $overallStart = Get-Date

    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Magenta
    Write-Host "  PWSPostProcessingSuite - Windows Active Mode (Live Scan)" -ForegroundColor Magenta
    Write-Host "============================================================" -ForegroundColor Magenta
    Write-Host "[*] Mode: ACTIVE - Live Windows system collection + analysis" -ForegroundColor White
    Write-Host "[*] Started: $overallStart" -ForegroundColor White
    Write-Host ""

    # Platform check
    if ($PSVersionTable.Platform -and $PSVersionTable.Platform -eq 'Unix') {
        Write-Warning "Windows active mode is designed to run on a Windows system."
        Write-Warning "Current platform: Unix/Linux. Collectors will not work correctly."
    }

    # Ensure output directory exists
    if (-not (Test-Path $OutputDirectory)) {
        New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
    }
    $OutputDirectory = (Resolve-Path $OutputDirectory).Path

    # =====================================================================
    # Phase 1: Collection
    # =====================================================================
    $collectionResult = $null

    if (-not $SkipCollection) {
        Write-Host "============================================" -ForegroundColor Cyan
        Write-Host "  Phase 1: Windows Evidence Collection" -ForegroundColor Cyan
        Write-Host "============================================" -ForegroundColor Cyan

        if (-not $EvidencePath) {
            $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
            $hostName = 'localhost'
            try { $hostName = $env:COMPUTERNAME -replace '[^\w\-\.]', '_' } catch { }
            $EvidencePath = Join-Path $OutputDirectory "evidence_${hostName}_${timestamp}"
        }

        $collectorParams = @{
            OutputPath         = $EvidencePath
            MaxEventLogEntries = $MaxEventLogEntries
        }
        if ($IncludeCategories)  { $collectorParams['IncludeCategories'] = $IncludeCategories }
        if ($ExcludeCategories)  { $collectorParams['ExcludeCategories'] = $ExcludeCategories }
        if ($SkipCommands)       { $collectorParams['SkipCommands'] = $true }
        if ($CollectUserProfiles) { $collectorParams['CollectUserProfiles'] = $true }

        $collectionResult = Invoke-WindowsArtifactCollector @collectorParams
        $EvidencePath = $collectionResult.OutputPath
    }
    else {
        if (-not $EvidencePath) {
            throw "When using -SkipCollection, you must provide -EvidencePath pointing to previously collected evidence."
        }
        if (-not (Test-Path $EvidencePath -PathType Container)) {
            throw "Evidence path not found: $EvidencePath"
        }
        $EvidencePath = (Resolve-Path $EvidencePath).Path
        Write-Host "[*] Skipping collection, using existing evidence: $EvidencePath" -ForegroundColor Yellow
    }

    # =====================================================================
    # Phase 2: Analysis
    # =====================================================================
    $scanResult = $null

    if (-not $SkipAnalysis) {
        Write-Host ""
        Write-Host "============================================" -ForegroundColor Cyan
        Write-Host "  Phase 2: Windows Security Analysis" -ForegroundColor Cyan
        Write-Host "============================================" -ForegroundColor Cyan

        $scanParams = @{
            EvidencePath    = $EvidencePath
            OutputDirectory = $OutputDirectory
            MinimumSeverity = $MinimumSeverity
        }
        if ($IncludeAnalyzers) { $scanParams['IncludeAnalyzers'] = $IncludeAnalyzers }
        if ($ExcludeAnalyzers) { $scanParams['ExcludeAnalyzers'] = $ExcludeAnalyzers }
        if ($CustomRulesPath)  { $scanParams['CustomRulesPath'] = $CustomRulesPath }
        if ($SkipHtmlReport)   { $scanParams['SkipHtmlReport'] = $true }
        if ($SkipCsvReport)    { $scanParams['SkipCsvReport'] = $true }

        $scanResult = Invoke-WindowsArtifactScan @scanParams
    }
    else {
        Write-Host ""
        Write-Host "[*] Skipping analysis phase (collection only)." -ForegroundColor Yellow
        Write-Host "[*] To analyze later, run:" -ForegroundColor White
        Write-Host "    Invoke-WindowsArtifactScan -EvidencePath '$EvidencePath'" -ForegroundColor White
    }

    # =====================================================================
    # Build combined result
    # =====================================================================
    $overallEnd = Get-Date
    $overallDuration = $overallEnd - $overallStart

    $liveScanResult = [PSCustomObject]@{
        PSTypeName       = 'PWSPostProcessingSuite.LiveScanResult'
        Mode             = 'Active'
        Platform         = 'Windows'
        EvidencePath     = $EvidencePath
        Collection       = $collectionResult
        Analysis         = $scanResult
        TotalFindings    = if ($scanResult) { $scanResult.TotalFindings } else { 0 }
        BySeverity       = if ($scanResult) { $scanResult.BySeverity } else { @{} }
        ReportPaths      = if ($scanResult) { $scanResult.ReportPaths } else { @{} }
        OverallStart     = $overallStart
        OverallEnd       = $overallEnd
        OverallDuration  = $overallDuration
    }

    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Magenta
    Write-Host "  Windows Active Scan Complete" -ForegroundColor Magenta
    Write-Host "============================================================" -ForegroundColor Magenta
    Write-Host "[*] Total duration: $($overallDuration.TotalSeconds.ToString('F1'))s" -ForegroundColor White

    if ($collectionResult) {
        Write-Host "[*] Evidence: $($collectionResult.FilesCopied) items, $($collectionResult.CommandsRun) commands" -ForegroundColor White
    }
    if ($scanResult) {
        $sev = $scanResult.BySeverity
        Write-Host "[*] Findings: $($scanResult.TotalFindings) total" -NoNewline -ForegroundColor White
        if ($sev.Critical -gt 0) { Write-Host " | Critical: $($sev.Critical)" -NoNewline -ForegroundColor Red }
        if ($sev.High -gt 0)     { Write-Host " | High: $($sev.High)" -NoNewline -ForegroundColor DarkRed }
        if ($sev.Medium -gt 0)   { Write-Host " | Medium: $($sev.Medium)" -NoNewline -ForegroundColor Yellow }
        Write-Host ""
    }

    Write-Host "[*] Evidence stored: $EvidencePath" -ForegroundColor Green
    if ($scanResult -and $scanResult.ReportPaths.Count -gt 0) {
        foreach ($rp in $scanResult.ReportPaths.GetEnumerator()) {
            Write-Host "[*] $($rp.Key) report: $($rp.Value)" -ForegroundColor Green
        }
    }
    Write-Host ""

    return $liveScanResult
}
