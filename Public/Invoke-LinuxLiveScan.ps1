function Invoke-LinuxLiveScan {
    <#
    .SYNOPSIS
        Active mode: Collects evidence from the live Linux system and runs all analyzers.
    .DESCRIPTION
        Two-phase operation:
          Phase 1 - Collection: Gathers files, configs, logs, and command outputs from the
                    running system into a filesystem-mirror evidence directory.
          Phase 2 - Analysis:   Runs the standard Invoke-LinuxArtifactScan against the
                    collected evidence using all 28 analyzers.

        This is the "active mode" equivalent of the offline Invoke-LinuxArtifactScan.
        Instead of requiring pre-collected evidence, it gathers everything it needs
        from the live host and then analyzes it in one shot.
    .PARAMETER OutputDirectory
        Directory where evidence and reports will be stored.
        Creates a timestamped subdirectory for the collection.
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
        Path to a custom YAML rules file for additional detection patterns.
    .PARAMETER MinimumSeverity
        Minimum severity level to include in output. Default: Informational.
    .PARAMETER SkipCollection
        Skip Phase 1 (collection) and use the existing EvidencePath. Useful for
        re-analyzing previously collected evidence.
    .PARAMETER SkipAnalysis
        Skip Phase 2 (analysis). Only collect artifacts without running analyzers.
    .PARAMETER SkipCommands
        During collection, skip running live commands (only copy files).
    .PARAMETER CollectTempDirs
        Include /tmp, /var/tmp, /dev/shm directory listings during collection.
    .PARAMETER MaxLogLines
        Maximum lines to collect from large log files. Default: 50000.
    .PARAMETER SkipHtmlReport
        Skip HTML report generation.
    .PARAMETER SkipCsvReport
        Skip CSV report generation.
    .EXAMPLE
        Invoke-LinuxLiveScan -OutputDirectory '/cases/incident1'

        Full active scan: collects all evidence, runs all 28 analyzers, generates all reports.
    .EXAMPLE
        Invoke-LinuxLiveScan -OutputDirectory './output' -MinimumSeverity High

        Active scan showing only High and Critical findings.
    .EXAMPLE
        Invoke-LinuxLiveScan -OutputDirectory './output' -SkipAnalysis

        Collection only - gather evidence without running analyzers.
    .EXAMPLE
        Invoke-LinuxLiveScan -OutputDirectory './output' -SkipCollection -EvidencePath './previous_collection/evidence'

        Re-analyze previously collected evidence.
    .EXAMPLE
        Invoke-LinuxLiveScan -OutputDirectory './output' -IncludeCategories 'UserAccounts','SSH','Sudoers' -IncludeAnalyzers 'UserAccount','SSHConfig','Sudoers'

        Targeted scan: only collect and analyze user/SSH/sudo artifacts.
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

        [switch]$CollectTempDirs,

        [int]$MaxLogLines = 50000,

        [switch]$SkipHtmlReport,

        [switch]$SkipCsvReport
    )

    $overallStart = Get-Date

    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Magenta
    Write-Host "  PWSPostProcessingSuite - Active Mode (Live Scan)" -ForegroundColor Magenta
    Write-Host "============================================================" -ForegroundColor Magenta
    Write-Host "[*] Mode: ACTIVE - Live system collection + analysis" -ForegroundColor White
    Write-Host "[*] Started: $overallStart" -ForegroundColor White
    Write-Host ""

    # Platform check
    if ($PSVersionTable.Platform -and $PSVersionTable.Platform -ne 'Unix') {
        Write-Warning "Active mode is designed to run on a live Linux system."
        Write-Warning "Current platform: $($PSVersionTable.Platform). Some collectors may not work."
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
        Write-Host "  Phase 1: Evidence Collection" -ForegroundColor Cyan
        Write-Host "============================================" -ForegroundColor Cyan

        # Determine evidence output path
        if (-not $EvidencePath) {
            $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
            $hostName = 'localhost'
            try { $hostName = (hostname 2>/dev/null) -replace '[^\w\-\.]', '_' } catch { }
            $EvidencePath = Join-Path $OutputDirectory "evidence_${hostName}_${timestamp}"
        }

        # Build collector parameters
        $collectorParams = @{
            OutputPath = $EvidencePath
            MaxLogLines = $MaxLogLines
        }
        if ($IncludeCategories) { $collectorParams['IncludeCategories'] = $IncludeCategories }
        if ($ExcludeCategories) { $collectorParams['ExcludeCategories'] = $ExcludeCategories }
        if ($SkipCommands)      { $collectorParams['SkipCommands'] = $true }
        if ($CollectTempDirs)   { $collectorParams['CollectTempDirs'] = $true }

        $collectionResult = Invoke-ArtifactCollector @collectorParams
        $EvidencePath = $collectionResult.OutputPath
    }
    else {
        # Validate evidence path when skipping collection
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
        Write-Host "  Phase 2: Security Analysis" -ForegroundColor Cyan
        Write-Host "============================================" -ForegroundColor Cyan

        # Build scan parameters
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

        $scanResult = Invoke-LinuxArtifactScan @scanParams
    }
    else {
        Write-Host ""
        Write-Host "[*] Skipping analysis phase (collection only)." -ForegroundColor Yellow
        Write-Host "[*] To analyze later, run:" -ForegroundColor White
        Write-Host "    Invoke-LinuxArtifactScan -EvidencePath '$EvidencePath'" -ForegroundColor White
    }

    # =====================================================================
    # Build combined result
    # =====================================================================
    $overallEnd = Get-Date
    $overallDuration = $overallEnd - $overallStart

    $liveScanResult = [PSCustomObject]@{
        PSTypeName       = 'PWSPostProcessingSuite.LiveScanResult'
        Mode             = 'Active'
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
    Write-Host "  Active Scan Complete" -ForegroundColor Magenta
    Write-Host "============================================================" -ForegroundColor Magenta
    Write-Host "[*] Total duration: $($overallDuration.TotalSeconds.ToString('F1'))s" -ForegroundColor White

    if ($collectionResult) {
        Write-Host "[*] Evidence: $($collectionResult.FilesCopied) files, $($collectionResult.CommandsRun) commands" -ForegroundColor White
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
