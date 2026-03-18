function Invoke-WindowsArtifactScan {
    <#
    .SYNOPSIS
        Main entry point for Windows artifact security analysis.
    .DESCRIPTION
        Scans a folder containing collected Windows system artifacts for security
        issues, misconfigurations, persistence mechanisms, and indicators of compromise.
    .PARAMETER EvidencePath
        Root folder path containing collected Windows artifacts.
    .PARAMETER IncludeAnalyzers
        Run only these specific analyzers (by name).
    .PARAMETER ExcludeAnalyzers
        Skip these specific analyzers.
    .PARAMETER CustomRulesPath
        Path to a custom YAML rules file for additional detection patterns.
    .PARAMETER OutputDirectory
        Directory for report output files. Defaults to current directory.
    .PARAMETER MinimumSeverity
        Minimum severity level to include in output. Default: Informational.
    .PARAMETER SkipHtmlReport
        Skip HTML report generation.
    .PARAMETER SkipCsvReport
        Skip CSV report generation.
    .EXAMPLE
        Invoke-WindowsArtifactScan -EvidencePath 'C:\Cases\incident1\windows_evidence'
    .EXAMPLE
        Invoke-WindowsArtifactScan -EvidencePath './evidence' -IncludeAnalyzers 'WinUserAccount','WinService' -MinimumSeverity High
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [ValidateScript({ Test-Path $_ -PathType Container })]
        [string]$EvidencePath,

        [string[]]$IncludeAnalyzers,

        [string[]]$ExcludeAnalyzers,

        [string]$CustomRulesPath,

        [string]$OutputDirectory = '.',

        [ValidateSet('All', 'Critical', 'High', 'Medium', 'Low', 'Informational')]
        [string]$MinimumSeverity = 'Informational',

        [switch]$SkipHtmlReport,

        [switch]$SkipCsvReport
    )

    $scanStart = Get-Date
    $EvidencePath = (Resolve-Path $EvidencePath).Path

    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "  PWSPostProcessingSuite - Windows Artifact Security Scanner" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "[*] Evidence path: $EvidencePath" -ForegroundColor White
    Write-Host "[*] Scan started: $scanStart" -ForegroundColor White
    Write-Host ""

    # Load rules - try Windows-specific rules first, fall back to default
    $rules = @{}
    if ($Script:DefaultRules) {
        $rules = $Script:DefaultRules.Clone()
    }

    # Merge Windows-specific rules
    $winRulesPath = Join-Path (Join-Path $Script:ModuleRoot 'Config') 'WindowsDefaultRules.yaml'
    if (Test-Path $winRulesPath) {
        try {
            $winRules = Import-YamlConfig -Path $winRulesPath
            foreach ($key in $winRules.Keys) {
                $rules[$key] = $winRules[$key]
            }
        }
        catch {
            Write-Warning "Failed to load Windows rules: $_"
        }
    }

    if ($CustomRulesPath) {
        try {
            $customRules = Import-YamlConfig -Path $CustomRulesPath
            foreach ($key in $customRules.Keys) {
                $rules[$key] = $customRules[$key]
            }
        }
        catch {
            Write-Warning "Failed to load custom rules: $_"
        }
    }

    # Detect evidence structure
    $structureType = 'unknown'
    $knownDirs = @('registry', 'eventlogs', 'services', 'users', 'firewall', 'security', 'collected_commands')
    $foundDirs = @($knownDirs | Where-Object { Test-Path (Join-Path $EvidencePath $_) })
    if ($foundDirs.Count -ge 2) {
        $structureType = 'structured'
        Write-Host "[*] Evidence structure: Structured Windows collection detected ($($foundDirs.Count) categories)" -ForegroundColor Green
    }
    else {
        $structureType = 'flat'
        Write-Host "[*] Evidence structure: Flat/custom collection detected" -ForegroundColor Yellow
    }

    # Define all Windows analyzers
    $allAnalyzers = @(
        @{ Name = 'WinUserAccount';      Function = 'Invoke-WinUserAccountAnalyzer';      Category = 'Windows User Accounts' }
        @{ Name = 'WinRegistryPersist';  Function = 'Invoke-WinRegistryPersistenceAnalyzer'; Category = 'Registry Persistence' }
        @{ Name = 'WinService';          Function = 'Invoke-WinServiceAnalyzer';           Category = 'Windows Services' }
        @{ Name = 'WinScheduledTask';    Function = 'Invoke-WinScheduledTaskAnalyzer';     Category = 'Scheduled Tasks' }
        @{ Name = 'WinFirewall';         Function = 'Invoke-WinFirewallAnalyzer';          Category = 'Windows Firewall' }
        @{ Name = 'WinNetwork';          Function = 'Invoke-WinNetworkAnalyzer';           Category = 'Network Configuration' }
        @{ Name = 'WinSecurityEventLog'; Function = 'Invoke-WinSecurityEventLogAnalyzer';  Category = 'Security Event Log' }
        @{ Name = 'WinPowerShell';       Function = 'Invoke-WinPowerShellAnalyzer';        Category = 'PowerShell Security' }
        @{ Name = 'WinDefender';         Function = 'Invoke-WinDefenderAnalyzer';          Category = 'Windows Defender' }
        @{ Name = 'WinInstalledSoftware'; Function = 'Invoke-WinInstalledSoftwareAnalyzer'; Category = 'Installed Software' }
        @{ Name = 'WinGroupPolicy';      Function = 'Invoke-WinGroupPolicyAnalyzer';       Category = 'Group Policy' }
        @{ Name = 'WinShare';            Function = 'Invoke-WinShareAnalyzer';             Category = 'Network Shares' }
        @{ Name = 'WinRDP';              Function = 'Invoke-WinRDPAnalyzer';               Category = 'Remote Desktop' }
        @{ Name = 'WinWMIPersistence';   Function = 'Invoke-WinWMIPersistenceAnalyzer';    Category = 'WMI Persistence' }
        @{ Name = 'WinProcess';          Function = 'Invoke-WinProcessAnalyzer';           Category = 'Process Analysis' }
    )

    # Filter analyzers
    $analyzersToRun = $allAnalyzers
    if ($IncludeAnalyzers) {
        $analyzersToRun = $allAnalyzers | Where-Object { $_.Name -in $IncludeAnalyzers }
    }
    if ($ExcludeAnalyzers) {
        $analyzersToRun = $analyzersToRun | Where-Object { $_.Name -notin $ExcludeAnalyzers }
    }

    Write-Host "[*] Running $($analyzersToRun.Count) Windows analyzers..." -ForegroundColor White
    Write-Host ""

    # Run analyzers and collect findings
    $allFindings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $analyzerResults = @{}

    foreach ($analyzer in $analyzersToRun) {
        $analyzerName = $analyzer.Name
        $functionName = $analyzer.Function

        if (-not (Get-Command $functionName -ErrorAction SilentlyContinue)) {
            Write-Verbose "Analyzer function not found: $functionName (skipping)"
            continue
        }

        Write-Host "  [>] Running: $analyzerName analyzer..." -ForegroundColor DarkGray -NoNewline

        try {
            $findings = & $functionName -EvidencePath $EvidencePath -Rules $rules
            $findingCount = @($findings).Count

            if ($findingCount -gt 0) {
                foreach ($f in $findings) {
                    $allFindings.Add($f)
                }
                $critCount = @($findings | Where-Object { $_.Severity -eq 'Critical' }).Count
                $highCount = @($findings | Where-Object { $_.Severity -eq 'High' }).Count

                $color = if ($critCount -gt 0) { 'Red' } elseif ($highCount -gt 0) { 'DarkRed' } else { 'Yellow' }
                Write-Host " $findingCount findings" -ForegroundColor $color
            }
            else {
                Write-Host " OK" -ForegroundColor Green
            }

            $analyzerResults[$analyzerName] = @{
                FindingCount = $findingCount
                Status       = 'Completed'
            }
        }
        catch {
            Write-Host " ERROR: $_" -ForegroundColor Red
            $analyzerResults[$analyzerName] = @{
                FindingCount = 0
                Status       = "Error: $_"
            }
        }
    }

    # Apply minimum severity filter
    $severityOrder = @{ 'Critical' = 0; 'High' = 1; 'Medium' = 2; 'Low' = 3; 'Informational' = 4 }
    $minSevLevel = if ($MinimumSeverity -eq 'All') { 4 } else { $severityOrder[$MinimumSeverity] }
    $filteredFindings = @($allFindings | Where-Object { $severityOrder[$_.Severity] -le $minSevLevel })

    # Sort by severity
    $sortedFindings = $filteredFindings | Sort-Object { $severityOrder[$_.Severity] }

    # Build severity summary
    $bySeverity = @{
        Critical      = @($sortedFindings | Where-Object { $_.Severity -eq 'Critical' }).Count
        High          = @($sortedFindings | Where-Object { $_.Severity -eq 'High' }).Count
        Medium        = @($sortedFindings | Where-Object { $_.Severity -eq 'Medium' }).Count
        Low           = @($sortedFindings | Where-Object { $_.Severity -eq 'Low' }).Count
        Informational = @($sortedFindings | Where-Object { $_.Severity -eq 'Informational' }).Count
    }

    # Build timeline
    $timeline = $sortedFindings | ConvertTo-Timeline

    $scanEnd = Get-Date
    $scanDuration = $scanEnd - $scanStart

    # Build metadata
    $metadata = [PSCustomObject]@{
        EvidencePath    = $EvidencePath
        StructureType   = $structureType
        Platform        = 'Windows'
        ScanStart       = $scanStart
        ScanEnd         = $scanEnd
        ScanDuration    = $scanDuration
        AnalyzersRun    = $analyzersToRun.Count
        AnalyzerResults = $analyzerResults
        MinimumSeverity = $MinimumSeverity
    }

    # Build result object
    $scanResult = [PSCustomObject]@{
        PSTypeName    = 'PWSPostProcessingSuite.ScanResult'
        TotalFindings = $sortedFindings.Count
        BySeverity    = $bySeverity
        Findings      = $sortedFindings
        Timeline      = @($timeline)
        Metadata      = $metadata
        ReportPaths   = @{}
    }

    # Generate reports
    Write-Host ""

    if (-not (Test-Path $OutputDirectory)) {
        New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
    }

    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'

    # Console summary
    Write-ConsoleSummary -Findings $sortedFindings -BySeverity $bySeverity

    # HTML report
    if (-not $SkipHtmlReport) {
        $htmlPath = Join-Path $OutputDirectory "WindowsArtifactScan_${timestamp}.html"
        Export-HtmlReport -Findings $sortedFindings -Timeline @($timeline) -OutputPath $htmlPath -ScanMetadata $metadata
        $scanResult.ReportPaths['HTML'] = $htmlPath
        Write-Host "[+] HTML report saved: $htmlPath" -ForegroundColor Green
    }

    # CSV report
    if (-not $SkipCsvReport) {
        $csvPath = Join-Path $OutputDirectory "WindowsArtifactScan_${timestamp}.csv"
        Export-CsvReport -Findings $sortedFindings -OutputPath $csvPath
        $scanResult.ReportPaths['CSV'] = $csvPath
        Write-Host "[+] CSV report saved: $csvPath" -ForegroundColor Green

        if ($timeline.Count -gt 0) {
            $timelinePath = Join-Path $OutputDirectory "WindowsArtifactScan_Timeline_${timestamp}.csv"
            Export-TimelineReport -Timeline @($timeline) -OutputPath $timelinePath
            $scanResult.ReportPaths['Timeline'] = $timelinePath
            Write-Host "[+] Timeline report saved: $timelinePath" -ForegroundColor Green
        }
    }

    Write-Host ""
    Write-Host "[*] Scan completed in $($scanDuration.TotalSeconds.ToString('F1'))s" -ForegroundColor Cyan
    Write-Host ""

    return $scanResult
}
