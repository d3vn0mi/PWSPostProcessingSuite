function Invoke-LinuxArtifactScan {
    <#
    .SYNOPSIS
        Main entry point for Linux artifact security analysis.
    .DESCRIPTION
        Scans a folder containing collected Linux system artifacts for security
        issues, misconfigurations, persistence mechanisms, and indicators of compromise.
        Supports both filesystem-mirror and flat-collection folder structures.
    .PARAMETER EvidencePath
        Root folder path containing collected Linux artifacts.
    .PARAMETER IncludeAnalyzers
        Run only these specific analyzers (by name, e.g., 'UserAccount', 'SSH').
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
        Invoke-LinuxArtifactScan -EvidencePath '/cases/incident1/linux_evidence'
    .EXAMPLE
        Invoke-LinuxArtifactScan -EvidencePath './evidence' -IncludeAnalyzers 'UserAccount','SSH' -MinimumSeverity High
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
    Write-Host "  PWSPostProcessingSuite - Linux Artifact Security Scanner" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "[*] Evidence path: $EvidencePath" -ForegroundColor White
    Write-Host "[*] Scan started: $scanStart" -ForegroundColor White
    Write-Host ""

    # Load rules
    $rules = @{}
    if ($Script:DefaultRules) {
        $rules = $Script:DefaultRules.Clone()
    }
    else {
        $defaultRulesPath = Join-Path (Join-Path $Script:ModuleRoot 'Config') 'DefaultRules.yaml'
        if (Test-Path $defaultRulesPath) {
            try {
                $rules = Import-YamlConfig -Path $defaultRulesPath
            }
            catch {
                Write-Warning "Failed to load default rules: $_"
            }
        }
    }

    if ($CustomRulesPath) {
        try {
            Import-ScanRules -Path $CustomRulesPath
            $rules = $Script:DefaultRules
        }
        catch {
            Write-Warning "Failed to load custom rules: $_"
        }
    }

    # Detect evidence structure
    $structureType = 'unknown'
    if (Test-Path (Join-Path $EvidencePath 'etc')) {
        $structureType = 'mirror'
        Write-Host "[*] Evidence structure: Filesystem mirror detected" -ForegroundColor Green
    }
    else {
        $structureType = 'flat'
        Write-Host "[*] Evidence structure: Flat/custom collection detected" -ForegroundColor Yellow
    }

    # Define all analyzers
    $allAnalyzers = @(
        @{ Name = 'UserAccount';    Function = 'Invoke-UserAccountAnalyzer';    Category = 'System Configuration' }
        @{ Name = 'Sudoers';        Function = 'Invoke-SudoersAnalyzer';        Category = 'Privilege Escalation' }
        @{ Name = 'SSHConfig';      Function = 'Invoke-SSHConfigAnalyzer';      Category = 'System Configuration' }
        @{ Name = 'PAM';            Function = 'Invoke-PAMAnalyzer';            Category = 'System Configuration' }
        @{ Name = 'Cron';           Function = 'Invoke-CronAnalyzer';           Category = 'Persistence' }
        @{ Name = 'Systemd';        Function = 'Invoke-SystemdAnalyzer';        Category = 'Persistence' }
        @{ Name = 'ShellProfile';   Function = 'Invoke-ShellProfileAnalyzer';   Category = 'Persistence' }
        @{ Name = 'ShellHistory';   Function = 'Invoke-ShellHistoryAnalyzer';   Category = 'User Artifacts' }
        @{ Name = 'SSHKey';         Function = 'Invoke-SSHKeyAnalyzer';         Category = 'User Artifacts' }
        @{ Name = 'Sysctl';         Function = 'Invoke-SysctlAnalyzer';         Category = 'System Configuration' }
        @{ Name = 'Fstab';          Function = 'Invoke-FstabAnalyzer';          Category = 'System Configuration' }
        @{ Name = 'NetworkConfig';  Function = 'Invoke-NetworkConfigAnalyzer';  Category = 'Network' }
        @{ Name = 'Firewall';       Function = 'Invoke-FirewallAnalyzer';       Category = 'Network' }
        @{ Name = 'WebServer';      Function = 'Invoke-WebServerAnalyzer';      Category = 'Network' }
        @{ Name = 'AuthLog';        Function = 'Invoke-AuthLogAnalyzer';        Category = 'Log Analysis' }
        @{ Name = 'Syslog';         Function = 'Invoke-SyslogAnalyzer';         Category = 'Log Analysis' }
        @{ Name = 'AuditLog';       Function = 'Invoke-AuditLogAnalyzer';       Category = 'Log Analysis' }
        @{ Name = 'PackageLog';     Function = 'Invoke-PackageLogAnalyzer';     Category = 'Log Analysis' }
        @{ Name = 'KernelModule';   Function = 'Invoke-KernelModuleAnalyzer';   Category = 'System Configuration' }
        @{ Name = 'LDPreload';      Function = 'Invoke-LDPreloadAnalyzer';      Category = 'Persistence' }
        @{ Name = 'Environment';    Function = 'Invoke-EnvironmentAnalyzer';    Category = 'Persistence' }
        @{ Name = 'Process';        Function = 'Invoke-ProcessAnalyzer';        Category = 'Runtime Analysis' }
        @{ Name = 'Filesystem';     Function = 'Invoke-FilesystemAnalyzer';     Category = 'Filesystem' }
        @{ Name = 'LogIntegrity';   Function = 'Invoke-LogIntegrityAnalyzer';   Category = 'Log Analysis' }
        @{ Name = 'Container';      Function = 'Invoke-ContainerAnalyzer';      Category = 'Container Security' }
        @{ Name = 'CredentialScan'; Function = 'Invoke-CredentialScanAnalyzer'; Category = 'Credential Exposure' }
        @{ Name = 'CloudSecurity';  Function = 'Invoke-CloudSecurityAnalyzer';  Category = 'Cloud Security' }
        @{ Name = 'Socket';         Function = 'Invoke-SocketAnalyzer';         Category = 'Socket Security' }
    )

    # Filter analyzers
    $analyzersToRun = $allAnalyzers
    if ($IncludeAnalyzers) {
        $analyzersToRun = $allAnalyzers | Where-Object { $_.Name -in $IncludeAnalyzers }
    }
    if ($ExcludeAnalyzers) {
        $analyzersToRun = $analyzersToRun | Where-Object { $_.Name -notin $ExcludeAnalyzers }
    }

    Write-Host "[*] Running $($analyzersToRun.Count) analyzers..." -ForegroundColor White
    Write-Host ""

    # Run analyzers and collect findings
    $allFindings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $analyzerResults = @{}

    foreach ($analyzer in $analyzersToRun) {
        $analyzerName = $analyzer.Name
        $functionName = $analyzer.Function

        # Check if the function exists
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
        $htmlPath = Join-Path $OutputDirectory "LinuxArtifactScan_${timestamp}.html"
        Export-HtmlReport -Findings $sortedFindings -Timeline @($timeline) -OutputPath $htmlPath -ScanMetadata $metadata
        $scanResult.ReportPaths['HTML'] = $htmlPath
        Write-Host "[+] HTML report saved: $htmlPath" -ForegroundColor Green
    }

    # CSV report
    if (-not $SkipCsvReport) {
        $csvPath = Join-Path $OutputDirectory "LinuxArtifactScan_${timestamp}.csv"
        Export-CsvReport -Findings $sortedFindings -OutputPath $csvPath
        $scanResult.ReportPaths['CSV'] = $csvPath
        Write-Host "[+] CSV report saved: $csvPath" -ForegroundColor Green

        # Timeline CSV
        if ($timeline.Count -gt 0) {
            $timelinePath = Join-Path $OutputDirectory "LinuxArtifactScan_Timeline_${timestamp}.csv"
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
