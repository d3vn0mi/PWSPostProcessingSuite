function Invoke-ShellHistoryAnalyzer {
    <#
    .SYNOPSIS
        Analyzes shell history files for suspicious commands and activity.
    .DESCRIPTION
        Examines bash and zsh history files across user home directories and root
        for suspicious commands including reverse shells, credential access,
        reconnaissance, privilege escalation tools, data exfiltration, encoded
        commands, defense evasion, download-and-execute patterns, and cryptomining.
    .PARAMETER EvidencePath
        Root folder path containing collected Linux artifacts.
    .PARAMETER Rules
        Hashtable of detection rules from the rules engine.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$EvidencePath,

        [Parameter(Mandatory)]
        [hashtable]$Rules
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $analyzerCategory = 'Shell History'

    # ----------------------------------------------------------------
    # Collect all history files
    # ----------------------------------------------------------------
    $historyFiles = [System.Collections.Generic.List[hashtable]]::new()

    $historyFileNames = @('.bash_history', '.zsh_history')

    # Search in home/*/ directories
    $homePath = Resolve-ArtifactPath -EvidencePath $EvidencePath -LinuxPath 'home'
    if (Test-Path $homePath -PathType Container) {
        $userDirs = Get-ChildItem -Path $homePath -Directory -ErrorAction SilentlyContinue
        foreach ($userDir in $userDirs) {
            foreach ($histName in $historyFileNames) {
                $histFile = Join-Path $userDir.FullName $histName
                if (Test-Path $histFile -PathType Leaf) {
                    $historyFiles.Add(@{
                        Path      = $histFile
                        LinuxPath = "/home/$($userDir.Name)/$histName"
                        Username  = $userDir.Name
                        Lines     = @(Read-ArtifactContent -Path $histFile)
                    })
                }
            }
        }
    }

    # Search in root/ directory
    $rootPath = Resolve-ArtifactPath -EvidencePath $EvidencePath -LinuxPath 'root'
    if (Test-Path $rootPath -PathType Container) {
        foreach ($histName in $historyFileNames) {
            $histFile = Join-Path $rootPath $histName
            if (Test-Path $histFile -PathType Leaf) {
                $historyFiles.Add(@{
                    Path      = $histFile
                    LinuxPath = "/root/$histName"
                    Username  = 'root'
                    Lines     = @(Read-ArtifactContent -Path $histFile)
                })
            }
        }
    }

    if ($historyFiles.Count -eq 0) {
        Write-Verbose "ShellHistoryAnalyzer: No history files found, skipping."
        return @()
    }

    # ----------------------------------------------------------------
    # Get suspicious command patterns from rules
    # ----------------------------------------------------------------
    $suspiciousCommands = @{}
    if ($Rules.ContainsKey('suspicious_commands') -and $null -ne $Rules['suspicious_commands']) {
        $suspiciousCommands = $Rules['suspicious_commands']
    }

    if ($suspiciousCommands.Count -eq 0) {
        Write-Verbose "ShellHistoryAnalyzer: No suspicious_commands patterns in rules, skipping pattern matching."
    }

    # ----------------------------------------------------------------
    # HIST-001: Scan each history file against all pattern categories
    # ----------------------------------------------------------------
    $totalCommandsAnalyzed = 0

    # Accumulate matches by category across all history files
    # Structure: category -> list of @{ Line; Username; LinuxPath; Match }
    $categoryMatches = @{}

    foreach ($histFile in $historyFiles) {
        $totalCommandsAnalyzed += $histFile.Lines.Count

        foreach ($rawLine in $histFile.Lines) {
            $line = $rawLine.Trim()
            if ([string]::IsNullOrWhiteSpace($line)) { continue }

            # For each pattern category, check the line
            foreach ($categoryName in $suspiciousCommands.Keys) {
                $patterns = $suspiciousCommands[$categoryName]
                if ($null -eq $patterns -or $patterns.Count -eq 0) { continue }

                $matchResult = Test-PatternMatch -InputText $line -Patterns $patterns
                if ($matchResult.Matched) {
                    if (-not $categoryMatches.ContainsKey($categoryName)) {
                        $categoryMatches[$categoryName] = [System.Collections.Generic.List[hashtable]]::new()
                    }

                    $categoryMatches[$categoryName].Add(@{
                        Line      = $line
                        Username  = $histFile.Username
                        LinuxPath = $histFile.LinuxPath
                        Severity  = $matchResult.Severity
                        MITRE     = $matchResult.MITRE
                        RuleName  = $matchResult.RuleName
                        Pattern   = $matchResult.Pattern
                    })
                }
            }
        }
    }

    # ----------------------------------------------------------------
    # Generate findings grouped by category
    # ----------------------------------------------------------------
    # Severity mapping for categories (use highest severity from matches)
    $severityOrder = @{ 'Critical' = 0; 'High' = 1; 'Medium' = 2; 'Low' = 3; 'Informational' = 4 }

    foreach ($categoryName in $categoryMatches.Keys) {
        $matches = $categoryMatches[$categoryName]
        if ($matches.Count -eq 0) { continue }

        # Determine the highest severity across all matches in this category
        $highestSeverity = 'Informational'
        $mitreRefs = [System.Collections.Generic.HashSet[string]]::new()

        foreach ($m in $matches) {
            if ($severityOrder.ContainsKey($m.Severity) -and $severityOrder[$m.Severity] -lt $severityOrder[$highestSeverity]) {
                $highestSeverity = $m.Severity
            }
            if (-not [string]::IsNullOrWhiteSpace($m.MITRE)) {
                [void]$mitreRefs.Add($m.MITRE)
            }
        }

        $mitreString = ($mitreRefs | Sort-Object) -join ', '

        # Build evidence lines - show each matching command with context
        $evidenceLines = [System.Collections.Generic.List[string]]::new()
        $evidenceLines.Add("Category: $categoryName ($($matches.Count) matches)")

        # Group matches by user for cleaner output
        $byUser = $matches | Group-Object -Property Username
        foreach ($userGroup in $byUser) {
            $evidenceLines.Add("  User: $($userGroup.Name)")
            foreach ($m in $userGroup.Group) {
                $evidenceLines.Add("    [$($m.RuleName)] $($m.Line)")
            }
        }

        # Format the category name for the title
        $displayCategory = ($categoryName -replace '_', ' ')
        $displayCategory = (Get-Culture).TextInfo.ToTitleCase($displayCategory)

        # Determine CVSSv3 score based on severity
        $cvssScore = switch ($highestSeverity) {
            'Critical' { '9.8' }
            'High'     { '7.5' }
            'Medium'   { '5.3' }
            'Low'      { '3.1' }
            default    { '' }
        }

        # Determine technical impact based on category
        $techImpact = switch -Wildcard ($categoryName) {
            '*reverse_shell*'        { 'Indicates active command-and-control channel allowing remote attacker to execute arbitrary commands on the system.' }
            '*credential*'           { 'May allow attacker to harvest credentials for lateral movement or privilege escalation.' }
            '*privilege_escalation*' { 'Enables privilege escalation from current user to root or other privileged accounts.' }
            '*reconnaissance*'       { 'Exposes system configuration and network topology data that could aid further attacks.' }
            '*exfiltration*'         { 'Indicates potential data theft or unauthorized transfer of sensitive information.' }
            '*cryptomining*'         { 'Unauthorized use of system resources for cryptocurrency mining, indicating compromise.' }
            '*defense_evasion*'      { 'Attacker may have tampered with logging or security controls to hide malicious activity.' }
            default                  { 'Suspicious command execution detected that may indicate system compromise or unauthorized activity.' }
        }

        $findings.Add((New-Finding `
            -Id 'HIST-001' `
            -Severity $highestSeverity `
            -Category $analyzerCategory `
            -Title "Suspicious commands detected: $displayCategory ($($matches.Count) matches)" `
            -Description "Found $($matches.Count) command(s) in shell history matching '$categoryName' detection patterns. These commands may indicate malicious activity or compromise." `
            -ArtifactPath ($historyFiles[0].Path) `
            -Evidence @($evidenceLines) `
            -Recommendation "Investigate the flagged commands in context. Determine if they were executed by an authorized user for legitimate purposes or represent attacker activity. Correlate with authentication logs and other artifacts." `
            -MITRE $mitreString `
            -CVSSv3Score $cvssScore `
            -TechnicalImpact $techImpact
        ))
    }

    # ----------------------------------------------------------------
    # HIST-002 (Informational): Summary of history files analyzed
    # ----------------------------------------------------------------
    $summaryEvidence = [System.Collections.Generic.List[string]]::new()
    $summaryEvidence.Add("History files found: $($historyFiles.Count)")
    foreach ($hf in $historyFiles) {
        $summaryEvidence.Add("  - $($hf.LinuxPath) ($($hf.Username)): $($hf.Lines.Count) commands")
    }
    $summaryEvidence.Add("Total commands analyzed: $totalCommandsAnalyzed")

    $totalMatches = 0
    foreach ($categoryName in $categoryMatches.Keys) {
        $totalMatches += $categoryMatches[$categoryName].Count
    }
    $summaryEvidence.Add("Total suspicious matches: $totalMatches")

    if ($categoryMatches.Count -gt 0) {
        $summaryEvidence.Add("Categories with matches:")
        foreach ($categoryName in ($categoryMatches.Keys | Sort-Object)) {
            $summaryEvidence.Add("  - ${categoryName}: $($categoryMatches[$categoryName].Count) matches")
        }
    }

    $findings.Add((New-Finding `
        -Id 'HIST-002' `
        -Severity 'Informational' `
        -Category $analyzerCategory `
        -Title 'Shell history analysis summary' `
        -Description 'Summary of shell history files analyzed and suspicious patterns detected.' `
        -ArtifactPath ($historyFiles[0].Path) `
        -Evidence @($summaryEvidence) `
        -Recommendation 'Review the full history files for additional context around suspicious commands.' `
        -MITRE '' `
        -CVSSv3Score '' `
        -TechnicalImpact ''
    ))

    return $findings.ToArray()
}
