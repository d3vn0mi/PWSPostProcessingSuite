function Invoke-WinScheduledTaskAnalyzer {
    <#
    .SYNOPSIS
        Analyzes Windows scheduled tasks for persistence and suspicious activity.
    .DESCRIPTION
        Examines collected scheduled task data for indicators of compromise including
        tasks with suspicious actions (encoded PowerShell, download-execute, LOLBins),
        tasks executing from user-writable paths, tasks running as SYSTEM with suspicious
        actions, hidden tasks, and tasks without author information.
    .PARAMETER EvidencePath
        Root folder path containing collected Windows artifacts.
    .PARAMETER Rules
        Hashtable of detection rules from the rules engine.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$EvidencePath,
        [Parameter(Mandatory)][hashtable]$Rules
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $analyzerCategory = 'Windows Scheduled Tasks'
    $mitrePersistence = 'T1053.005'

    # ----------------------------------------------------------------
    # Load artifacts
    # ----------------------------------------------------------------
    $tasksDir = Join-Path $EvidencePath 'tasks'
    $commandsDir = Join-Path $EvidencePath 'collected_commands'

    $tasksCsvPath = Join-Path $tasksDir 'scheduled_tasks.csv'
    $schtasksPath = Join-Path $commandsDir 'schtasks_verbose.txt'

    # Get suspicious patterns from rules
    $suspiciousPatterns = @()
    if ($Rules -and $Rules.ContainsKey('suspicious_task_patterns')) {
        $suspiciousPatterns = $Rules['suspicious_task_patterns']
    }

    # User-writable path patterns
    $userWritablePaths = @(
        '(?i)\\Temp\\',
        '(?i)\\tmp\\',
        '(?i)\\AppData\\',
        '(?i)\\Users\\[^\\]+\\Desktop\\',
        '(?i)\\Users\\[^\\]+\\Documents\\',
        '(?i)\\Users\\[^\\]+\\Downloads\\',
        '(?i)\\Users\\Public\\',
        '(?i)\\ProgramData\\',
        '(?i)\\Windows\\Temp\\'
    )

    # Built-in suspicious action patterns
    $suspiciousActionPatterns = @(
        '(?i)-[eE]nc(?:odedCommand)?\s+',
        '(?i)powershell.*-e\s+[A-Za-z0-9+/=]{20,}',
        '(?i)Invoke-(WebRequest|RestMethod|Expression)',
        '(?i)Net\.WebClient',
        '(?i)DownloadFile|DownloadString|DownloadData',
        '(?i)Start-BitsTransfer',
        '(?i)certutil.*-urlcache',
        '(?i)bitsadmin.*\/transfer',
        '(?i)mshta\s+(http|javascript|vbscript)',
        '(?i)regsvr32\s+/s\s+/n\s+/u\s+/i:',
        '(?i)rundll32.*javascript',
        '(?i)wscript.*\.js',
        '(?i)cscript.*\.js',
        '(?i)cmd\.exe\s+/c.*powershell',
        '(?i)IEX\s*\(',
        '(?i)\|\s*IEX',
        '(?i)FromBase64String'
    )

    # ----------------------------------------------------------------
    # Parse scheduled tasks - try CSV first, then schtasks fallback
    # ----------------------------------------------------------------
    $tasks = [System.Collections.Generic.List[hashtable]]::new()

    if (Test-Path $tasksCsvPath) {
        try {
            $csvData = Import-Csv -Path $tasksCsvPath
            foreach ($row in $csvData) {
                $task = @{
                    TaskName = if ($row.TaskName) { $row.TaskName } else { '' }
                    TaskPath = if ($row.TaskPath) { $row.TaskPath } else { '' }
                    State    = if ($row.State) { $row.State } else { '' }
                    Actions  = if ($row.Actions) { $row.Actions } else { '' }
                    Author   = if ($row.Author) { $row.Author } else { '' }
                    UserId   = if ($row.UserId) { $row.UserId } elseif ($row.RunAs) { $row.RunAs } else { '' }
                    Description = if ($row.Description) { $row.Description } else { '' }
                    RawLine  = ($row.PSObject.Properties | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join '; '
                }
                if (-not [string]::IsNullOrWhiteSpace($task.TaskName)) {
                    $tasks.Add($task)
                }
            }
        }
        catch {
            Write-Verbose "WinScheduledTaskAnalyzer: Failed to parse tasks CSV: $_"
        }
    }
    elseif (Test-Path $schtasksPath) {
        # Parse schtasks /query /fo LIST /v output
        $content = Get-Content -Path $schtasksPath -ErrorAction SilentlyContinue
        $currentTask = $null
        foreach ($line in $content) {
            $trimmed = $line.Trim()
            if ([string]::IsNullOrWhiteSpace($trimmed)) {
                if ($currentTask -and $currentTask.TaskName) {
                    $tasks.Add($currentTask)
                    $currentTask = $null
                }
                continue
            }

            if ($trimmed -match '(?i)^TaskName\s*[=:]\s*(.+)$') {
                if ($currentTask -and $currentTask.TaskName) { $tasks.Add($currentTask) }
                $taskFullPath = $Matches[1].Trim()
                $taskNameOnly = $taskFullPath.Split('\')[-1]
                $taskPathOnly = if ($taskFullPath.Contains('\')) {
                    $taskFullPath.Substring(0, $taskFullPath.LastIndexOf('\') + 1)
                } else { '\' }
                $currentTask = @{
                    TaskName = $taskNameOnly; TaskPath = $taskPathOnly; State = ''
                    Actions = ''; Author = ''; UserId = ''; Description = ''
                    RawLine = $trimmed
                }
            }
            elseif ($currentTask) {
                if ($trimmed -match '(?i)^Status\s*[=:]\s*(.+)$') {
                    $currentTask.State = $Matches[1].Trim()
                }
                elseif ($trimmed -match '(?i)^(Task To Run|Actions)\s*[=:]\s*(.+)$') {
                    $currentTask.Actions = $Matches[2].Trim()
                }
                elseif ($trimmed -match '(?i)^Author\s*[=:]\s*(.+)$') {
                    $currentTask.Author = $Matches[1].Trim()
                }
                elseif ($trimmed -match '(?i)^(Run As User|UserId)\s*[=:]\s*(.+)$') {
                    $currentTask.UserId = $Matches[2].Trim()
                }
                elseif ($trimmed -match '(?i)^(Comment|Description)\s*[=:]\s*(.+)$') {
                    $currentTask.Description = $Matches[2].Trim()
                }
                $currentTask.RawLine += "; $trimmed"
            }
        }
        if ($currentTask -and $currentTask.TaskName) { $tasks.Add($currentTask) }
    }
    else {
        Write-Verbose "WinScheduledTaskAnalyzer: No scheduled task data found, skipping."
        return @()
    }

    if ($tasks.Count -eq 0) {
        Write-Verbose "WinScheduledTaskAnalyzer: No tasks parsed from evidence, skipping."
        return @()
    }

    $artifactPath = if (Test-Path $tasksCsvPath) { $tasksCsvPath } else { $schtasksPath }

    # Counters for summary
    $totalTasks = $tasks.Count
    $systemTasks = 0
    $suspiciousCount = 0

    # ----------------------------------------------------------------
    # Analyze each task
    # ----------------------------------------------------------------
    foreach ($task in $tasks) {
        $taskName = $task.TaskName
        $taskPath = $task.TaskPath
        $actions = $task.Actions
        $userId = $task.UserId
        $author = $task.Author
        $description = $task.Description
        $fullPath = "$taskPath$taskName"

        $isSystem = $userId -match '(?i)(SYSTEM|Local System|S-1-5-18)'
        if ($isSystem) { $systemTasks++ }

        if ([string]::IsNullOrWhiteSpace($actions)) { continue }

        # ----------------------------------------------------------------
        # WTASK-001: Task action matches suspicious patterns
        # ----------------------------------------------------------------
        $isSuspicious = $false
        $matchedPattern = ''

        # Check against Rules patterns
        if ($suspiciousPatterns.Count -gt 0) {
            $patternResult = Test-PatternMatch -InputText $actions -Patterns $suspiciousPatterns
            if ($patternResult.Matched) {
                $isSuspicious = $true
                $matchedPattern = $patternResult.RuleName
                if ([string]::IsNullOrWhiteSpace($matchedPattern)) {
                    $matchedPattern = $patternResult.Pattern
                }
            }
        }

        # Check against built-in suspicious action patterns
        if (-not $isSuspicious) {
            foreach ($pattern in $suspiciousActionPatterns) {
                if ($actions -match $pattern) {
                    $isSuspicious = $true
                    $matchedPattern = $pattern
                    break
                }
            }
        }

        if ($isSuspicious) {
            $suspiciousCount++
            $findings.Add((New-Finding `
                -Id 'WTASK-001' `
                -Severity 'Critical' `
                -Category $analyzerCategory `
                -Title "Suspicious scheduled task action: $taskName" `
                -Description "Scheduled task '$fullPath' has an action matching known malicious patterns such as encoded PowerShell, download-execute, or LOLBin usage." `
                -ArtifactPath $artifactPath `
                -Evidence @("Task: $fullPath", "Action: $actions", "RunAs: $userId", "Author: $author", "Matched: $matchedPattern") `
                -Recommendation 'Investigate this scheduled task immediately. Analyze the referenced commands and binaries. Disable and remove if confirmed malicious.' `
                -MITRE $mitrePersistence `
                -CVSSv3Score '9.8' `
                -TechnicalImpact 'Malicious scheduled tasks provide persistent, automated execution of attacker commands, enabling ongoing access and data exfiltration.'
            ))

            # Also check WTASK-003 if running as SYSTEM
            if ($isSystem) {
                $findings.Add((New-Finding `
                    -Id 'WTASK-003' `
                    -Severity 'High' `
                    -Category $analyzerCategory `
                    -Title "SYSTEM task with suspicious action: $taskName" `
                    -Description "Scheduled task '$fullPath' runs as SYSTEM and has a suspicious action. This combination provides maximum impact for an attacker." `
                    -ArtifactPath $artifactPath `
                    -Evidence @("Task: $fullPath", "Action: $actions", "RunAs: SYSTEM", "Author: $author") `
                    -Recommendation 'Investigate immediately. A SYSTEM-level task with suspicious actions indicates high-impact compromise.' `
                    -MITRE $mitrePersistence `
                    -CVSSv3Score '9.8' `
                    -TechnicalImpact 'SYSTEM-level scheduled task with malicious actions provides the highest privilege persistent access to the system.'
                ))
            }
            continue
        }

        # ----------------------------------------------------------------
        # WTASK-002: Task executing from user-writable paths
        # ----------------------------------------------------------------
        $isUserWritable = $false
        foreach ($uwPattern in $userWritablePaths) {
            if ($actions -match $uwPattern) {
                $isUserWritable = $true
                break
            }
        }

        if ($isUserWritable) {
            $findings.Add((New-Finding `
                -Id 'WTASK-002' `
                -Severity 'High' `
                -Category $analyzerCategory `
                -Title "Task executing from user-writable path: $taskName" `
                -Description "Scheduled task '$fullPath' executes a binary from a user-writable location. An attacker could replace the binary to gain code execution." `
                -ArtifactPath $artifactPath `
                -Evidence @("Task: $fullPath", "Action: $actions", "RunAs: $userId", "Author: $author") `
                -Recommendation 'Move task binaries to a protected location (Program Files or System32). Update the task action accordingly.' `
                -MITRE $mitrePersistence `
                -CVSSv3Score '7.8' `
                -TechnicalImpact 'Scheduled tasks referencing user-writable paths allow binary replacement attacks for privilege escalation and persistence.'
            ))
        }

        # ----------------------------------------------------------------
        # WTASK-004: Hidden task in unusual Microsoft paths
        # ----------------------------------------------------------------
        if ($taskPath -match '(?i)^\\Microsoft\\Windows\\' -and
            $taskPath -notmatch '(?i)\\(Defrag|Maintenance|Servicing|UpdateOrchestrator|WindowsUpdate|Application Experience|Autochk|Customer Experience|DiskDiagnostic|Multimedia|Power Efficiency|RAC|Registry|Shell|SystemRestore|Time Synchronization|Windows Error Reporting|Windows Filtering Platform|Wininet|Workplace Join)\\') {
            # This task is in the Microsoft\Windows tree but not in a common sub-path
            if ($author -notmatch '(?i)Microsoft' -and -not [string]::IsNullOrWhiteSpace($author)) {
                $findings.Add((New-Finding `
                    -Id 'WTASK-004' `
                    -Severity 'Medium' `
                    -Category $analyzerCategory `
                    -Title "Potentially hidden task in system path: $taskName" `
                    -Description "Scheduled task '$fullPath' is located in the Microsoft\Windows task path but appears to be created by a non-Microsoft author ('$author'). Attackers hide tasks in system paths to avoid detection." `
                    -ArtifactPath $artifactPath `
                    -Evidence @("Task: $fullPath", "Author: $author", "Action: $actions", "RunAs: $userId") `
                    -Recommendation 'Verify this task is legitimate. Tasks hidden in Microsoft paths by non-Microsoft authors are suspicious.' `
                    -MITRE $mitrePersistence `
                    -CVSSv3Score '5.3' `
                    -TechnicalImpact 'Tasks hidden in system paths evade casual inspection and may persist through security reviews.'
                ))
            }
        }

        # ----------------------------------------------------------------
        # WTASK-005: Task with no author or description
        # ----------------------------------------------------------------
        if ([string]::IsNullOrWhiteSpace($author) -and [string]::IsNullOrWhiteSpace($description)) {
            # Skip common Windows built-in tasks that may lack author info
            if ($taskPath -notmatch '(?i)^\\Microsoft\\') {
                $findings.Add((New-Finding `
                    -Id 'WTASK-005' `
                    -Severity 'Medium' `
                    -Category $analyzerCategory `
                    -Title "Task with no author or description: $taskName" `
                    -Description "Scheduled task '$fullPath' has no author or description set. Post-exploitation tools often create tasks without filling in metadata." `
                    -ArtifactPath $artifactPath `
                    -Evidence @("Task: $fullPath", "Author: (empty)", "Description: (empty)", "Action: $actions", "RunAs: $userId") `
                    -Recommendation 'Investigate this task. Legitimate software typically sets author and description metadata on scheduled tasks.' `
                    -MITRE $mitrePersistence `
                    -CVSSv3Score '5.3' `
                    -TechnicalImpact 'Tasks without metadata may indicate automated creation by post-exploitation tools or malware persistence mechanisms.'
                ))
            }
        }

        # ----------------------------------------------------------------
        # WTASK-006: Task running as high privilege but created by non-admin
        # ----------------------------------------------------------------
        if ($isSystem -and -not [string]::IsNullOrWhiteSpace($author)) {
            # Check if author looks like a regular user (not SYSTEM, not a known admin pattern)
            if ($author -notmatch '(?i)(SYSTEM|Administrator|BUILTIN|NT AUTHORITY|Microsoft|Domain Admins)' -and
                $author -notmatch '(?i)^S-1-5-(18|19|20)$') {
                $findings.Add((New-Finding `
                    -Id 'WTASK-006' `
                    -Severity 'Medium' `
                    -Category $analyzerCategory `
                    -Title "High-privilege task by non-admin author: $taskName" `
                    -Description "Scheduled task '$fullPath' runs as SYSTEM but was authored by '$author', which does not appear to be an administrative account. This may indicate privilege escalation." `
                    -ArtifactPath $artifactPath `
                    -Evidence @("Task: $fullPath", "RunAs: SYSTEM", "Author: $author", "Action: $actions") `
                    -Recommendation 'Investigate how this task was created with SYSTEM privileges by a non-admin author. This may indicate exploitation of a privilege escalation vulnerability.' `
                    -MITRE 'T1053.005' `
                    -CVSSv3Score '6.5' `
                    -TechnicalImpact 'SYSTEM-level tasks created by non-admin users indicate potential privilege escalation, allowing unprivileged users to execute commands as SYSTEM.'
                ))
            }
        }
    }

    # ----------------------------------------------------------------
    # WTASK-007 (Informational): Scheduled task summary
    # ----------------------------------------------------------------
    $summaryEvidence = @(
        "Total scheduled tasks: $totalTasks"
        "Tasks running as SYSTEM: $systemTasks"
        "Suspicious tasks detected: $suspiciousCount"
        "Security findings generated: $($findings.Count)"
    )

    $findings.Add((New-Finding `
        -Id 'WTASK-007' `
        -Severity 'Informational' `
        -Category $analyzerCategory `
        -Title 'Scheduled task analysis summary' `
        -Description 'Summary of Windows scheduled tasks examined during security analysis.' `
        -ArtifactPath $artifactPath `
        -Evidence $summaryEvidence `
        -MITRE $mitrePersistence `
        -CVSSv3Score '' `
        -TechnicalImpact ''
    ))

    return $findings.ToArray()
}
