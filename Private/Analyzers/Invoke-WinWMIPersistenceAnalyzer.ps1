function Invoke-WinWMIPersistenceAnalyzer {
    <#
    .SYNOPSIS
        Analyzes WMI event subscriptions for persistence mechanisms.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory)][string]$EvidencePath,
        [Parameter(Mandatory)][hashtable]$Rules
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Load WMI evidence files
    $filtersPath = Join-Path $EvidencePath 'security/wmi_filters.txt'
    $consumersPath = Join-Path $EvidencePath 'security/wmi_consumers.txt'
    $bindingsPath = Join-Path $EvidencePath 'security/wmi_bindings.txt'

    # Parse WMI objects from text output (property = value format)
    function Parse-WmiObjects {
        param([string[]]$Lines)
        $objects = @()
        $current = @{}
        foreach ($line in $Lines) {
            $trimmed = $line.Trim()
            if ([string]::IsNullOrWhiteSpace($trimmed)) {
                if ($current.Count -gt 0) {
                    $objects += [PSCustomObject]$current
                    $current = @{}
                }
                continue
            }
            if ($trimmed -match '^(\w+)\s*[:=]\s*(.*)$') {
                $current[$Matches[1]] = $Matches[2].Trim()
            }
            elseif ($trimmed -match '^__') {
                # Class header line like __EventFilter
                if ($current.Count -gt 0) {
                    $objects += [PSCustomObject]$current
                    $current = @{}
                }
                $current['__Class'] = $trimmed
            }
        }
        if ($current.Count -gt 0) {
            $objects += [PSCustomObject]$current
        }
        return $objects
    }

    $filters = @()
    $consumers = @()
    $bindings = @()

    if (Test-Path $filtersPath) {
        $filterLines = Read-ArtifactContent -Path $filtersPath
        $filters = Parse-WmiObjects -Lines $filterLines
    }

    if (Test-Path $consumersPath) {
        $consumerLines = Read-ArtifactContent -Path $consumersPath
        $consumers = Parse-WmiObjects -Lines $consumerLines
    }

    if (Test-Path $bindingsPath) {
        $bindingLines = Read-ArtifactContent -Path $bindingsPath
        $bindings = Parse-WmiObjects -Lines $bindingLines
    }

    # Suspicious path patterns
    $suspiciousPaths = @('\\Temp\\', '\\tmp\\', '\\AppData\\', '\\Public\\', '\\ProgramData\\', '\\Downloads\\', '\\Recycle')

    # ----------------------------------------------------------------
    # WWMI-001: CommandLineEventConsumer (command execution persistence)
    # ----------------------------------------------------------------
    $cmdConsumers = @()
    foreach ($consumer in $consumers) {
        $className = ''
        if ($consumer.PSObject.Properties['__Class']) { $className = $consumer.__Class }
        if ($consumer.PSObject.Properties['__SUPERCLASS']) { $className = $consumer.__SUPERCLASS }

        $isCommandLine = $false
        if ($className -match 'CommandLineEventConsumer') {
            $isCommandLine = $true
        }
        # Also check for CommandLineTemplate property as indicator
        if ($consumer.PSObject.Properties['CommandLineTemplate']) {
            $isCommandLine = $true
        }
        if ($consumer.PSObject.Properties['ExecutablePath'] -and -not [string]::IsNullOrWhiteSpace($consumer.ExecutablePath)) {
            $isCommandLine = $true
        }

        if ($isCommandLine) {
            $name = if ($consumer.PSObject.Properties['Name']) { $consumer.Name } else { 'Unknown' }
            $cmdLine = ''
            if ($consumer.PSObject.Properties['CommandLineTemplate']) {
                $cmdLine = $consumer.CommandLineTemplate
            }
            elseif ($consumer.PSObject.Properties['ExecutablePath']) {
                $cmdLine = $consumer.ExecutablePath
            }
            $cmdConsumers += "Consumer: $name | Command: $cmdLine"
        }
    }

    if ($cmdConsumers.Count -gt 0) {
        $findings.Add((New-Finding -Id 'WWMI-001' -Severity 'Critical' -Category 'WMI Persistence' `
            -Title 'Active WMI event subscription with CommandLineEventConsumer' `
            -Description "Found $($cmdConsumers.Count) WMI CommandLineEventConsumer(s) configured to execute commands. This is a well-known persistence mechanism used by APTs and malware to survive reboots." `
            -ArtifactPath 'security/wmi_consumers.txt' `
            -Evidence @($cmdConsumers | Select-Object -First 10) `
            -Recommendation 'Investigate each CommandLineEventConsumer and its bound filter. Remove unauthorized subscriptions using: Get-WMIObject -Namespace root\Subscription -Class CommandLineEventConsumer | Remove-WmiObject' `
            -MITRE 'T1546.003' `
            -CVSSv3Score '9.1' `
            -TechnicalImpact 'WMI CommandLineEventConsumer provides fileless persistence, executing arbitrary commands when trigger conditions are met, surviving reboots without files on disk.'))
    }

    # ----------------------------------------------------------------
    # WWMI-002: ActiveScriptEventConsumer (script execution persistence)
    # ----------------------------------------------------------------
    $scriptConsumers = @()
    foreach ($consumer in $consumers) {
        $className = ''
        if ($consumer.PSObject.Properties['__Class']) { $className = $consumer.__Class }

        $isScript = $false
        if ($className -match 'ActiveScriptEventConsumer') {
            $isScript = $true
        }
        if ($consumer.PSObject.Properties['ScriptText']) {
            $isScript = $true
        }
        if ($consumer.PSObject.Properties['ScriptFileName']) {
            $isScript = $true
        }

        if ($isScript) {
            $name = if ($consumer.PSObject.Properties['Name']) { $consumer.Name } else { 'Unknown' }
            $scriptInfo = ''
            if ($consumer.PSObject.Properties['ScriptText']) {
                $scriptSnippet = $consumer.ScriptText
                if ($scriptSnippet.Length -gt 200) { $scriptSnippet = $scriptSnippet.Substring(0, 200) + '...' }
                $scriptInfo = "Inline script: $scriptSnippet"
            }
            elseif ($consumer.PSObject.Properties['ScriptFileName']) {
                $scriptInfo = "Script file: $($consumer.ScriptFileName)"
            }
            $engine = if ($consumer.PSObject.Properties['ScriptingEngine']) { $consumer.ScriptingEngine } else { 'Unknown' }
            $scriptConsumers += "Consumer: $name | Engine: $engine | $scriptInfo"
        }
    }

    if ($scriptConsumers.Count -gt 0) {
        $findings.Add((New-Finding -Id 'WWMI-002' -Severity 'Critical' -Category 'WMI Persistence' `
            -Title 'Active WMI event subscription with ActiveScriptEventConsumer' `
            -Description "Found $($scriptConsumers.Count) WMI ActiveScriptEventConsumer(s) configured to execute scripts. This enables execution of VBScript or JScript code triggered by WMI events, a powerful persistence and execution technique." `
            -ArtifactPath 'security/wmi_consumers.txt' `
            -Evidence @($scriptConsumers | Select-Object -First 10) `
            -Recommendation 'Investigate each ActiveScriptEventConsumer for malicious scripts. Remove unauthorized subscriptions and review bound filters. Consider disabling ActiveScriptEventConsumer via Group Policy.' `
            -MITRE 'T1546.003' `
            -CVSSv3Score '9.1' `
            -TechnicalImpact 'WMI ActiveScriptEventConsumer provides fileless script execution persistence, running VBScript/JScript in SYSTEM context when trigger events fire, enabling stealthy code execution.'))
    }

    # ----------------------------------------------------------------
    # WWMI-003: WMI filter targeting process creation or logon events
    # ----------------------------------------------------------------
    $suspiciousFilters = @()
    $c2FilterPatterns = @(
        'Win32_ProcessStartTrace',
        'Win32_LogonSession',
        '__InstanceCreationEvent',
        '__InstanceModificationEvent',
        'Win32_ProcessStart',
        'Win32_LoggedOnUser',
        'WITHIN\s+\d+',
        'TargetInstance\s+ISA'
    )

    foreach ($filter in $filters) {
        $query = ''
        if ($filter.PSObject.Properties['Query']) { $query = $filter.Query }
        if ($filter.PSObject.Properties['QueryLanguage']) { }  # Just noting it exists

        if ([string]::IsNullOrWhiteSpace($query)) { continue }

        foreach ($pattern in $c2FilterPatterns) {
            if ($query -match $pattern) {
                $name = if ($filter.PSObject.Properties['Name']) { $filter.Name } else { 'Unknown' }
                $suspiciousFilters += "Filter: $name | Query: $query"
                break
            }
        }
    }

    if ($suspiciousFilters.Count -gt 0) {
        $findings.Add((New-Finding -Id 'WWMI-003' -Severity 'High' -Category 'WMI Persistence' `
            -Title 'WMI filter targeting process creation or logon events' `
            -Description "Found $($suspiciousFilters.Count) WMI event filter(s) monitoring for process creation or user logon events. These are commonly used by C2 frameworks and APTs to trigger malicious actions upon specific system events." `
            -ArtifactPath 'security/wmi_filters.txt' `
            -Evidence @($suspiciousFilters | Select-Object -First 10) `
            -Recommendation 'Review each WMI filter query to determine if it serves a legitimate purpose. Malicious filters often monitor for process start or logon events with WITHIN polling intervals.' `
            -MITRE 'T1546.003' `
            -CVSSv3Score '8.1' `
            -TechnicalImpact 'WMI filters monitoring process/logon events enable triggered execution of malicious payloads, allowing attackers to maintain persistent C2 callbacks or escalate privileges upon user logon.'))
    }

    # ----------------------------------------------------------------
    # WWMI-004: WMI consumer executing from suspicious path
    # ----------------------------------------------------------------
    $suspiciousPathConsumers = @()

    foreach ($consumer in $consumers) {
        $execPath = ''
        if ($consumer.PSObject.Properties['CommandLineTemplate']) {
            $execPath = $consumer.CommandLineTemplate
        }
        if ($consumer.PSObject.Properties['ExecutablePath']) {
            $execPath = $consumer.ExecutablePath
        }
        if ($consumer.PSObject.Properties['ScriptFileName']) {
            $execPath += " $($consumer.ScriptFileName)"
        }
        if ($consumer.PSObject.Properties['ScriptText']) {
            $execPath += " $($consumer.ScriptText)"
        }

        if ([string]::IsNullOrWhiteSpace($execPath)) { continue }

        foreach ($susPath in $suspiciousPaths) {
            if ($execPath -match [regex]::Escape($susPath)) {
                $name = if ($consumer.PSObject.Properties['Name']) { $consumer.Name } else { 'Unknown' }
                $suspiciousPathConsumers += "Consumer: $name | Path: $execPath"
                break
            }
        }
    }

    if ($suspiciousPathConsumers.Count -gt 0) {
        $findings.Add((New-Finding -Id 'WWMI-004' -Severity 'High' -Category 'WMI Persistence' `
            -Title 'WMI consumer executing from suspicious path' `
            -Description "Found $($suspiciousPathConsumers.Count) WMI consumer(s) referencing executables or scripts in suspicious directories (Temp, AppData, Public). Legitimate WMI consumers typically reference binaries in System32 or Program Files." `
            -ArtifactPath 'security/wmi_consumers.txt' `
            -Evidence @($suspiciousPathConsumers | Select-Object -First 10) `
            -Recommendation 'Investigate the binaries/scripts referenced by these consumers. Legitimate management tools rarely execute from Temp or user-writable directories.' `
            -MITRE 'T1546.003' `
            -CVSSv3Score '8.1' `
            -TechnicalImpact 'WMI consumers executing from user-writable directories indicate likely malicious persistence, as attackers stage payloads in Temp/AppData to avoid detection and maintain access.'))
    }

    # ----------------------------------------------------------------
    # WWMI-005: WMI persistence summary (Informational)
    # ----------------------------------------------------------------
    $summaryItems = @()
    $summaryItems += "Event filters found: $($filters.Count)"
    $summaryItems += "Event consumers found: $($consumers.Count)"
    $summaryItems += "Filter-to-consumer bindings found: $($bindings.Count)"

    if (Test-Path $filtersPath) {
        $summaryItems += 'Source: security/wmi_filters.txt'
    }
    else {
        $summaryItems += 'WMI filters file NOT found'
    }
    if (Test-Path $consumersPath) {
        $summaryItems += 'Source: security/wmi_consumers.txt'
    }
    else {
        $summaryItems += 'WMI consumers file NOT found'
    }
    if (Test-Path $bindingsPath) {
        $summaryItems += 'Source: security/wmi_bindings.txt'
    }
    else {
        $summaryItems += 'WMI bindings file NOT found'
    }

    # List filter names
    foreach ($filter in $filters) {
        $name = if ($filter.PSObject.Properties['Name']) { $filter.Name } else { 'Unnamed' }
        $query = if ($filter.PSObject.Properties['Query']) { $filter.Query } else { 'N/A' }
        $summaryItems += "  Filter: $name -> $query"
    }

    # List consumer names
    foreach ($consumer in $consumers) {
        $name = if ($consumer.PSObject.Properties['Name']) { $consumer.Name } else { 'Unnamed' }
        $className = if ($consumer.PSObject.Properties['__Class']) { $consumer.__Class } else { 'Unknown' }
        $summaryItems += "  Consumer: $name ($className)"
    }

    # List bindings
    foreach ($binding in $bindings) {
        $bFilter = if ($binding.PSObject.Properties['Filter']) { $binding.Filter } else { 'Unknown' }
        $bConsumer = if ($binding.PSObject.Properties['Consumer']) { $binding.Consumer } else { 'Unknown' }
        $summaryItems += "  Binding: $bFilter -> $bConsumer"
    }

    $findings.Add((New-Finding -Id 'WWMI-005' -Severity 'Informational' -Category 'WMI Persistence' `
        -Title 'WMI persistence summary' `
        -Description 'Summary of WMI event subscription components (filters, consumers, and bindings) found in the collected evidence.' `
        -ArtifactPath 'security/wmi_filters.txt' `
        -Evidence @($summaryItems | Select-Object -First 25) `
        -Recommendation 'Review all WMI event subscriptions and remove any that are not associated with legitimate management tools or monitoring agents.' `
        -MITRE '' `
        -CVSSv3Score '' `
        -TechnicalImpact 'Informational overview of WMI event subscription persistence landscape.'))

    return $findings.ToArray()
}
