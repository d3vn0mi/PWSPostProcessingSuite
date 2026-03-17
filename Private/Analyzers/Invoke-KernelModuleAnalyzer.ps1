function Invoke-KernelModuleAnalyzer {
    <#
    .SYNOPSIS
        Analyzes kernel module configuration and loaded modules for suspicious entries.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory)][string]$EvidencePath,
        [Parameter(Mandatory)][hashtable]$Rules
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Known suspicious/rootkit module names
    $suspiciousModules = @(
        'diamorphine', 'reptile', 'suterusu', 'adore-ng', 'knark', 'rial',
        'heroin', 'mood-nt', 'phalanx', 'suckit', 'override', 'bdvl',
        'jynx', 'jynx2', 'azazel', 'brootus', 'vlany', 'beurk'
    )

    # Analyze lsmod output (if collected)
    $lsmodPaths = @('/proc/modules')
    # Also check for common collection filenames
    $lsmodFiles = Get-ArtifactFiles -EvidencePath $EvidencePath -LinuxPath '/' -Filter 'lsmod*'
    foreach ($f in $lsmodFiles) { $lsmodPaths += $f.FullName }

    $loadedModules = [System.Collections.Generic.List[string]]::new()

    foreach ($modPath in $lsmodPaths) {
        $resolved = if ($modPath.StartsWith('/')) { Resolve-ArtifactPath -EvidencePath $EvidencePath -LinuxPath $modPath } else { $modPath }
        if (-not (Test-Path $resolved)) { continue }

        $lines = Read-ArtifactContent -Path $resolved
        foreach ($line in $lines) {
            $trimmed = $line.Trim()
            if ([string]::IsNullOrWhiteSpace($trimmed) -or $trimmed.StartsWith('Module')) { continue }

            $modName = ($trimmed -split '\s+')[0]
            if (-not [string]::IsNullOrWhiteSpace($modName)) {
                $loadedModules.Add($modName)
            }
        }
    }

    # Check for suspicious module names
    foreach ($mod in $loadedModules) {
        if ($mod.ToLower() -in $suspiciousModules) {
            $findings.Add((New-Finding -Id "KMOD-001" -Severity "Critical" -Category "Kernel Modules" `
                -Title "Known rootkit kernel module loaded: $mod" `
                -Description "The kernel module '$mod' is associated with known Linux rootkits. This is a strong indicator of compromise." `
                -ArtifactPath "/proc/modules" `
                -Evidence @("Loaded module: $mod") `
                -Recommendation "This system is likely compromised. Perform full forensic analysis and consider reimaging." `
                -MITRE "T1547.006" `
                -CVSSv3Score '9.8' `
                -TechnicalImpact "Active kernel rootkit provides complete system compromise with root-level access, process hiding, and ability to intercept all system operations"))
        }
    }

    # Check /etc/modules
    $modulesPath = Resolve-ArtifactPath -EvidencePath $EvidencePath -LinuxPath '/etc/modules'
    if (Test-Path $modulesPath) {
        $moduleLines = Read-ArtifactContent -Path $modulesPath
        foreach ($line in $moduleLines) {
            $trimmed = $line.Trim()
            if ([string]::IsNullOrWhiteSpace($trimmed) -or $trimmed.StartsWith('#')) { continue }

            if ($trimmed.ToLower() -in $suspiciousModules) {
                $findings.Add((New-Finding -Id "KMOD-002" -Severity "Critical" -Category "Kernel Modules" `
                    -Title "Rootkit module configured for auto-load: $trimmed" `
                    -Description "A known rootkit module is configured to load automatically on boot via /etc/modules." `
                    -ArtifactPath "/etc/modules" `
                    -Evidence @("Module: $trimmed") `
                    -Recommendation "Remove the module entry and investigate the system thoroughly" `
                    -MITRE "T1547.006" `
                    -CVSSv3Score '9.8' `
                    -TechnicalImpact "Kernel rootkit persists across reboots via auto-load, maintaining complete system compromise with root-level access and stealth capabilities"))
            }
        }
    }

    # Check modprobe.d for suspicious entries
    $modprobeFiles = Get-ArtifactFiles -EvidencePath $EvidencePath -LinuxPath '/etc/modprobe.d' -Filter '*.conf'
    foreach ($mpFile in $modprobeFiles) {
        $lines = Read-ArtifactContent -Path $mpFile.FullName
        foreach ($line in $lines) {
            $trimmed = $line.Trim()
            if ([string]::IsNullOrWhiteSpace($trimmed) -or $trimmed.StartsWith('#')) { continue }

            # Check for install directives that run commands
            if ($trimmed -match '^install\s+\S+\s+(/bin/|/usr/bin/|/tmp/)') {
                $findings.Add((New-Finding -Id "KMOD-003" -Severity "High" -Category "Kernel Modules" `
                    -Title "Modprobe install directive executes command: $($mpFile.Name)" `
                    -Description "A modprobe configuration uses 'install' to execute a command when a module is loaded. This can be used for persistence." `
                    -ArtifactPath "/etc/modprobe.d/$($mpFile.Name)" `
                    -Evidence @($trimmed) `
                    -Recommendation "Review the install command for legitimacy" `
                    -MITRE "T1547.006" `
                    -CVSSv3Score '7.8' `
                    -TechnicalImpact "Allows arbitrary command execution with root privileges when a kernel module is loaded, enabling persistent backdoor access"))
            }
        }
    }

    # Summary
    if ($loadedModules.Count -gt 0) {
        $findings.Add((New-Finding -Id "KMOD-INFO" -Severity "Informational" -Category "Kernel Modules" `
            -Title "Kernel module summary" `
            -Description "Found $($loadedModules.Count) loaded kernel modules." `
            -ArtifactPath "/proc/modules" `
            -Evidence @("Total loaded modules: $($loadedModules.Count)") `
            -Recommendation "Review loaded modules against system baseline" `
            -CVSSv3Score '' `
            -TechnicalImpact ''))
    }

    return $findings.ToArray()
}
