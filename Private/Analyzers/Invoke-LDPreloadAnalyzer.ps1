function Invoke-LDPreloadAnalyzer {
    <#
    .SYNOPSIS
        Analyzes LD_PRELOAD and library loading configuration for injection indicators.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory)][string]$EvidencePath,
        [Parameter(Mandatory)][hashtable]$Rules
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    $standardLibPaths = @('/lib', '/lib64', '/usr/lib', '/usr/lib64', '/usr/local/lib', '/usr/local/lib64',
        '/usr/lib/x86_64-linux-gnu', '/usr/lib/aarch64-linux-gnu', '/usr/lib/i386-linux-gnu',
        '/lib/x86_64-linux-gnu', '/lib/i386-linux-gnu')
    $suspiciousDirs = @('/tmp', '/dev/shm', '/var/tmp', '/home', '/root', '/opt')

    # Check /etc/ld.so.preload (should normally be empty or nonexistent)
    $preloadPath = Resolve-ArtifactPath -EvidencePath $EvidencePath -LinuxPath '/etc/ld.so.preload'
    if (Test-Path $preloadPath) {
        $preloadLines = Read-ArtifactContent -Path $preloadPath
        $activeEntries = $preloadLines | Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and -not $_.TrimStart().StartsWith('#') }

        if ($activeEntries.Count -gt 0) {
            $findings.Add((New-Finding -Id "LDPRE-001" -Severity "Critical" -Category "Library Injection" `
                -Title "ld.so.preload contains entries - possible rootkit/backdoor" `
                -Description "/etc/ld.so.preload forces shared libraries to be loaded before all others for every program on the system. This file should normally be empty. Active entries are a strong indicator of a userland rootkit or LD_PRELOAD-based backdoor (e.g., Jynx, Azazel, BEURK)." `
                -ArtifactPath "/etc/ld.so.preload" `
                -Evidence @($activeEntries) `
                -Recommendation "Investigate each library listed. Compare library hashes to known-good versions. This is a critical finding requiring immediate response." `
                -MITRE "T1574.006"))
        }
    }

    # Check /etc/environment for LD_PRELOAD
    $envPath = Resolve-ArtifactPath -EvidencePath $EvidencePath -LinuxPath '/etc/environment'
    if (Test-Path $envPath) {
        $envLines = Read-ArtifactContent -Path $envPath
        $ldPreloadLines = $envLines | Where-Object { $_ -match '^\s*LD_PRELOAD\s*=' }
        if ($ldPreloadLines) {
            $findings.Add((New-Finding -Id "LDPRE-002" -Severity "Critical" -Category "Library Injection" `
                -Title "LD_PRELOAD set in /etc/environment" `
                -Description "LD_PRELOAD is configured in /etc/environment, affecting all user sessions system-wide." `
                -ArtifactPath "/etc/environment" `
                -Evidence @($ldPreloadLines) `
                -Recommendation "Remove LD_PRELOAD from /etc/environment and analyze the referenced library" `
                -MITRE "T1574.006"))
        }
    }

    # Check profile files for LD_PRELOAD
    $profilePaths = @('/etc/profile', '/etc/bash.bashrc', '/etc/bashrc')
    $profileDFiles = Get-ArtifactFiles -EvidencePath $EvidencePath -LinuxPath '/etc/profile.d' -Filter '*.sh'

    foreach ($profPath in $profilePaths) {
        $resolved = Resolve-ArtifactPath -EvidencePath $EvidencePath -LinuxPath $profPath
        if (Test-Path $resolved) {
            $content = (Read-ArtifactContent -Path $resolved) -join "`n"
            if ($content -match 'LD_PRELOAD') {
                $matchLines = (Read-ArtifactContent -Path $resolved) | Where-Object { $_ -match 'LD_PRELOAD' }
                $findings.Add((New-Finding -Id "LDPRE-002" -Severity "High" -Category "Library Injection" `
                    -Title "LD_PRELOAD referenced in $profPath" `
                    -Description "LD_PRELOAD is referenced in a system profile file, which could inject a malicious library into all user sessions." `
                    -ArtifactPath $profPath `
                    -Evidence @($matchLines) `
                    -Recommendation "Review and remove LD_PRELOAD entries from profile files" `
                    -MITRE "T1574.006"))
            }
        }
    }

    foreach ($pdFile in $profileDFiles) {
        $content = (Read-ArtifactContent -Path $pdFile.FullName) -join "`n"
        if ($content -match 'LD_PRELOAD') {
            $matchLines = (Read-ArtifactContent -Path $pdFile.FullName) | Where-Object { $_ -match 'LD_PRELOAD' }
            $findings.Add((New-Finding -Id "LDPRE-002" -Severity "High" -Category "Library Injection" `
                -Title "LD_PRELOAD in /etc/profile.d/$($pdFile.Name)" `
                -Description "LD_PRELOAD is referenced in a profile.d script." `
                -ArtifactPath "/etc/profile.d/$($pdFile.Name)" `
                -Evidence @($matchLines) `
                -Recommendation "Review and remove LD_PRELOAD entries" `
                -MITRE "T1574.006"))
        }
    }

    # Analyze /etc/ld.so.conf and ld.so.conf.d/
    $ldConfPath = Resolve-ArtifactPath -EvidencePath $EvidencePath -LinuxPath '/etc/ld.so.conf'
    $allLibPaths = [System.Collections.Generic.List[PSCustomObject]]::new()

    if (Test-Path $ldConfPath) {
        $ldConfLines = Read-ArtifactContent -Path $ldConfPath
        foreach ($line in $ldConfLines) {
            $trimmed = $line.Trim()
            if ([string]::IsNullOrWhiteSpace($trimmed) -or $trimmed.StartsWith('#')) { continue }
            if ($trimmed -match '^include\s+') { continue }  # include directives
            $allLibPaths.Add([PSCustomObject]@{ Path = $trimmed; Source = '/etc/ld.so.conf' })
        }
    }

    $ldConfDFiles = Get-ArtifactFiles -EvidencePath $EvidencePath -LinuxPath '/etc/ld.so.conf.d' -Filter '*.conf'
    foreach ($confFile in $ldConfDFiles) {
        $lines = Read-ArtifactContent -Path $confFile.FullName
        foreach ($line in $lines) {
            $trimmed = $line.Trim()
            if ([string]::IsNullOrWhiteSpace($trimmed) -or $trimmed.StartsWith('#')) { continue }
            $allLibPaths.Add([PSCustomObject]@{ Path = $trimmed; Source = "/etc/ld.so.conf.d/$($confFile.Name)" })
        }
    }

    # Check for suspicious library paths
    foreach ($libEntry in $allLibPaths) {
        $libPath = $libEntry.Path
        $isSuspicious = $false

        foreach ($dir in $suspiciousDirs) {
            if ($libPath.StartsWith($dir)) {
                $isSuspicious = $true
                $findings.Add((New-Finding -Id "LDPRE-003" -Severity "High" -Category "Library Injection" `
                    -Title "Suspicious library path: $libPath" `
                    -Description "Library search path '$libPath' from $($libEntry.Source) points to a suspicious location. Attackers can place malicious libraries here." `
                    -ArtifactPath $libEntry.Source `
                    -Evidence @("$libPath (from $($libEntry.Source))") `
                    -Recommendation "Remove this library path and investigate any libraries in it" `
                    -MITRE "T1574.006"))
                break
            }
        }

        # Check for hidden directories in path
        if (-not $isSuspicious -and $libPath -match '/\.') {
            $findings.Add((New-Finding -Id "LDPRE-003" -Severity "High" -Category "Library Injection" `
                -Title "Hidden directory in library path: $libPath" `
                -Description "A library search path contains a hidden directory component, which is unusual and suspicious." `
                -ArtifactPath $libEntry.Source `
                -Evidence @("$libPath (from $($libEntry.Source))") `
                -Recommendation "Investigate this library path" `
                -MITRE "T1574.006"))
        }

        # Check for non-standard paths
        $isStandard = $false
        foreach ($stdPath in $standardLibPaths) {
            if ($libPath -eq $stdPath -or $libPath.StartsWith("$stdPath/")) {
                $isStandard = $true
                break
            }
        }
        if (-not $isStandard -and -not $isSuspicious) {
            $findings.Add((New-Finding -Id "LDPRE-004" -Severity "Low" -Category "Library Injection" `
                -Title "Non-standard library path: $libPath" `
                -Description "Library path '$libPath' is not a standard system library directory." `
                -ArtifactPath $libEntry.Source `
                -Evidence @("$libPath (from $($libEntry.Source))") `
                -Recommendation "Verify this library path is legitimate and expected" `
                -MITRE "T1574.006"))
        }
    }

    # Summary
    if ($allLibPaths.Count -gt 0) {
        $findings.Add((New-Finding -Id "LDPRE-INFO" -Severity "Informational" -Category "Library Injection" `
            -Title "Library loading configuration summary" `
            -Description "Found $($allLibPaths.Count) library search paths configured." `
            -ArtifactPath "/etc/ld.so.conf" `
            -Evidence @($allLibPaths | ForEach-Object { $_.Path }) `
            -Recommendation "Review all library paths against system baseline"))
    }

    return $findings.ToArray()
}
