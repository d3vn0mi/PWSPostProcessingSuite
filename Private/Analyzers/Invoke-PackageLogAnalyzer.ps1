function Invoke-PackageLogAnalyzer {
    <#
    .SYNOPSIS
        Analyzes package management logs for suspicious installations and removals.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory)][string]$EvidencePath,
        [Parameter(Mandatory)][hashtable]$Rules
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Collect package logs from multiple distro formats
    $logSources = @(
        @{ Path = '/var/log/apt/history.log'; Type = 'apt' }
        @{ Path = '/var/log/apt/history.log.1'; Type = 'apt' }
        @{ Path = '/var/log/dpkg.log'; Type = 'dpkg' }
        @{ Path = '/var/log/dpkg.log.1'; Type = 'dpkg' }
        @{ Path = '/var/log/yum.log'; Type = 'yum' }
        @{ Path = '/var/log/dnf.log'; Type = 'dnf' }
        @{ Path = '/var/log/dnf.rpm.log'; Type = 'dnf' }
    )

    $installations = [System.Collections.Generic.List[PSCustomObject]]::new()
    $removals = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Get suspicious package lists from rules
    $reconTools = @('nmap', 'masscan', 'zmap', 'nikto', 'gobuster', 'ffuf', 'sqlmap', 'dirb', 'wfuzz', 'enum4linux')
    $postExploit = @('netcat', 'ncat', 'socat', 'chisel', 'proxychains', 'pwncat', 'ncat')
    $securityRemovals = @('auditd', 'rsyslog', 'syslog-ng', 'apparmor', 'selinux', 'fail2ban', 'clamav', 'rkhunter', 'chkrootkit', 'aide')

    if ($Rules.ContainsKey('suspicious_packages')) {
        $sp = $Rules['suspicious_packages']
        if ($sp -is [hashtable]) {
            if ($sp.ContainsKey('recon_tools')) { $reconTools = @($sp['recon_tools']) }
            if ($sp.ContainsKey('post_exploitation')) { $postExploit = @($sp['post_exploitation']) }
            if ($sp.ContainsKey('security_removals')) { $securityRemovals = @($sp['security_removals']) }
        }
    }

    foreach ($source in $logSources) {
        $resolved = Resolve-ArtifactPath -EvidencePath $EvidencePath -LinuxPath $source.Path
        if (-not (Test-Path $resolved)) { continue }

        $lines = Read-ArtifactContent -Path $resolved

        switch ($source.Type) {
            'apt' {
                # APT history format: Start-Date, Commandline, Install/Remove/Upgrade lines
                $currentDate = $null
                foreach ($line in $lines) {
                    if ($line -match '^Start-Date:\s*(.+)') {
                        try { $currentDate = [datetime]::Parse($Matches[1].Trim()) } catch { $currentDate = $null }
                    }
                    elseif ($line -match '^Install:\s*(.+)') {
                        $pkgs = $Matches[1] -split ',\s*' | ForEach-Object { ($_ -split ':')[0].Trim().Split('(')[0].Trim() }
                        foreach ($pkg in $pkgs) {
                            $installations.Add([PSCustomObject]@{ Package = $pkg; Action = 'Install'; Timestamp = $currentDate; Source = $source.Path })
                        }
                    }
                    elseif ($line -match '^Remove:\s*(.+)') {
                        $pkgs = $Matches[1] -split ',\s*' | ForEach-Object { ($_ -split ':')[0].Trim().Split('(')[0].Trim() }
                        foreach ($pkg in $pkgs) {
                            $removals.Add([PSCustomObject]@{ Package = $pkg; Action = 'Remove'; Timestamp = $currentDate; Source = $source.Path })
                        }
                    }
                }
            }
            'dpkg' {
                foreach ($line in $lines) {
                    if ($line -match '^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+install\s+(\S+)') {
                        $ts = try { [datetime]::Parse($Matches[1]) } catch { $null }
                        $installations.Add([PSCustomObject]@{ Package = $Matches[2]; Action = 'Install'; Timestamp = $ts; Source = $source.Path })
                    }
                    elseif ($line -match '^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+remove\s+(\S+)') {
                        $ts = try { [datetime]::Parse($Matches[1]) } catch { $null }
                        $removals.Add([PSCustomObject]@{ Package = $Matches[2]; Action = 'Remove'; Timestamp = $ts; Source = $source.Path })
                    }
                }
            }
            'yum' {
                foreach ($line in $lines) {
                    if ($line -match '(Installed|Updated):\s*(.+)') {
                        $installations.Add([PSCustomObject]@{ Package = $Matches[2].Trim(); Action = $Matches[1]; Timestamp = $null; Source = $source.Path })
                    }
                    elseif ($line -match 'Erased:\s*(.+)') {
                        $removals.Add([PSCustomObject]@{ Package = $Matches[1].Trim(); Action = 'Remove'; Timestamp = $null; Source = $source.Path })
                    }
                }
            }
            'dnf' {
                foreach ($line in $lines) {
                    if ($line -match '(Installed|Upgraded):\s*(\S+)') {
                        $installations.Add([PSCustomObject]@{ Package = $Matches[2]; Action = $Matches[1]; Timestamp = $null; Source = $source.Path })
                    }
                    elseif ($line -match '(Removed|Erased):\s*(\S+)') {
                        $removals.Add([PSCustomObject]@{ Package = $Matches[2]; Action = 'Remove'; Timestamp = $null; Source = $source.Path })
                    }
                }
            }
        }
    }

    # Check for suspicious package installations
    $suspiciousInstalls = @()
    foreach ($install in $installations) {
        $pkgName = $install.Package.ToLower()
        if ($reconTools | Where-Object { $pkgName -match $_ }) {
            $suspiciousInstalls += $install
        }
        elseif ($postExploit | Where-Object { $pkgName -match $_ }) {
            $suspiciousInstalls += $install
        }
    }

    if ($suspiciousInstalls.Count -gt 0) {
        $findings.Add((New-Finding -Id "PKG-001" -Severity "Medium" -Category "Package Management" `
            -Title "Suspicious packages installed ($($suspiciousInstalls.Count))" `
            -Description "Packages commonly used for reconnaissance or post-exploitation were installed." `
            -ArtifactPath "/var/log/apt/" `
            -Evidence @($suspiciousInstalls | ForEach-Object { "$($_.Action): $($_.Package) $(if($_.Timestamp){"at $($_.Timestamp)"})" }) `
            -Recommendation "Investigate why these tools were installed and by whom" `
            -MITRE "T1588.002" `
            -CVSSv3Score "5.3" `
            -TechnicalImpact "Reconnaissance and post-exploitation tools indicate an attacker may be actively enumerating the network or establishing footholds."))
    }

    # Check for security tool removals
    $secRemovals = @()
    foreach ($removal in $removals) {
        $pkgName = $removal.Package.ToLower()
        if ($securityRemovals | Where-Object { $pkgName -match $_ }) {
            $secRemovals += $removal
        }
    }

    if ($secRemovals.Count -gt 0) {
        $findings.Add((New-Finding -Id "PKG-002" -Severity "High" -Category "Package Management" `
            -Title "Security packages removed ($($secRemovals.Count))" `
            -Description "Security-related packages were removed. This could indicate an attacker disabling defenses." `
            -ArtifactPath "/var/log/apt/" `
            -Evidence @($secRemovals | ForEach-Object { "Removed: $($_.Package) $(if($_.Timestamp){"at $($_.Timestamp)"})" }) `
            -Recommendation "Re-install removed security packages and investigate who removed them" `
            -MITRE "T1562.001" `
            -CVSSv3Score "7.5" `
            -TechnicalImpact "Removal of security tools disables defenses such as auditing, intrusion detection, and antivirus, allowing attacker activity to go undetected."))
    }

    # Summary
    if ($installations.Count -gt 0 -or $removals.Count -gt 0) {
        $findings.Add((New-Finding -Id "PKG-INFO" -Severity "Informational" -Category "Package Management" `
            -Title "Package management summary" `
            -Description "Found $($installations.Count) installations and $($removals.Count) removals in package logs." `
            -ArtifactPath "/var/log/" `
            -Evidence @("Installations: $($installations.Count)", "Removals: $($removals.Count)") `
            -Recommendation "Review package change history for unauthorized modifications" `
            -CVSSv3Score '' `
            -TechnicalImpact ''))
    }

    return $findings.ToArray()
}
