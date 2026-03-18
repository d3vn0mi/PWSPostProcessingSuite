function Invoke-SocketAnalyzer {
    <#
    .SYNOPSIS
        Analyzes Unix sockets, D-Bus policies, systemd socket units, and legacy r-commands.
    .DESCRIPTION
        Inspired by LinPEAS socket and D-Bus analysis sections. Examines systemd .socket
        files, Unix socket permissions, D-Bus policy configurations, and legacy remote
        command services for security issues.
    .PARAMETER EvidencePath
        Root folder path containing collected Linux artifacts.
    .PARAMETER Rules
        Hashtable of detection rules from the rules engine.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory)][string]$EvidencePath,
        [Parameter(Mandatory)][hashtable]$Rules
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $analyzerCategory = 'Socket Security'

    # ----------------------------------------------------------------
    # SOCK-001: World-writable Unix sockets
    # Look for socket listing output or known socket paths
    # ----------------------------------------------------------------
    $socketListFiles = @()
    foreach ($pattern in @('ss_*', 'netstat*', 'socket*', 'unix_sockets*', 'lsof*')) {
        $files = Get-ArtifactFiles -EvidencePath $EvidencePath -LinuxPath '/' -Filter $pattern
        foreach ($f in $files) { $socketListFiles += $f }
    }

    # Check for known sensitive socket paths
    $sensitiveSockets = @(
        @{ Path = '/var/run/docker.sock'; Desc = 'Docker daemon socket'; Severity = 'Critical'; Id = 'SOCK-002' }
        @{ Path = '/run/docker.sock'; Desc = 'Docker daemon socket'; Severity = 'Critical'; Id = 'SOCK-002' }
        @{ Path = '/var/run/containerd/containerd.sock'; Desc = 'Containerd socket'; Severity = 'High'; Id = 'SOCK-001' }
        @{ Path = '/run/containerd/containerd.sock'; Desc = 'Containerd socket'; Severity = 'High'; Id = 'SOCK-001' }
        @{ Path = '/var/run/snapd.socket'; Desc = 'Snapd socket'; Severity = 'Medium'; Id = 'SOCK-001' }
        @{ Path = '/run/snapd.socket'; Desc = 'Snapd socket'; Severity = 'Medium'; Id = 'SOCK-001' }
    )

    foreach ($sock in $sensitiveSockets) {
        $resolved = Resolve-ArtifactPath -EvidencePath $EvidencePath -LinuxPath $sock.Path
        if (Test-Path $resolved) {
            $findings.Add((New-Finding -Id $sock.Id -Severity $sock.Severity -Category $analyzerCategory `
                -Title "Sensitive socket found: $($sock.Desc)" `
                -Description "The $($sock.Desc) at $($sock.Path) exists and may be accessible. If accessible by non-root users, this can lead to privilege escalation." `
                -ArtifactPath $sock.Path `
                -Evidence @("Socket: $($sock.Path)", "Type: $($sock.Desc)") `
                -Recommendation "Restrict socket permissions to root only. For Docker socket, use rootless Docker or socket proxy with restricted API access." `
                -MITRE 'T1611' `
                -CVSSv3Score $(if ($sock.Severity -eq 'Critical') { '9.9' } elseif ($sock.Severity -eq 'High') { '8.1' } else { '5.3' }) `
                -TechnicalImpact "Accessible $($sock.Desc) allows privilege escalation, container escape, or unauthorized service control."))
        }
    }

    # Parse socket listing files for world-writable sockets
    foreach ($sockFile in $socketListFiles) {
        $lines = Read-ArtifactContent -Path $sockFile.FullName
        foreach ($line in $lines) {
            $trimmed = $line.Trim()
            # Look for Unix socket lines with world-writable permission indicators
            if ($trimmed -match 'STREAM|DGRAM|SEQPACKET' -and $trimmed -match '/') {
                # Extract socket path from the line
                $socketPath = ''
                if ($trimmed -match '(/[^\s]+\.sock\S*)') {
                    $socketPath = $Matches[1]
                }
                elseif ($trimmed -match '(/var/run/[^\s]+)') {
                    $socketPath = $Matches[1]
                }
                elseif ($trimmed -match '(/run/[^\s]+)') {
                    $socketPath = $Matches[1]
                }

                if ($socketPath -and $socketPath -match 'docker\.sock|containerd\.sock') {
                    # Already handled above
                    continue
                }
            }
        }
    }

    # ----------------------------------------------------------------
    # SOCK-003: Systemd .socket files with weak configurations
    # ----------------------------------------------------------------
    $socketUnitPaths = @(
        '/etc/systemd/system'
        '/usr/lib/systemd/system'
        '/lib/systemd/system'
        '/run/systemd/system'
    )

    $allSocketUnits = [System.Collections.Generic.List[System.IO.FileInfo]]::new()
    foreach ($unitPath in $socketUnitPaths) {
        $files = Get-ArtifactFiles -EvidencePath $EvidencePath -LinuxPath $unitPath -Filter '*.socket' -Recurse
        foreach ($f in $files) { $allSocketUnits.Add($f) }
    }

    foreach ($socketUnit in $allSocketUnits) {
        $lines = Read-ArtifactContent -Path $socketUnit.FullName
        $content = $lines -join "`n"
        $fileName = $socketUnit.Name

        # Check for SocketMode allowing broad access
        if ($content -match 'SocketMode\s*=\s*(0?666|0?777)') {
            $findings.Add((New-Finding -Id 'SOCK-003' -Severity 'High' -Category $analyzerCategory `
                -Title "Systemd socket with world-accessible mode: $fileName" `
                -Description "Systemd socket unit '$fileName' has SocketMode set to a world-accessible permission, allowing any user to connect." `
                -ArtifactPath $socketUnit.FullName `
                -Evidence @("File: $fileName", ($lines | Where-Object { $_ -match 'SocketMode' })) `
                -Recommendation "Restrict SocketMode to 0600 or 0660 and use SocketGroup for access control." `
                -MITRE 'T1559' `
                -CVSSv3Score '7.8' `
                -TechnicalImpact "World-accessible socket mode allows any local user to connect to the service, potentially enabling privilege escalation or unauthorized service manipulation."))
        }

        # Check for ExecStartPost/Pre with suspicious commands
        if ($content -match 'Exec(Start|Stop)(Pre|Post)?\s*=.*(/tmp/|/dev/shm/|curl|wget|base64)') {
            $execLines = $lines | Where-Object { $_ -match 'Exec(Start|Stop)' }
            $findings.Add((New-Finding -Id 'SOCK-003' -Severity 'High' -Category $analyzerCategory `
                -Title "Systemd socket with suspicious execution: $fileName" `
                -Description "Systemd socket unit '$fileName' contains suspicious execution commands in its configuration." `
                -ArtifactPath $socketUnit.FullName `
                -Evidence @("File: $fileName") + @($execLines | ForEach-Object { $_.Trim() }) `
                -Recommendation "Investigate the commands executed by this socket unit for potential malicious activity." `
                -MITRE 'T1543.002' `
                -CVSSv3Score '8.1' `
                -TechnicalImpact "Socket-activated services with suspicious commands may indicate persistence or privilege escalation via socket activation."))
        }

        # Check if socket service runs as root without restrictions
        if ($content -match 'ListenStream\s*=' -and $content -notmatch 'SocketUser\s*=' -and $content -notmatch 'SocketGroup\s*=') {
            # Only flag if it has Accept=yes (inetd-style) which processes connections inline
            if ($content -match 'Accept\s*=\s*yes') {
                $findings.Add((New-Finding -Id 'SOCK-003' -Severity 'Medium' -Category $analyzerCategory `
                    -Title "Systemd socket with Accept=yes and no user restriction: $fileName" `
                    -Description "Systemd socket '$fileName' uses Accept=yes (inetd-style) without SocketUser/SocketGroup restrictions." `
                    -ArtifactPath $socketUnit.FullName `
                    -Evidence @("File: $fileName", "Accept=yes without SocketUser/SocketGroup") `
                    -Recommendation "Set SocketUser and SocketGroup to restrict who can connect to this socket." `
                    -MITRE 'T1559' `
                    -CVSSv3Score '5.3' `
                    -TechnicalImpact "Unrestricted socket access may allow any local user to trigger service activation, potentially leading to resource abuse or privilege escalation."))
            }
        }
    }

    # ----------------------------------------------------------------
    # SOCK-004: D-Bus policy files with weak allow rules
    # ----------------------------------------------------------------
    $dbusPaths = @(
        '/etc/dbus-1/system.d'
        '/etc/dbus-1/session.d'
        '/usr/share/dbus-1/system.d'
        '/usr/share/dbus-1/system-services'
    )

    foreach ($dbusPath in $dbusPaths) {
        $dbusFiles = Get-ArtifactFiles -EvidencePath $EvidencePath -LinuxPath $dbusPath -Filter '*.conf' -Recurse
        foreach ($dbusFile in $dbusFiles) {
            $content = (Read-ArtifactContent -Path $dbusFile.FullName) -join "`n"
            $fileName = $dbusFile.Name

            # Check for overly permissive policies allowing any user
            if ($content -match '<allow\s+[^>]*send_destination\s*=\s*"[^"]*"[^>]*/>' -and
                $content -match 'user\s*=\s*"\*"') {
                $findings.Add((New-Finding -Id 'SOCK-004' -Severity 'Medium' -Category $analyzerCategory `
                    -Title "D-Bus policy allows all users: $fileName" `
                    -Description "D-Bus policy file '$fileName' contains rules allowing any user to send messages to a service." `
                    -ArtifactPath $dbusFile.FullName `
                    -Evidence @("File: $dbusPath/$fileName", "Policy contains user='*' with send permissions") `
                    -Recommendation "Restrict D-Bus policies to specific users or groups. Apply principle of least privilege." `
                    -MITRE 'T1559.001' `
                    -CVSSv3Score '5.3' `
                    -TechnicalImpact "Overly permissive D-Bus policies allow any local user to interact with privileged system services via IPC."))
            }

            # Check for policies granting own/send to root-owned services from unprivileged users
            if ($content -match '<allow\s+[^>]*own\s*=\s*"[^"]*"' -and $content -notmatch 'user\s*=\s*"root"') {
                if ($content -match '<policy\s+context\s*=\s*"default"') {
                    $findings.Add((New-Finding -Id 'SOCK-004' -Severity 'Medium' -Category $analyzerCategory `
                        -Title "D-Bus default policy grants bus name ownership: $fileName" `
                        -Description "D-Bus policy '$fileName' allows ownership of a bus name in the default context, potentially enabling service impersonation." `
                        -ArtifactPath $dbusFile.FullName `
                        -Evidence @("File: $dbusPath/$fileName", "Default policy grants bus name ownership") `
                        -Recommendation "Restrict bus name ownership to specific service users only." `
                        -MITRE 'T1559.001' `
                        -CVSSv3Score '6.5' `
                        -TechnicalImpact "Unrestricted D-Bus name ownership allows service impersonation, potentially enabling privilege escalation through D-Bus method calls."))
                }
            }
        }
    }

    # ----------------------------------------------------------------
    # SOCK-005: Legacy r-commands enabled (rsh, rlogin, rexec)
    # ----------------------------------------------------------------
    $rCommandFiles = @(
        @{ Path = '/etc/hosts.equiv'; Desc = 'Global r-command trust file' }
        @{ Path = '/etc/xinetd.d/rsh'; Desc = 'rsh xinetd configuration' }
        @{ Path = '/etc/xinetd.d/rlogin'; Desc = 'rlogin xinetd configuration' }
        @{ Path = '/etc/xinetd.d/rexec'; Desc = 'rexec xinetd configuration' }
    )

    foreach ($rcmd in $rCommandFiles) {
        $resolved = Resolve-ArtifactPath -EvidencePath $EvidencePath -LinuxPath $rcmd.Path
        if (Test-Path $resolved -PathType Leaf) {
            $content = (Read-ArtifactContent -Path $resolved) -join "`n"

            # For xinetd configs, check if disabled
            if ($rcmd.Path -match 'xinetd') {
                if ($content -match 'disable\s*=\s*no') {
                    $findings.Add((New-Finding -Id 'SOCK-005' -Severity 'High' -Category $analyzerCategory `
                        -Title "Legacy r-command enabled: $($rcmd.Desc)" `
                        -Description "Legacy remote command service is enabled at $($rcmd.Path). R-commands transmit data including credentials in cleartext." `
                        -ArtifactPath $resolved `
                        -Evidence @("File: $($rcmd.Path)", "Service is NOT disabled (disable = no)") `
                        -Recommendation "Disable all r-commands (rsh, rlogin, rexec). Use SSH instead." `
                        -MITRE 'T1021.004' `
                        -CVSSv3Score '8.1' `
                        -TechnicalImpact "Legacy r-commands transmit credentials in cleartext and use weak host-based trust, enabling credential interception and unauthorized remote access."))
                }
            }
            else {
                # hosts.equiv file exists - check for overly permissive entries
                $hasWildcard = $content -match '^\+\s*$' -or $content -match '^\+\s+'
                $severity = if ($hasWildcard) { 'Critical' } else { 'Medium' }

                $findings.Add((New-Finding -Id 'SOCK-005' -Severity $severity -Category $analyzerCategory `
                    -Title "R-command trust file found: $($rcmd.Path)" `
                    -Description "The hosts.equiv file configures host-based trust for r-commands. $(if ($hasWildcard) { 'Contains wildcard (+) entries trusting ALL hosts.' } else { 'Contains host trust entries.' })" `
                    -ArtifactPath $resolved `
                    -Evidence @("File: $($rcmd.Path)", $(if ($hasWildcard) { "WARNING: Wildcard (+) entry found - trusts all hosts" } else { "Host-based trust entries present" })) `
                    -Recommendation "Remove hosts.equiv file and disable all r-commands. Use SSH with key-based authentication instead." `
                    -MITRE 'T1078.003' `
                    -CVSSv3Score $(if ($hasWildcard) { '9.8' } else { '6.5' }) `
                    -TechnicalImpact "$(if ($hasWildcard) { 'Wildcard trust in hosts.equiv allows any host to authenticate without passwords, enabling trivial unauthorized access.' } else { 'Host-based trust may allow unauthorized access from trusted hosts without password authentication.' })"))
            }
        }
    }

    # Also check for .rhosts files in home directories
    if (Test-Path $homeDir -PathType Container) {
        $userDirs = Get-ChildItem -Path $homeDir -Directory -ErrorAction SilentlyContinue
        foreach ($userDir in $userDirs) {
            $rhostsPath = Join-Path $userDir.FullName '.rhosts'
            if (Test-Path $rhostsPath -PathType Leaf) {
                $content = (Read-ArtifactContent -Path $rhostsPath) -join "`n"
                $hasWildcard = $content -match '^\+\s*$' -or $content -match '^\+\s+'

                $findings.Add((New-Finding -Id 'SOCK-005' -Severity $(if ($hasWildcard) { 'Critical' } else { 'High' }) -Category $analyzerCategory `
                    -Title ".rhosts file found for user $($userDir.Name)" `
                    -Description "A .rhosts file was found in $($userDir.Name)'s home directory, enabling host-based trust for r-commands." `
                    -ArtifactPath $rhostsPath `
                    -Evidence @("File: /home/$($userDir.Name)/.rhosts", $(if ($hasWildcard) { "WARNING: Contains wildcard (+) entry" } else { "Contains host trust entries" })) `
                    -Recommendation "Remove .rhosts files. Disable r-commands entirely and use SSH." `
                    -MITRE 'T1078.003' `
                    -CVSSv3Score $(if ($hasWildcard) { '9.8' } else { '7.5' }) `
                    -TechnicalImpact "$(if ($hasWildcard) { 'Wildcard .rhosts allows any host to access this account without a password.' } else { '.rhosts trust may allow unauthorized access from specified hosts.' })"))
            }
        }
    }

    # Summary
    $findings.Add((New-Finding -Id 'SOCK-INFO' -Severity 'Informational' -Category $analyzerCategory `
        -Title "Socket and IPC analysis summary" `
        -Description "Analyzed systemd socket units, D-Bus policies, Unix sockets, and legacy r-command configurations." `
        -ArtifactPath $EvidencePath `
        -Evidence @("Systemd socket units found: $($allSocketUnits.Count)", "Socket-related findings: $($findings.Count)") `
        -CVSSv3Score '' `
        -TechnicalImpact ''))

    return $findings.ToArray()
}
