function Invoke-FilesystemAnalyzer {
    <#
    .SYNOPSIS
        Analyzes filesystem artifacts for SUID/SGID binaries, world-writable files, and suspicious files.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory)][string]$EvidencePath,
        [Parameter(Mandatory)][hashtable]$Rules
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Look for file listing outputs (find, ls -la, etc.)
    $fileListings = @()
    foreach ($pattern in @('find_suid*', 'suid*', 'find_sgid*', 'sgid*', 'find_writable*', 'world_writable*', 'file_listing*', 'ls_*')) {
        $files = Get-ArtifactFiles -EvidencePath $EvidencePath -LinuxPath '/' -Filter $pattern
        foreach ($f in $files) { $fileListings += $f }
    }

    # Expected SUID binaries (common legitimate ones)
    $expectedSuid = @(
        '/usr/bin/passwd', '/usr/bin/su', '/usr/bin/sudo', '/usr/bin/newgrp',
        '/usr/bin/gpasswd', '/usr/bin/chsh', '/usr/bin/chfn', '/usr/bin/mount',
        '/usr/bin/umount', '/usr/bin/pkexec', '/usr/bin/crontab', '/usr/bin/at',
        '/usr/bin/ssh-agent', '/usr/lib/openssh/ssh-keysign',
        '/usr/lib/dbus-1.0/dbus-daemon-launch-helper',
        '/usr/lib/policykit-1/polkit-agent-helper-1',
        '/bin/mount', '/bin/umount', '/bin/su', '/bin/ping', '/bin/ping6',
        '/usr/bin/traceroute6.iputils', '/usr/sbin/pppd'
    )

    foreach ($listing in $fileListings) {
        $lines = Read-ArtifactContent -Path $listing.FullName
        $fileName = $listing.Name

        foreach ($line in $lines) {
            $trimmed = $line.Trim()
            if ([string]::IsNullOrWhiteSpace($trimmed)) { continue }

            # Detect SUID files from find output (just paths)
            if ($fileName -match 'suid' -and $trimmed.StartsWith('/')) {
                if ($trimmed -notin $expectedSuid) {
                    # Check for especially suspicious locations
                    $severity = 'Medium'
                    if ($trimmed -match '/tmp/|/dev/shm/|/var/tmp/|/home/') {
                        $severity = 'Critical'
                    }
                    elseif ($trimmed -match '/opt/|/usr/local/') {
                        $severity = 'High'
                    }

                    $findings.Add((New-Finding -Id "FS-001" -Severity $severity -Category "Filesystem" `
                        -Title "Unusual SUID binary: $trimmed" `
                        -Description "A SUID binary was found that is not in the expected list of standard SUID files." `
                        -ArtifactPath $trimmed `
                        -Evidence @($line) `
                        -Recommendation "Investigate this SUID binary. Check if it was recently modified or is a known GTFOBin." `
                        -MITRE "T1548.001" `
                        -CVSSv3Score $(if ($severity -eq 'Critical') { '9.8' } elseif ($severity -eq 'High') { '7.8' } else { '6.7' }) `
                        -TechnicalImpact "Enables privilege escalation from any local user to root via SUID execution in $(if ($trimmed -match '/tmp/|/dev/shm/|/var/tmp/|/home/') { 'a world-writable or user-controlled directory' } else { 'a non-standard location' })"))
                }
            }

            # Detect world-writable files in sensitive locations
            if ($fileName -match 'writable') {
                if ($trimmed -match '^/(etc|usr|bin|sbin|lib|var/log)') {
                    $findings.Add((New-Finding -Id "FS-002" -Severity "High" -Category "Filesystem" `
                        -Title "World-writable file in sensitive location" `
                        -Description "A world-writable file was found in a sensitive system directory." `
                        -ArtifactPath $trimmed `
                        -Evidence @($line) `
                        -Recommendation "Remove world-writable permission from files in system directories" `
                        -MITRE "T1222.002" `
                        -CVSSv3Score '7.5' `
                        -TechnicalImpact "Allows any local user to modify sensitive system files, potentially enabling privilege escalation or system compromise"))
                }
            }
        }
    }

    # Check for suspicious files in /tmp, /dev/shm
    $tempDirs = @('/tmp', '/dev/shm', '/var/tmp')
    foreach ($tempDir in $tempDirs) {
        $resolved = Resolve-ArtifactPath -EvidencePath $EvidencePath -LinuxPath $tempDir
        if (-not (Test-Path $resolved -PathType Container)) { continue }

        $tempFiles = Get-ChildItem -Path $resolved -Recurse -File -ErrorAction SilentlyContinue

        # Hidden files in temp dirs
        $hiddenFiles = $tempFiles | Where-Object { $_.Name.StartsWith('.') -and $_.Name -ne '.gitkeep' }
        if ($hiddenFiles.Count -gt 0) {
            $findings.Add((New-Finding -Id "FS-003" -Severity "High" -Category "Filesystem" `
                -Title "Hidden files in $tempDir ($($hiddenFiles.Count))" `
                -Description "Hidden files were found in a temporary directory. Attackers commonly use hidden files in /tmp to stage tools." `
                -ArtifactPath $tempDir `
                -Evidence @($hiddenFiles | Select-Object -First 10 | ForEach-Object { "$($_.Name) ($($_.Length) bytes)" }) `
                -Recommendation "Investigate hidden files in temporary directories" `
                -MITRE "T1564.001" `
                -CVSSv3Score '7.1' `
                -TechnicalImpact "May allow attacker to stage tools and maintain persistent access using hidden files in world-writable directories"))
        }

        # Executable scripts/binaries in temp dirs
        $execFiles = $tempFiles | Where-Object { $_.Extension -in @('.sh', '.py', '.pl', '.rb', '.elf', '') -and $_.Length -gt 0 }
        if ($execFiles.Count -gt 0) {
            $findings.Add((New-Finding -Id "FS-004" -Severity "Medium" -Category "Filesystem" `
                -Title "Executable files in $tempDir ($($execFiles.Count))" `
                -Description "Potentially executable files were found in a temporary directory." `
                -ArtifactPath $tempDir `
                -Evidence @($execFiles | Select-Object -First 10 | ForEach-Object { "$($_.Name) ($($_.Length) bytes)" }) `
                -Recommendation "Review executable files in temporary directories for malicious content" `
                -MITRE "T1059" `
                -CVSSv3Score '5.3' `
                -TechnicalImpact "Indicates possible attacker tool staging or malware execution from temporary directories"))
        }
    }

    # Check for suspicious files in web root
    $webRoots = @('/var/www', '/srv/www', '/var/www/html')
    foreach ($webRoot in $webRoots) {
        $resolved = Resolve-ArtifactPath -EvidencePath $EvidencePath -LinuxPath $webRoot
        if (-not (Test-Path $resolved -PathType Container)) { continue }

        $webFiles = Get-ChildItem -Path $resolved -Recurse -File -ErrorAction SilentlyContinue

        # Webshells - PHP files with suspicious names
        $suspiciousWebFiles = $webFiles | Where-Object {
            $_.Name -match '(shell|cmd|c99|r57|b374k|wso|alfa|webshell|backdoor|hack|upload)' -and
            $_.Extension -in @('.php', '.php5', '.phtml', '.jsp', '.asp', '.aspx')
        }
        if ($suspiciousWebFiles.Count -gt 0) {
            $findings.Add((New-Finding -Id "FS-005" -Severity "Critical" -Category "Filesystem" `
                -Title "Potential webshell detected in $webRoot" `
                -Description "Files with names matching common webshell patterns were found in the web root." `
                -ArtifactPath $webRoot `
                -Evidence @($suspiciousWebFiles | ForEach-Object { "$($_.FullName.Replace($EvidencePath,'')) ($($_.Length) bytes)" }) `
                -Recommendation "Analyze these files for webshell code. Remove if confirmed malicious." `
                -MITRE "T1505.003" `
                -CVSSv3Score '9.8' `
                -TechnicalImpact "Allows unauthenticated remote code execution on the web server, enabling full system compromise"))
        }

        # Hidden files in web root
        $hiddenWebFiles = $webFiles | Where-Object { $_.Name.StartsWith('.') -and $_.Name -notin @('.htaccess', '.htpasswd', '.gitignore', '.gitkeep') }
        if ($hiddenWebFiles.Count -gt 0) {
            $findings.Add((New-Finding -Id "FS-006" -Severity "Medium" -Category "Filesystem" `
                -Title "Hidden files in web root" `
                -Description "Unexpected hidden files found in the web root directory." `
                -ArtifactPath $webRoot `
                -Evidence @($hiddenWebFiles | Select-Object -First 10 | ForEach-Object { $_.Name }) `
                -Recommendation "Review hidden files in web root for backdoors or data staging" `
                -MITRE "T1505.003" `
                -CVSSv3Score '5.3' `
                -TechnicalImpact "Hidden files in web root may indicate backdoor access or data exfiltration staging"))
        }
    }

    return $findings.ToArray()
}
