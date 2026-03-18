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

    # ----------------------------------------------------------------
    # FS-007: SGID binaries in unusual paths
    # ----------------------------------------------------------------
    foreach ($listing in $fileListings) {
        $lines = Read-ArtifactContent -Path $listing.FullName
        $fileName = $listing.Name

        if ($fileName -match 'sgid') {
            foreach ($line in $lines) {
                $trimmed = $line.Trim()
                if ([string]::IsNullOrWhiteSpace($trimmed) -or -not $trimmed.StartsWith('/')) { continue }

                if ($trimmed -match '/tmp/|/dev/shm/|/var/tmp/|/home/|/opt/|/usr/local/') {
                    $severity = if ($trimmed -match '/tmp/|/dev/shm/|/var/tmp/') { 'Critical' } else { 'High' }
                    $findings.Add((New-Finding -Id "FS-007" -Severity $severity -Category "Filesystem" `
                        -Title "SGID binary in unusual path: $trimmed" `
                        -Description "A SGID binary was found in a non-standard location. SGID binaries execute with the group privileges of the file's group." `
                        -ArtifactPath $trimmed `
                        -Evidence @($line) `
                        -Recommendation "Investigate this SGID binary. Remove SGID bit if not required: chmod g-s $trimmed" `
                        -MITRE "T1548.001" `
                        -CVSSv3Score $(if ($severity -eq 'Critical') { '9.8' } else { '7.8' }) `
                        -TechnicalImpact "SGID binaries in non-standard locations may enable privilege escalation via group permission inheritance."))
                }
            }
        }
    }

    # ----------------------------------------------------------------
    # FS-008: Files with Linux capabilities set
    # ----------------------------------------------------------------
    $capFiles = @()
    foreach ($pattern in @('getcap*', 'capabilities*', 'cap_*', 'file_caps*')) {
        $files = Get-ArtifactFiles -EvidencePath $EvidencePath -LinuxPath '/' -Filter $pattern
        foreach ($f in $files) { $capFiles += $f }
    }

    $dangerousCaps = @('cap_sys_admin', 'cap_sys_ptrace', 'cap_dac_override', 'cap_dac_read_search',
                       'cap_setuid', 'cap_setgid', 'cap_net_raw', 'cap_chown', 'cap_fowner',
                       'cap_sys_module', 'cap_net_admin')

    foreach ($capFile in $capFiles) {
        $lines = Read-ArtifactContent -Path $capFile.FullName
        foreach ($line in $lines) {
            $trimmed = $line.Trim()
            if ([string]::IsNullOrWhiteSpace($trimmed)) { continue }

            # getcap output format: /path/to/binary = cap_xxx+ep
            if ($trimmed -match '^(/\S+)\s*=\s*(.+)$') {
                $binaryPath = $Matches[1]
                $capsStr = $Matches[2].ToLower()

                $hasDangerous = $false
                $matchedCaps = @()
                foreach ($dc in $dangerousCaps) {
                    if ($capsStr -match $dc) {
                        $hasDangerous = $true
                        $matchedCaps += $dc
                    }
                }

                if ($hasDangerous) {
                    $findings.Add((New-Finding -Id "FS-008" -Severity "High" -Category "Filesystem" `
                        -Title "Dangerous capabilities on binary: $binaryPath" `
                        -Description "Binary '$binaryPath' has dangerous Linux capabilities set: $($matchedCaps -join ', '). These capabilities can be exploited for privilege escalation." `
                        -ArtifactPath $binaryPath `
                        -Evidence @($trimmed) `
                        -Recommendation "Remove unnecessary capabilities: setcap -r $binaryPath. Check if the binary is a known GTFOBin with capabilities." `
                        -MITRE "T1548.001" `
                        -CVSSv3Score '8.4' `
                        -TechnicalImpact "Dangerous Linux capabilities on binaries enable privilege escalation without requiring SUID/SGID, potentially granting root-equivalent access."))
                }
            }
        }
    }

    # ----------------------------------------------------------------
    # FS-009: ACL-based permissions granting unexpected access
    # ----------------------------------------------------------------
    $aclFiles = @()
    foreach ($pattern in @('getfacl*', 'acl_*', 'facl*')) {
        $files = Get-ArtifactFiles -EvidencePath $EvidencePath -LinuxPath '/' -Filter $pattern
        foreach ($f in $files) { $aclFiles += $f }
    }

    foreach ($aclFile in $aclFiles) {
        $lines = Read-ArtifactContent -Path $aclFile.FullName
        $currentFile = ''
        foreach ($line in $lines) {
            $trimmed = $line.Trim()
            if ($trimmed -match '^# file:\s*(.+)') {
                $currentFile = $Matches[1]
            }
            # Check for user/group ACLs granting write to sensitive files
            if ($currentFile -match '^/(etc|usr|bin|sbin|lib)' -and $trimmed -match '^(user|group):\w+:.*w') {
                $findings.Add((New-Finding -Id "FS-009" -Severity "High" -Category "Filesystem" `
                    -Title "ACL grants write access to sensitive file: $currentFile" `
                    -Description "File '$currentFile' has an ACL entry granting write access: $trimmed. This may bypass standard Unix permission restrictions." `
                    -ArtifactPath $currentFile `
                    -Evidence @("File: $currentFile", "ACL: $trimmed") `
                    -Recommendation "Review and remove unnecessary ACL entries: setfacl -b $currentFile" `
                    -MITRE "T1222.002" `
                    -CVSSv3Score '7.5' `
                    -TechnicalImpact "ACL-based write access to system files bypasses standard permission checks, enabling unauthorized modification of system binaries or configurations."))
            }
        }
    }

    # ----------------------------------------------------------------
    # FS-010/011/012: Writable files and scripts in PATH, broken symlinks
    # ----------------------------------------------------------------
    $pathFiles = @()
    foreach ($pattern in @('path_writable*', 'writable_path*', 'path_check*')) {
        $files = Get-ArtifactFiles -EvidencePath $EvidencePath -LinuxPath '/' -Filter $pattern
        foreach ($f in $files) { $pathFiles += $f }
    }

    foreach ($pathFile in $pathFiles) {
        $lines = Read-ArtifactContent -Path $pathFile.FullName
        foreach ($line in $lines) {
            $trimmed = $line.Trim()
            if ([string]::IsNullOrWhiteSpace($trimmed)) { continue }

            if ($trimmed -match '\.(sh|bash|py|pl|rb)$') {
                $findings.Add((New-Finding -Id "FS-011" -Severity "High" -Category "Filesystem" `
                    -Title "Writable script in PATH: $trimmed" `
                    -Description "A writable script file was found in a PATH directory. This can be hijacked for privilege escalation." `
                    -ArtifactPath $trimmed `
                    -Evidence @($line) `
                    -Recommendation "Remove write permissions from scripts in PATH directories: chmod o-w $trimmed" `
                    -MITRE "T1574.007" `
                    -CVSSv3Score '7.8' `
                    -TechnicalImpact "Writable scripts in PATH can be modified by attackers to inject malicious code that executes with the privileges of users or services invoking the script."))
            }
            else {
                $findings.Add((New-Finding -Id "FS-010" -Severity "Medium" -Category "Filesystem" `
                    -Title "Writable file in PATH directory: $trimmed" `
                    -Description "A writable file was found in a PATH directory, potentially allowing binary hijacking." `
                    -ArtifactPath $trimmed `
                    -Evidence @($line) `
                    -Recommendation "Remove write permissions: chmod o-w $trimmed" `
                    -MITRE "T1574.007" `
                    -CVSSv3Score '6.7' `
                    -TechnicalImpact "Writable files in PATH directories can be replaced with malicious binaries, enabling code execution with the privileges of users whose PATH includes this directory."))
            }
        }
    }

    # ----------------------------------------------------------------
    # FS-014: Writable log files (logrotten exploitation)
    # ----------------------------------------------------------------
    $logDir = Resolve-ArtifactPath -EvidencePath $EvidencePath -LinuxPath '/var/log'
    if (Test-Path $logDir -PathType Container) {
        # Look for writable log file listings
        foreach ($listing in $fileListings) {
            $lines = Read-ArtifactContent -Path $listing.FullName
            $fileName = $listing.Name
            if ($fileName -match 'writable') {
                foreach ($line in $lines) {
                    $trimmed = $line.Trim()
                    if ($trimmed -match '^/var/log/') {
                        $findings.Add((New-Finding -Id "FS-014" -Severity "High" -Category "Filesystem" `
                            -Title "World-writable log file: $trimmed" `
                            -Description "A world-writable log file was found. This could enable log manipulation or exploitation via logrotten-style attacks." `
                            -ArtifactPath $trimmed `
                            -Evidence @($line) `
                            -Recommendation "Remove world-writable permissions from log files: chmod o-w $trimmed" `
                            -MITRE "T1070.002" `
                            -CVSSv3Score '7.5' `
                            -TechnicalImpact "Writable log files enable evidence tampering and may allow privilege escalation via logrotate exploitation (logrotten)."))
                    }
                }
            }
        }
    }

    # ----------------------------------------------------------------
    # FS-015: Backup files with potentially sensitive data
    # ----------------------------------------------------------------
    $backupExtensions = @('*.bak', '*.old', '*.backup', '*.orig', '*.save', '*.swp', '*~')
    $sensitiveBackupDirs = @('/etc', '/var/www', '/root', '/home')

    foreach ($backupDir in $sensitiveBackupDirs) {
        foreach ($ext in $backupExtensions) {
            $backupFiles = Get-ArtifactFiles -EvidencePath $EvidencePath -LinuxPath $backupDir -Filter $ext -Recurse
            foreach ($bFile in $backupFiles) {
                $relativePath = $bFile.FullName.Replace($EvidencePath, '').TrimStart('/\')
                # Flag backups of known sensitive files
                if ($relativePath -match '(shadow|passwd|sudoers|sshd_config|\.env|wp-config|database|credentials)') {
                    $findings.Add((New-Finding -Id "FS-015" -Severity "High" -Category "Filesystem" `
                        -Title "Backup of sensitive file: $relativePath" `
                        -Description "A backup copy of a sensitive file was found. Backup files may have weaker permissions than the originals and contain credentials or security configurations." `
                        -ArtifactPath $bFile.FullName `
                        -Evidence @("Backup file: $relativePath", "Size: $($bFile.Length) bytes") `
                        -Recommendation "Remove unnecessary backup files from sensitive locations. Ensure backup files have the same permissions as originals." `
                        -MITRE "T1552.001" `
                        -CVSSv3Score '7.5' `
                        -TechnicalImpact "Backup files of sensitive configs may have relaxed permissions, exposing passwords, hashes, or security configurations to unauthorized users."))
                }
                elseif ($relativePath -match '^etc/') {
                    $findings.Add((New-Finding -Id "FS-015" -Severity "Medium" -Category "Filesystem" `
                        -Title "Backup file in /etc: $relativePath" `
                        -Description "A backup file was found in /etc which may contain outdated but sensitive configuration data." `
                        -ArtifactPath $bFile.FullName `
                        -Evidence @("Backup file: $relativePath", "Size: $($bFile.Length) bytes") `
                        -Recommendation "Review and remove unnecessary backup files from system directories." `
                        -MITRE "T1552.001" `
                        -CVSSv3Score '5.3' `
                        -TechnicalImpact "Backup files in system directories may expose configuration details or credentials."))
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
