function Invoke-CredentialScanAnalyzer {
    <#
    .SYNOPSIS
        Scans collected artifacts for leaked credentials, API keys, tokens, and secrets.
    .DESCRIPTION
        Inspired by LinPEAS API Keys Regex section. Searches text-based artifact files
        for patterns matching known credential formats including AWS keys, GCP/Azure tokens,
        GitHub/GitLab tokens, private keys, database connection strings, and passwords
        in configuration files.
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
    $analyzerCategory = 'Credential Exposure'

    # Built-in credential patterns (supplemented by rules)
    $credPatterns = @(
        @{ Id = 'CRED-001'; Pattern = 'AKIA[0-9A-Z]{16}'; Name = 'AWS Access Key ID'; Severity = 'Critical'; MITRE = 'T1552.001'; CVSSv3 = '9.8' }
        @{ Id = 'CRED-001'; Pattern = '["\x27]?(?:aws)?_?secret_?(?:access)?_?key["\x27]?\s*[:=]\s*["\x27]?[A-Za-z0-9/+=]{40}'; Name = 'AWS Secret Access Key'; Severity = 'Critical'; MITRE = 'T1552.001'; CVSSv3 = '9.8' }
        @{ Id = 'CRED-002'; Pattern = '"type"\s*:\s*"service_account"'; Name = 'GCP Service Account Key'; Severity = 'Critical'; MITRE = 'T1552.001'; CVSSv3 = '9.8' }
        @{ Id = 'CRED-002'; Pattern = '["\x27]?(?:client|azure)[-_]?secret["\x27]?\s*[:=]'; Name = 'Azure Client Secret'; Severity = 'Critical'; MITRE = 'T1552.001'; CVSSv3 = '9.8' }
        @{ Id = 'CRED-003'; Pattern = '-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'; Name = 'Private Key'; Severity = 'High'; MITRE = 'T1552.004'; CVSSv3 = '8.1' }
        @{ Id = 'CRED-004'; Pattern = '(mysql|postgres|mongodb|redis|mssql)://[^:]+:[^@]+@'; Name = 'Database Connection String'; Severity = 'High'; MITRE = 'T1552.001'; CVSSv3 = '8.1' }
        @{ Id = 'CRED-006'; Pattern = 'gh[pousr]_[A-Za-z0-9_]{36,255}'; Name = 'GitHub Token'; Severity = 'Critical'; MITRE = 'T1528'; CVSSv3 = '9.1' }
        @{ Id = 'CRED-006'; Pattern = 'glpat-[A-Za-z0-9\-]{20,}'; Name = 'GitLab Token'; Severity = 'Critical'; MITRE = 'T1528'; CVSSv3 = '9.1' }
        @{ Id = 'CRED-006'; Pattern = 'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,34}'; Name = 'Slack Token'; Severity = 'High'; MITRE = 'T1528'; CVSSv3 = '7.5' }
        @{ Id = 'CRED-006'; Pattern = '(?:r|s)k_live_[0-9a-zA-Z]{24,}'; Name = 'Stripe Secret Key'; Severity = 'Critical'; MITRE = 'T1528'; CVSSv3 = '9.1' }
        @{ Id = 'CRED-006'; Pattern = '[hH][eE][rR][oO][kK][uU].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}'; Name = 'Heroku API Key'; Severity = 'High'; MITRE = 'T1528'; CVSSv3 = '7.5' }
        @{ Id = 'CRED-006'; Pattern = 'eyJ[A-Za-z0-9-_]{10,}\.eyJ[A-Za-z0-9-_]{10,}'; Name = 'JWT Token'; Severity = 'Medium'; MITRE = 'T1528'; CVSSv3 = '5.3' }
    )

    # File extensions to scan for credentials
    $scanExtensions = @('.conf', '.cfg', '.ini', '.env', '.yaml', '.yml', '.json', '.xml',
                        '.properties', '.cnf', '.php', '.py', '.rb', '.sh', '.bash',
                        '.config', '.toml', '.tf', '.tfvars', '.pem', '.key')

    # File name patterns to scan
    $scanNamePatterns = @('*credentials*', '*secret*', '*.env', '*.env.*', '*config*',
                          '*password*', '*token*', '.boto', '.s3cfg', '.gitconfig',
                          '.npmrc', '.pypirc', '.netrc', '.pgpass', '.my.cnf',
                          'wp-config*', 'database*', 'settings*', 'application*')

    # Directories to scan
    $scanDirs = @(
        '/etc', '/home', '/root', '/opt', '/var/www', '/srv',
        '/usr/local/etc', '/var/lib'
    )

    # Track found credentials to avoid duplicates
    $foundCredentials = [System.Collections.Generic.HashSet[string]]::new()
    $totalFilesScanned = 0

    foreach ($dir in $scanDirs) {
        # Get files by extension
        foreach ($ext in $scanExtensions) {
            $files = Get-ArtifactFiles -EvidencePath $EvidencePath -LinuxPath $dir -Filter "*$ext" -Recurse
            foreach ($file in $files) {
                $totalFilesScanned++
                $lines = Read-ArtifactContent -Path $file.FullName
                if ($lines.Count -eq 0) { continue }

                $lineNum = 0
                foreach ($line in $lines) {
                    $lineNum++
                    $trimmed = $line.Trim()
                    if ([string]::IsNullOrWhiteSpace($trimmed) -or $trimmed.StartsWith('#') -or $trimmed.StartsWith('//')) { continue }

                    foreach ($cred in $credPatterns) {
                        if ($trimmed -match $cred.Pattern) {
                            $matchValue = $Matches[0]
                            # Create a dedup key
                            $dedupKey = "$($cred.Name)|$($file.FullName)|$lineNum"
                            if ($foundCredentials.Contains($dedupKey)) { continue }
                            $null = $foundCredentials.Add($dedupKey)

                            # Redact the credential in evidence
                            $redacted = if ($matchValue.Length -gt 12) {
                                $matchValue.Substring(0, 8) + '...' + $matchValue.Substring($matchValue.Length - 4)
                            } else {
                                $matchValue.Substring(0, [Math]::Min(4, $matchValue.Length)) + '***'
                            }

                            $relativePath = $file.FullName.Replace($EvidencePath, '').TrimStart('/\')
                            $findings.Add((New-Finding -Id $cred.Id -Severity $cred.Severity -Category $analyzerCategory `
                                -Title "$($cred.Name) found in $relativePath" `
                                -Description "A $($cred.Name) pattern was detected in file '$relativePath' at line $lineNum. This credential may grant unauthorized access to external services or systems." `
                                -ArtifactPath $file.FullName `
                                -Evidence @("File: $relativePath", "Line $lineNum (redacted): $redacted", "Pattern: $($cred.Name)") `
                                -Recommendation "Immediately rotate this credential. Remove it from the file and use a secrets manager instead." `
                                -MITRE $cred.MITRE `
                                -CVSSv3Score $cred.CVSSv3 `
                                -TechnicalImpact "Exposed $($cred.Name) can be used by attackers to access external services, escalate privileges, or move laterally."))
                            break  # One finding per line
                        }
                    }
                }
            }
        }

        # Also scan by name pattern
        foreach ($namePattern in $scanNamePatterns) {
            $files = Get-ArtifactFiles -EvidencePath $EvidencePath -LinuxPath $dir -Filter $namePattern -Recurse
            foreach ($file in $files) {
                # Skip if already scanned (by extension)
                if ($file.Extension -in $scanExtensions) { continue }
                $totalFilesScanned++

                $lines = Read-ArtifactContent -Path $file.FullName
                if ($lines.Count -eq 0) { continue }

                $lineNum = 0
                foreach ($line in $lines) {
                    $lineNum++
                    $trimmed = $line.Trim()
                    if ([string]::IsNullOrWhiteSpace($trimmed) -or $trimmed.StartsWith('#')) { continue }

                    foreach ($cred in $credPatterns) {
                        if ($trimmed -match $cred.Pattern) {
                            $matchValue = $Matches[0]
                            $dedupKey = "$($cred.Name)|$($file.FullName)|$lineNum"
                            if ($foundCredentials.Contains($dedupKey)) { continue }
                            $null = $foundCredentials.Add($dedupKey)

                            $redacted = if ($matchValue.Length -gt 12) {
                                $matchValue.Substring(0, 8) + '...' + $matchValue.Substring($matchValue.Length - 4)
                            } else {
                                $matchValue.Substring(0, [Math]::Min(4, $matchValue.Length)) + '***'
                            }

                            $relativePath = $file.FullName.Replace($EvidencePath, '').TrimStart('/\')
                            $findings.Add((New-Finding -Id $cred.Id -Severity $cred.Severity -Category $analyzerCategory `
                                -Title "$($cred.Name) found in $relativePath" `
                                -Description "A $($cred.Name) pattern was detected in file '$relativePath' at line $lineNum." `
                                -ArtifactPath $file.FullName `
                                -Evidence @("File: $relativePath", "Line $lineNum (redacted): $redacted", "Pattern: $($cred.Name)") `
                                -Recommendation "Immediately rotate this credential. Remove it from the file and use a secrets manager instead." `
                                -MITRE $cred.MITRE `
                                -CVSSv3Score $cred.CVSSv3 `
                                -TechnicalImpact "Exposed $($cred.Name) can be used by attackers to access external services, escalate privileges, or move laterally."))
                            break
                        }
                    }
                }
            }
        }
    }

    # CRED-005: Passwords in .env files and config files
    $envFiles = @()
    foreach ($dir in @('/home', '/root', '/var/www', '/opt', '/srv')) {
        $files = Get-ArtifactFiles -EvidencePath $EvidencePath -LinuxPath $dir -Filter '.env*' -Recurse
        foreach ($f in $files) { $envFiles += $f }
        $files = Get-ArtifactFiles -EvidencePath $EvidencePath -LinuxPath $dir -Filter '*.env' -Recurse
        foreach ($f in $files) { $envFiles += $f }
    }

    foreach ($envFile in $envFiles) {
        $lines = Read-ArtifactContent -Path $envFile.FullName
        $lineNum = 0
        foreach ($line in $lines) {
            $lineNum++
            $trimmed = $line.Trim()
            if ([string]::IsNullOrWhiteSpace($trimmed) -or $trimmed.StartsWith('#')) { continue }

            if ($trimmed -match '(?i)(password|passwd|secret|token|api_key|apikey|access_key)\s*=\s*\S+') {
                $dedupKey = "CRED-005|$($envFile.FullName)|$lineNum"
                if ($foundCredentials.Contains($dedupKey)) { continue }
                $null = $foundCredentials.Add($dedupKey)

                # Redact the value
                $parts = $trimmed -split '=', 2
                $redactedLine = "$($parts[0])=***REDACTED***"
                $relativePath = $envFile.FullName.Replace($EvidencePath, '').TrimStart('/\')

                $findings.Add((New-Finding -Id 'CRED-005' -Severity 'High' -Category $analyzerCategory `
                    -Title "Password/secret in env file: $relativePath" `
                    -Description "A password or secret value was found in environment file '$relativePath' at line $lineNum." `
                    -ArtifactPath $envFile.FullName `
                    -Evidence @("File: $relativePath", "Line $lineNum: $redactedLine") `
                    -Recommendation "Move secrets to a vault or secrets manager. Never store credentials in .env files in production." `
                    -MITRE 'T1552.001' `
                    -CVSSv3Score '7.5' `
                    -TechnicalImpact "Credentials stored in environment files can be read by any process or user with file access, enabling unauthorized access to connected services."))
            }
        }
    }

    # CRED-007: Hashed passwords in unexpected files (outside /etc/shadow)
    $hashPatterns = @(
        '\$1\$[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{22}'    # MD5
        '\$5\$[a-zA-Z0-9./]{8,16}\$[a-zA-Z0-9./]{43}'  # SHA-256
        '\$6\$[a-zA-Z0-9./]{8,16}\$[a-zA-Z0-9./]{86}'  # SHA-512
        '\$y\$[^\$]+\$[a-zA-Z0-9./]+\$[a-zA-Z0-9./]+'  # yescrypt
        '\$2[aby]?\$\d{2}\$[a-zA-Z0-9./]{53}'           # bcrypt
    )

    foreach ($dir in @('/etc', '/home', '/var', '/opt', '/tmp')) {
        $configFiles = Get-ArtifactFiles -EvidencePath $EvidencePath -LinuxPath $dir -Filter '*.conf' -Recurse
        $configFiles += @(Get-ArtifactFiles -EvidencePath $EvidencePath -LinuxPath $dir -Filter '*.cfg' -Recurse)
        $configFiles += @(Get-ArtifactFiles -EvidencePath $EvidencePath -LinuxPath $dir -Filter '*.bak' -Recurse)
        $configFiles += @(Get-ArtifactFiles -EvidencePath $EvidencePath -LinuxPath $dir -Filter '*.old' -Recurse)
        $configFiles += @(Get-ArtifactFiles -EvidencePath $EvidencePath -LinuxPath $dir -Filter '*.backup' -Recurse)

        foreach ($file in $configFiles) {
            # Skip actual shadow file
            if ($file.Name -eq 'shadow' -or $file.Name -eq 'shadow-' -or $file.FullName -match 'etc[\\/]shadow') { continue }

            $lines = Read-ArtifactContent -Path $file.FullName
            $lineNum = 0
            foreach ($line in $lines) {
                $lineNum++
                foreach ($hp in $hashPatterns) {
                    if ($line -match $hp) {
                        $dedupKey = "CRED-007|$($file.FullName)|$lineNum"
                        if ($foundCredentials.Contains($dedupKey)) { continue }
                        $null = $foundCredentials.Add($dedupKey)

                        $relativePath = $file.FullName.Replace($EvidencePath, '').TrimStart('/\')
                        $findings.Add((New-Finding -Id 'CRED-007' -Severity 'High' -Category $analyzerCategory `
                            -Title "Password hash in unexpected file: $relativePath" `
                            -Description "A password hash pattern was found in '$relativePath' at line $lineNum. This file is not /etc/shadow and should not contain password hashes." `
                            -ArtifactPath $file.FullName `
                            -Evidence @("File: $relativePath", "Line $lineNum: <hash detected - redacted>") `
                            -Recommendation "Remove password hashes from this file. Investigate how they got there - could indicate a shadow file backup or data leak." `
                            -MITRE 'T1003.008' `
                            -CVSSv3Score '7.5' `
                            -TechnicalImpact "Password hashes outside /etc/shadow can be read by unauthorized users and cracked offline, compromising user accounts."))
                        break
                    }
                }
            }
        }
    }

    # CRED-009: Passwords in environment files
    $envFilePaths = @('/etc/environment', '/etc/default')
    foreach ($envPath in $envFilePaths) {
        $resolved = Resolve-ArtifactPath -EvidencePath $EvidencePath -LinuxPath $envPath
        $filesToCheck = @()
        if (Test-Path $resolved -PathType Leaf) {
            $filesToCheck += Get-Item $resolved
        }
        elseif (Test-Path $resolved -PathType Container) {
            $filesToCheck += @(Get-ChildItem -Path $resolved -File -ErrorAction SilentlyContinue)
        }

        foreach ($file in $filesToCheck) {
            $lines = Read-ArtifactContent -Path $file.FullName
            $lineNum = 0
            foreach ($line in $lines) {
                $lineNum++
                if ($line -match '(?i)(password|passwd|secret|token|api_key|private_key)\s*=') {
                    $dedupKey = "CRED-009|$($file.FullName)|$lineNum"
                    if ($foundCredentials.Contains($dedupKey)) { continue }
                    $null = $foundCredentials.Add($dedupKey)

                    $parts = $line -split '=', 2
                    $redactedLine = "$($parts[0])=***REDACTED***"
                    $relativePath = $file.FullName.Replace($EvidencePath, '').TrimStart('/\')

                    $findings.Add((New-Finding -Id 'CRED-009' -Severity 'High' -Category $analyzerCategory `
                        -Title "Credentials in system environment file: $relativePath" `
                        -Description "A credential-like variable was found in system environment file '$relativePath' at line $lineNum. These values are inherited by all processes." `
                        -ArtifactPath $file.FullName `
                        -Evidence @("File: $relativePath", "Line $lineNum: $redactedLine") `
                        -Recommendation "Remove credentials from environment files. Use a secrets manager or systemd credential injection instead." `
                        -MITRE 'T1552.001' `
                        -CVSSv3Score '7.5' `
                        -TechnicalImpact "Credentials in system environment files are readable by all processes and users, enabling credential theft by any local user or malware."))
                }
            }
        }
    }

    # Check /proc/*/environ if collected
    $procPath = Resolve-ArtifactPath -EvidencePath $EvidencePath -LinuxPath '/proc'
    if (Test-Path $procPath -PathType Container) {
        $environFiles = Get-ChildItem -Path $procPath -Recurse -Filter 'environ' -ErrorAction SilentlyContinue
        foreach ($envFile in $environFiles) {
            $content = Read-ArtifactContent -Path $envFile.FullName
            foreach ($line in $content) {
                # environ files may be null-separated; split them
                $entries = $line -split '\0'
                foreach ($entry in $entries) {
                    if ($entry -match '(?i)(password|passwd|secret|token|api_key|private_key|aws_secret)\s*=') {
                        $parts = $entry -split '=', 2
                        $redactedEntry = "$($parts[0])=***REDACTED***"
                        $relativePath = $envFile.FullName.Replace($EvidencePath, '').TrimStart('/\')

                        $findings.Add((New-Finding -Id 'CRED-009' -Severity 'High' -Category $analyzerCategory `
                            -Title "Credentials in process environment: $relativePath" `
                            -Description "A credential-like environment variable was found in a process environ file." `
                            -ArtifactPath $envFile.FullName `
                            -Evidence @("File: $relativePath", "Variable: $redactedEntry") `
                            -Recommendation "Avoid passing credentials via environment variables. Use secrets injection or credential files with strict permissions." `
                            -MITRE 'T1552.001' `
                            -CVSSv3Score '7.5' `
                            -TechnicalImpact "Process environment variables with credentials can be read via /proc by users with appropriate permissions, enabling credential theft."))
                        break
                    }
                }
            }
        }
    }

    # CRED-008: Passwords in shell history (extending beyond what ShellHistory already checks)
    # Check for password-like patterns in any history files
    $historyFiles = @()
    foreach ($dir in @('/home', '/root')) {
        foreach ($pattern in @('.*_history', '.bash_history', '.zsh_history', '.mysql_history', '.psql_history', '.python_history')) {
            $files = Get-ArtifactFiles -EvidencePath $EvidencePath -LinuxPath $dir -Filter $pattern -Recurse
            foreach ($f in $files) { $historyFiles += $f }
        }
    }

    foreach ($histFile in $historyFiles) {
        $lines = Read-ArtifactContent -Path $histFile.FullName
        $lineNum = 0
        foreach ($line in $lines) {
            $lineNum++
            # Check for password arguments in commands
            if ($line -match '(?i)(-p\s*["\x27]?[^\s"]{4,}|--password[= ]["\x27]?[^\s"]{4,}|passwd\s+\S+\s+\S+|mysql\s+.*-p\S+)') {
                $dedupKey = "CRED-008|$($histFile.FullName)|$lineNum"
                if ($foundCredentials.Contains($dedupKey)) { continue }
                $null = $foundCredentials.Add($dedupKey)

                $relativePath = $histFile.FullName.Replace($EvidencePath, '').TrimStart('/\')
                $findings.Add((New-Finding -Id 'CRED-008' -Severity 'Medium' -Category $analyzerCategory `
                    -Title "Password in shell history: $relativePath" `
                    -Description "A command with an inline password was found in shell history file '$relativePath' at line $lineNum." `
                    -ArtifactPath $histFile.FullName `
                    -Evidence @("File: $relativePath", "Line $lineNum: <command with password - redacted>") `
                    -Recommendation "Clear the password from history. Use password prompts or credential files instead of command-line passwords." `
                    -MITRE 'T1552.003' `
                    -CVSSv3Score '5.3' `
                    -TechnicalImpact "Passwords in shell history files can be read by other users or processes with access, enabling credential theft."))
            }
        }
    }

    # Summary
    $findings.Add((New-Finding -Id 'CRED-INFO' -Severity 'Informational' -Category $analyzerCategory `
        -Title "Credential scan summary" `
        -Description "Scanned files across evidence for credential patterns. Found $($findings.Count) credential-related findings." `
        -ArtifactPath $EvidencePath `
        -Evidence @("Total credential findings: $($findings.Count)", "Unique credentials found: $($foundCredentials.Count)") `
        -Recommendation "Review all credential findings and rotate any exposed secrets." `
        -CVSSv3Score '' `
        -TechnicalImpact ''))

    return $findings.ToArray()
}
