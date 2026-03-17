function Invoke-EnvironmentAnalyzer {
    <#
    .SYNOPSIS
        Analyzes environment configuration for PATH manipulation and suspicious variables.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory)][string]$EvidencePath,
        [Parameter(Mandatory)][hashtable]$Rules
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    $envFiles = @('/etc/environment', '/etc/default/locale')
    $suspiciousDirs = @('/tmp', '/dev/shm', '/var/tmp', '/home/', '/.', '/run/')

    foreach ($envFile in $envFiles) {
        $resolved = Resolve-ArtifactPath -EvidencePath $EvidencePath -LinuxPath $envFile
        if (-not (Test-Path $resolved)) { continue }

        $lines = Read-ArtifactContent -Path $resolved
        foreach ($line in $lines) {
            $trimmed = $line.Trim()
            if ([string]::IsNullOrWhiteSpace($trimmed) -or $trimmed.StartsWith('#')) { continue }

            # Check for LD_PRELOAD
            if ($trimmed -match '^LD_PRELOAD\s*=') {
                $findings.Add((New-Finding -Id "ENV-001" -Severity "Critical" -Category "Environment" `
                    -Title "LD_PRELOAD set in $envFile" `
                    -Description "LD_PRELOAD is configured system-wide, which forces a shared library to be loaded before all others. This is a common rootkit/backdoor technique." `
                    -ArtifactPath $envFile `
                    -Evidence @($trimmed) `
                    -Recommendation "Remove LD_PRELOAD from environment and investigate the referenced library" `
                    -MITRE "T1574.006"))
            }

            # Check for LD_LIBRARY_PATH manipulation
            if ($trimmed -match '^LD_LIBRARY_PATH\s*=') {
                $value = ($trimmed -split '=', 2)[1].Trim('"').Trim("'")
                foreach ($dir in $suspiciousDirs) {
                    if ($value -match [regex]::Escape($dir)) {
                        $findings.Add((New-Finding -Id "ENV-002" -Severity "High" -Category "Environment" `
                            -Title "Suspicious LD_LIBRARY_PATH in $envFile" `
                            -Description "LD_LIBRARY_PATH includes a suspicious directory ($dir) which could be used for library hijacking." `
                            -ArtifactPath $envFile `
                            -Evidence @($trimmed) `
                            -Recommendation "Remove suspicious paths from LD_LIBRARY_PATH" `
                            -MITRE "T1574.006"))
                        break
                    }
                }
            }

            # Check for PATH manipulation
            if ($trimmed -match '^PATH\s*=') {
                $pathValue = ($trimmed -split '=', 2)[1].Trim('"').Trim("'")
                $pathDirs = $pathValue -split ':'

                # Check for suspicious directories in PATH
                foreach ($pathDir in $pathDirs) {
                    foreach ($dir in $suspiciousDirs) {
                        if ($pathDir -match [regex]::Escape($dir)) {
                            $findings.Add((New-Finding -Id "ENV-003" -Severity "High" -Category "Environment" `
                                -Title "Suspicious directory in system PATH" `
                                -Description "The system PATH includes '$pathDir' which is a world-writable or unusual location. Attackers can place malicious binaries here to hijack commands." `
                                -ArtifactPath $envFile `
                                -Evidence @($trimmed) `
                                -Recommendation "Remove suspicious directories from PATH" `
                                -MITRE "T1574.007"))
                            break
                        }
                    }

                    # Check for empty PATH entry (current directory - hijack risk)
                    if ([string]::IsNullOrEmpty($pathDir)) {
                        $findings.Add((New-Finding -Id "ENV-004" -Severity "Medium" -Category "Environment" `
                            -Title "Empty entry in PATH (current directory in PATH)" `
                            -Description "PATH contains an empty entry which means the current directory is in PATH. This allows command hijacking by placing malicious binaries in any directory." `
                            -ArtifactPath $envFile `
                            -Evidence @($trimmed) `
                            -Recommendation "Remove empty entries from PATH" `
                            -MITRE "T1574.007"))
                    }
                }

                # Check for . (dot) in PATH
                if ($pathDirs -contains '.') {
                    $findings.Add((New-Finding -Id "ENV-005" -Severity "Medium" -Category "Environment" `
                        -Title "Current directory (.) in system PATH" `
                        -Description "PATH contains '.' which includes the current directory in search path. This enables command hijacking." `
                        -ArtifactPath $envFile `
                        -Evidence @($trimmed) `
                        -Recommendation "Remove '.' from PATH" `
                        -MITRE "T1574.007"))
                }
            }

            # Check for proxy variables (potential MITM)
            if ($trimmed -match '^(http_proxy|https_proxy|HTTP_PROXY|HTTPS_PROXY|ftp_proxy|all_proxy)\s*=') {
                $findings.Add((New-Finding -Id "ENV-006" -Severity "Medium" -Category "Environment" `
                    -Title "System-wide proxy configured: $envFile" `
                    -Description "A proxy is configured in the system environment, which routes traffic through an intermediary." `
                    -ArtifactPath $envFile `
                    -Evidence @($trimmed) `
                    -Recommendation "Verify the proxy server is legitimate and authorized" `
                    -MITRE "T1090"))
            }
        }
    }

    return $findings.ToArray()
}
