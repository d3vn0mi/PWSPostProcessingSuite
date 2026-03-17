function Invoke-WebServerAnalyzer {
    <#
    .SYNOPSIS
        Analyzes web server configurations (nginx, Apache) for security issues.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory)][string]$EvidencePath,
        [Parameter(Mandatory)][hashtable]$Rules
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Collect web server config files
    $configLocations = @(
        @{ Path = '/etc/nginx'; Type = 'nginx' }
        @{ Path = '/etc/apache2'; Type = 'apache' }
        @{ Path = '/etc/httpd'; Type = 'apache' }
    )

    foreach ($loc in $configLocations) {
        $files = Get-ArtifactFiles -EvidencePath $EvidencePath -LinuxPath $loc.Path -Filter '*.conf' -Recurse
        $serverType = $loc.Type

        if ($files.Count -eq 0) { continue }

        foreach ($configFile in $files) {
            $lines = Read-ArtifactContent -Path $configFile.FullName
            $content = $lines -join "`n"
            $fileName = $configFile.Name

            # Check for directory listing
            if ($serverType -eq 'nginx' -and $content -match 'autoindex\s+on') {
                $findings.Add((New-Finding -Id "WEB-001" -Severity "Medium" -Category "Web Server" `
                    -Title "Directory listing enabled (nginx): $fileName" `
                    -Description "Nginx autoindex is enabled, which exposes directory contents to visitors." `
                    -ArtifactPath "$($loc.Path)/$fileName" `
                    -Evidence @(($lines | Where-Object { $_ -match 'autoindex\s+on' }) | Select-Object -First 3) `
                    -Recommendation "Disable autoindex unless explicitly needed" `
                    -MITRE "T1083" `
                    -CVSSv3Score '5.3' `
                    -TechnicalImpact 'Exposes directory contents to unauthenticated users, potentially revealing sensitive files, backup data, or application internals.'))
            }

            if ($serverType -eq 'apache' -and $content -match 'Options.*Indexes') {
                $findings.Add((New-Finding -Id "WEB-001" -Severity "Medium" -Category "Web Server" `
                    -Title "Directory listing enabled (Apache): $fileName" `
                    -Description "Apache Options Indexes is enabled, which exposes directory contents." `
                    -ArtifactPath "$($loc.Path)/$fileName" `
                    -Evidence @(($lines | Where-Object { $_ -match 'Options.*Indexes' }) | Select-Object -First 3) `
                    -Recommendation "Remove 'Indexes' from Options directive" `
                    -MITRE "T1083" `
                    -CVSSv3Score '5.3' `
                    -TechnicalImpact 'Exposes directory contents to unauthenticated users, potentially revealing sensitive files, backup data, or application internals.'))
            }

            # Check for server tokens (version disclosure)
            if ($serverType -eq 'nginx' -and $content -notmatch 'server_tokens\s+off') {
                $findings.Add((New-Finding -Id "WEB-002" -Severity "Low" -Category "Web Server" `
                    -Title "Nginx server version disclosure not disabled: $fileName" `
                    -Description "server_tokens is not set to off. The Nginx version will be disclosed in HTTP headers." `
                    -ArtifactPath "$($loc.Path)/$fileName" `
                    -Evidence @("server_tokens not set to off") `
                    -Recommendation "Add 'server_tokens off;' to nginx.conf" `
                    -MITRE "T1592" `
                    -CVSSv3Score '3.1' `
                    -TechnicalImpact 'Discloses web server version information that aids attackers in identifying known vulnerabilities for targeted exploitation.'))
            }

            if ($serverType -eq 'apache' -and $content -notmatch 'ServerTokens\s+Prod') {
                if ($content -match 'ServerTokens\s+(Full|OS|Minimal|Minor|Major)') {
                    $findings.Add((New-Finding -Id "WEB-002" -Severity "Low" -Category "Web Server" `
                        -Title "Apache server version disclosure: $fileName" `
                        -Description "ServerTokens is not set to Prod. Apache version info will be disclosed." `
                        -ArtifactPath "$($loc.Path)/$fileName" `
                        -Evidence @(($lines | Where-Object { $_ -match 'ServerTokens' }) | Select-Object -First 1) `
                        -Recommendation "Set 'ServerTokens Prod' in Apache config" `
                        -MITRE "T1592" `
                        -CVSSv3Score '3.1' `
                        -TechnicalImpact 'Discloses web server version information that aids attackers in identifying known vulnerabilities for targeted exploitation.'))
                }
            }

            # Check for SSL/TLS weaknesses
            if ($content -match 'ssl_protocols?.*SSLv[23]|SSLv[23]|SSLProtocol.*SSLv[23]') {
                $findings.Add((New-Finding -Id "WEB-003" -Severity "High" -Category "Web Server" `
                    -Title "Weak SSL/TLS protocol enabled: $fileName" `
                    -Description "SSLv2 or SSLv3 protocol is enabled. These are vulnerable to known attacks (POODLE, DROWN)." `
                    -ArtifactPath "$($loc.Path)/$fileName" `
                    -Evidence @(($lines | Where-Object { $_ -match 'SSLv[23]' }) | Select-Object -First 3) `
                    -Recommendation "Disable SSLv2 and SSLv3. Use TLSv1.2+ only." `
                    -MITRE "T1557" `
                    -CVSSv3Score '7.4' `
                    -TechnicalImpact 'Enables man-in-the-middle attacks via known SSL/TLS protocol vulnerabilities (POODLE, DROWN), allowing interception of encrypted traffic.'))
            }

            # Check for missing security headers
            $securityHeaders = @('X-Frame-Options', 'X-Content-Type-Options', 'X-XSS-Protection', 'Content-Security-Policy', 'Strict-Transport-Security')
            $missingHeaders = $securityHeaders | Where-Object {
                $header = $_
                $content -notmatch [regex]::Escape($header)
            }
            if ($missingHeaders.Count -gt 0 -and ($fileName -eq 'nginx.conf' -or $fileName -eq 'httpd.conf' -or $fileName -eq 'apache2.conf')) {
                $findings.Add((New-Finding -Id "WEB-004" -Severity "Low" -Category "Web Server" `
                    -Title "Missing security headers in $fileName" `
                    -Description "The main web server config is missing recommended security headers." `
                    -ArtifactPath "$($loc.Path)/$fileName" `
                    -Evidence @($missingHeaders | ForEach-Object { "Missing: $_" }) `
                    -Recommendation "Add security headers: $($missingHeaders -join ', ')" `
                    -MITRE "T1190" `
                    -CVSSv3Score '3.1' `
                    -TechnicalImpact 'Missing security headers increase exposure to client-side attacks such as clickjacking, XSS, and MIME-type confusion.'))
            }
        }
    }

    return $findings.ToArray()
}
