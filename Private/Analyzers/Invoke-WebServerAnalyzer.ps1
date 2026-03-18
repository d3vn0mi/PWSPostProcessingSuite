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

    # ----------------------------------------------------------------
    # WEB-005: PHP configuration weaknesses
    # ----------------------------------------------------------------
    $phpIniPaths = @('/etc/php', '/etc/php5', '/etc/php7.0', '/etc/php7.4', '/etc/php8.0', '/etc/php8.1', '/etc/php8.2', '/etc/php8.3')
    foreach ($phpPath in $phpIniPaths) {
        $phpFiles = Get-ArtifactFiles -EvidencePath $EvidencePath -LinuxPath $phpPath -Filter 'php.ini' -Recurse
        foreach ($phpFile in $phpFiles) {
            $lines = Read-ArtifactContent -Path $phpFile.FullName
            $content = $lines -join "`n"
            $relativePath = $phpFile.FullName.Replace($EvidencePath, '').TrimStart('/\')
            $phpIssues = @()

            if ($content -match '(?m)^\s*allow_url_include\s*=\s*On') {
                $phpIssues += "allow_url_include = On (remote file inclusion risk)"
            }
            if ($content -match '(?m)^\s*allow_url_fopen\s*=\s*On') {
                $phpIssues += "allow_url_fopen = On (remote file access enabled)"
            }
            if ($content -match '(?m)^\s*display_errors\s*=\s*On') {
                $phpIssues += "display_errors = On (information disclosure)"
            }
            if ($content -match '(?m)^\s*expose_php\s*=\s*On') {
                $phpIssues += "expose_php = On (PHP version disclosure)"
            }
            if ($content -match '(?m)^\s*register_globals\s*=\s*On') {
                $phpIssues += "register_globals = On (critical - variable injection)"
            }
            if ($content -match '(?m)^\s*enable_dl\s*=\s*On') {
                $phpIssues += "enable_dl = On (dynamic extension loading)"
            }

            if ($phpIssues.Count -gt 0) {
                $severity = if ($phpIssues -match 'allow_url_include|register_globals') { 'High' } else { 'Medium' }
                $findings.Add((New-Finding -Id "WEB-005" -Severity $severity -Category "Web Server" `
                    -Title "PHP configuration weaknesses in $relativePath ($($phpIssues.Count) issues)" `
                    -Description "PHP configuration file contains $($phpIssues.Count) security weakness(es) that increase the application attack surface." `
                    -ArtifactPath $phpFile.FullName `
                    -Evidence $phpIssues `
                    -Recommendation "Disable allow_url_include, display_errors, expose_php. Set allow_url_fopen=Off unless required." `
                    -MITRE "T1190" `
                    -CVSSv3Score $(if ($severity -eq 'High') { '7.5' } else { '5.3' }) `
                    -TechnicalImpact "Insecure PHP settings enable remote file inclusion, information disclosure, or other web application attacks."))
            }
        }
    }

    # ----------------------------------------------------------------
    # WEB-006: .htaccess files with weak authentication
    # ----------------------------------------------------------------
    $webRoots = @('/var/www', '/srv/www')
    foreach ($webRoot in $webRoots) {
        $htaccessFiles = Get-ArtifactFiles -EvidencePath $EvidencePath -LinuxPath $webRoot -Filter '.htaccess' -Recurse
        foreach ($htFile in $htaccessFiles) {
            $content = (Read-ArtifactContent -Path $htFile.FullName) -join "`n"
            $relativePath = $htFile.FullName.Replace($EvidencePath, '').TrimStart('/\')

            if ($content -match 'AuthType\s+Basic') {
                $findings.Add((New-Finding -Id "WEB-006" -Severity "Medium" -Category "Web Server" `
                    -Title "Basic authentication in .htaccess: $relativePath" `
                    -Description ".htaccess file uses Basic authentication which transmits credentials in base64 (easily decoded). Should use Digest or external auth." `
                    -ArtifactPath $htFile.FullName `
                    -Evidence @("File: $relativePath", "AuthType Basic detected") `
                    -Recommendation "Use AuthType Digest or implement application-level authentication. Ensure HTTPS is enforced." `
                    -MITRE "T1078" `
                    -CVSSv3Score "5.3" `
                    -TechnicalImpact "Basic authentication transmits credentials in easily-decoded base64, enabling credential interception on non-HTTPS connections."))
            }

            # Check for Require all granted (open access override)
            if ($content -match 'Require\s+all\s+granted' -and $content -match 'Allow\s+from\s+all') {
                $findings.Add((New-Finding -Id "WEB-006" -Severity "Low" -Category "Web Server" `
                    -Title "Open access in .htaccess: $relativePath" `
                    -Description ".htaccess grants access to all without restrictions." `
                    -ArtifactPath $htFile.FullName `
                    -Evidence @("File: $relativePath", "Require all granted / Allow from all") `
                    -Recommendation "Review access controls. Restrict access to authorized IPs or users where appropriate." `
                    -MITRE "T1190" `
                    -CVSSv3Score "3.1" `
                    -TechnicalImpact "Unrestricted access in .htaccess may expose sensitive directories or override parent directory restrictions."))
            }
        }
    }

    # ----------------------------------------------------------------
    # WEB-007: Web server running as root
    # ----------------------------------------------------------------
    $processFiles = @()
    foreach ($pattern in @('ps_*', 'processes*', 'ps-aux*')) {
        $files = Get-ArtifactFiles -EvidencePath $EvidencePath -LinuxPath '/' -Filter $pattern
        foreach ($f in $files) { $processFiles += $f }
    }

    foreach ($pFile in $processFiles) {
        $lines = Read-ArtifactContent -Path $pFile.FullName
        foreach ($line in $lines) {
            if ($line -match '^\s*root\s+.*\b(nginx|apache2|httpd|lighttpd)\b' -and $line -notmatch 'master process') {
                # Web server worker running as root (not just the master process)
                $findings.Add((New-Finding -Id "WEB-007" -Severity "High" -Category "Web Server" `
                    -Title "Web server worker process running as root" `
                    -Description "A web server worker process is running as root. Web server workers should run as an unprivileged user (www-data, nginx, apache)." `
                    -ArtifactPath $pFile.FullName `
                    -Evidence @($line.Trim()) `
                    -Recommendation "Configure the web server to run worker processes as an unprivileged user (e.g., www-data)." `
                    -MITRE "T1190" `
                    -CVSSv3Score "8.1" `
                    -TechnicalImpact "Web server workers running as root means any web application vulnerability leads to immediate root compromise."))
                break
            }
        }
    }

    return $findings.ToArray()
}
