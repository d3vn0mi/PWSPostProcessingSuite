function Invoke-WinRDPAnalyzer {
    <#
    .SYNOPSIS
        Analyzes Remote Desktop Protocol (RDP) configuration for security issues.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory)][string]$EvidencePath,
        [Parameter(Mandatory)][hashtable]$Rules
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Load RDP registry settings
    $tsRegPath = Join-Path $EvidencePath 'registry/terminal_services.txt'
    $rdpConfigPath = Join-Path $EvidencePath 'security/rdp_config.txt'
    $qwinstaPath = Join-Path $EvidencePath 'collected_commands/qwinsta.txt'

    $regContent = ''
    $regLines = @()
    if (Test-Path $tsRegPath) {
        $regLines = Read-ArtifactContent -Path $tsRegPath
        $regContent = $regLines -join "`n"
    }

    $rdpConfigContent = ''
    if (Test-Path $rdpConfigPath) {
        $rdpConfigLines = Read-ArtifactContent -Path $rdpConfigPath
        $rdpConfigContent = $rdpConfigLines -join "`n"
    }

    # Combine all config sources for setting lookups
    $allConfig = "$regContent`n$rdpConfigContent"

    # Helper: extract registry integer value
    function Get-RegValue {
        param([string]$Content, [string]$Name)
        if ($Content -match "$Name\s*[:=]\s*(\d+)") {
            return [int]$Matches[1]
        }
        return $null
    }

    $fDenyTSConnections = Get-RegValue -Content $allConfig -Name 'fDenyTSConnections'
    $userAuthentication = Get-RegValue -Content $allConfig -Name 'UserAuthentication'
    $securityLayer = Get-RegValue -Content $allConfig -Name 'SecurityLayer'
    $minEncryptionLevel = Get-RegValue -Content $allConfig -Name 'MinEncryptionLevel'

    # ----------------------------------------------------------------
    # WRDP-001: RDP enabled (fDenyTSConnections = 0)
    # ----------------------------------------------------------------
    $rdpEnabled = $false
    if ($null -ne $fDenyTSConnections -and $fDenyTSConnections -eq 0) {
        $rdpEnabled = $true
        $findings.Add((New-Finding -Id 'WRDP-001' -Severity 'High' -Category 'Remote Desktop' `
            -Title 'Remote Desktop Protocol (RDP) is enabled' `
            -Description 'RDP is enabled on this system (fDenyTSConnections = 0). RDP is a common attack vector for brute-force attacks, credential stuffing, and lateral movement.' `
            -ArtifactPath 'registry/terminal_services.txt' `
            -Evidence @("fDenyTSConnections = 0") `
            -Recommendation 'Disable RDP if not required. If required, enforce NLA, use strong passwords, restrict access via firewall rules, and consider using an RDP gateway or VPN.' `
            -MITRE 'T1021.001' `
            -CVSSv3Score '7.5' `
            -TechnicalImpact 'Enabled RDP exposes the system to remote brute-force attacks, pass-the-hash, and BlueKeep-class vulnerabilities if not properly patched and hardened.'))
    }

    # ----------------------------------------------------------------
    # WRDP-002: Network Level Authentication (NLA) disabled
    # ----------------------------------------------------------------
    if ($null -ne $userAuthentication -and $userAuthentication -eq 0) {
        $findings.Add((New-Finding -Id 'WRDP-002' -Severity 'High' -Category 'Remote Desktop' `
            -Title 'Network Level Authentication (NLA) is disabled for RDP' `
            -Description 'NLA is disabled (UserAuthentication = 0). Without NLA, the RDP server presents the login screen before authentication, exposing it to pre-authentication exploits and resource exhaustion attacks.' `
            -ArtifactPath 'registry/terminal_services.txt' `
            -Evidence @("UserAuthentication = 0") `
            -Recommendation 'Enable NLA by setting UserAuthentication to 1 via Group Policy or registry: HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\UserAuthentication = 1' `
            -MITRE 'T1021.001' `
            -CVSSv3Score '8.1' `
            -TechnicalImpact 'Without NLA, attackers can interact with the RDP login screen without credentials, enabling exploitation of pre-auth vulnerabilities (e.g., BlueKeep CVE-2019-0708) and denial-of-service attacks.'))
    }
    elseif ($rdpEnabled -and $null -eq $userAuthentication) {
        $findings.Add((New-Finding -Id 'WRDP-002' -Severity 'High' -Category 'Remote Desktop' `
            -Title 'Network Level Authentication (NLA) setting not found for RDP' `
            -Description 'RDP is enabled but the UserAuthentication registry value was not found, which may indicate NLA is not configured. Default behavior varies by OS version.' `
            -ArtifactPath 'registry/terminal_services.txt' `
            -Evidence @('UserAuthentication registry value not found in terminal services configuration') `
            -Recommendation 'Explicitly enable NLA by setting UserAuthentication to 1 in the terminal services registry key.' `
            -MITRE 'T1021.001' `
            -CVSSv3Score '7.5' `
            -TechnicalImpact 'NLA configuration is not explicitly set, potentially leaving the system vulnerable to pre-authentication RDP attacks depending on OS defaults.'))
    }

    # ----------------------------------------------------------------
    # WRDP-003: RDP security layer set to "RDP Security Layer" instead of TLS/NLA
    # ----------------------------------------------------------------
    if ($null -ne $securityLayer -and $securityLayer -eq 0) {
        $findings.Add((New-Finding -Id 'WRDP-003' -Severity 'Medium' -Category 'Remote Desktop' `
            -Title 'RDP security layer set to legacy RDP Security Layer' `
            -Description 'The RDP security layer is set to 0 (RDP Security Layer) instead of TLS (1) or Negotiate (2). Legacy RDP encryption is weaker and susceptible to man-in-the-middle attacks.' `
            -ArtifactPath 'registry/terminal_services.txt' `
            -Evidence @("SecurityLayer = 0 (RDP Security Layer - legacy, no TLS)") `
            -Recommendation 'Set SecurityLayer to 2 (Negotiate) or 1 (TLS) via Group Policy: Computer Configuration > Administrative Templates > Windows Components > Remote Desktop Services > Security > Require use of specific security layer.' `
            -MITRE 'T1557' `
            -CVSSv3Score '6.8' `
            -TechnicalImpact 'Legacy RDP security layer uses weaker encryption vulnerable to MITM attacks, allowing session hijacking, credential interception, and traffic decryption.'))
    }

    # ----------------------------------------------------------------
    # WRDP-004: RDP minimum encryption level too low
    # ----------------------------------------------------------------
    if ($null -ne $minEncryptionLevel -and $minEncryptionLevel -lt 3) {
        $levelNames = @{ 1 = 'Low'; 2 = 'Client Compatible'; 3 = 'High'; 4 = 'FIPS Compliant' }
        $levelName = if ($levelNames.ContainsKey($minEncryptionLevel)) { $levelNames[$minEncryptionLevel] } else { "Unknown ($minEncryptionLevel)" }

        $findings.Add((New-Finding -Id 'WRDP-004' -Severity 'Medium' -Category 'Remote Desktop' `
            -Title 'RDP minimum encryption level is below High' `
            -Description "The RDP minimum encryption level is set to $minEncryptionLevel ($levelName). A level below 3 (High) allows weaker encryption that may be susceptible to cryptographic attacks." `
            -ArtifactPath 'registry/terminal_services.txt' `
            -Evidence @("MinEncryptionLevel = $minEncryptionLevel ($levelName)") `
            -Recommendation 'Set MinEncryptionLevel to 3 (High) or 4 (FIPS Compliant) via Group Policy: Computer Configuration > Administrative Templates > Windows Components > Remote Desktop Services > Security > Set client connection encryption level.' `
            -MITRE 'T1557' `
            -CVSSv3Score '5.9' `
            -TechnicalImpact "RDP sessions using $levelName encryption may be vulnerable to traffic decryption or downgrade attacks, exposing credentials and session data."))
    }

    # ----------------------------------------------------------------
    # WRDP-005: Active RDP sessions detected (from qwinsta)
    # ----------------------------------------------------------------
    if (Test-Path $qwinstaPath) {
        $qwinstaLines = Read-ArtifactContent -Path $qwinstaPath
        $activeSessions = @()
        $disconnectedSessions = @()

        foreach ($line in $qwinstaLines) {
            $trimmed = $line.Trim()
            if ([string]::IsNullOrWhiteSpace($trimmed)) { continue }
            if ($trimmed -match '^\s*SESSIONNAME' -or $trimmed -match '^-{2,}') { continue }

            if ($trimmed -match 'Active') {
                $activeSessions += $trimmed
            }
            elseif ($trimmed -match 'Disc') {
                $disconnectedSessions += $trimmed
            }
        }

        if ($activeSessions.Count -gt 0 -or $disconnectedSessions.Count -gt 0) {
            $sessionEvidence = @()
            foreach ($s in $activeSessions) {
                $sessionEvidence += "ACTIVE: $s"
            }
            foreach ($s in $disconnectedSessions) {
                $sessionEvidence += "DISCONNECTED: $s"
            }

            $totalSessions = $activeSessions.Count + $disconnectedSessions.Count
            $findings.Add((New-Finding -Id 'WRDP-005' -Severity 'Medium' -Category 'Remote Desktop' `
                -Title 'Active or disconnected RDP sessions detected' `
                -Description "Found $totalSessions RDP session(s): $($activeSessions.Count) active, $($disconnectedSessions.Count) disconnected. Disconnected sessions may retain cached credentials and can be hijacked by privileged users." `
                -ArtifactPath 'collected_commands/qwinsta.txt' `
                -Evidence @($sessionEvidence | Select-Object -First 15) `
                -Recommendation 'Review active sessions for unauthorized access. Configure session time limits and force logoff for disconnected sessions via Group Policy.' `
                -MITRE 'T1021.001' `
                -CVSSv3Score '6.5' `
                -TechnicalImpact 'Active RDP sessions indicate remote access usage. Disconnected sessions retain credentials in memory and can be hijacked via session takeover (tscon) by local admins.'))
        }
    }

    # ----------------------------------------------------------------
    # WRDP-006: RDP configuration summary (Informational)
    # ----------------------------------------------------------------
    $summaryItems = @()

    if ($null -ne $fDenyTSConnections) {
        $summaryItems += "RDP Enabled: $(if ($fDenyTSConnections -eq 0) { 'Yes' } else { 'No' }) (fDenyTSConnections = $fDenyTSConnections)"
    }
    else {
        $summaryItems += 'RDP Enabled: Unknown (fDenyTSConnections not found)'
    }

    if ($null -ne $userAuthentication) {
        $summaryItems += "NLA Enabled: $(if ($userAuthentication -eq 1) { 'Yes' } else { 'No' }) (UserAuthentication = $userAuthentication)"
    }
    else {
        $summaryItems += 'NLA Enabled: Unknown (UserAuthentication not found)'
    }

    if ($null -ne $securityLayer) {
        $layerDesc = switch ($securityLayer) {
            0 { 'RDP Security Layer (legacy)' }
            1 { 'TLS 1.0' }
            2 { 'Negotiate (TLS with fallback)' }
            default { "Unknown ($securityLayer)" }
        }
        $summaryItems += "Security Layer: $layerDesc (SecurityLayer = $securityLayer)"
    }
    else {
        $summaryItems += 'Security Layer: Unknown (SecurityLayer not found)'
    }

    if ($null -ne $minEncryptionLevel) {
        $encDesc = switch ($minEncryptionLevel) {
            1 { 'Low' }
            2 { 'Client Compatible' }
            3 { 'High' }
            4 { 'FIPS Compliant' }
            default { "Unknown ($minEncryptionLevel)" }
        }
        $summaryItems += "Min Encryption Level: $encDesc (MinEncryptionLevel = $minEncryptionLevel)"
    }
    else {
        $summaryItems += 'Min Encryption Level: Unknown (MinEncryptionLevel not found)'
    }

    if (Test-Path $tsRegPath) {
        $summaryItems += 'Source: registry/terminal_services.txt'
    }
    if (Test-Path $rdpConfigPath) {
        $summaryItems += 'Source: security/rdp_config.txt'
    }
    if (Test-Path $qwinstaPath) {
        $summaryItems += 'Source: collected_commands/qwinsta.txt'
    }

    $findings.Add((New-Finding -Id 'WRDP-006' -Severity 'Informational' -Category 'Remote Desktop' `
        -Title 'RDP configuration summary' `
        -Description 'Summary of Remote Desktop Protocol configuration and session state from collected evidence.' `
        -ArtifactPath 'registry/terminal_services.txt' `
        -Evidence $summaryItems `
        -Recommendation 'Review the RDP configuration summary and ensure settings align with organizational security policy.' `
        -MITRE '' `
        -CVSSv3Score '' `
        -TechnicalImpact 'Informational overview of RDP security posture.'))

    return $findings.ToArray()
}
