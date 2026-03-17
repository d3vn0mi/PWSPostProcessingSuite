# PWSPostProcessingSuite - Usage Guide

## Installation

```powershell
# 1. Install the YAML parser dependency
Install-Module powershell-yaml -Scope CurrentUser

# 2. Clone or copy the module to your system
# 3. Import the module
Import-Module /path/to/PWSPostProcessingSuite/PWSPostProcessingSuite.psd1
```

## Basic Usage

### Full Scan

```powershell
$results = Invoke-LinuxArtifactScan -EvidencePath '/cases/incident-2025/linux_root'
```

This runs all 25 analyzers and generates:
- Console summary with color-coded findings
- HTML report in current directory
- CSV report in current directory
- Timeline CSV (if timestamped findings exist)

### Selective Analysis

Run only specific analyzers:
```powershell
$results = Invoke-LinuxArtifactScan -EvidencePath './evidence' `
    -IncludeAnalyzers 'UserAccount', 'Sudoers', 'SSHConfig', 'AuthLog'
```

Exclude specific analyzers:
```powershell
$results = Invoke-LinuxArtifactScan -EvidencePath './evidence' `
    -ExcludeAnalyzers 'WebServer', 'Container'
```

### Filter by Severity

```powershell
# Only show High and Critical findings
$results = Invoke-LinuxArtifactScan -EvidencePath './evidence' -MinimumSeverity High
```

### Custom Output Location

```powershell
$results = Invoke-LinuxArtifactScan -EvidencePath './evidence' `
    -OutputDirectory '/reports/incident-2025'
```

### Skip Reports

```powershell
# Console-only output
$results = Invoke-LinuxArtifactScan -EvidencePath './evidence' `
    -SkipHtmlReport -SkipCsvReport
```

## Working with Results

The scan returns a result object:

```powershell
$results = Invoke-LinuxArtifactScan -EvidencePath './evidence'

# Access findings
$results.TotalFindings       # Total count
$results.BySeverity          # Hashtable: Critical=N, High=N, etc.
$results.Findings            # Array of Finding objects
$results.Timeline            # Sorted timeline entries
$results.ReportPaths         # Hashtable of generated file paths
$results.Metadata            # Scan metadata (duration, analyzers run, etc.)

# Filter findings
$critical = $results.Findings | Where-Object { $_.Severity -eq 'Critical' }
$persistence = $results.Findings | Where-Object { $_.Category -like '*Persist*' }

# Re-generate reports
$results | Get-ScanReport -Format HTML, CSV -OutputDirectory './new-reports'
```

### Finding Object Properties

| Property | Description |
|---|---|
| `Id` | Unique identifier (e.g., ACCT-001, SSH-003) |
| `Severity` | Critical, High, Medium, Low, Informational |
| `Category` | Analysis category (e.g., UserAccounts, SSH, Persistence) |
| `Title` | Short finding description |
| `Description` | Detailed explanation |
| `ArtifactPath` | Linux path the finding relates to |
| `Evidence` | Array of evidence strings (log lines, config entries) |
| `Recommendation` | Remediation guidance |
| `Timestamp` | Event timestamp (if applicable, for timeline) |
| `MITRE` | ATT&CK technique ID |

## Custom Rules

### Rule File Format

```yaml
# my-custom-rules.yaml
suspicious_commands:
  my_iocs:
    - pattern: 'known-bad-c2-domain\.example\.com'
      severity: Critical
      mitre: "T1071.001"
      name: "Known C2 domain"
    - pattern: 'specific-malware-string'
      severity: Critical
      mitre: "T1059"
      name: "Malware indicator"

# Add to dangerous sudoers binaries list
dangerous_sudoers_binaries:
  - /opt/custom-tool

# Custom SSH checks
ssh_config_checks:
  critical:
    - key: "CustomDirective"
      bad_values: ["insecure"]
      finding_id: "SSH-CUSTOM"
      title: "Custom SSH check"
      recommendation: "Fix the custom directive"
```

### Loading Custom Rules

```powershell
# Merge with defaults (additive)
Import-ScanRules -Path './my-rules.yaml'

# Replace all defaults
Import-ScanRules -Path './my-rules.yaml' -ReplaceDefaults

# Or pass to scan directly
Invoke-LinuxArtifactScan -EvidencePath './evidence' -CustomRulesPath './my-rules.yaml'
```

## Available Analyzers

| Name | Description |
|---|---|
| `UserAccount` | /etc/passwd, shadow, group analysis |
| `Sudoers` | Sudoers privilege escalation paths |
| `SSHConfig` | SSH server hardening checks |
| `PAM` | PAM authentication configuration |
| `Cron` | Cron job persistence detection |
| `Systemd` | Systemd service/timer analysis |
| `ShellProfile` | .bashrc/.profile backdoor detection |
| `ShellHistory` | Command history analysis |
| `SSHKey` | SSH key and authorized_keys analysis |
| `Sysctl` | Kernel security parameters |
| `Fstab` | Mount option security |
| `NetworkConfig` | DNS, hosts, network config |
| `Firewall` | iptables/UFW rule analysis |
| `WebServer` | nginx/Apache security checks |
| `AuthLog` | Authentication log analysis (brute force) |
| `Syslog` | System event analysis |
| `AuditLog` | Audit trail analysis |
| `PackageLog` | Package installation/removal analysis |
| `KernelModule` | Kernel module/rootkit detection |
| `LDPreload` | Library injection detection |
| `Environment` | Environment variable manipulation |
| `Process` | Running process analysis |
| `Filesystem` | SUID/SGID, webshells, suspicious files |
| `LogIntegrity` | Log tampering/gap detection |
| `Container` | Docker/container escape detection |
