# PWSPostProcessingSuite

A PowerShell 7+ module for post-processing and security analysis of collected Linux system artifacts. Designed for DFIR (Digital Forensics & Incident Response) workflows, it scans evidence folders containing Linux filesystem artifacts and identifies security issues, misconfigurations, persistence mechanisms, and indicators of compromise.

## Features

- **25 specialized analyzers** covering system config, persistence, user artifacts, logs, network, and containers
- **100+ security checks** with severity ratings (Critical/High/Medium/Low/Informational)
- **MITRE ATT&CK mapping** for every finding
- **YAML-based rules engine** with customizable detection patterns and IOC signatures
- **Flexible input** - handles both filesystem-mirror and flat-collection evidence structures
- **Multiple output formats** - Console summary, HTML report, CSV export, Timeline view
- **Extensible architecture** - add custom analyzers and detection rules

## Quick Start

```powershell
# Install the module dependency
Install-Module powershell-yaml -Scope CurrentUser

# Import the module
Import-Module ./PWSPostProcessingSuite.psd1

# Run a scan against collected Linux evidence
Invoke-LinuxArtifactScan -EvidencePath '/path/to/linux/evidence'

# Run specific analyzers only
Invoke-LinuxArtifactScan -EvidencePath './evidence' -IncludeAnalyzers 'UserAccount','SSH','AuthLog'

# Filter by severity
Invoke-LinuxArtifactScan -EvidencePath './evidence' -MinimumSeverity High

# Use custom detection rules
Invoke-LinuxArtifactScan -EvidencePath './evidence' -CustomRulesPath './my-rules.yaml'
```

## What It Analyzes

| Category | Analyzers | Key Checks |
|---|---|---|
| **System Configuration** | UserAccount, Sudoers, SSHConfig, PAM, Sysctl, Fstab | UID 0 backdoors, weak hashes, NOPASSWD sudo, SSH hardening, ASLR, mount options |
| **Persistence** | Cron, Systemd, ShellProfile, LDPreload, Environment, KernelModule | Malicious cron jobs, rogue services, profile backdoors, library injection, rootkit modules |
| **User Artifacts** | ShellHistory, SSHKey | Reverse shells, recon commands, priv-esc tools, unauthorized SSH keys |
| **Log Analysis** | AuthLog, Syslog, AuditLog, PackageLog, LogIntegrity | Brute force, privilege escalation, suspicious packages, log tampering |
| **Network** | NetworkConfig, Firewall, WebServer | DNS hijacking, firewall gaps, web server misconfigs |
| **Runtime** | Process, Filesystem, Container | Deleted binaries, crypto miners, SUID abuse, webshells, container escapes |

## Output

### Console Summary
Color-coded severity breakdown with top critical/high findings displayed in-terminal.

### HTML Report
Self-contained HTML report with:
- Executive summary with severity breakdown
- Detailed findings with evidence snippets and MITRE ATT&CK references
- Chronological event timeline

### CSV Export
Machine-readable CSV for import into SIEM, spreadsheets, or further analysis tools.

## Custom Rules

Create a YAML file with custom detection patterns:

```yaml
suspicious_commands:
  custom_iocs:
    - pattern: 'known-bad-domain\.com'
      severity: Critical
      mitre: "T1071"
      name: "Known C2 domain"
    - pattern: 'malware-hash-here'
      severity: Critical
      mitre: "T1059"
      name: "Known malware indicator"

dangerous_sudoers_binaries:
  - /usr/bin/custom-dangerous-tool
```

Load custom rules:
```powershell
Import-ScanRules -Path './custom-rules.yaml'
# Or pass directly to scan:
Invoke-LinuxArtifactScan -EvidencePath './evidence' -CustomRulesPath './custom-rules.yaml'
```

## Expected Evidence Structure

### Filesystem Mirror (preferred)
```
evidence_root/
├── etc/
│   ├── passwd
│   ├── shadow
│   ├── sudoers
│   ├── ssh/sshd_config
│   ├── crontab
│   └── ...
├── var/log/
│   ├── auth.log
│   ├── syslog
│   └── ...
├── home/
│   └── username/
│       ├── .bash_history
│       └── .ssh/authorized_keys
└── ...
```

### Flat Collection
The tool will also search for artifacts by filename if the mirror structure is not detected.

## Requirements

- **PowerShell 7.0+**
- **powershell-yaml** module (`Install-Module powershell-yaml`)

## Testing

```powershell
# Install Pester
Install-Module Pester -MinimumVersion 5.0 -Scope CurrentUser

# Run tests
Invoke-Pester ./Tests/ -Output Detailed
```

## License

See LICENSE file for details.
