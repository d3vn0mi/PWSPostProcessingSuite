#Requires -Version 5.1

<#
.SYNOPSIS
    PWSPostProcessingSuite - Cross-Platform Forensic Artifact Analysis Module
.DESCRIPTION
    Analyzes collected Linux and Windows system artifacts for security issues,
    misconfigurations, persistence mechanisms, and indicators of compromise.
    Supports both offline post-processing and active live-system scanning.
#>

# Module-scoped variables
$Script:ModuleRoot = $PSScriptRoot
$Script:DefaultRules = $null
$Script:SeverityOrder = @{
    'Critical'      = 0
    'High'          = 1
    'Medium'        = 2
    'Low'           = 3
    'Informational' = 4
}

# Dot-source all private functions (utilities, analyzers, reporting)
$PrivateFunctions = Get-ChildItem -Path (Join-Path $PSScriptRoot 'Private') -Recurse -Filter '*.ps1' -ErrorAction SilentlyContinue
foreach ($file in $PrivateFunctions) {
    try {
        . $file.FullName
    }
    catch {
        Write-Error "Failed to import private function: $($file.FullName): $_"
    }
}

# Dot-source all public functions
$PublicFunctions = Get-ChildItem -Path (Join-Path $PSScriptRoot 'Public') -Filter '*.ps1' -ErrorAction SilentlyContinue
foreach ($file in $PublicFunctions) {
    try {
        . $file.FullName
    }
    catch {
        Write-Error "Failed to import public function: $($file.FullName): $_"
    }
}

# Load default rules on module import
try {
    $rulesPath = Join-Path (Join-Path $PSScriptRoot 'Config') 'DefaultRules.yaml'
    if (Test-Path $rulesPath) {
        $Script:DefaultRules = Import-YamlConfig -Path $rulesPath
    }
}
catch {
    Write-Warning "Failed to load default rules: $_"
}

# Load Windows rules and merge into defaults
try {
    $winRulesPath = Join-Path (Join-Path $PSScriptRoot 'Config') 'WindowsDefaultRules.yaml'
    if (Test-Path $winRulesPath) {
        $Script:WindowsDefaultRules = Import-YamlConfig -Path $winRulesPath
    }
}
catch {
    Write-Warning "Failed to load Windows default rules: $_"
}

# Export public functions
Export-ModuleMember -Function @(
    'Invoke-LinuxArtifactScan',
    'Invoke-LinuxLiveScan',
    'Invoke-BatchLinuxScan',
    'Invoke-WindowsArtifactScan',
    'Invoke-WindowsLiveScan',
    'Get-ScanReport',
    'Import-ScanRules'
)
