#Requires -Version 7.0

<#
.SYNOPSIS
    PWSPostProcessingSuite - Linux Forensic Artifact Analysis Module
.DESCRIPTION
    Analyzes collected Linux system artifacts for security issues,
    misconfigurations, persistence mechanisms, and indicators of compromise.
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
$PrivateFunctions = Get-ChildItem -Path "$PSScriptRoot/Private" -Recurse -Filter '*.ps1' -ErrorAction SilentlyContinue
foreach ($file in $PrivateFunctions) {
    try {
        . $file.FullName
    }
    catch {
        Write-Error "Failed to import private function: $($file.FullName): $_"
    }
}

# Dot-source all public functions
$PublicFunctions = Get-ChildItem -Path "$PSScriptRoot/Public" -Filter '*.ps1' -ErrorAction SilentlyContinue
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
    $rulesPath = Join-Path $PSScriptRoot 'Config' 'DefaultRules.yaml'
    if (Test-Path $rulesPath) {
        $Script:DefaultRules = Import-YamlConfig -Path $rulesPath
    }
}
catch {
    Write-Warning "Failed to load default rules: $_"
}

# Export public functions
Export-ModuleMember -Function @(
    'Invoke-LinuxArtifactScan',
    'Get-ScanReport',
    'Import-ScanRules'
)
