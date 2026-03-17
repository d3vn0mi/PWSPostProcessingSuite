@{
    RootModule        = 'PWSPostProcessingSuite.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890'
    Author            = 'd3vn0mi'
    CompanyName       = 'PWSPostProcessingSuite'
    Copyright         = '(c) 2025 d3vn0mi. All rights reserved.'
    Description       = 'Post-processing analysis suite for Linux forensic artifacts. Scans collected Linux system evidence for security issues, misconfigurations, and indicators of compromise.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @(
        'Invoke-LinuxArtifactScan',
        'Invoke-BatchLinuxScan',
        'Get-ScanReport',
        'Import-ScanRules'
    )
    CmdletsToExport   = @()
    VariablesToExport  = @()
    AliasesToExport    = @()
    PrivateData        = @{
        PSData = @{
            Tags       = @('Linux', 'Forensics', 'Security', 'IncidentResponse', 'DFIR', 'PostProcessing')
            LicenseUri = ''
            ProjectUri = ''
        }
    }
}
