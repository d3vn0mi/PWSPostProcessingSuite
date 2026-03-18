@{
    RootModule        = 'PWSPostProcessingSuite.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890'
    Author            = 'd3vn0mi'
    CompanyName       = 'PWSPostProcessingSuite'
    Copyright         = '(c) 2025 d3vn0mi. All rights reserved.'
    Description       = 'Cross-platform security analysis suite for Linux and Windows forensic artifacts. Supports offline analysis of collected evidence and active live-system scanning with built-in artifact collection.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @(
        'Invoke-LinuxArtifactScan',
        'Invoke-LinuxLiveScan',
        'Invoke-BatchLinuxScan',
        'Invoke-WindowsArtifactScan',
        'Invoke-WindowsLiveScan',
        'Get-ScanReport',
        'Import-ScanRules'
    )
    CmdletsToExport   = @()
    VariablesToExport  = @()
    AliasesToExport    = @()
    PrivateData        = @{
        PSData = @{
            Tags       = @('Linux', 'Windows', 'Forensics', 'Security', 'IncidentResponse', 'DFIR', 'PostProcessing', 'LiveScan', 'ActiveMode')
            LicenseUri = ''
            ProjectUri = ''
        }
    }
}
