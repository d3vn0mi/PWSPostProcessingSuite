function Get-ArtifactFiles {
    <#
    .SYNOPSIS
        Enumerates files within a Linux artifact directory in the evidence folder.
    #>
    [CmdletBinding()]
    [OutputType([System.IO.FileInfo[]])]
    param(
        [Parameter(Mandatory)]
        [string]$EvidencePath,

        [Parameter(Mandatory)]
        [string]$LinuxPath,

        [string]$Filter = '*',

        [switch]$Recurse
    )

    $resolvedPath = Resolve-ArtifactPath -EvidencePath $EvidencePath -LinuxPath $LinuxPath

    if (-not (Test-Path $resolvedPath -PathType Container)) {
        Write-Verbose "Artifact directory not found: $resolvedPath"
        return @()
    }

    $params = @{
        Path        = $resolvedPath
        Filter      = $Filter
        File        = $true
        ErrorAction = 'SilentlyContinue'
    }

    if ($Recurse) {
        $params['Recurse'] = $true
    }

    return @(Get-ChildItem @params)
}
