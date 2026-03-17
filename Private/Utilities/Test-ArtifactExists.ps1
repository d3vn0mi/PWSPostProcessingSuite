function Test-ArtifactExists {
    <#
    .SYNOPSIS
        Checks if a Linux artifact exists within the evidence folder.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [string]$EvidencePath,

        [Parameter(Mandatory)]
        [string]$LinuxPath
    )

    $resolvedPath = Resolve-ArtifactPath -EvidencePath $EvidencePath -LinuxPath $LinuxPath
    return (Test-Path $resolvedPath)
}
