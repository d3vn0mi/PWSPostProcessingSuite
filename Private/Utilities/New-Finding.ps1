function New-Finding {
    <#
    .SYNOPSIS
        Creates a standardized Finding object for security analysis results.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [string]$Id,

        [Parameter(Mandatory)]
        [ValidateSet('Critical', 'High', 'Medium', 'Low', 'Informational')]
        [string]$Severity,

        [Parameter(Mandatory)]
        [string]$Category,

        [Parameter(Mandatory)]
        [string]$Title,

        [Parameter(Mandatory)]
        [string]$Description,

        [string]$ArtifactPath = '',

        [string[]]$Evidence = @(),

        [string]$Recommendation = '',

        [Nullable[datetime]]$Timestamp,

        [string]$MITRE = ''
    )

    $finding = [PSCustomObject]@{
        PSTypeName     = 'PWSPostProcessingSuite.Finding'
        Id             = $Id
        Severity       = $Severity
        Category       = $Category
        Title          = $Title
        Description    = $Description
        ArtifactPath   = $ArtifactPath
        Evidence       = $Evidence
        Recommendation = $Recommendation
        Timestamp      = $Timestamp
        MITRE          = $MITRE
    }

    return $finding
}
