function Export-CsvReport {
    <#
    .SYNOPSIS
        Exports scan findings to a CSV file.
    .DESCRIPTION
        Converts finding objects to a flat CSV format with evidence arrays joined
        using pipe delimiters. The output file uses UTF-8 encoding.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [PSCustomObject[]]$Findings,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$OutputPath
    )

    try {
        # Ensure output directory exists
        $outputDir = Split-Path -Path $OutputPath -Parent
        if ($outputDir -and -not (Test-Path $outputDir)) {
            New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
        }

        $csvData = foreach ($finding in $Findings) {
            $evidenceJoined = if ($finding.Evidence -and $finding.Evidence.Count -gt 0) {
                $finding.Evidence -join '|'
            } else {
                ''
            }

            $timestampStr = if ($null -ne $finding.Timestamp) {
                $finding.Timestamp.ToString('yyyy-MM-dd HH:mm:ss')
            } else {
                ''
            }

            [PSCustomObject]@{
                Id             = $finding.Id
                Severity       = $finding.Severity
                Category       = $finding.Category
                Title          = $finding.Title
                Description    = $finding.Description
                ArtifactPath   = $finding.ArtifactPath
                Evidence       = $evidenceJoined
                Recommendation = $finding.Recommendation
                Timestamp      = $timestampStr
                MITRE          = $finding.MITRE
            }
        }

        if ($csvData) {
            $csvData | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding utf8 -Force
        } else {
            # Write an empty CSV with headers only
            [PSCustomObject]@{
                Id = ''; Severity = ''; Category = ''; Title = ''
                Description = ''; ArtifactPath = ''; Evidence = ''
                Recommendation = ''; Timestamp = ''; MITRE = ''
            } | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding utf8 -Force
            # Overwrite with just the header line
            $header = '"Id","Severity","Category","Title","Description","ArtifactPath","Evidence","Recommendation","Timestamp","MITRE"'
            $header | Out-File -FilePath $OutputPath -Encoding utf8 -Force
        }

        Write-Verbose "CSV report written to: $OutputPath"
    }
    catch {
        Write-Error "Failed to export CSV report to '${OutputPath}': $_"
    }
}
