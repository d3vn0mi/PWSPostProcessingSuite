function Export-TimelineReport {
    <#
    .SYNOPSIS
        Exports timeline entries to a CSV file sorted by timestamp.
    .DESCRIPTION
        Takes timeline entry objects (as produced by ConvertTo-Timeline) and writes
        them to a CSV file ordered chronologically with UTF-8 encoding.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [PSCustomObject[]]$Timeline,

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

        $sortedTimeline = $Timeline | Sort-Object Timestamp

        $csvData = foreach ($entry in $sortedTimeline) {
            $timestampStr = if ($null -ne $entry.Timestamp) {
                $entry.Timestamp.ToString('yyyy-MM-dd HH:mm:ss')
            } else {
                ''
            }

            [PSCustomObject]@{
                Timestamp   = $timestampStr
                Severity    = $entry.Severity
                Category    = $entry.Category
                Title       = $entry.Title
                Description = $entry.Description
                FindingId   = $entry.FindingId
                MITRE       = $entry.MITRE
            }
        }

        if ($csvData) {
            $csvData | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding utf8 -Force
        } else {
            # Write an empty CSV with headers only
            $header = '"Timestamp","Severity","Category","Title","Description","FindingId","MITRE"'
            $header | Out-File -FilePath $OutputPath -Encoding utf8 -Force
        }

        Write-Verbose "Timeline report written to: $OutputPath"
    }
    catch {
        Write-Error "Failed to export timeline report to '${OutputPath}': $_"
    }
}
