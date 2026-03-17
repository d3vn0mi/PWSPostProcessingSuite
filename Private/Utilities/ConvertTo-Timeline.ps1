function ConvertTo-Timeline {
    <#
    .SYNOPSIS
        Converts findings with timestamps into a sorted timeline of events.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [PSCustomObject[]]$Findings
    )

    begin {
        $timelineEntries = [System.Collections.Generic.List[PSCustomObject]]::new()
    }

    process {
        foreach ($finding in $Findings) {
            if ($null -ne $finding.Timestamp) {
                $entry = [PSCustomObject]@{
                    PSTypeName  = 'PWSPostProcessingSuite.TimelineEntry'
                    Timestamp   = $finding.Timestamp
                    Severity    = $finding.Severity
                    Category    = $finding.Category
                    Title       = $finding.Title
                    Description = $finding.Description
                    FindingId   = $finding.Id
                    MITRE       = $finding.MITRE
                }
                $timelineEntries.Add($entry)
            }
        }
    }

    end {
        return $timelineEntries | Sort-Object Timestamp
    }
}
