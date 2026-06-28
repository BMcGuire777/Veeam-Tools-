<#
.SYNOPSIS
    VBR tag GUID comparison and repair tool.

.DESCRIPTION
    Solves the problem of vCenter inventory service recompiles changing tag
    GUIDs/MoRefs, which causes VBR tag-based backup jobs to treat their
    objects as new and fire unexpected active full backups.

    When vCenter recompiles its inventory service database, the internal
    UUIDs assigned to tags (Reference, TagQsId) are reassigned. VBR stores
    those UUIDs in its own database when you define a tag-based backup job.
    Once they no longer match, VBR cannot resolve the tag to a VM list and
    triggers an active full. The fix is to update VBR's stored references
    to match the current vCenter GUIDs -- which is what FixJob does.

    MODES
    -----
    GetTag    Pull a specific named tag from vCenter (or cache) and display
              all its stored GUID/reference fields. Use this to inspect
              current values before running Compare or FixJob.

    Compare   Pull all tag references stored inside every VBR backup job and
              compare them field-by-field against live vCenter data. Outputs
              a timestamped CSV flagging every stale GUID. Run this first to
              understand the scope of drift before using FixJob.

    FixJob    Update a specific VBR backup job's stored tag reference to match
              the current live vCenter GUIDs. Removes the stale tag object
              from the job and re-adds it using the fresh entity from vCenter,
              so future backups enumerate the correct VMs and run incrementally.

    CACHE
    -----
    All modes share the same live-pull / cache system. The first run pulls
    live from vCenter and saves a raw tag cache CSV. Pass -UseCache on
    subsequent runs to skip the pull (useful in large environments where
    the pull takes several minutes).

    Cache file: <OutputFolder>\VBR_TagCache_<vCenterServer>.csv

.PARAMETER Mode
    One of: GetTag | Compare | FixJob
    If not supplied, an interactive menu is shown.

.PARAMETER VCenterServer
    The vCenter server name or IP as registered in VBR.

.PARAMETER TagName
    The display name of the tag to work with.
    Required for: GetTag, FixJob.

.PARAMETER JobName
    The VBR backup job name whose tag reference should be corrected.
    Required for: FixJob.

.PARAMETER OutputFolder
    Where CSV reports and the tag cache are saved. Default: C:\Temp

.PARAMETER UseCache
    Load vCenter tag data from the saved cache instead of hitting vCenter live.

.PARAMETER TagCacheFile
    Explicit path to a cache CSV. Overrides the auto-discovered cache path.

.PARAMETER MaxCacheAgeHours
    Maximum cache age in hours before falling back to a live pull. Default: 24.
    Set to 0 to treat the cache as always fresh.

.PARAMETER ForceRefresh
    Always pull live from vCenter, even if a valid cache exists.
    The fresh data overwrites the cache for the next run.

.PARAMETER IncludeMatchingRows
    (Compare mode only) Write all rows to the CSV, including clean matches.
    By default only rows with differences are written.

.EXAMPLE
    # Interactive -- shows menu, prompts for everything
    .\Manage-VBRTags.ps1

.EXAMPLE
    # Pull and display a specific tag (live)
    .\Manage-VBRTags.ps1 -Mode GetTag -VCenterServer "10.0.0.20" -TagName "Prod Backup Tag"

.EXAMPLE
    # Compare all VBR jobs vs vCenter (live pull, save cache)
    .\Manage-VBRTags.ps1 -Mode Compare -VCenterServer "10.0.0.20"

.EXAMPLE
    # Compare using cached tag data (fast -- skips vCenter pull)
    .\Manage-VBRTags.ps1 -Mode Compare -VCenterServer "10.0.0.20" -UseCache

.EXAMPLE
    # Fix a job's stale tag reference -- dry run first, then apply
    .\Manage-VBRTags.ps1 -Mode FixJob -VCenterServer "10.0.0.20" -TagName "Prod Backup Tag" -JobName "Prod-VM-Backup" -WhatIf
    .\Manage-VBRTags.ps1 -Mode FixJob -VCenterServer "10.0.0.20" -TagName "Prod Backup Tag" -JobName "Prod-VM-Backup"

.NOTES
    Run from PowerShell ISE (or any PowerShell host) directly on the VBR server.
    In VBR 12, all Veeam cmdlets are registered automatically -- no snap-in needed.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $false)]
    [ValidateSet("GetTag","Compare","FixJob","Cache")]
    [string]$Mode,

    [Parameter(Mandatory = $false)]
    [string]$VCenterServer,

    [Parameter(Mandatory = $false)]
    [string]$TagName,

    [Parameter(Mandatory = $false)]
    [string]$JobName,

    [Parameter(Mandatory = $false)]
    [string]$OutputFolder = "C:\Temp",

    [Parameter(Mandatory = $false)]
    [switch]$UseCache,

    [Parameter(Mandatory = $false)]
    [string]$TagCacheFile,

    [Parameter(Mandatory = $false)]
    [int]$MaxCacheAgeHours = 24,

    [Parameter(Mandatory = $false)]
    [switch]$ForceRefresh,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeMatchingRows
)

$ErrorActionPreference = "Continue"

# ---------------------------------------------------------------------------
# Interactive menu -- shown when Mode is not supplied on the command line
# ---------------------------------------------------------------------------
if (-not $Mode) {
    Write-Host ""
    Write-Host "  Manage-VBRTags.ps1" -ForegroundColor Green
    Write-Host "  ==================" -ForegroundColor DarkGray
    # Show cache status banner if a cache file already exists for this vCenter
    if ($VCenterServer) {
        $safeTmp      = $VCenterServer -replace '[^\w\-\.]', '_'
        $tmpCachePath = Join-Path $OutputFolder "VBR_TagCache_$safeTmp.csv"
        if (Test-Path $tmpCachePath) {
            $tmpItem     = Get-Item $tmpCachePath
            $tmpAgeHours = [Math]::Round(((Get-Date) - $tmpItem.LastWriteTime).TotalHours, 1)
            Write-Host "  [CACHE] Cache found -- $tmpAgeHours h old  ($tmpCachePath)" -ForegroundColor Cyan
        } else {
            Write-Host "  [CACHE] No cache found -- first run will pull live from vCenter." -ForegroundColor Yellow
        }
    }
    Write-Host ""
    Write-Host "  [1] GetTag   -- Inspect a tag's current GUIDs from vCenter or cache"
    Write-Host "  [2] Compare  -- Compare VBR job tag GUIDs vs live vCenter (outputs CSV)"
    Write-Host "  [3] FixJob   -- Update a VBR job's stale tag GUIDs to match vCenter"
    Write-Host "  [4] Cache    -- View, refresh, or delete the local tag cache"
    Write-Host ""
    $choice = (Read-Host "  Select a mode (1-4)").Trim()
    switch ($choice) {
        "1" { $Mode = "GetTag"  }
        "2" { $Mode = "Compare" }
        "3" { $Mode = "FixJob"  }
        "4" { $Mode = "Cache"   }
        default {
            Write-Error "Invalid selection '$choice'. Run the script again and choose 1-4."
            exit 1
        }
    }
}

if (-not $VCenterServer) {
    $VCenterServer = (Read-Host "  VCenterServer (name or IP as registered in VBR)").Trim()
    if (-not $VCenterServer) { Write-Error "VCenterServer is required."; exit 1 }
}

if (-not (Test-Path $OutputFolder)) {
    New-Item -ItemType Directory -Path $OutputFolder | Out-Null
    Write-Host "[OK] Created output folder: $OutputFolder" -ForegroundColor Green
}

# Auto-cache path derived from vCenter name (sanitised for filesystem)
$safeName      = $VCenterServer -replace '[^\w\-\.]', '_'
$autoCachePath = Join-Path $OutputFolder "VBR_TagCache_$safeName.csv"

if ($TagCacheFile) {
    $UseCache      = $true
    $autoCachePath = $TagCacheFile
}

# ---------------------------------------------------------------------------
# Helper: numbered pick-list, returns selected value
# ---------------------------------------------------------------------------
function Show-PickList {
    param(
        [string]$Prompt,
        [string[]]$Items
    )
    Write-Host ""
    for ($i = 0; $i -lt $Items.Count; $i++) {
        Write-Host ("  [{0,2}] {1}" -f ($i + 1), $Items[$i])
    }
    Write-Host ""
    $raw = (Read-Host "  $Prompt").Trim()
    $n   = 0
    if ([int]::TryParse($raw, [ref]$n) -and $n -ge 1 -and $n -le $Items.Count) {
        return $Items[$n - 1]
    }
    if ($Items -contains $raw) { return $raw }
    Write-Error "  '$raw' is not a valid selection."
    exit 1
}

# ---------------------------------------------------------------------------
# Helper: load tag list from vCenter or cache and present pick-list
# Returns the tag Name (not full path) of the user's selection
# ---------------------------------------------------------------------------
function Select-TagInteractively {
    param([string]$VCenterName, [string]$CachePath, [bool]$UseCacheNow)

    $earlyVc = Get-VBRServer -Type VC |
        Where-Object { $_.Name -like "*$VCenterName*" } | Select-Object -First 1
    if (-not $earlyVc) { Write-Error "Could not find vCenter '$VCenterName' in VBR."; exit 1 }

    $tags = $null
    if ($UseCacheNow -and (Test-Path $CachePath)) {
        $tags = @(Import-Csv -Path $CachePath -Encoding UTF8)
        Write-Host "  (Loaded $($tags.Count) tag(s) from cache)" -ForegroundColor DarkGray
    } else {
        Write-Host "  Pulling tag list from vCenter..." -ForegroundColor Cyan
        $tags = @(Find-VBRViEntity -Server $earlyVc -Tags | Where-Object { $_.Type -eq "Tag" })
        $tags | Select-Object ConnHostId, Type, Reference, TagQsId, Id, Name, Path, Description |
            Export-Csv -Path $CachePath -NoTypeInformation -Encoding UTF8
        Write-Host "  (Pulled $($tags.Count) tag(s) live -- cache saved)" -ForegroundColor DarkGray
        $script:UseCache = $true   # mark cache as current for mode functions
    }

    if ($tags.Count -eq 0) { Write-Error "No tags found in vCenter '$VCenterName'."; exit 1 }

    $paths = $tags | Sort-Object Path | Select-Object -ExpandProperty Path
    Write-Host "`n  Available tags:" -ForegroundColor Cyan
    $selectedPath = Show-PickList -Prompt "Select tag" -Items $paths
    $match = $tags | Where-Object { $_.Path -eq $selectedPath } | Select-Object -First 1
    if ($match) { return $match.Name } else { return $selectedPath }
}

# Prompt for TagName interactively if needed
if ($Mode -in @("GetTag","FixJob") -and -not $TagName) {
    $TagName = Select-TagInteractively -VCenterName $VCenterServer `
        -CachePath $autoCachePath -UseCacheNow $UseCache
}

# Prompt for JobName interactively if needed (FixJob only)
if ($Mode -eq "FixJob" -and -not $JobName) {
    Write-Host "`n  Loading backup jobs from VBR..." -ForegroundColor Cyan
    $allJobNames = @(Get-VBRJob -WarningAction SilentlyContinue |
        Sort-Object Name | Select-Object -ExpandProperty Name)
    if ($allJobNames.Count -gt 0) {
        Write-Host "`n  Available backup jobs:" -ForegroundColor Cyan
        $JobName = Show-PickList -Prompt "Select job" -Items $allJobNames
    } else {
        $JobName = (Read-Host "  JobName").Trim()
    }
}

# Final validation
switch ($Mode) {
    "GetTag"  { if (-not $TagName) { Write-Error "-TagName is required for GetTag.";  exit 1 } }
    "FixJob"  {
        if (-not $TagName) { Write-Error "-TagName is required for FixJob.";  exit 1 }
        if (-not $JobName) { Write-Error "-JobName is required for FixJob.";  exit 1 }
    }
}

# ---------------------------------------------------------------------------
# SHARED: Resolve vCenter server object in VBR
# ---------------------------------------------------------------------------
function Get-VBRVCenterServer {
    param([string]$Name)
    $srv = Get-VBRServer -Type VC | Where-Object { $_.Name -like "*$Name*" } | Select-Object -First 1
    if (-not $srv) { Write-Error "Could not find vCenter '$Name' in VBR."; exit 1 }
    return $srv
}

# ---------------------------------------------------------------------------
# SHARED: Load tag data from cache or live vCenter
# ---------------------------------------------------------------------------
function Get-TagData {
    param(
        [string]$VCenterName,
        [string]$CachePath,
        [bool]$UseCacheFlag,
        [bool]$ForceRefreshFlag,
        [int]$MaxAgeHours
    )

    $doLivePull = $true

    if ($UseCacheFlag -and -not $ForceRefreshFlag) {
        if (Test-Path $CachePath) {
            $cacheItem     = Get-Item $CachePath
            $cacheAgeHours = ((Get-Date) - $cacheItem.LastWriteTime).TotalHours
            if ($MaxAgeHours -eq 0 -or $cacheAgeHours -le $MaxAgeHours) {
                $doLivePull = $false
                Write-Host "[CACHE] Using cached tag data (age: $([Math]::Round($cacheAgeHours,1)) h): $CachePath" -ForegroundColor Cyan
            } else {
                Write-Host "[WARN]  Cache is $([Math]::Round($cacheAgeHours,1)) h old (max: $MaxAgeHours h). Falling back to live pull." -ForegroundColor Yellow
            }
        } else {
            Write-Host "[WARN]  Cache not found at $CachePath -- falling back to live pull." -ForegroundColor Yellow
        }
    }

    if ($doLivePull) {
        Write-Host "[LIVE]  Pulling tag data from vCenter '$VCenterName'..." -ForegroundColor Cyan
        $vc        = Get-VBRVCenterServer -Name $VCenterName
        $pullStart = Get-Date
        $tags      = @(Find-VBRViEntity -Server $vc -Tags | Where-Object { $_.Type -eq "Tag" })
        $elapsed   = [Math]::Round(((Get-Date) - $pullStart).TotalSeconds, 1)
        Write-Host "       $($tags.Count) tag(s) pulled in $elapsed s." -ForegroundColor Green
        Write-Host "       Saving cache: $CachePath" -ForegroundColor DarkGray
        $tags | Select-Object ConnHostId, Type, Reference, TagQsId, Id, Name, Path, Description |
            Export-Csv -Path $CachePath -NoTypeInformation -Encoding UTF8
        Write-Host "       Cache saved. Add -UseCache on the next run to skip this step." -ForegroundColor DarkGray
        return $tags
    } else {
        $tags = @(Import-Csv -Path $CachePath -Encoding UTF8)
        if ($tags.Count -eq 0) { Write-Error "Cache file is empty: $CachePath"; exit 1 }
        Write-Host "       Loaded $($tags.Count) tag(s)." -ForegroundColor Cyan
        return $tags
    }
}

# ---------------------------------------------------------------------------
# SHARED: Find a named tag from the full tag list
# ---------------------------------------------------------------------------
function Find-NamedTag {
    param([string]$Name, [array]$AllTags)
    $found = @($AllTags | Where-Object { $_.Name -eq $Name })
    if ($found.Count -eq 0) {
        Write-Warning "Tag '$Name' was not found in the tag data."
        return $null
    }
    if ($found.Count -gt 1) {
        Write-Warning "Multiple tags named '$Name' exist (different categories). Using the first match."
        $found | ForEach-Object { Write-Warning "  Path: $($_.Path)" }
    }
    return $found[0]
}

# ===========================================================================
# MODE: GetTag
# Display all GUID/reference fields for a specific tag
# ===========================================================================
function Invoke-GetTag {
    Write-Host "`n=== MODE: GetTag ===" -ForegroundColor Green

    $allTags = Get-TagData -VCenterName $VCenterServer -CachePath $autoCachePath `
        -UseCacheFlag $UseCache -ForceRefreshFlag $ForceRefresh -MaxAgeHours $MaxCacheAgeHours

    $tag = Find-NamedTag -Name $TagName -AllTags $allTags
    if (-not $tag) { return }

    Write-Host ""
    Write-Host "  Tag: $($tag.Name)" -ForegroundColor Green
    Write-Host ("  " + "-" * 50) -ForegroundColor DarkGray
    Write-Host "  Name        : $($tag.Name)"
    Write-Host "  Path        : $($tag.Path)"
    Write-Host "  Description : $($tag.Description)"
    Write-Host ""
    Write-Host "  -- GUIDs / References --" -ForegroundColor Cyan
    Write-Host "  ConnHostId  : $($tag.ConnHostId)"
    Write-Host "  Reference   : $($tag.Reference)"
    Write-Host "  TagQsId     : $($tag.TagQsId)"
    Write-Host "  Id          : $($tag.Id)"
}

# ===========================================================================
# MODE: Compare
# Compare VBR backup job tag GUIDs against vCenter data, output CSV report
# ===========================================================================
function Invoke-Compare {
    Write-Host "`n=== MODE: Compare ===" -ForegroundColor Green

    $allTags = Get-TagData -VCenterName $VCenterServer -CachePath $autoCachePath `
        -UseCacheFlag $UseCache -ForceRefreshFlag $ForceRefresh -MaxAgeHours $MaxCacheAgeHours

    # Hashtable keyed by tag Name for fast lookup
    $vcTagIndex = @{}
    foreach ($t in $allTags) {
        if (-not $vcTagIndex.ContainsKey($t.Name)) {
            $vcTagIndex[$t.Name] = [System.Collections.Generic.List[object]]::new()
        }
        $vcTagIndex[$t.Name].Add($t)
    }

    Write-Host "`n[Compare] Iterating VBR backup jobs..." -ForegroundColor Cyan
    $allJobs      = @(Get-VBRJob -WarningAction SilentlyContinue)
    $results      = [System.Collections.Generic.List[PSCustomObject]]::new()
    $jobsWithTags = 0

    Write-Host "          Found $($allJobs.Count) job(s) in VBR." -ForegroundColor Green

    foreach ($job in $allJobs) {

        $jobObjects = @(Get-VBRJobObject -Job $job -ErrorAction SilentlyContinue)
        if (-not $jobObjects) { continue }

        # Identify tag-type objects by inspecting the underlying entity
        $tagObjects = $jobObjects | Where-Object {
            $entity = if ($_.PSObject.Properties["Object"] -and $_.Object) { $_.Object } else { $_ }
            $isTag  = $false
            if ($entity.PSObject.Properties["TagQsId"] -and $entity.TagQsId)               { $isTag = $true }
            elseif ($entity.PSObject.Properties["Reference"] -and
                    $entity.Reference -like "*InventoryServiceTag*")                         { $isTag = $true }
            elseif ($entity.GetType().Name -like "*Tag*")                                    { $isTag = $true }
            Write-Verbose "  Job '$($job.Name)' | '$($_.Name)' | $($entity.GetType().Name) | IsTag: $isTag"
            $isTag
        }

        if (-not $tagObjects) { continue }
        $jobsWithTags++

        foreach ($tagObj in $tagObjects) {
            $entity = if ($tagObj.PSObject.Properties["Object"] -and $tagObj.Object) { $tagObj.Object } else { $tagObj }

            $vbrName = $vbrPath = $vbrDescription = $vbrConnHostId = $vbrReference = $vbrTagQsId = $vbrId = $null
            if ($entity.PSObject.Properties["Name"])        { $vbrName        = $entity.Name }        else { $vbrName = $tagObj.Name }
            if ($entity.PSObject.Properties["Path"])        { $vbrPath        = $entity.Path }
            if ($entity.PSObject.Properties["Description"]) { $vbrDescription = $entity.Description }
            if ($entity.PSObject.Properties["ConnHostId"])  { $vbrConnHostId  = $entity.ConnHostId }
            if ($entity.PSObject.Properties["Reference"])   { $vbrReference   = $entity.Reference }
            if ($entity.PSObject.Properties["TagQsId"])     { $vbrTagQsId     = $entity.TagQsId }
            if ($entity.PSObject.Properties["Id"])          { $vbrId          = $entity.Id }
            if (-not $vbrName) { $vbrName = "(unknown)" }

            # Match to vCenter data by name
            $vcMatches = $vcTagIndex[$vbrName]
            $vcTag = $null; $vcFound = $false; $ambiguous = $false

            if ($vcMatches -and $vcMatches.Count -gt 0) {
                $vcFound = $true
                if ($vcMatches.Count -gt 1) {
                    $ambiguous = $true
                    $vcTag = $vcMatches | Sort-Object {
                        $score = 0
                        if ($vbrPath -and $_.Path) {
                            $a = $vbrPath -split "\\"; $b = $_.Path -split "\\"
                            $lim = [Math]::Min($a.Count, $b.Count)
                            for ($i = 0; $i -lt $lim; $i++) { if ($a[$i] -eq $b[$i]) { $score++ } else { break } }
                        }
                        -$score
                    } | Select-Object -First 1
                } else { $vcTag = $vcMatches[0] }
            }

            $connMatch = $refMatch = $qsIdMatch = $idMatch = $false
            $diffFields = [System.Collections.Generic.List[string]]::new()

            if ($vcFound -and $vcTag) {
                $connMatch = ($vbrConnHostId -eq $vcTag.ConnHostId)
                $refMatch  = ($vbrReference  -eq $vcTag.Reference)
                $qsIdMatch = ($vbrTagQsId    -eq $vcTag.TagQsId)
                $idMatch   = ($vbrId         -eq $vcTag.Id)
                if (-not $connMatch)  { $diffFields.Add("ConnHostId") }
                if (-not $refMatch)   { $diffFields.Add("Reference") }
                if (-not $qsIdMatch)  { $diffFields.Add("TagQsId") }
                if (-not $idMatch)    { $diffFields.Add("Id") }
                if ($vbrPath        -and $vbrPath        -ne $vcTag.Path)        { $diffFields.Add("Path(info)") }
                if ($vbrDescription -and $vbrDescription -ne $vcTag.Description) { $diffFields.Add("Description(info)") }
            }

            $hasDiff   = (-not $vcFound) -or ($diffFields.Count -gt 0)
            if (-not $hasDiff -and -not $IncludeMatchingRows) { continue }

            $dataSource = if ($UseCache -and -not $ForceRefresh -and (Test-Path $autoCachePath)) { "Cache: $autoCachePath" } else { "LiveVCenter" }

            $results.Add([PSCustomObject]@{
                JobName            = $job.Name
                TagName            = $vbrName
                VC_TagFound        = $vcFound
                AmbiguousNameMatch = $ambiguous
                HasDifferences     = $hasDiff
                DifferentFields    = ($diffFields -join ", ")
                DataSource         = $dataSource
                VBR_ConnHostId     = $vbrConnHostId
                VC_ConnHostId      = if ($vcTag) { $vcTag.ConnHostId  } else { "(not found)" }
                ConnHostId_Match   = if ($vcFound) { $connMatch  } else { $false }
                VBR_Reference      = $vbrReference
                VC_Reference       = if ($vcTag) { $vcTag.Reference   } else { "(not found)" }
                Reference_Match    = if ($vcFound) { $refMatch   } else { $false }
                VBR_TagQsId        = $vbrTagQsId
                VC_TagQsId         = if ($vcTag) { $vcTag.TagQsId     } else { "(not found)" }
                TagQsId_Match      = if ($vcFound) { $qsIdMatch  } else { $false }
                VBR_Id             = $vbrId
                VC_Id              = if ($vcTag) { $vcTag.Id          } else { "(not found)" }
                Id_Match           = if ($vcFound) { $idMatch    } else { $false }
                VBR_Path           = $vbrPath
                VC_Path            = if ($vcTag) { $vcTag.Path        } else { "(not found)" }
                VBR_Description    = $vbrDescription
                VC_Description     = if ($vcTag) { $vcTag.Description } else { "(not found)" }
            })
        }
    }

    Write-Host "          $jobsWithTags job(s) had tag-based inclusions." -ForegroundColor Green

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $csvPath   = Join-Path $OutputFolder "VBR_TagGUID_Compare_$timestamp.csv"

    if ($results.Count -eq 0) {
        Write-Host "`n[Compare] No differences found -- all VBR tag GUIDs match vCenter." -ForegroundColor Green
        Write-Host "          Add -IncludeMatchingRows to write a full report anyway." -ForegroundColor Yellow
    } else {
        $results | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
        Write-Host "`n[Compare] Report written to : $csvPath" -ForegroundColor Green
        Write-Host "          Total rows         : $($results.Count)"
        $diffCount = ($results | Where-Object { $_.HasDifferences }).Count
        Write-Host "          Stale GUID rows    : $diffCount" -ForegroundColor $(if ($diffCount -gt 0) { "Yellow" } else { "Green" })
    }

    if ($results.Count -gt 0) {
        Write-Host "`n--- Summary by Job ---" -ForegroundColor Cyan
        $results | Group-Object JobName | ForEach-Object {
            $diffs  = ($_.Group | Where-Object { $_.HasDifferences }).Count
            $status = if ($diffs -gt 0) { "[STALE]" } else { "[OK]   " }
            $color  = if ($diffs -gt 0) { "Yellow" }  else { "Green" }
            Write-Host ("  {0}  {1,-45}  {2} tag(s) with stale GUIDs" -f $status, $_.Name, $diffs) -ForegroundColor $color
        }
        if (($results | Where-Object { $_.HasDifferences }).Count -gt 0) {
            Write-Host "`n  Jobs marked [STALE] will trigger active full backups until fixed." -ForegroundColor Yellow
            Write-Host "  Run mode [3] FixJob to correct each stale job." -ForegroundColor Yellow
        }
    }
}

# ===========================================================================
# MODE: FixJob
# Update a VBR backup job's stored tag GUIDs to match current vCenter data
# ===========================================================================
function Invoke-FixJob {
    Write-Host "`n=== MODE: FixJob ===" -ForegroundColor Green
    Write-Host "  Pulling live vCenter data to ensure accuracy..." -ForegroundColor Cyan

    # FixJob always uses live data unless caller explicitly passes -UseCache.
    # We need authoritative GUIDs when making changes to job definitions.
    $allTags = Get-TagData -VCenterName $VCenterServer -CachePath $autoCachePath `
        -UseCacheFlag $UseCache -ForceRefreshFlag $ForceRefresh -MaxAgeHours $MaxCacheAgeHours

    $liveTag = Find-NamedTag -Name $TagName -AllTags $allTags
    if (-not $liveTag) { return }

    Write-Host "`n[FixJob]  Current vCenter GUIDs for '$($liveTag.Name)':" -ForegroundColor Cyan
    Write-Host "  Reference   : $($liveTag.Reference)"
    Write-Host "  TagQsId     : $($liveTag.TagQsId)"
    Write-Host "  ConnHostId  : $($liveTag.ConnHostId)"
    Write-Host "  Id          : $($liveTag.Id)"

    # Locate the target job
    $job = Get-VBRJob -WarningAction SilentlyContinue |
        Where-Object { $_.Name -eq $JobName } | Select-Object -First 1
    if (-not $job) { Write-Error "Backup job '$JobName' not found in VBR."; return }

    Write-Host "`n[FixJob]  Target job: $($job.Name)" -ForegroundColor Cyan

    # Find the stale tag entry inside the job
    $jobObjects  = @(Get-VBRJobObject -Job $job -ErrorAction SilentlyContinue)
    $staleTagObj = $jobObjects | Where-Object {
        $entity    = if ($_.PSObject.Properties["Object"] -and $_.Object) { $_.Object } else { $_ }
        $nameMatch = ($entity.PSObject.Properties["Name"]   -and $entity.Name -eq $TagName) -or ($_.Name -eq $TagName)
        $isTag     = $false
        if ($entity.PSObject.Properties["TagQsId"] -and $entity.TagQsId)             { $isTag = $true }
        elseif ($entity.PSObject.Properties["Reference"] -and
                $entity.Reference -like "*InventoryServiceTag*")                       { $isTag = $true }
        elseif ($entity.GetType().Name -like "*Tag*")                                  { $isTag = $true }
        $nameMatch -and $isTag
    } | Select-Object -First 1

    if (-not $staleTagObj) {
        Write-Warning "Tag '$TagName' was not found as an inclusion in job '$JobName'."
        Write-Warning "Inspect the job with: Get-VBRJobObject -Job (Get-VBRJob -Name '$JobName')"
        return
    }

    $entity = if ($staleTagObj.PSObject.Properties["Object"] -and $staleTagObj.Object) { $staleTagObj.Object } else { $staleTagObj }

    Write-Host "`n[FixJob]  GUIDs currently stored in VBR for this job:" -ForegroundColor Yellow
    if ($entity.PSObject.Properties["Reference"])  { Write-Host "  Reference   : $($entity.Reference)"  -ForegroundColor Yellow }
    if ($entity.PSObject.Properties["TagQsId"])    { Write-Host "  TagQsId     : $($entity.TagQsId)"    -ForegroundColor Yellow }
    if ($entity.PSObject.Properties["ConnHostId"]) { Write-Host "  ConnHostId  : $($entity.ConnHostId)" -ForegroundColor Yellow }

    # Check if already in sync
    $alreadyMatch = $true
    if ($entity.PSObject.Properties["Reference"]  -and $entity.Reference  -ne $liveTag.Reference)  { $alreadyMatch = $false }
    if ($entity.PSObject.Properties["TagQsId"]    -and $entity.TagQsId    -ne $liveTag.TagQsId)    { $alreadyMatch = $false }
    if ($entity.PSObject.Properties["ConnHostId"] -and $entity.ConnHostId -ne $liveTag.ConnHostId) { $alreadyMatch = $false }

    if ($alreadyMatch) {
        Write-Host "`n[FixJob]  GUIDs already match vCenter. No fix needed." -ForegroundColor Green
        return
    }

    Write-Host "`n[FixJob]  Replacement GUIDs (from vCenter):" -ForegroundColor Green
    Write-Host "  Reference   : $($liveTag.Reference)"
    Write-Host "  TagQsId     : $($liveTag.TagQsId)"
    Write-Host "  ConnHostId  : $($liveTag.ConnHostId)"

    if ($WhatIfPreference) {
        Write-Host "`n[WHATIF]  No changes made. Remove -WhatIf to apply the fix." -ForegroundColor Yellow
        return
    }

    # Remove the stale tag object and re-add using the fresh live entity from vCenter.
    # VBR needs a properly-typed ViBrViEntity, not a PSCustomObject from the CSV,
    # so we resolve the entity directly from vCenter for the re-add.
    try {
        Write-Host "`n[FixJob]  Removing stale tag entry..." -ForegroundColor Cyan
        Remove-VBRJobObject -Objects $staleTagObj -ErrorAction Stop
        Write-Host "          Removed." -ForegroundColor Green

        Write-Host "[FixJob]  Resolving fresh tag entity from vCenter..." -ForegroundColor Cyan
        $vc            = Get-VBRVCenterServer -Name $VCenterServer
        $liveTagEntity = Find-VBRViEntity -Server $vc -Tags |
            Where-Object { $_.Type -eq "Tag" -and $_.Name -eq $TagName } |
            Select-Object -First 1

        if (-not $liveTagEntity) {
            Write-Error "Could not re-resolve tag '$TagName' live from vCenter. Check connectivity and try again."
            Write-Warning "The job has had its tag entry removed but not re-added. Re-add manually in the VBR console."
            return
        }

        Write-Host "[FixJob]  Adding corrected tag entry..." -ForegroundColor Cyan
        Add-VBRJobObject -Job $job -Entities $liveTagEntity -ErrorAction Stop
        Write-Host "          Done." -ForegroundColor Green

        Write-Host "`n[FixJob]  Job '$JobName' has been corrected." -ForegroundColor Green
        Write-Host "          The next backup run will use the current vCenter GUIDs" -ForegroundColor Green
        Write-Host "          and should resume incrementally rather than running an active full." -ForegroundColor Green
        Write-Host "          Run mode [2] Compare to verify." -ForegroundColor DarkGray
    }
    catch {
        Write-Error "Failed to update job '$JobName': $_"
        Write-Warning "The job may be in a partial state. Check the VBR console."
        Write-Warning "Correct values to re-add manually:"
        Write-Warning "  Tag Name  : $($liveTag.Name)"
        Write-Warning "  Reference : $($liveTag.Reference)"
        Write-Warning "  TagQsId   : $($liveTag.TagQsId)"
    }
}

# ===========================================================================
# MODE: Cache
# View info about, refresh, or delete the local tag cache
# ===========================================================================
function Invoke-CacheManage {
    Write-Host "`n=== MODE: Cache ===" -ForegroundColor Green

    # Show current cache status
    if (Test-Path $autoCachePath) {
        $cacheItem     = Get-Item $autoCachePath
        $cacheAgeHours = [Math]::Round(((Get-Date) - $cacheItem.LastWriteTime).TotalHours, 1)
        $cacheRows     = @(Import-Csv -Path $autoCachePath -Encoding UTF8 -ErrorAction SilentlyContinue)
        Write-Host ""
        Write-Host "  Cache file  : $autoCachePath" -ForegroundColor Cyan
        Write-Host "  Last saved  : $($cacheItem.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'))  ($cacheAgeHours h ago)"
        Write-Host "  Tag entries : $($cacheRows.Count)"
        Write-Host "  Size        : $([Math]::Round($cacheItem.Length / 1KB, 1)) KB"
    } else {
        Write-Host ""
        Write-Host "  No cache file found." -ForegroundColor Yellow
        Write-Host "  Expected path: $autoCachePath" -ForegroundColor DarkGray
    }

    Write-Host ""
    Write-Host "  [1] Refresh cache  -- Pull fresh tag data from vCenter and save"
    Write-Host "  [2] Delete cache   -- Remove the cache file"
    Write-Host "  [3] Back to menu"
    Write-Host ""
    $sub = (Read-Host "  Select (1-3)").Trim()

    switch ($sub) {
        "1" {
            Write-Host ""
            Write-Host "[CACHE]  Pulling fresh tag data from vCenter '$VCenterServer'..." -ForegroundColor Cyan
            $vc = Get-VBRVCenterServer -Name $VCenterServer
            $pullStart = Get-Date
            $tags = @(Find-VBRViEntity -Server $vc -Tags | Where-Object { $_.Type -eq "Tag" })
            $elapsed = [Math]::Round(((Get-Date) - $pullStart).TotalSeconds, 1)
            $tags | Select-Object ConnHostId, Type, Reference, TagQsId, Id, Name, Path, Description |
                Export-Csv -Path $autoCachePath -NoTypeInformation -Encoding UTF8
            Write-Host "[CACHE]  $($tags.Count) tag(s) pulled in $elapsed s -- cache updated." -ForegroundColor Green
            Write-Host "         $autoCachePath" -ForegroundColor DarkGray
            $script:UseCache = $true
        }
        "2" {
            if (Test-Path $autoCachePath) {
                Remove-Item $autoCachePath -Force
                Write-Host ""
                Write-Host "[CACHE]  Cache deleted: $autoCachePath" -ForegroundColor Yellow
                $script:UseCache = $false
            } else {
                Write-Host ""
                Write-Host "[CACHE]  Nothing to delete -- cache file does not exist." -ForegroundColor DarkGray
            }
        }
        "3" {
            # Nothing to do, just return to the main loop
        }
        default {
            Write-Warning "Invalid selection '$sub'."
        }
    }
}

# ===========================================================================
# ENTRY POINT -- main loop, returns to menu after each operation
# ===========================================================================
$interactiveMode = (-not $PSBoundParameters.ContainsKey('Mode'))
$loopIteration   = 0

do {
    # On loop iterations after the first, re-prompt for mode and parameters
    if ($interactiveMode -and $loopIteration -gt 0) {
        $Mode    = $null
        $TagName = $null
        $JobName = $null

        Write-Host ""
        Write-Host "  ==================" -ForegroundColor DarkGray
        # Cache status banner
        if (Test-Path $autoCachePath) {
            $loopCacheItem     = Get-Item $autoCachePath
            $loopCacheAgeHours = [Math]::Round(((Get-Date) - $loopCacheItem.LastWriteTime).TotalHours, 1)
            Write-Host "  [CACHE] Cache found -- $loopCacheAgeHours h old  ($autoCachePath)" -ForegroundColor Cyan
        } else {
            Write-Host "  [CACHE] No cache -- next run will pull live from vCenter." -ForegroundColor Yellow
        }
        Write-Host ""
        Write-Host "  [1] GetTag   -- Inspect a tag's current GUIDs from vCenter or cache"
        Write-Host "  [2] Compare  -- Compare VBR job tag GUIDs vs live vCenter (outputs CSV)"
        Write-Host "  [3] FixJob   -- Update a VBR job's stale tag GUIDs to match vCenter"
        Write-Host "  [4] Cache    -- View, refresh, or delete the local tag cache"
        Write-Host "  [Q] Quit"
        Write-Host ""
        $choice = (Read-Host "  Select a mode (1-4 or Q)").Trim()
        switch ($choice.ToUpper()) {
            "1" { $Mode = "GetTag"  }
            "2" { $Mode = "Compare" }
            "3" { $Mode = "FixJob"  }
            "4" { $Mode = "Cache"   }
            "Q" { Write-Host "`nGoodbye." -ForegroundColor Green; exit 0 }
            default {
                Write-Warning "Invalid selection '$choice'. Please choose 1-4 or Q."
                continue
            }
        }

        # Re-prompt for tag / job as needed for the selected mode
        if ($Mode -in @("GetTag","FixJob") -and -not $TagName) {
            $TagName = Select-TagInteractively -VCenterName $VCenterServer `
                -CachePath $autoCachePath -UseCacheNow ($UseCache -or (Test-Path $autoCachePath))
        }

        if ($Mode -eq "FixJob" -and -not $JobName) {
            $allJobNames2 = @(Get-VBRJob -WarningAction SilentlyContinue |
                Sort-Object Name | Select-Object -ExpandProperty Name)
            if ($allJobNames2.Count -gt 0) {
                Write-Host "`n  Available backup jobs:" -ForegroundColor Cyan
                $JobName = Show-PickList -Prompt "Select job" -Items $allJobNames2
            } else {
                $JobName = (Read-Host "  JobName").Trim()
            }
        }
    }

    $loopIteration++

    Write-Host ""
    Write-Host "  Manage-VBRTags  |  Mode: $Mode  |  vCenter: $VCenterServer" -ForegroundColor White
    Write-Host ("  " + "-" * 58) -ForegroundColor DarkGray

    switch ($Mode) {
        "GetTag"  { Invoke-GetTag      }
        "Compare" { Invoke-Compare     }
        "FixJob"  { Invoke-FixJob      }
        "Cache"   { Invoke-CacheManage }
    }

    Write-Host ""
    if (Test-Path $autoCachePath) {
        Write-Host "  [CACHE] $autoCachePath" -ForegroundColor DarkGray
        Write-Host "          Add -UseCache to skip the live vCenter pull next time." -ForegroundColor DarkGray
    }

    if (-not $interactiveMode) { break }

    Write-Host ""
    $again = (Read-Host "  Run another operation? [Y/N]").Trim().ToUpper()
    if ($again -ne "Y") { Write-Host "`nGoodbye." -ForegroundColor Green; break }

} while ($true)
