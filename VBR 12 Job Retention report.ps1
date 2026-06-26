<#
.SYNOPSIS
    Exports a full VBR job retention report to CSV - configured retention settings
    AND actual restore points currently stored on disk for every backup job.

.DESCRIPTION
    Collects the following for each Backup and Backup Copy job:
      - Configured retention (restore points or days)
      - GFS settings (weekly / monthly / yearly)
      - Deleted VM retention
      - Actual restore point count from storage
      - Newest and oldest restore point dates
      - Restore point type breakdown (Full / SyntheticFull / Increment / Rollback)
      - Last job result and last run time

.PARAMETER OutputFolder
    Folder to write the CSV to. Defaults to the script's own directory.

.PARAMETER IncludeAgentJobs
    Also collect agent (computer) backup jobs via Get-VBRComputerBackupJob.

.EXAMPLE
    .\Get-VBRJobRetentionReport.ps1
    .\Get-VBRJobRetentionReport.ps1 -OutputFolder "C:\Reports" -IncludeAgentJobs
#>

[CmdletBinding()]
param(
    [string] $OutputFolder    = "",
    [switch] $IncludeAgentJobs
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Resolve output folder here in the script body where $PSScriptRoot is guaranteed to be set.
# Fall back to current working directory if $PSScriptRoot is also empty (e.g. run via full UNC path).
if ([string]::IsNullOrEmpty($OutputFolder)) {
    $OutputFolder = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
}

# -- Helpers -------------------------------------------------------------------
function Write-Step  { param($m) Write-Host "  [>] $m" -ForegroundColor Cyan   }
function Write-OK    { param($m) Write-Host "  [+] $m" -ForegroundColor Green  }
function Write-Warn  { param($m) Write-Host "  [!] $m" -ForegroundColor Yellow }
function Write-Err   { param($m) Write-Host "  [x] $m" -ForegroundColor Red    }

function Get-RetentionString {
    <#
      Returns a human-readable configured retention string.
      Works for both standard jobs (.Options.BackupStorageOptions)
      and agent jobs (.BackupStorageOptions).
    #>
    param($Job)
    try {
        $opts = if ($Job.PSObject.Properties['Options']) {
            $Job.Options.BackupStorageOptions
        } else {
            $Job.BackupStorageOptions
        }
        if (-not $opts) { return "N/A" }

        if     ($opts.RetainCycles -gt 0) { return "$($opts.RetainCycles) pts"  }
        elseif ($opts.RetainDays   -gt 0) { return "$($opts.RetainDays) days"   }
        else                              { return "N/A" }
    } catch { return "N/A" }
}

function Get-StorageOptions {
    param($Job)
    try {
        if ($Job.PSObject.Properties['Options']) { return $Job.Options.BackupStorageOptions }
        return $Job.BackupStorageOptions
    } catch { return $null }
}

# -- Verify VBR is available ---------------------------------------------------
Write-Host ""
Write-Host "  VBR Job Retention Report" -ForegroundColor White
Write-Host "  ---------------------------------------------" -ForegroundColor DarkGray
Write-Host ""

try {
    $null = Get-VBRJob -WarningAction SilentlyContinue -ErrorAction Stop | Select-Object -First 1
} catch {
    Write-Err "Cannot reach VBR PowerShell provider. Are you running this on the VBR server?"
    Write-Err $_.Exception.Message
    exit 1
}

# -- Collect jobs --------------------------------------------------------------
Write-Step "Collecting backup and backup copy jobs..."
$standardJobs = @(
    Get-VBRJob -WarningAction SilentlyContinue |
    Where-Object { $_.JobType -eq "Backup" -or $_.JobType -eq "BackupSync" } |
    Sort-Object Name
)
Write-OK "$($standardJobs.Count) standard jobs found."

$agentJobs = @()
if ($IncludeAgentJobs) {
    Write-Step "Collecting agent (computer) backup jobs..."
    try {
        $agentJobs = @(Get-VBRComputerBackupJob -ErrorAction Stop | Sort-Object Name)
        Write-OK "$($agentJobs.Count) agent jobs found."
    } catch {
        Write-Warn "Could not retrieve agent jobs: $($_.Exception.Message)"
    }
}

# -- Pre-load restore point data (single DB round trip each) -------------------
Write-Step "Loading backup chains from VBR database..."
$allBackups = @(Get-VBRBackup)
Write-OK "$($allBackups.Count) backup chain(s) loaded."

Write-Step "Loading all restore points (this may take a moment on large environments)..."
$allRestorePoints = @(Get-VBRRestorePoint)
Write-OK "$($allRestorePoints.Count) restore point(s) loaded."

# -- Build report rows ---------------------------------------------------------
Write-Step "Building report rows..."
$rows = [System.Collections.Generic.List[PSCustomObject]]::new()

function Add-JobRow {
    param($Job, [string]$Source)

    $opts = Get-StorageOptions -Job $Job

    # -- Configured retention ---------------------------------------------
    $retainCycles = try { if ($opts) { $opts.RetainCycles } else { 0 } } catch { 0 }
    $retainDays   = try { if ($opts) { $opts.RetainDays   } else { 0 } } catch { 0 }
    $retentionStr = Get-RetentionString -Job $Job

    # -- GFS --------------------------------------------------------------
    $gfsEnabled = try { if ($opts) { [bool]$opts.EnableGFSRetentionPolicy } else { $false } } catch { $false }
    $gfsWeekly  = try { if ($gfsEnabled) { $opts.GFSWeeklyRetainCycles  } else { 0 } } catch { 0 }
    $gfsMonthly = try { if ($gfsEnabled) { $opts.GFSMonthlyRetainCycles } else { 0 } } catch { 0 }
    $gfsYearly  = try { if ($gfsEnabled) { $opts.GFSYearlyRetainCycles  } else { 0 } } catch { 0 }

    # -- Deleted VM retention ---------------------------------------------
    $delEnabled = try { if ($opts) { [bool]$opts.EnableDeletedVmDataRetention } else { $false } } catch { $false }
    $delDays    = try { if ($delEnabled) { $opts.DeletedVmRetainDays } else { 0 } } catch { 0 }

    # -- Repository -------------------------------------------------------
    $repo = try { $Job.GetTargetRepository().Name } catch { "N/A" }

    # -- Actual restore points on disk ------------------------------------
    # Match all backup chains for this job (handles multiple chains after active full)
    $jobBackups = @($allBackups | Where-Object { $_.JobName -eq $Job.Name })
    $jobPoints  = @()
    if ($jobBackups.Count -gt 0) {
        $backupIds = $jobBackups.Id
        $jobPoints = @($allRestorePoints | Where-Object { $_.BackupId -in $backupIds })
    }

    $pointCount   = $jobPoints.Count
    $newestPoint  = if ($pointCount -gt 0) {
        ($jobPoints | Sort-Object CreationTime -Descending | Select-Object -First 1).CreationTime
    } else { $null }
    $oldestPoint  = if ($pointCount -gt 0) {
        ($jobPoints | Sort-Object CreationTime | Select-Object -First 1).CreationTime
    } else { $null }

    # Restore point type breakdown
    $typeCounts   = $jobPoints | Group-Object Type
    $countFull    = ($typeCounts | Where-Object Name -eq "Full"         | Select-Object -ExpandProperty Count -ErrorAction SilentlyContinue) -as [int]
    $countSynth   = ($typeCounts | Where-Object Name -eq "SyntheticFull"| Select-Object -ExpandProperty Count -ErrorAction SilentlyContinue) -as [int]
    $countInc     = ($typeCounts | Where-Object Name -eq "Increment"    | Select-Object -ExpandProperty Count -ErrorAction SilentlyContinue) -as [int]
    $countRollback= ($typeCounts | Where-Object Name -eq "Rollback"     | Select-Object -ExpandProperty Count -ErrorAction SilentlyContinue) -as [int]

    # -- Last result / last run -------------------------------------------
    $lastResult   = try { $Job.GetLastResult().ToString()                } catch { "Unknown" }
    $lastRun      = try {
        $s = $Job.FindLastSession()
        if ($s) { $s.CreationTime } else { $null }
    } catch { $null }

    # -- Assemble row -----------------------------------------------------
    $rows.Add([PSCustomObject]@{
        JobName                  = $Job.Name
        JobType                  = $Source
        Repository               = $repo

        # Configured
        RetentionConfigured      = $retentionStr
        RetainCycles             = $retainCycles
        RetainDays               = $retainDays

        # GFS
        GFSEnabled               = $gfsEnabled
        GFSWeeklyPoints          = $gfsWeekly
        GFSMonthlyPoints         = $gfsMonthly
        GFSYearlyPoints          = $gfsYearly

        # Deleted VM
        DeletedVMRetentionEnabled = $delEnabled
        DeletedVMRetainDays      = $delDays

        # Actual on disk
        RestorePointsOnDisk      = $pointCount
        NewestRestorePoint       = if ($newestPoint) { $newestPoint.ToString("yyyy-MM-dd HH:mm:ss") } else { "" }
        OldestRestorePoint       = if ($oldestPoint) { $oldestPoint.ToString("yyyy-MM-dd HH:mm:ss") } else { "" }
        Points_Full              = $countFull
        Points_SyntheticFull     = $countSynth
        Points_Increment         = $countInc
        Points_Rollback          = $countRollback

        # Job health
        LastResult               = $lastResult
        LastRun                  = if ($lastRun) { $lastRun.ToString("yyyy-MM-dd HH:mm:ss") } else { "" }
    })
}

foreach ($job in $standardJobs) {
    $source = if ($job.JobType -eq "BackupSync") { "Backup Copy" } else { "VMware Backup" }
    Add-JobRow -Job $job -Source $source
}

foreach ($job in $agentJobs) {
    Add-JobRow -Job $job -Source "Agent Backup"
}

# -- Export CSV ----------------------------------------------------------------
if ($rows.Count -eq 0) {
    Write-Warn "No rows to export. Check that VBR has backup jobs configured."
    exit 0
}

if (-not (Test-Path $OutputFolder)) {
    New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null
}

$timestamp  = Get-Date -Format "yyyyMMdd_HHmmss"
$outputPath = Join-Path $OutputFolder "VBR_RetentionReport_$timestamp.csv"

$rows | Export-Csv -Path $outputPath -NoTypeInformation -Encoding UTF8

Write-OK "Report exported: $outputPath"
Write-Host ""

# -- Console summary -----------------------------------------------------------
Write-Host "  Summary" -ForegroundColor White
Write-Host "  -------------------------------------------------------------------" -ForegroundColor DarkGray
Write-Host ("  {0,-38} {1,-10} {2,-10} {3,-8} {4}" -f "Job Name", "Configured", "On Disk", "GFS", "Last Result") -ForegroundColor White
Write-Host ("  {0,-38} {1,-10} {2,-10} {3,-8} {4}" -f "--------", "----------", "-------", "---", "-----------") -ForegroundColor DarkGray

foreach ($r in $rows | Sort-Object JobName) {
    $gfsFlag = if ($r.GFSEnabled) { "Yes" } else { "No" }
    $color   = switch ($r.LastResult) {
        "Success" { "Green"  }
        "Warning" { "Yellow" }
        "Failed"  { "Red"    }
        default   { "Gray"   }
    }
    Write-Host ("  {0,-38} {1,-10} {2,-10} {3,-8} {4}" -f `
        ($r.JobName -replace "(.{37}).+", '$1...'),
        $r.RetentionConfigured,
        $r.RestorePointsOnDisk,
        $gfsFlag,
        $r.LastResult) -ForegroundColor $color
}

Write-Host ""
Write-Host "  Total jobs : $($rows.Count)" -ForegroundColor White
Write-Host "  Total RPs  : $(($rows | Measure-Object RestorePointsOnDisk -Sum).Sum)" -ForegroundColor White
Write-Host "  Output     : $outputPath" -ForegroundColor Cyan
Write-Host ""
