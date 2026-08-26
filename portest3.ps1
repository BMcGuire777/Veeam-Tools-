<#
.SYNOPSIS
    Veeam port diagnostic tool - remote reachability + LOCAL port conflict detection.

.DESCRIPTION
    Two kinds of check:

    REMOTE  - can this machine reach the Veeam ports on a target host?
              (same behaviour as portest2.ps1)

    LOCAL   - which process actually owns each Veeam-required port on THIS
              machine, and is it a non-Veeam process squatting on it?
              This is the pre-upgrade check: e.g. if a third-party NFS or
              ONC/RPC Portmapper service holds TCP/UDP 111, the Veeam
              vPower NFS Service will not start and a VBR upgrade fails.

    Local results are classified:
      OK        - free, or held by Veeam / Windows / the config DB as expected
      CONFLICT  - held by a process that is not the expected owner
      UNKNOWN   - a listener exists but the owner could not be resolved
                  (run the script elevated)

.NOTES
    Run ELEVATED for local checks - resolving process paths and service
    names for other users' processes requires admin.

    Non-interactive examples:
      .\portest3.ps1 -LocalCheck
      .\portest3.ps1 -LocalCheck -IncludeEnterpriseManager -IncludeCloudConnect
      .\portest3.ps1 -LocalCheck -OutFile C:\temp\portcheck.csv
      .\portest3.ps1 -Target 192.168.1.50
      .\portest3.ps1 -Target 192.168.1.50 -ScanRange -RangeStart 2500 -RangeEnd 2509

    PORT DATA: the $veeamPorts table below is the single source of truth for
    the local check. Port assignments change between VBR versions - verify
    against the "Ports" page of the User Guide for YOUR version before
    relying on this in production, and edit the table rather than the logic.
#>

[CmdletBinding()]
param(
    # Remote mode
    [string]$Target,
    [switch]$ScanRange,
    [ValidateRange(2500,3300)][int]$RangeStart = 2500,
    [ValidateRange(2500,3300)][int]$RangeEnd   = 3300,

    # Local mode
    [switch]$LocalCheck,
    [switch]$IncludeEnterpriseManager,
    [switch]$IncludeCloudConnect,
    [switch]$IncludeWanAccelerator,
    [switch]$SkipDynamicRange,
    [string]$OutFile
)

# =============================================================================
#  PORT DATA
# =============================================================================
# ExpectedOwner : Veeam | Windows | Database
#   Veeam    - a Veeam service should own this, or it should be free
#   Windows  - the OS legitimately owns this (not a conflict)
#   Database - the VBR configuration database engine owns this
# Profile : Core | EnterpriseManager | CloudConnect | WanAccelerator

$veeamPorts = @(
    # -- vPower NFS: the classic upgrade-breaking conflicts ---------------------
    @{Port=111;   Proto='TCP+UDP'; Component='Veeam vPower NFS Service (RPC portmapper)'; ExpectedOwner='Veeam'; Profile='Core';
      Notes='HIGH RISK. Not configurable. Common squatters: ONC/RPC Portmapper (portmap.exe), Windows "Server for NFS" / Services for UNIX, hanewin NFS, Arcserve, Cygwin rpcbind.'}
    @{Port=1058;  Proto='TCP+UDP'; Component='Veeam vPower NFS mount service'; ExpectedOwner='Veeam'; Profile='Core';
      Notes='Can be grabbed by RPC dynamic allocation or third-party NFS.'}
    @{Port=2049;  Proto='TCP+UDP'; Component='Veeam vPower NFS server'; ExpectedOwner='Veeam'; Profile='Core';
      Notes='HIGH RISK. Standard NFS port - any other NFS server on the box will take it.'}
    @{Port=6161;  Proto='TCP';     Component='Veeam vPower NFS Service (control)'; ExpectedOwner='Veeam'; Profile='Core'; Notes=''}

    # -- Backup server services ------------------------------------------------
    @{Port=9392;  Proto='TCP';     Component='Veeam Backup Service (console / Enterprise Manager)'; ExpectedOwner='Veeam'; Profile='Core'; Notes=''}
    @{Port=9393;  Proto='TCP';     Component='Veeam Guest Catalog Service'; ExpectedOwner='Veeam'; Profile='Core'; Notes=''}
    @{Port=9401;  Proto='TCP';     Component='Veeam Mount Service (mount server <-> backup server)'; ExpectedOwner='Veeam'; Profile='Core'; Notes=''}
    @{Port=9419;  Proto='TCP';     Component='Veeam RESTful API Service'; ExpectedOwner='Veeam'; Profile='Core';
      Notes='VBR 11+. Optional at install; skip if REST API was not installed.'}
    @{Port=9380;  Proto='TCP';     Component='Veeam Distribution Service (agent management)'; ExpectedOwner='Veeam'; Profile='Core'; Notes=''}
    @{Port=6160;  Proto='TCP';     Component='Veeam Installer Service'; ExpectedOwner='Veeam'; Profile='Core'; Notes=''}
    @{Port=6162;  Proto='TCP';     Component='Veeam Data Mover Service (transport)'; ExpectedOwner='Veeam'; Profile='Core'; Notes=''}

    # -- Configuration database ------------------------------------------------
    @{Port=5432;  Proto='TCP';     Component='PostgreSQL - VBR configuration database (VBR 12+)'; ExpectedOwner='Database'; Profile='Core';
      Notes='A second PostgreSQL instance bundled with another product will collide.'}
    @{Port=1433;  Proto='TCP';     Component='Microsoft SQL Server - VBR configuration database'; ExpectedOwner='Database'; Profile='Core';
      Notes='Only relevant if the config DB is MSSQL. Another SQL instance may hold it.'}

    # -- Operating system ports Veeam depends on -------------------------------
    @{Port=135;   Proto='TCP';     Component='RPC Endpoint Mapper (used for agent/component deploy)'; ExpectedOwner='Windows'; Profile='Core'; Notes='Owned by svchost - expected.'}
    @{Port=445;   Proto='TCP';     Component='SMB (component deploy / upgrade file copy)'; ExpectedOwner='Windows'; Profile='Core'; Notes='Owned by System - expected.'}
    @{Port=139;   Proto='TCP';     Component='NetBIOS session service'; ExpectedOwner='Windows'; Profile='Core'; Notes='Owned by System - expected.'}

    # -- Enterprise Manager ----------------------------------------------------
    @{Port=9394;  Proto='TCP';     Component='Veeam Backup Enterprise Manager Service'; ExpectedOwner='Veeam'; Profile='EnterpriseManager'; Notes=''}
    @{Port=9443;  Proto='TCP';     Component='Enterprise Manager web UI (HTTPS)'; ExpectedOwner='Veeam'; Profile='EnterpriseManager';
      Notes='Commonly taken by VMware appliances, other web consoles, IIS bindings.'}
    @{Port=9398;  Proto='TCP';     Component='Enterprise Manager RESTful API (HTTPS)'; ExpectedOwner='Veeam'; Profile='EnterpriseManager'; Notes=''}
    @{Port=9399;  Proto='TCP';     Component='Enterprise Manager RESTful API (HTTP)'; ExpectedOwner='Veeam'; Profile='EnterpriseManager'; Notes=''}

    # -- Cloud Connect ---------------------------------------------------------
    @{Port=6180;  Proto='TCP';     Component='Veeam Cloud Connect Service'; ExpectedOwner='Veeam'; Profile='CloudConnect'; Notes=''}
    @{Port=10003; Proto='TCP';     Component='Veeam Cloud Gateway'; ExpectedOwner='Veeam'; Profile='CloudConnect'; Notes=''}

    # -- WAN accelerator -------------------------------------------------------
    @{Port=6164;  Proto='TCP';     Component='Veeam WAN Accelerator Service (control)'; ExpectedOwner='Veeam'; Profile='WanAccelerator'; Notes=''}
    @{Port=6165;  Proto='TCP';     Component='Veeam WAN Accelerator Service (data)'; ExpectedOwner='Veeam'; Profile='WanAccelerator'; Notes=''}
)

# Ports commonly used by other software inside the 2500-3300 data transfer range
$knownRangeSquatters = @{
    2598 = 'Citrix ICA session reliability'
    2701 = 'SCCM / SMS remote control'
    2702 = 'SCCM / SMS remote control'
    2869 = 'Windows UPnP / SSDP event notification'
    2967 = 'Symantec Endpoint Protection'
    3050 = 'Firebird / InterBase database'
    3260 = 'iSCSI target'
    3268 = 'Active Directory Global Catalog (LDAP)'
    3269 = 'Active Directory Global Catalog (LDAPS)'
    3306 = 'MySQL / MariaDB'
}

# Remote-mode core port list (reachability only)
$corePorts = @(
    @{Port=9392;  Description='Veeam Backup Service (console/EM)'}
    @{Port=9393;  Description='Veeam Guest Catalog Service'}
    @{Port=9401;  Description='Veeam Mount Service'}
    @{Port=9419;  Description='Veeam RESTful API Service'}
    @{Port=9380;  Description='Veeam Distribution Service'}
    @{Port=6160;  Description='Veeam Installer Service'}
    @{Port=6162;  Description='Veeam Data Mover Service'}
    @{Port=6161;  Description='Veeam vPower NFS Service'}
    @{Port=2500;  Description='Data transfer range start (2500-3300)'}
    @{Port=3300;  Description='Data transfer range end   (2500-3300)'}
    @{Port=445;   Description='SMB - component deploy/upgrade'}
    @{Port=135;   Description='RPC Endpoint Mapper'}
)

$script:LastLocalResults = @()

# =============================================================================
#  SHARED HELPERS
# =============================================================================

function Test-Admin {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        return ([Security.Principal.WindowsPrincipal]$id).IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

function Write-Rule($text, $color = 'Cyan') {
    Write-Host ('-- {0} {1}' -f $text, ('-' * [math]::Max(0, 54 - $text.Length))) -ForegroundColor $color
}

# =============================================================================
#  REMOTE MODE
# =============================================================================

function Test-Port($server, $port) {
    $tcp = New-Object System.Net.Sockets.TcpClient
    try {
        $ar = $tcp.BeginConnect($server, $port, $null, $null)
        if ($ar.AsyncWaitHandle.WaitOne(500, $false)) {
            $tcp.EndConnect($ar)
            return $true
        }
        return $false
    } catch {
        return $false
    } finally {
        $tcp.Close()
    }
}

function Write-Result($port, $description, $open) {
    $status = if ($open) { '  OPEN  ' } else { ' FAILED ' }
    $color  = if ($open) { 'Green'   } else { 'Red'      }
    Write-Host ('[{0}] {1,-8} {2}' -f $status, $port, $description) -ForegroundColor $color
}

function Compress-Ranges($ports) {
    if (-not $ports -or $ports.Count -eq 0) { return }
    $sorted = @($ports | Sort-Object)
    $start = $sorted[0]; $prev = $sorted[0]
    if ($sorted.Count -gt 1) {
        foreach ($p in $sorted[1..($sorted.Count - 1)]) {
            if ($p -ne $prev + 1) {
                if ($start -eq $prev) { "$start" } else { "$start - $prev" }
                $start = $p
            }
            $prev = $p
        }
    }
    if ($start -eq $prev) { "$start" } else { "$start - $prev" }
}

function Read-PortNumber($prompt, $min, $max, $default) {
    while ($true) {
        $raw = (Read-Host "  $prompt [$min-$max, Enter=$default]").Trim()
        if ($raw -eq '') { return $default }
        if ($raw -match '^\d+$') {
            $n = [int]$raw
            if ($n -ge $min -and $n -le $max) { return $n }
        }
        Write-Host "  Invalid - enter a number between $min and $max." -ForegroundColor Red
    }
}

function Ensure-Target($current) {
    if ($current) { return $current }
    $val = (Read-Host '  Enter VBR server hostname or IP').Trim()
    if (-not $val) {
        Write-Host '  No target entered. Returning to menu.' -ForegroundColor Red
        return $null
    }
    return $val
}

function Invoke-CoreScan($testTarget) {
    Write-Host ''
    Write-Rule 'Core Ports' 'Yellow'
    $coreFailures = @()
    foreach ($entry in $corePorts) {
        $open = Test-Port $testTarget $entry.Port
        Write-Result $entry.Port $entry.Description $open
        if (-not $open) { $coreFailures += $entry.Port }
    }
    Write-Host ''
    if ($coreFailures.Count -eq 0) {
        Write-Host '  All core ports OPEN.' -ForegroundColor Green
    } else {
        Write-Host "  Blocked core ports: $($coreFailures -join ', ')" -ForegroundColor Red
    }
}

function Invoke-RangeScan($testTarget, $scanStart, $scanEnd) {
    $total  = $scanEnd - $scanStart + 1
    $estMin = [math]::Round($total * 0.5 / 60, 1)

    Write-Host ''
    Write-Rule ('Dynamic Range Scan (TCP {0}-{1})' -f $scanStart, $scanEnd) 'Yellow'
    Write-Host ('  Scanning {0} ports, est. ~{1} min...' -f $total, $estMin) -ForegroundColor DarkCyan
    Write-Host '  Press Ctrl+C to abort and return to the menu.' -ForegroundColor DarkCyan
    Write-Host ''

    $failed = @(); $open = @()
    $i = 0; $aborted = $false

    try {
        foreach ($port in $scanStart..$scanEnd) {
            try {
                if ($Host.UI.RawUI.KeyAvailable) {
                    $key = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
                    if ($key.VirtualKeyCode -eq 67 -and
                        ($key.ControlKeyState -band [System.Management.Automation.Host.ControlKeyStates]::LeftCtrlPressed -or
                         $key.ControlKeyState -band [System.Management.Automation.Host.ControlKeyStates]::RightCtrlPressed)) {
                        $aborted = $true; break
                    }
                }
            } catch { }

            $i++
            Write-Progress -Activity "Scanning $testTarget" `
                           -Status "Port $port  ($i of $total)" `
                           -PercentComplete (($i / $total) * 100)

            if (Test-Port $testTarget $port) { $open += $port } else { $failed += $port }
        }
    } catch { $aborted = $true }

    Write-Progress -Completed -Activity 'Scan'

    if ($aborted) {
        Write-Host ''
        Write-Host "  ** Scan aborted after $i of $total ports." -ForegroundColor Yellow
    }

    Write-Host ('  OPEN  : {0} ports' -f $open.Count)   -ForegroundColor Green
    Write-Host ('  FAILED: {0} ports' -f $failed.Count) -ForegroundColor Red

    if ($failed.Count -gt 0) {
        Write-Host ''
        Write-Host '  Blocked ranges:' -ForegroundColor Red
        Compress-Ranges $failed | ForEach-Object { Write-Host "    $_" -ForegroundColor Red }
    }

    if (-not $aborted -and $open.Count -eq $total) {
        Write-Host ('  Full range {0}-{1} is open.' -f $scanStart, $scanEnd) -ForegroundColor Green
    }
}

# =============================================================================
#  LOCAL MODE - listener inventory
# =============================================================================

# Returns @{ TCP = @{port -> @(pids)}; UDP = @{port -> @(pids)} }
function Get-ListenerMap {
    $tcp = @{}
    $udp = @{}
    $usedFallback = $false

    if (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue) {
        foreach ($c in @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue)) {
            $p = [int]$c.LocalPort
            if (-not $tcp.ContainsKey($p)) { $tcp[$p] = @() }
            if ($tcp[$p] -notcontains $c.OwningProcess) { $tcp[$p] += [int]$c.OwningProcess }
        }
        foreach ($u in @(Get-NetUDPEndpoint -ErrorAction SilentlyContinue)) {
            $p = [int]$u.LocalPort
            if (-not $udp.ContainsKey($p)) { $udp[$p] = @() }
            if ($udp[$p] -notcontains $u.OwningProcess) { $udp[$p] += [int]$u.OwningProcess }
        }
    } else {
        # Fallback for older OS / PowerShell without the NetTCPIP module
        $usedFallback = $true
        foreach ($line in (netstat -ano)) {
            $t = $line.Trim()
            if ($t -match '^TCP\s+\S+:(\d+)\s+\S+\s+LISTENING\s+(\d+)$') {
                $p = [int]$Matches[1]; $procId = [int]$Matches[2]
                if (-not $tcp.ContainsKey($p)) { $tcp[$p] = @() }
                if ($tcp[$p] -notcontains $procId) { $tcp[$p] += $procId }
            } elseif ($t -match '^UDP\s+\S+:(\d+)\s+\S+\s+(\d+)$') {
                $p = [int]$Matches[1]; $procId = [int]$Matches[2]
                if (-not $udp.ContainsKey($p)) { $udp[$p] = @() }
                if ($udp[$p] -notcontains $procId) { $udp[$p] += $procId }
            }
        }
    }

    return @{ TCP = $tcp; UDP = $udp; Fallback = $usedFallback }
}

# pid -> @{ Name; Path; Company; Services }
function Get-ProcessMap {
    $map = @{}

    $svcByPid = @{}
    try {
        foreach ($s in @(Get-CimInstance Win32_Service -ErrorAction Stop |
                         Where-Object { $_.ProcessId -and $_.ProcessId -gt 0 })) {
            $k = [int]$s.ProcessId
            if (-not $svcByPid.ContainsKey($k)) { $svcByPid[$k] = @() }
            $svcByPid[$k] += $s.Name
        }
    } catch { }

    foreach ($p in @(Get-Process -ErrorAction SilentlyContinue)) {
        $path = ''; $company = ''
        try { $path    = $p.Path } catch { }
        try { $company = $p.Company } catch { }
        $map[[int]$p.Id] = @{
            Name     = $p.ProcessName
            Path     = $path
            Company  = $company
            Services = if ($svcByPid.ContainsKey([int]$p.Id)) { $svcByPid[[int]$p.Id] } else { @() }
        }
    }
    return $map
}

function Get-OwnerDescription($procId, $procMap) {
    if ($procId -eq 0 -or $procId -eq 4) { return 'System (kernel)' }
    if (-not $procMap.ContainsKey([int]$procId)) { return "PID $procId (unresolved)" }
    $info = $procMap[[int]$procId]
    $desc = '{0} (PID {1})' -f $info.Name, $procId
    if ($info.Services.Count -gt 0) { $desc += ' svc: ' + ($info.Services -join ',') }
    return $desc
}

function Get-OwnerClass($procId, $procMap) {
    if ($procId -eq 0 -or $procId -eq 4) { return 'Windows' }
    if (-not $procMap.ContainsKey([int]$procId)) { return 'Unknown' }

    $info = $procMap[[int]$procId]
    $hay  = ('{0} {1} {2} {3}' -f $info.Name, $info.Path, $info.Company, ($info.Services -join ' '))

    if ($hay -match '(?i)veeam')                                  { return 'Veeam' }
    if ($info.Name -match '(?i)^(postgres|sqlservr|mysqld|mariadbd)$') { return 'Database' }
    if ($info.Name -match '(?i)^(System|Idle|svchost|lsass|services|spoolsv|wininit|dns|Registry)$') { return 'Windows' }
    if ($info.Path -and $info.Path -match '(?i)^[A-Z]:\\Windows\\')    { return 'Windows' }
    return 'ThirdParty'
}

function Get-VeeamServiceState {
    $svcs = @()
    try {
        $svcs = @(Get-Service -ErrorAction SilentlyContinue |
                  Where-Object { $_.Name -like 'Veeam*' -or $_.DisplayName -like 'Veeam*' })
    } catch { }
    return $svcs
}

# =============================================================================
#  LOCAL MODE - the conflict check
# =============================================================================

function Invoke-LocalConflictCheck {
    param(
        [switch]$WithEM,
        [switch]$WithCC,
        [switch]$WithWan,
        [switch]$NoRange
    )

    if (-not (Test-Admin)) {
        Write-Host ''
        Write-Host '  ! Not running elevated. Process owners for other accounts may show as' -ForegroundColor Yellow
        Write-Host '    UNKNOWN. Re-run PowerShell as Administrator for complete results.' -ForegroundColor Yellow
    }

    Write-Host ''
    Write-Rule 'Collecting listeners and process owners' 'Yellow'
    $listeners = Get-ListenerMap
    $procMap   = Get-ProcessMap

    if ($listeners.Fallback) {
        Write-Host '  (NetTCPIP module unavailable - used netstat fallback.)' -ForegroundColor DarkYellow
    }
    Write-Host ('  {0} TCP listening ports, {1} UDP endpoints, {2} processes.' -f
        $listeners.TCP.Count, $listeners.UDP.Count, $procMap.Count) -ForegroundColor DarkCyan

    # Which profiles are in scope
    $profiles = @('Core')
    if ($WithEM)  { $profiles += 'EnterpriseManager' }
    if ($WithCC)  { $profiles += 'CloudConnect' }
    if ($WithWan) { $profiles += 'WanAccelerator' }

    $results = @()

    foreach ($entry in ($veeamPorts | Where-Object { $profiles -contains $_.Profile })) {
        $protos = @()
        if ($entry.Proto -like '*TCP*') { $protos += 'TCP' }
        if ($entry.Proto -like '*UDP*') { $protos += 'UDP' }

        foreach ($proto in $protos) {
            $table = if ($proto -eq 'TCP') { $listeners.TCP } else { $listeners.UDP }
            $pids  = if ($table.ContainsKey([int]$entry.Port)) { $table[[int]$entry.Port] } else { @() }

            if ($pids.Count -eq 0) {
                $results += [pscustomobject]@{
                    Port      = $entry.Port
                    Protocol  = $proto
                    Component = $entry.Component
                    Status    = 'FREE'
                    Owner     = ''
                    OwnerType = ''
                    Notes     = $entry.Notes
                }
                continue
            }

            foreach ($procId in $pids) {
                $class = Get-OwnerClass $procId $procMap
                $owner = Get-OwnerDescription $procId $procMap

                $status = switch ($class) {
                    'Unknown' { 'UNKNOWN' }
                    default   { if ($class -eq $entry.ExpectedOwner) { 'OK' } else { 'CONFLICT' } }
                }

                $results += [pscustomobject]@{
                    Port      = $entry.Port
                    Protocol  = $proto
                    Component = $entry.Component
                    Status    = $status
                    Owner     = $owner
                    OwnerType = $class
                    Notes     = $entry.Notes
                }
            }
        }
    }

    # -- Dynamic data transfer range 2500-3300 --------------------------------
    $rangeConflicts = @()
    if (-not $NoRange) {
        foreach ($port in @($listeners.TCP.Keys | Where-Object { $_ -ge 2500 -and $_ -le 3300 } | Sort-Object)) {
            foreach ($procId in $listeners.TCP[[int]$port]) {
                $class = Get-OwnerClass $procId $procMap
                if ($class -eq 'Veeam') { continue }
                $note = if ($knownRangeSquatters.ContainsKey([int]$port)) { $knownRangeSquatters[[int]$port] } else { '' }
                $row = [pscustomobject]@{
                    Port      = $port
                    Protocol  = 'TCP'
                    Component = 'Data transfer range 2500-3300'
                    Status    = if ($class -eq 'Unknown') { 'UNKNOWN' } else { 'CONFLICT' }
                    Owner     = Get-OwnerDescription $procId $procMap
                    OwnerType = $class
                    Notes     = $note
                }
                $rangeConflicts += $row
                $results += $row
            }
        }
    }

    $script:LastLocalResults = $results

    # -- Report ---------------------------------------------------------------
    Write-Host ''
    Write-Rule 'Veeam Port Ownership' 'Yellow'
    Write-Host ''
    Write-Host ('  {0,-6} {1,-5} {2,-9} {3}' -f 'PORT','PROTO','STATUS','OWNER / COMPONENT') -ForegroundColor White
    Write-Host ('  ' + ('-' * 72)) -ForegroundColor DarkGray

    foreach ($r in ($results | Where-Object { $_.Component -ne 'Data transfer range 2500-3300' })) {
        $color = switch ($r.Status) {
            'CONFLICT' { 'Red' }
            'UNKNOWN'  { 'Yellow' }
            'OK'       { 'Green' }
            default    { 'DarkGray' }
        }
        $right = if ($r.Owner) { $r.Owner } else { $r.Component }
        Write-Host ('  {0,-6} {1,-5} {2,-9} {3}' -f $r.Port, $r.Protocol, $r.Status, $right) -ForegroundColor $color
        if ($r.Status -ne 'OK' -and $r.Status -ne 'FREE') {
            Write-Host ('           -> needs: {0}' -f $r.Component) -ForegroundColor DarkGray
        }
    }

    if (-not $NoRange) {
        Write-Host ''
        Write-Rule 'Data Transfer Range 2500-3300 (local listeners)' 'Yellow'
        if ($rangeConflicts.Count -eq 0) {
            Write-Host '  No non-Veeam process is listening in the range.' -ForegroundColor Green
        } else {
            Write-Host ('  {0} non-Veeam listener(s) inside the range:' -f $rangeConflicts.Count) -ForegroundColor Red
            foreach ($r in $rangeConflicts) {
                $line = '    {0,-6} {1}' -f $r.Port, $r.Owner
                if ($r.Notes) { $line += '  [' + $r.Notes + ']' }
                Write-Host $line -ForegroundColor Red
            }
            Write-Host ''
            Write-Host '  Veeam allocates data mover connections from this range. A few occupied' -ForegroundColor DarkCyan
            Write-Host '  ports are usually tolerable; large blocks are not. Consider narrowing' -ForegroundColor DarkCyan
            Write-Host '  the Veeam range or moving the other service.' -ForegroundColor DarkCyan
        }
    }

    # -- Veeam service state --------------------------------------------------
    $veeamSvcs = Get-VeeamServiceState
    if ($veeamSvcs.Count -gt 0) {
        Write-Host ''
        Write-Rule 'Veeam Services On This Host' 'Yellow'
        foreach ($s in $veeamSvcs) {
            $color = if ($s.Status -eq 'Running') { 'Green' } else { 'Yellow' }
            Write-Host ('  {0,-9} {1}' -f $s.Status, $s.DisplayName) -ForegroundColor $color
        }
        $stopped = @($veeamSvcs | Where-Object { $_.Status -ne 'Running' })
        if ($stopped.Count -gt 0) {
            Write-Host ''
            Write-Host ('  {0} Veeam service(s) not running. If one of these owns a port above,' -f $stopped.Count) -ForegroundColor Yellow
            Write-Host '  that port will read FREE now but must still be free at upgrade time.' -ForegroundColor Yellow
        }
    } else {
        Write-Host ''
        Write-Host '  No Veeam services found - treating this as a pre-install / pre-upgrade host.' -ForegroundColor DarkCyan
    }

    # -- Verdict --------------------------------------------------------------
    $conflicts = @($results | Where-Object { $_.Status -eq 'CONFLICT' })
    $unknowns  = @($results | Where-Object { $_.Status -eq 'UNKNOWN' })

    Write-Host ''
    Write-Host '=======================================================' -ForegroundColor Cyan
    if ($conflicts.Count -eq 0 -and $unknowns.Count -eq 0) {
        Write-Host '  RESULT: No port conflicts detected.' -ForegroundColor Green
    } else {
        if ($conflicts.Count -gt 0) {
            Write-Host ('  RESULT: {0} CONFLICT(S) - resolve before upgrading VBR.' -f $conflicts.Count) -ForegroundColor Red
            Write-Host ''
            foreach ($c in $conflicts) {
                Write-Host ('  * {0}/{1} held by {2}' -f $c.Port, $c.Protocol, $c.Owner) -ForegroundColor Red
                Write-Host ('    Needed by: {0}' -f $c.Component) -ForegroundColor DarkGray
                if ($c.Notes) { Write-Host ('    {0}' -f $c.Notes) -ForegroundColor DarkGray }
            }
        }
        if ($unknowns.Count -gt 0) {
            Write-Host ''
            Write-Host ('  {0} port(s) have an unresolvable owner - re-run elevated.' -f $unknowns.Count) -ForegroundColor Yellow
        }
    }
    Write-Host '=======================================================' -ForegroundColor Cyan

    return $results
}

function Show-LocalInventory {
    Write-Host ''
    Write-Rule 'All TCP Listeners On This Host' 'Yellow'
    $listeners = Get-ListenerMap
    $procMap   = Get-ProcessMap

    Write-Host ''
    Write-Host ('  {0,-6} {1,-12} {2}' -f 'PORT','TYPE','OWNER') -ForegroundColor White
    Write-Host ('  ' + ('-' * 72)) -ForegroundColor DarkGray
    foreach ($port in @($listeners.TCP.Keys | Sort-Object)) {
        foreach ($procId in $listeners.TCP[[int]$port]) {
            $class = Get-OwnerClass $procId $procMap
            $color = switch ($class) {
                'Veeam'    { 'Green' }
                'Windows'  { 'DarkGray' }
                'Database' { 'Cyan' }
                'Unknown'  { 'Yellow' }
                default    { 'White' }
            }
            Write-Host ('  {0,-6} {1,-12} {2}' -f $port, $class, (Get-OwnerDescription $procId $procMap)) -ForegroundColor $color
        }
    }
}

function Export-LocalResults($path) {
    if (-not $script:LastLocalResults -or $script:LastLocalResults.Count -eq 0) {
        Write-Host '  Nothing to export - run the local conflict check first.' -ForegroundColor Red
        return
    }
    try {
        $script:LastLocalResults |
            Select-Object Port, Protocol, Status, OwnerType, Owner, Component, Notes |
            Sort-Object Status, Port |
            Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
        Write-Host ("  Exported $($script:LastLocalResults.Count) rows to $path") -ForegroundColor Green
    } catch {
        Write-Host "  Export failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# =============================================================================
#  HEADERS / FOOTERS
# =============================================================================

function Write-Header($testTarget) {
    Write-Host ''
    Write-Host '=======================================================' -ForegroundColor Cyan
    Write-Host "  Veeam Port Diagnostic  ->  $testTarget" -ForegroundColor Cyan
    Write-Host "  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor DarkCyan
    Write-Host '=======================================================' -ForegroundColor Cyan
}

function Write-LocalHeader {
    Write-Host ''
    Write-Host '=======================================================' -ForegroundColor Cyan
    Write-Host "  Veeam Local Port Conflict Check  ->  $env:COMPUTERNAME" -ForegroundColor Cyan
    Write-Host "  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor DarkCyan
    Write-Host '=======================================================' -ForegroundColor Cyan
}

function Write-Footer {
    Write-Host ''
    Write-Host '=======================================================' -ForegroundColor Cyan
    Write-Host '  Done. Press Enter to return to the menu.' -ForegroundColor Cyan
    Write-Host '=======================================================' -ForegroundColor Cyan
    $null = Read-Host
}

# =============================================================================
#  NON-INTERACTIVE ENTRY POINTS
# =============================================================================

if ($LocalCheck) {
    Write-LocalHeader
    Invoke-LocalConflictCheck -WithEM:$IncludeEnterpriseManager `
                              -WithCC:$IncludeCloudConnect `
                              -WithWan:$IncludeWanAccelerator `
                              -NoRange:$SkipDynamicRange | Out-Null
    if ($OutFile) { Export-LocalResults $OutFile }
    Write-Host ''
    exit 0
}

if ($Target) {
    if ($RangeStart -gt $RangeEnd) {
        Write-Host "  Error: RangeStart ($RangeStart) must be <= RangeEnd ($RangeEnd)." -ForegroundColor Red
        exit 1
    }
    Write-Header $Target
    Invoke-CoreScan $Target
    if ($ScanRange) { Invoke-RangeScan $Target $RangeStart $RangeEnd }
    Write-Host ''
    Write-Host '=======================================================' -ForegroundColor Cyan
    Write-Host '  Done.' -ForegroundColor Cyan
    Write-Host '=======================================================' -ForegroundColor Cyan
    Write-Host ''
    exit 0
}

# =============================================================================
#  INTERACTIVE MENU
# =============================================================================

$menuTarget = ''
$optEM      = $false
$optCC      = $false
$optWan     = $false
$quit       = $false

while (-not $quit) {

    $targetDisplay = if ($menuTarget) { $menuTarget } else { '(not set - will prompt when you run)' }
    $extras = @()
    if ($optEM)  { $extras += 'EM' }
    if ($optCC)  { $extras += 'CloudConnect' }
    if ($optWan) { $extras += 'WAN' }
    $extrasDisplay = if ($extras.Count -gt 0) { $extras -join ', ' } else { 'none' }

    Write-Host ''
    Write-Host '=======================================================' -ForegroundColor Cyan
    Write-Host '  Veeam Port Diagnostic' -ForegroundColor Cyan
    Write-Host '=======================================================' -ForegroundColor Cyan
    Write-Host ''
    Write-Host ('  This host      : {0}' -f $env:COMPUTERNAME) -ForegroundColor White
    Write-Host ('  Remote target  : {0}' -f $targetDisplay) -ForegroundColor White
    Write-Host ('  Extra profiles : {0}' -f $extrasDisplay) -ForegroundColor White
    Write-Host ''
    Write-Host '  LOCAL - what is using the ports on THIS server' -ForegroundColor Magenta
    Write-Host '  [1] Port conflict check (pre-upgrade)' -ForegroundColor Green
    Write-Host '       Flags non-Veeam processes holding Veeam-required ports'
    Write-Host '  [2] Full listener inventory' -ForegroundColor Green
    Write-Host '       Every TCP listener with its owning process/service'
    Write-Host '  [3] Export last conflict check to CSV' -ForegroundColor Green
    Write-Host '  [4] Toggle extra profiles (EM / Cloud Connect / WAN)' -ForegroundColor Yellow
    Write-Host '  -----------------------------------------------'
    Write-Host '  REMOTE - can this host reach a target' -ForegroundColor Magenta
    Write-Host '  [5] Set / change target server' -ForegroundColor Yellow
    Write-Host '  [6] Core ports only' -ForegroundColor Green
    Write-Host '  [7] Core ports + full dynamic range (2500-3300)' -ForegroundColor Green
    Write-Host '  [8] Core ports + custom range' -ForegroundColor Green
    Write-Host '  -----------------------------------------------'
    Write-Host '  [Q] Quit' -ForegroundColor Red
    Write-Host ''

    $choice = (Read-Host '  Select').Trim().ToUpper()

    switch ($choice) {

        '1' {
            Write-LocalHeader
            Invoke-LocalConflictCheck -WithEM:$optEM -WithCC:$optCC -WithWan:$optWan | Out-Null
            Write-Footer
        }

        '2' {
            Show-LocalInventory
            Write-Footer
        }

        '3' {
            $default = Join-Path $env:TEMP ('VeeamPortCheck_{0}_{1}.csv' -f $env:COMPUTERNAME, (Get-Date -Format 'yyyyMMdd_HHmmss'))
            $path = (Read-Host "  CSV path [Enter=$default]").Trim()
            if (-not $path) { $path = $default }
            Export-LocalResults $path
        }

        '4' {
            Write-Host ''
            Write-Host '  [A] Enterprise Manager  [B] Cloud Connect  [C] WAN Accelerator' -ForegroundColor DarkCyan
            $t = (Read-Host '  Toggle which').Trim().ToUpper()
            switch ($t) {
                'A' { $optEM  = -not $optEM;  Write-Host "  Enterprise Manager: $optEM" -ForegroundColor DarkCyan }
                'B' { $optCC  = -not $optCC;  Write-Host "  Cloud Connect: $optCC"      -ForegroundColor DarkCyan }
                'C' { $optWan = -not $optWan; Write-Host "  WAN Accelerator: $optWan"   -ForegroundColor DarkCyan }
                default { Write-Host '  No change.' -ForegroundColor Red }
            }
        }

        '5' {
            $val = (Read-Host '  Enter VBR server hostname or IP').Trim()
            if ($val) {
                $menuTarget = $val
                Write-Host "  Target set to: $menuTarget" -ForegroundColor DarkCyan
            }
        }

        '6' {
            $t = Ensure-Target $menuTarget
            if ($t) {
                $menuTarget = $t
                Write-Header $t
                Invoke-CoreScan $t
                Write-Footer
            }
        }

        '7' {
            $t = Ensure-Target $menuTarget
            if ($t) {
                $menuTarget = $t
                Write-Header $t
                Invoke-CoreScan $t
                Invoke-RangeScan $t 2500 3300
                Write-Footer
            }
        }

        '8' {
            Write-Host ''
            Write-Host '  Enter the sub-range to scan (within 2500-3300):' -ForegroundColor DarkCyan
            $s = Read-PortNumber 'Start port' 2500 3300 2500
            $e = Read-PortNumber 'End port  ' $s   3300 3300
            $t = Ensure-Target $menuTarget
            if ($t) {
                $menuTarget = $t
                Write-Host ''
                Write-Host ('  About to scan {0} ports ({1}-{2}) on {3}.' -f ($e-$s+1), $s, $e, $t) -ForegroundColor DarkCyan
                $confirm = (Read-Host '  Press Enter to start, or [B] to go back').Trim().ToUpper()
                if ($confirm -ne 'B') {
                    Write-Header $t
                    Invoke-CoreScan $t
                    Invoke-RangeScan $t $s $e
                    Write-Footer
                }
            }
        }

        'Q' { $quit = $true }

        default { Write-Host '  Invalid choice.' -ForegroundColor Red }
    }
}

Write-Host ''
Write-Host '  Goodbye.' -ForegroundColor DarkCyan
Write-Host ''
