<#
.SYNOPSIS
    Interactive Veeam port diagnostic tool.

.DESCRIPTION
    Menu-driven script that tests Veeam-required TCP ports against a target
    host. Each menu option is a direct action - no separate "run" step needed.
    Press Ctrl+C during a scan to abort and return to the menu.
    Results are color-coded: GREEN = open, RED = blocked/unreachable.

.NOTES
    Can also be run non-interactively:
      .\portest2.ps1 -Target 192.168.1.50
      .\portest2.ps1 -Target 192.168.1.50 -ScanRange
      .\portest2.ps1 -Target 192.168.1.50 -ScanRange -RangeStart 2500 -RangeEnd 2509
#>

param(
    [string]$Target,
    [switch]$ScanRange,
    [ValidateRange(2500,3300)][int]$RangeStart = 2500,
    [ValidateRange(2500,3300)][int]$RangeEnd   = 3300
)

# -- Core Veeam ports ----------------------------------------------------------
$corePorts = @(
    @{Port=10001; Description="Veeam Backup Service (VBR)"},
    @{Port=9380;  Description="Veeam Agent Management Service"},
    @{Port=6160;  Description="Veeam Installer Service"},
    @{Port=6162;  Description="Veeam Data Mover Service"},
    @{Port=2500;  Description="Data Transfer range start (2500-3300)"},
    @{Port=3300;  Description="Data Transfer range end  (2500-3300)"},
    @{Port=445;   Description="SMB - agent deploy/upgrade"},
    @{Port=135;   Description="RPC Endpoint Mapper"}
)

# -- Helper: test a single TCP port (500ms timeout) ----------------------------
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

# -- Helper: print a color-coded result line -----------------------------------
function Write-Result($port, $description, $open) {
    $status = if ($open) { "  OPEN  " } else { " FAILED " }
    $color  = if ($open) { "Green"   } else { "Red"    }
    Write-Host ("[{0}] {1,-8} {2}" -f $status, $port, $description) -ForegroundColor $color
}

# -- Helper: collapse sorted integers into human-readable ranges ---------------
function Compress-Ranges($ports) {
    if ($ports.Count -eq 0) { return }
    $start = $ports[0]; $prev = $ports[0]
    foreach ($p in $ports[1..($ports.Count - 1)]) {
        if ($p -ne $prev + 1) {
            if ($start -eq $prev) { "$start" } else { "$start - $prev" }
            $start = $p
        }
        $prev = $p
    }
    if ($start -eq $prev) { "$start" } else { "$start - $prev" }
}

# -- Helper: prompt for a valid integer within a range -------------------------
function Read-PortNumber($prompt, $min, $max, $default) {
    while ($true) {
        $raw = (Read-Host "  $prompt [$min-$max, Enter=$default]").Trim()
        if ($raw -eq "") { return $default }
        if ($raw -match '^\d+$') {
            $n = [int]$raw
            if ($n -ge $min -and $n -le $max) { return $n }
        }
        Write-Host "  Invalid - enter a number between $min and $max." -ForegroundColor Red
    }
}

# -- Helper: prompt for target if not already set ------------------------------
function Ensure-Target($current) {
    if ($current) { return $current }
    $val = (Read-Host "  Enter VBR server hostname or IP").Trim()
    if (-not $val) {
        Write-Host "  No target entered. Returning to menu." -ForegroundColor Red
        return $null
    }
    return $val
}

# -- Core port scan ------------------------------------------------------------
function Run-CoreScan($testTarget) {
    Write-Host ""
    Write-Host "-- Core Ports ------------------------------------------" -ForegroundColor Yellow
    $coreFailures = @()
    foreach ($entry in $corePorts) {
        $open = Test-Port $testTarget $entry.Port
        Write-Result $entry.Port $entry.Description $open
        if (-not $open) { $coreFailures += $entry.Port }
    }
    Write-Host ""
    if ($coreFailures.Count -eq 0) {
        Write-Host "  All core ports OPEN." -ForegroundColor Green
    } else {
        Write-Host "  Blocked core ports: $($coreFailures -join ', ')" -ForegroundColor Red
    }
}

# -- Dynamic range scan --------------------------------------------------------
function Run-RangeScan($testTarget, $scanStart, $scanEnd) {
    $total   = $scanEnd - $scanStart + 1
    $estMin  = [math]::Round($total * 0.5 / 60, 1)

    Write-Host ""
    Write-Host ("-- Dynamic Range Scan (TCP {0}-{1}) --------------------" -f $scanStart, $scanEnd) -ForegroundColor Yellow
    Write-Host ("  Scanning {0} ports, est. ~{1} min..." -f $total, $estMin) -ForegroundColor DarkCyan
    Write-Host "  Press Ctrl+C to abort and return to the menu." -ForegroundColor DarkCyan
    Write-Host ""

    $failed = @(); $open = @()
    $i = 0; $aborted = $false

    try {
        foreach ($port in $scanStart..$scanEnd) {
            try {
                if ($Host.UI.RawUI.KeyAvailable) {
                    $key = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
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

            if (Test-Port $testTarget $port) { $open += $port }
            else                             { $failed += $port }
        }
    } catch { $aborted = $true }

    Write-Progress -Completed -Activity "Scan"

    if ($aborted) {
        Write-Host ""
        Write-Host "  ** Scan aborted after $i of $total ports." -ForegroundColor Yellow
    }

    Write-Host ("  OPEN  : {0} ports" -f $open.Count)   -ForegroundColor Green
    Write-Host ("  FAILED: {0} ports" -f $failed.Count) -ForegroundColor Red

    if ($failed.Count -gt 0) {
        Write-Host ""
        Write-Host "  Blocked ranges:" -ForegroundColor Red
        Compress-Ranges $failed | ForEach-Object { Write-Host "    $_" -ForegroundColor Red }
    }

    if (-not $aborted -and $open.Count -eq $total) {
        Write-Host ("  Full range {0}-{1} is open." -f $scanStart, $scanEnd) -ForegroundColor Green
    }
}

# -- Print the run header ------------------------------------------------------
function Write-Header($testTarget) {
    Write-Host ""
    Write-Host "=======================================================" -ForegroundColor Cyan
    Write-Host "  Veeam Port Diagnostic  ->  $testTarget" -ForegroundColor Cyan
    Write-Host "  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor DarkCyan
    Write-Host "=======================================================" -ForegroundColor Cyan
}

# -- Print the done footer -----------------------------------------------------
function Write-Footer {
    Write-Host ""
    Write-Host "=======================================================" -ForegroundColor Cyan
    Write-Host "  Done. Press Enter to return to the menu." -ForegroundColor Cyan
    Write-Host "=======================================================" -ForegroundColor Cyan
    $null = Read-Host
}

# -- Non-interactive mode ------------------------------------------------------
if ($Target) {
    if ($RangeStart -gt $RangeEnd) {
        Write-Host "  Error: RangeStart ($RangeStart) must be <= RangeEnd ($RangeEnd)." -ForegroundColor Red
        exit 1
    }
    Write-Header $Target
    Run-CoreScan $Target
    if ($ScanRange) { Run-RangeScan $Target $RangeStart $RangeEnd }
    Write-Host ""
    Write-Host "=======================================================" -ForegroundColor Cyan
    Write-Host "  Done." -ForegroundColor Cyan
    Write-Host "=======================================================" -ForegroundColor Cyan
    Write-Host ""
    exit 0
}

# -- Interactive menu ----------------------------------------------------------
$menuTarget = ""
$quit       = $false

while (-not $quit) {

    $targetDisplay = if ($menuTarget) { $menuTarget } else { "(not set - will prompt when you run)" }

    Write-Host ""
    Write-Host "=======================================================" -ForegroundColor Cyan
    Write-Host "  Veeam Port Diagnostic" -ForegroundColor Cyan
    Write-Host "=======================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host ("  Target: {0}" -f $targetDisplay) -ForegroundColor White
    Write-Host ""
    Write-Host "  [1] Set / change target server" -ForegroundColor Yellow
    Write-Host "  -----------------------------------------------"
    Write-Host "  [2] Run core ports only" -ForegroundColor Green
    Write-Host "       Tests the 8 standard Veeam ports"
    Write-Host ""
    Write-Host "  [3] Run core ports + full dynamic range (2500-3300)" -ForegroundColor Green
    Write-Host "       Tests core ports, then all 801 dynamic ports"
    Write-Host ""
    Write-Host "  [4] Run core ports + custom range" -ForegroundColor Green
    Write-Host "       Tests core ports, then a sub-range you specify"
    Write-Host "  -----------------------------------------------"
    Write-Host "  [Q] Quit" -ForegroundColor Red
    Write-Host ""

    $choice = (Read-Host "  Select").Trim().ToUpper()

    switch ($choice) {
        '1' {
            $val = (Read-Host "  Enter VBR server hostname or IP").Trim()
            if ($val) {
                $menuTarget = $val
                Write-Host "  Target set to: $menuTarget" -ForegroundColor DarkCyan
            }
        }

        '2' {
            $t = Ensure-Target $menuTarget
            if ($t) {
                $menuTarget = $t
                Write-Header $t
                Run-CoreScan $t
                Write-Footer
            }
        }

        '3' {
            $t = Ensure-Target $menuTarget
            if ($t) {
                $menuTarget = $t
                Write-Header $t
                Run-CoreScan $t
                Run-RangeScan $t 2500 3300
                Write-Footer
            }
        }

        '4' {
            Write-Host ""
            Write-Host "  Enter the sub-range to scan (within 2500-3300):" -ForegroundColor DarkCyan
            $s = Read-PortNumber "Start port" 2500 3300 2500
            $e = Read-PortNumber "End port  " $s   3300 3300
            $t = Ensure-Target $menuTarget
            if ($t) {
                $menuTarget = $t
                Write-Host ""
                Write-Host ("  About to scan {0} ports ({1}-{2}) on {3}." -f ($e-$s+1), $s, $e, $t) -ForegroundColor DarkCyan
                $confirm = (Read-Host "  Press Enter to start, or [B] to go back").Trim().ToUpper()
                if ($confirm -ne 'B') {
                    Write-Header $t
                    Run-CoreScan $t
                    Run-RangeScan $t $s $e
                    Write-Footer
                }
            }
        }

        'Q' { $quit = $true }

        default { Write-Host "  Invalid choice." -ForegroundColor Red }
    }
}

Write-Host ""
Write-Host "  Goodbye." -ForegroundColor DarkCyan
Write-Host ""
