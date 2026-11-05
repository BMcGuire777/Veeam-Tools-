<#
.SYNOPSIS
    Two-ended TCP path diagnostic. Locates WHERE a half-open TCP handshake dies.

.DESCRIPTION
    Built for the failure where a server receives SYNs and generates SYN-ACKs, but the
    client's firewall sessions age out with no returning packets. A one-ended connect
    test cannot solve this: "FAILED" looks identical whether the SYN died outbound or
    the SYN-ACK died on the way back. This script is designed to be run on BOTH ends
    and the two reports compared.

    Per end it collects:
      - Interface identity and the egress source address the stack will actually use
      - DNS forward + reverse, and multi-A-record detection
      - Find-NetRoute selection, next hop, and ECMP / multiple-default-route detection
      - The dynamic (ephemeral) port range - see the firewall-scope note in the README
      - Windows Firewall profile state and any rule touching the service port
      - ICMP traceroute toward the peer
      - TCP traceroute on the actual service port (raw ICMP listener + TTL-limited SYN)
      - A TCP connect test that CLASSIFIES the failure instead of returning true/false
      - An optional pktmon capture, converted to pcapng, with drop reasons extracted

    -Compare then diffs two reports and reports path asymmetry, NAT, and route problems.

.PARAMETER Peer
    Hostname or IP of the other end.

.PARAMETER Port
    Service port(s) to test. Defaults to the Veeam data mover ports.

.PARAMETER Role
    Free-text label for this end, e.g. 'source-proxy' or 'destination-server'.
    Used in filenames and in the compare output.

.PARAMETER TimeoutMs
    TCP connect timeout. Default 5000. Do NOT lower this for a WAN target -
    the 500 ms default in the older portest toolkit reports every WAN port as blocked.

.PARAMETER Capture
    Wrap the tests in a pktmon capture filtered to the peer and service port.

.PARAMETER StartAt
    Wait until this wall-clock time before starting, so both ends run together.
    Accepts 'HH:mm:ss' (local) or a full datetime. Example: -StartAt '14:30:00'

.PARAMETER NoTcpPath
    Skip the TCP traceroute (which needs a raw socket). ICMP trace still runs.

.PARAMETER OutDir
    Where reports land. Defaults to the script directory.

.PARAMETER Compare
    Two report .json paths. Runs analysis only, collects nothing.

.EXAMPLE
    # On the source proxy, and on 10.201.21.10, at the same moment:
    .\Invoke-PathDiag.ps1 -Peer 10.201.21.10 -Port 6162 -Role source-proxy -Capture -StartAt '14:30:00'
    .\Invoke-PathDiag.ps1 -Peer 10.10.5.20   -Port 6162 -Role dest-server  -Capture -StartAt '14:30:00'

.EXAMPLE
    .\Invoke-PathDiag.ps1 -Compare .\pathdiag-source-proxy-*.json, .\pathdiag-dest-server-*.json

.NOTES
    PowerShell 5.1 compatible. Run elevated - the raw-socket TCP trace, pktmon, and
    some firewall queries all require it.

    Exit codes:
      0  Collection or comparison completed
      1  Completed, but a likely root cause was flagged
      2  Could not run (not elevated, bad parameters, peer did not resolve)
#>

[CmdletBinding(DefaultParameterSetName = 'Collect')]
param(
    [Parameter(ParameterSetName = 'Collect', Mandatory = $true, Position = 0)]
    [string]$Peer,

    # Explicit ports. Combined with -PortSet; if neither is given, Core is used.
    [Parameter(ParameterSetName = 'Collect')]
    [int[]]$Port,

    # Named groups from the Veeam port catalog. Combine freely:
    #   -PortSet DataMover,VPowerNfs
    [Parameter(ParameterSetName = 'Collect')]
    [ValidateSet('Core', 'DataMover', 'VPowerNfs', 'EnterpriseManager', 'CloudConnect',
                 'WanAccelerator', 'Database', 'VeeamOne', 'Os', 'GuestProcessing',
                 'Dependencies', 'All')]
    [string[]]$PortSet,

    # TCP traceroute is slow - up to MaxHops x HopTimeout per port. Tracing a
    # 12-port set would run for minutes, so only this many ports are traced, and
    # the ones whose connect FAILED are chosen first because that is where the
    # path actually matters. 0 disables tracing entirely.
    [Parameter(ParameterSetName = 'Collect')]
    [ValidateRange(0, 64)]
    [int]$TraceLimit = 2,

    [Parameter(ParameterSetName = 'Collect')]
    [string]$Role = $env:COMPUTERNAME,

    [Parameter(ParameterSetName = 'Collect')]
    [ValidateRange(500, 120000)]
    [int]$TimeoutMs = 5000,

    [Parameter(ParameterSetName = 'Collect')]
    [switch]$Capture,

    [Parameter(ParameterSetName = 'Collect')]
    [string]$StartAt,

    [Parameter(ParameterSetName = 'Collect')]
    [switch]$NoTcpPath,

    [Parameter(ParameterSetName = 'Collect')]
    [ValidateRange(1, 64)]
    [int]$MaxHops = 30,

    [Parameter(ParameterSetName = 'Collect')]
    [string]$OutDir,

    [Parameter(ParameterSetName = 'Compare', Mandatory = $true)]
    [string[]]$Compare,

    # Emit the report object to the pipeline so you can keep working with it:
    #   $r = .\Invoke-PathDiag.ps1 -Peer x -PassThru
    # Without this the console output stays clean and the report is still available
    # afterwards as $global:PathDiagLastReport.
    [switch]$PassThru,

    # Call exit and terminate the host process. OFF by default - see the note on
    # session safety below. Turn it on for CI or a scheduled task that reads
    # %ERRORLEVEL%.
    [switch]$ExitWithCode,

    # Hold the window open at the end. By default this happens automatically when
    # the host was started with -File or -Command (Run with PowerShell, a shortcut,
    # a .bat), because that host closes the moment the script returns no matter
    # what the script does. -NoPause suppresses it.
    [switch]$KeepOpen,
    [switch]$NoPause
)

# ---- session safety ---------------------------------------------------------
# This script must never take the caller's session down with it. 'exit' inside a
# .ps1 kills the whole process when the file is dot-sourced or launched with
# powershell.exe -File, so the result code is published through $LASTEXITCODE and
# a return value instead, and 'exit' is only reached under -ExitWithCode.
# Preferences are saved and restored for the same reason: a diagnostic should not
# leave the caller's shell configured differently than it found it.
$script:PriorErrorActionPreference = $ErrorActionPreference
$script:PriorProgressPreference    = $ProgressPreference
$ErrorActionPreference = 'Continue'

$script:Findings = New-Object System.Collections.ArrayList

function Restore-PathDiagPreference {
    # Set-Variable with an explicit scope, NOT a plain assignment. A bare
    # "$ErrorActionPreference = ..." inside a function creates a function-local
    # variable and restores nothing. Script scope is the caller's own scope when
    # this file is dot-sourced, which is the only case where the restore matters.
    # Idempotent, so the outer finally can call it again safely.
    Set-Variable -Name ErrorActionPreference -Value $script:PriorErrorActionPreference -Scope Script
    Set-Variable -Name ProgressPreference    -Value $script:PriorProgressPreference    -Scope Script
}

function Complete-PathDiag {
    param([int]$Code)
    Restore-PathDiagPreference
    $global:LASTEXITCODE = $Code
    if ($ExitWithCode) { exit $Code }
}

# Why this exists: when powershell.exe is started with -File or -Command, the HOST
# process terminates as soon as the script returns. That is the host's behaviour,
# not the script's - removing every 'exit' from this file cannot prevent it, which
# is why the window still vanished. "Run with PowerShell" from Explorer, a desktop
# shortcut, and a .bat wrapper all launch that way. The only in-script remedy is to
# block before returning.
function Test-HostWillClose {
    try {
        # Never block something that has no one watching it.
        if (-not [Environment]::UserInteractive) { return $false }
        if ($Host.Name -ne 'ConsoleHost') { return $false }   # ISE, VS Code: no close

        $cmdArgs = @([Environment]::GetCommandLineArgs())
        # -NoExit means the host was told to stay; nothing to do.
        if (@($cmdArgs | Where-Object { $_ -match '^[-/]{1,2}noe' }).Count -gt 0) { return $false }
        if (@($cmdArgs | Where-Object { $_ -match '^[-/]{1,2}f(ile)?$' }).Count -gt 0) { return $true }
        if (@($cmdArgs | Where-Object { $_ -match '^[-/]{1,2}c(ommand)?$' }).Count -gt 0) { return $true }
        return $false
    } catch { return $false }
}

function Suspend-ForOperator {
    param([string]$Reason)
    Write-Host ''
    Write-Host ('-' * 74) -ForegroundColor DarkGray
    if ($Reason) { Write-Host "  $Reason" -ForegroundColor Yellow }
    Write-Host '  Press any key to close this window...' -ForegroundColor Yellow
    try {
        # ReadKey throws when stdin is redirected, so fall back rather than blow up.
        $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
    } catch {
        try { $null = Read-Host } catch { Start-Sleep -Seconds 20 }
    }
}

# =============================================================================
#  CONSOLE HELPERS
# =============================================================================

function Write-Rule {
    param([string]$Text)
    Write-Host ''
    Write-Host ('-' * 74) -ForegroundColor DarkGray
    Write-Host "  $Text" -ForegroundColor Cyan
    Write-Host ('-' * 74) -ForegroundColor DarkGray
}

function Write-Info { param([string]$m) Write-Host "    $m" -ForegroundColor Gray }
function Write-Good { param([string]$m) Write-Host "  [ OK ] $m" -ForegroundColor Green }
function Write-Warn { param([string]$m) Write-Host "  [WARN] $m" -ForegroundColor Yellow }
function Write-Bad  { param([string]$m) Write-Host "  [FAIL] $m" -ForegroundColor Red }

# Record a finding so the summary and the JSON both carry it.
function Add-Finding {
    param(
        [ValidateSet('Info', 'Warning', 'Critical')][string]$Severity,
        [string]$Area,
        [string]$Message
    )
    $null = $script:Findings.Add([pscustomobject]@{
        Severity = $Severity
        Area     = $Area
        Message  = $Message
    })
    switch ($Severity) {
        'Critical' { Write-Bad  $Message }
        'Warning'  { Write-Warn $Message }
        default    { Write-Info $Message }
    }
}

# =============================================================================
#  VEEAM PORT CATALOG
# =============================================================================
# Derived from veeam-portcheck/functions/PortTables.ps1, which that toolkit calls
# THE SOURCE OF TRUTH. Verified=$false means the port is documented but not
# confirmed by service name against v13 docs - treat those results as indicative.
# Set names are what -PortSet accepts.
$script:VeeamPorts = @(
    # ---- Core: backup server <-> managed component --------------------------
    @{P=443;   Set='Core'; V=$true;  C='Backup server connection / certificate port (v13, Connect-VBRServer default)'}
    @{P=6160;  Set='Core'; V=$true;  C='Veeam Installer / Deployer Service'}
    @{P=6162;  Set='Core'; V=$true;  C='Veeam Data Mover / Transport Service'}
    @{P=6172;  Set='Core'; V=$true;  C='Backup server database communication'}
    @{P=9392;  Set='Core'; V=$true;  C='Windows backup server initial connection (console / EM)'}
    @{P=9393;  Set='Core'; V=$false; C='Veeam Guest Catalog Service'}
    @{P=9401;  Set='Core'; V=$false; C='Veeam Mount Service (mount server <-> backup server)'}
    @{P=9405;  Set='Core'; V=$true;  C='Certificate port for EM collecting from v12 backup servers'}
    @{P=9419;  Set='Core'; V=$true;  C='Veeam RESTful API Service (HTTPS)'}
    @{P=9380;  Set='Core'; V=$false; C='Veeam Distribution Service (agent management)'}
    @{P=10006; Set='Core'; V=$true;  C='Backup server connection port'}
    @{P=10443; Set='Core'; V=$true;  C='Veeam Host Management'}

    # ---- DataMover: the proxy/repository transfer path ----------------------
    @{P=6160;  Set='DataMover'; V=$true; C='Veeam Installer / Deployer Service'}
    @{P=6162;  Set='DataMover'; V=$true; C='Veeam Data Mover / Transport Service'}
    @{P=2500;  Set='DataMover'; V=$true; C='Data transfer range START (2500-3300) - endpoint sample'}
    @{P=2501;  Set='DataMover'; V=$true; C='Data transfer range (2500-3300) - sample'}
    @{P=3300;  Set='DataMover'; V=$true; C='Data transfer range END (2500-3300) - endpoint sample'}

    # ---- vPower NFS ---------------------------------------------------------
    @{P=111;   Set='VPowerNfs'; V=$true;  C='vPower NFS (RPC portmapper) - cannot be changed from v13'}
    @{P=1058;  Set='VPowerNfs'; V=$false; C='vPower NFS mount service'}
    @{P=2049;  Set='VPowerNfs'; V=$true;  C='vPower NFS server'}
    @{P=6161;  Set='VPowerNfs'; V=$false; C='Veeam vPower NFS Service (control)'}

    # ---- Enterprise Manager -------------------------------------------------
    @{P=9394;  Set='EnterpriseManager'; V=$true; C='EM Service <-> IIS extension / Nginx gRPC (internal)'}
    @{P=9080;  Set='EnterpriseManager'; V=$true; C='EM web UI (HTTP, Windows)'}
    @{P=9443;  Set='EnterpriseManager'; V=$true; C='EM web UI (HTTPS, Windows). Linux appliance uses 443.'}
    @{P=9398;  Set='EnterpriseManager'; V=$true; C='EM RESTful API (HTTPS) / vSphere plug-in'}
    @{P=9399;  Set='EnterpriseManager'; V=$true; C='EM RESTful API (HTTP, Windows only)'}
    @{P=10443; Set='EnterpriseManager'; V=$true; C='Veeam Host Management'}

    # ---- Cloud Connect ------------------------------------------------------
    @{P=6180;  Set='CloudConnect'; V=$false; C='Veeam Cloud Connect Service'}
    @{P=10003; Set='CloudConnect'; V=$false; C='Veeam Cloud Gateway'}
    @{P=443;   Set='CloudConnect'; V=$true;  C='Cloud Connect TLS endpoint'}

    # ---- WAN accelerator ----------------------------------------------------
    @{P=6164;  Set='WanAccelerator'; V=$false; C='WAN Accelerator Service (control)'}
    @{P=6165;  Set='WanAccelerator'; V=$false; C='WAN Accelerator Service (data)'}

    # ---- Configuration database ---------------------------------------------
    @{P=5432;  Set='Database'; V=$true;  C='PostgreSQL - VBR configuration database (v12+)'}
    @{P=1433;  Set='Database'; V=$false; C='Microsoft SQL Server - VBR configuration database'}

    # ---- Veeam ONE ----------------------------------------------------------
    @{P=50001; Set='VeeamOne'; V=$false; C='Veeam ONE monitoring collection (gRPC)'}

    # ---- OS ports Veeam depends on ------------------------------------------
    @{P=135;   Set='Os'; V=$true;  C='RPC Endpoint Mapper (component / agent deploy)'}
    @{P=445;   Set='Os'; V=$true;  C='SMB (component deploy / upgrade file copy)'}
    @{P=139;   Set='Os'; V=$false; C='NetBIOS session service'}

    # ---- Guest processing: dynamic RPC --------------------------------------
    # Range endpoints only. The whole 49152-65535 range is what a reverse ACL has
    # to permit; testing two ends tells you whether the range is open at all.
    @{P=49152; Set='GuestProcessing'; V=$true; C='Dynamic RPC range START (49152-65535) - endpoint sample'}
    @{P=65535; Set='GuestProcessing'; V=$true; C='Dynamic RPC range END (49152-65535) - endpoint sample'}
    @{P=135;   Set='GuestProcessing'; V=$true; C='RPC Endpoint Mapper'}
    @{P=445;   Set='GuestProcessing'; V=$true; C='SMB'}

    # ---- Infrastructure dependencies ----------------------------------------
    @{P=53;    Set='Dependencies'; V=$true; C='DNS (TCP; name resolution is also UDP/53)'}
    @{P=389;   Set='Dependencies'; V=$true; C='LDAP (Active Directory)'}
    @{P=636;   Set='Dependencies'; V=$true; C='LDAPS (LDAP over TLS)'}
    @{P=3268;  Set='Dependencies'; V=$true; C='LDAP Global Catalog'}
    @{P=3269;  Set='Dependencies'; V=$true; C='LDAP Global Catalog (TLS)'}
    @{P=80;    Set='Dependencies'; V=$true; C='License certificate validation / local update mirror'}
    @{P=443;   Set='Dependencies'; V=$true; C='vCenter / Veeam License Server / Update Repository'}
)

function Get-VeeamPortSet {
    param([string[]]$SetNames)
    $out = New-Object System.Collections.ArrayList
    foreach ($s in $SetNames) {
        if ($s -eq 'All') {
            foreach ($e in $script:VeeamPorts) { $null = $out.Add([int]$e.P) }
            continue
        }
        foreach ($e in $script:VeeamPorts) {
            if ($e.Set -eq $s) { $null = $out.Add([int]$e.P) }
        }
    }
    return @($out | Sort-Object -Unique)
}

# First matching catalog entry wins. A port in several sets (443, 135, 445, 6162)
# gets the description of whichever set listed it first, which is good enough as
# a label and avoids a wall of duplicate text in the output.
function Get-PortDescription {
    param([int]$PortNumber)
    foreach ($e in $script:VeeamPorts) {
        if ([int]$e.P -eq $PortNumber) {
            $tag = ''
            if (-not $e.V) { $tag = ' ~' }
            return "$($e.C)$tag"
        }
    }
    return ''
}

function Test-Elevated {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $p  = New-Object Security.Principal.WindowsPrincipal($id)
        return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

# =============================================================================
#  IDENTITY
# =============================================================================

function Get-LocalIdentity {
    $addresses = @()
    try {
        $addresses = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop |
            Where-Object { $_.IPAddress -ne '127.0.0.1' } |
            ForEach-Object {
                [pscustomobject]@{
                    IPAddress        = $_.IPAddress
                    PrefixLength     = $_.PrefixLength
                    InterfaceAlias   = $_.InterfaceAlias
                    InterfaceIndex   = $_.InterfaceIndex
                    PrefixOrigin     = [string]$_.PrefixOrigin
                    SkipAsSource     = $_.SkipAsSource
                }
            })
    } catch {
        Add-Finding -Severity Warning -Area Identity -Message "Could not enumerate IPv4 addresses: $($_.Exception.Message)"
    }

    $os = ''
    try { $os = (Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).Caption } catch { }

    # A host that cannot resolve its own name is itself a finding, so never let
    # this throw and abort the whole collection.
    $fqdn = $env:COMPUTERNAME
    try { $fqdn = ([System.Net.Dns]::GetHostEntry($env:COMPUTERNAME)).HostName } catch { }

    $tz = ''
    try { $tz = (Get-TimeZone).Id } catch { }

    return [pscustomobject]@{
        ComputerName  = $env:COMPUTERNAME
        Fqdn          = $fqdn
        OperatingSystem = $os
        CollectedUtc  = (Get-Date).ToUniversalTime().ToString('o')
        CollectedLocal = (Get-Date).ToString('o')
        TimeZone      = $tz
        Addresses     = $addresses
    }
}

# =============================================================================
#  DNS
# =============================================================================

# Forward and reverse resolution of the peer, plus reverse of ourselves.
# Multiple A records and a forward/reverse mismatch are both real causes of
# "I am not talking to the host I think I am talking to".
function Resolve-PeerDns {
    param([string]$Name)

    $result = [pscustomobject]@{
        Query            = $Name
        IsLiteralIp      = $false
        ForwardAddresses = @()
        ReverseName      = ''
        ForwardOfReverse = @()
        DnsServers       = @()
        Error            = ''
    }

    $parsed = [ipaddress]::Any
    if ([ipaddress]::TryParse($Name, [ref]$parsed)) {
        $result.IsLiteralIp = $true
        $result.ForwardAddresses = @($Name)
    }

    try {
        $result.DnsServers = @(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction Stop |
            Where-Object { $_.ServerAddresses } |
            ForEach-Object { "$($_.InterfaceAlias): $($_.ServerAddresses -join ', ')" })
    } catch { }

    if (-not $result.IsLiteralIp) {
        try {
            if (Get-Command Resolve-DnsName -ErrorAction SilentlyContinue) {
                # -DnsOnly restricts the PROTOCOL (no LLMNR/NetBIOS). It does NOT bypass
                # the hosts file - the resolver cache is seeded from hosts and is still
                # consulted. -NoHostsFile is what excludes it. Both are needed here, or a
                # stale hosts entry gets reported as the DNS answer, which is precisely the
                # wrong diagnosis in an "am I talking to the host I think I am" check.
                $recs = @(Resolve-DnsName -Name $Name -Type A -DnsOnly -NoHostsFile -ErrorAction Stop |
                          Where-Object { $_.IPAddress })
                $result.ForwardAddresses = @($recs | ForEach-Object { $_.IPAddress })
            } else {
                $result.ForwardAddresses = @([System.Net.Dns]::GetHostAddresses($Name) |
                    Where-Object { $_.AddressFamily -eq 'InterNetwork' } |
                    ForEach-Object { $_.IPAddressToString })
            }
        } catch {
            $result.Error = $_.Exception.Message
        }
    }

    $primary = $null
    if ($result.ForwardAddresses.Count -gt 0) { $primary = $result.ForwardAddresses[0] }

    if ($primary) {
        try {
            if (Get-Command Resolve-DnsName -ErrorAction SilentlyContinue) {
                $ptr = Resolve-DnsName -Name $primary -Type PTR -DnsOnly -NoHostsFile -ErrorAction Stop |
                       Where-Object { $_.NameHost } | Select-Object -First 1
                if ($ptr) { $result.ReverseName = $ptr.NameHost }
            } else {
                $result.ReverseName = ([System.Net.Dns]::GetHostEntry($primary)).HostName
            }
        } catch { }
    }

    if ($result.ReverseName) {
        try {
            $result.ForwardOfReverse = @([System.Net.Dns]::GetHostAddresses($result.ReverseName) |
                Where-Object { $_.AddressFamily -eq 'InterNetwork' } |
                ForEach-Object { $_.IPAddressToString })
        } catch { }
    }

    return $result
}

# =============================================================================
#  ROUTING  -  the highest-value section for an asymmetric-path problem
# =============================================================================

# Find-NetRoute asks the stack the same question the TCP connect will ask:
# "which route, which interface, and which source address for this destination?"
# If the answer differs from the interface the inbound SYN arrived on, you have
# found your asymmetry without needing a single capture.
function Get-RouteFacts {
    param([string]$PeerIp)

    $facts = [pscustomobject]@{
        PeerIp            = $PeerIp
        SelectedSourceIp  = ''
        InterfaceIndex    = $null
        InterfaceAlias    = ''
        NextHop           = ''
        DestinationPrefix = ''
        RouteMetric       = $null
        InterfaceMetric   = $null
        DefaultRoutes     = @()
        EcmpDetected      = $false
        MatchingRoutes    = @()
        Error             = ''
    }

    try {
        $fnr = Find-NetRoute -RemoteIPAddress $PeerIp -ErrorAction Stop
        # Find-NetRoute returns two objects: the IP address used, then the route.
        $addrObj  = $fnr | Where-Object { $_.PSObject.Properties.Name -contains 'IPAddress' } | Select-Object -First 1
        $routeObj = $fnr | Where-Object { $_.PSObject.Properties.Name -contains 'NextHop' }   | Select-Object -First 1

        if ($addrObj)  { $facts.SelectedSourceIp = $addrObj.IPAddress }
        if ($routeObj) {
            $facts.InterfaceIndex    = $routeObj.InterfaceIndex
            $facts.NextHop           = $routeObj.NextHop
            $facts.DestinationPrefix = $routeObj.DestinationPrefix
            $facts.RouteMetric       = $routeObj.RouteMetric
            try {
                $nif = Get-NetIPInterface -InterfaceIndex $routeObj.InterfaceIndex -AddressFamily IPv4 -ErrorAction Stop
                $facts.InterfaceAlias  = $nif.InterfaceAlias
                $facts.InterfaceMetric = $nif.InterfaceMetric
            } catch { }
        }
    } catch {
        $facts.Error = $_.Exception.Message
        Add-Finding -Severity Warning -Area Routing -Message "Find-NetRoute failed for ${PeerIp}: $($facts.Error)"
    }

    # Multiple default routes with different next hops is ECMP. Under ECMP the
    # path a flow takes depends on a 5-tuple hash, so an ICMP traceroute can take
    # a completely different path than the TCP session you are chasing.
    try {
        $defaults = @(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop)
        $facts.DefaultRoutes = @($defaults | ForEach-Object {
            [pscustomobject]@{
                NextHop        = $_.NextHop
                InterfaceIndex = $_.InterfaceIndex
                InterfaceAlias = $_.InterfaceAlias
                RouteMetric    = $_.RouteMetric
            }
        })
        $distinctHops = @($facts.DefaultRoutes | ForEach-Object { $_.NextHop } | Sort-Object -Unique)
        if ($distinctHops.Count -gt 1) {
            $facts.EcmpDetected = $true
            Add-Finding -Severity Warning -Area Routing -Message "$($distinctHops.Count) default routes with different next hops ($($distinctHops -join ', ')). Under ECMP an ICMP traceroute may not follow the same path as the TCP session."
        }
    } catch { }

    # Any route that could match the peer - catches a stale /32 or a VPN-injected prefix.
    try {
        $all = @(Get-NetRoute -AddressFamily IPv4 -ErrorAction Stop)
        $peerAddr = [ipaddress]$PeerIp
        $facts.MatchingRoutes = @($all | Where-Object {
            $parts = $_.DestinationPrefix -split '/'
            if ($parts.Count -ne 2) { return $false }
            $net = [ipaddress]$parts[0]
            $len = [int]$parts[1]
            if ($len -eq 0) { return $true }
            if ($len -lt 0 -or $len -gt 32) { return $false }
            # Build the mask in 64-bit and truncate. Doing this in 32 bits lets the
            # sign bit leak in and silently mis-matches every prefix shorter than /1.
            $shift = 32 - $len
            $maskInt = [uint32](((0xFFFFFFFFL -shl $shift) -band 0xFFFFFFFFL))
            $netBytes  = $net.GetAddressBytes();  [array]::Reverse($netBytes)
            $peerBytes = $peerAddr.GetAddressBytes(); [array]::Reverse($peerBytes)
            $netInt  = [BitConverter]::ToUInt32($netBytes, 0)
            $peerInt = [BitConverter]::ToUInt32($peerBytes, 0)
            return ((([uint64]$netInt) -band $maskInt) -eq (([uint64]$peerInt) -band $maskInt))
        } | Sort-Object { [int]($_.DestinationPrefix -split '/')[1] } -Descending | ForEach-Object {
            [pscustomobject]@{
                DestinationPrefix = $_.DestinationPrefix
                NextHop           = $_.NextHop
                InterfaceIndex    = $_.InterfaceIndex
                InterfaceAlias    = $_.InterfaceAlias
                RouteMetric       = $_.RouteMetric
            }
        })
    } catch { }

    return $facts
}

# =============================================================================
#  EPHEMERAL PORT RANGE
# =============================================================================

# Return traffic is sourced FROM the service port and destined TO the client's
# ephemeral port. A reverse ACL scoped to the old 1024-5000 range looks correct
# in review and silently drops everything modern Windows originates.
function Get-EphemeralRange {
    $r = [pscustomobject]@{ StartPort = $null; NumberOfPorts = $null; EndPort = $null; Source = ''; Raw = '' }

    # Preferred: locale-independent. netsh output is localised and the regexes below
    # match English only, so on a localised server that path silently yields nothing.
    try {
        $s = Get-NetTCPSetting -SettingName 'Internet' -ErrorAction Stop
        if ($s -and $s.DynamicPortRangeStartPort) {
            $r.StartPort     = [int]$s.DynamicPortRangeStartPort
            $r.NumberOfPorts = [int]$s.DynamicPortRangeNumberOfPorts
            $r.EndPort       = $r.StartPort + $r.NumberOfPorts - 1
            $r.Source        = 'Get-NetTCPSetting'
        }
    } catch { }

    try {
        $out = & netsh int ipv4 show dynamicport tcp 2>&1
        $r.Raw = ($out | Out-String).Trim()
        if (-not $r.StartPort) {
            $m1 = [regex]::Match($r.Raw, 'Start Port\s*:\s*(\d+)')
            $m2 = [regex]::Match($r.Raw, 'Number of Ports\s*:\s*(\d+)')
            if ($m1.Success -and $m2.Success) {
                $r.StartPort     = [int]$m1.Groups[1].Value
                $r.NumberOfPorts = [int]$m2.Groups[1].Value
                $r.EndPort       = $r.StartPort + $r.NumberOfPorts - 1
                $r.Source        = 'netsh'
            }
        }
    } catch { }

    if ($r.StartPort) {
        Add-Finding -Severity Info -Area Ephemeral -Message "Local ephemeral range is $($r.StartPort)-$($r.EndPort). Any return-path ACL must permit destination ports across this whole range."
    } else {
        Add-Finding -Severity Warning -Area Ephemeral -Message 'Could not determine the dynamic port range. Check it by hand - a return-path ACL scoped to the legacy 1024-5000 range is a silent cause of exactly this failure.'
    }
    return $r
}

# =============================================================================
#  LOCAL FIREWALL
# =============================================================================

function Get-FirewallFacts {
    param([int[]]$Ports)

    $facts = [pscustomobject]@{
        Profiles      = @()
        MatchingRules = @()
        Error         = ''
    }

    # ActiveStore, not the default PersistentStore. PersistentStore holds only locally
    # defined rules; on a domain-joined server the rules that matter arrive by GPO and
    # exist only in the merged ActiveStore. Querying the default store reports "no
    # inbound allow rule" while a GPO rule is in fact permitting the traffic.
    try {
        $facts.Profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop | ForEach-Object {
            [pscustomobject]@{
                Name                  = $_.Name
                Enabled               = [bool]$_.Enabled
                DefaultInboundAction  = [string]$_.DefaultInboundAction
                DefaultOutboundAction = [string]$_.DefaultOutboundAction
            }
        })
    } catch {
        $facts.Error = $_.Exception.Message
        return $facts
    }

    # Walk port filters rather than rules - far faster than Get-NetFirewallRule per rule.
    try {
        $wanted = @{}
        foreach ($p in $Ports) { $wanted["$p"] = $true }

        $filters = @(Get-NetFirewallPortFilter -PolicyStore ActiveStore -ErrorAction Stop)
        $hits = New-Object System.Collections.ArrayList
        foreach ($f in $filters) {
            $local = @($f.LocalPort)
            $match = $false
            foreach ($lp in $local) {
                if (-not $lp) { continue }
                # 'Any' must count as a match. A blanket inbound Block rule - the single
                # most likely local cause - carries LocalPort 'Any' and would otherwise
                # never appear in this list at all.
                if ([string]$lp -eq 'Any') { $match = $true; break }
                if ($wanted.ContainsKey([string]$lp)) { $match = $true; break }
                if ($lp -match '^(\d+)-(\d+)$') {
                    $lo = [int]$Matches[1]; $hi = [int]$Matches[2]
                    foreach ($p in $Ports) { if ($p -ge $lo -and $p -le $hi) { $match = $true; break } }
                }
            }
            if (-not $match) { continue }
            try {
                $rule = $f | Get-NetFirewallRule -ErrorAction Stop
                $null = $hits.Add([pscustomobject]@{
                    DisplayName = $rule.DisplayName
                    Direction   = [string]$rule.Direction
                    Action      = [string]$rule.Action
                    Enabled     = [string]$rule.Enabled
                    Profile     = [string]$rule.Profile
                    LocalPort   = ($local -join ',')
                    RemotePort  = (@($f.RemotePort) -join ',')
                    Protocol    = [string]$f.Protocol
                })
            } catch { }
        }
        $facts.MatchingRules = @($hits)

        $inboundAllow = @($facts.MatchingRules | Where-Object { $_.Direction -eq 'Inbound' -and $_.Action -eq 'Allow' -and $_.Enabled -eq 'True' })
        if ($inboundAllow.Count -eq 0) {
            Add-Finding -Severity Info -Area Firewall -Message "No enabled inbound Allow rule found on this host for port(s) $($Ports -join ', '). Expected on the listening end; harmless on the connecting end."
        }
        $inboundBlock = @($facts.MatchingRules | Where-Object { $_.Direction -eq 'Inbound' -and $_.Action -eq 'Block' -and $_.Enabled -eq 'True' })
        foreach ($b in $inboundBlock) {
            Add-Finding -Severity Warning -Area Firewall -Message "Enabled inbound BLOCK rule covering this port: '$($b.DisplayName)' (LocalPort $($b.LocalPort)). Block beats Allow in Windows Firewall regardless of rule order."
        }
    } catch {
        $facts.Error = $_.Exception.Message
    }

    return $facts
}

# =============================================================================
#  ICMP TRACEROUTE
# =============================================================================

# Implemented directly rather than shelling out to tracert.exe so we control the
# timeout and get structured output that -Compare can diff.
function Get-IcmpPath {
    param([string]$Target, [int]$MaxHops = 30, [int]$HopTimeoutMs = 2000)

    $hops = New-Object System.Collections.ArrayList
    $ping = New-Object System.Net.NetworkInformation.Ping
    $payload = New-Object byte[] 32
    for ($i = 0; $i -lt 32; $i++) { $payload[$i] = 0x41 }

    for ($ttl = 1; $ttl -le $MaxHops; $ttl++) {
        $opts = New-Object System.Net.NetworkInformation.PingOptions($ttl, $false)
        $addr = ''
        $rtt  = $null
        $stat = 'Error'
        try {
            $reply = $ping.Send($Target, $HopTimeoutMs, $payload, $opts)
            $stat = [string]$reply.Status
            if ($reply.Address) { $addr = $reply.Address.ToString() }
            if ($reply.Status -eq 'Success') { $rtt = $reply.RoundtripTime }
        } catch {
            $stat = 'Exception'
        }

        $null = $hops.Add([pscustomobject]@{
            Ttl     = $ttl
            Address = $addr
            Status  = $stat
            RttMs   = $rtt
        })

        if ($stat -eq 'Success') { break }
    }

    $ping.Dispose()
    return @($hops)
}

# =============================================================================
#  TCP TRACEROUTE  (TTL-limited SYN + raw ICMP listener)
# =============================================================================

# Why this exists: ICMP and TCP do not necessarily take the same path. ECMP hashes
# on the 5-tuple and policy-based routing can match on protocol, so a clean ICMP
# trace proves nothing about the TCP session. This traces the real service port.
#
# Mechanism: bind a raw ICMP socket to the egress address, then fire TCP SYNs with
# an increasing TTL. Routers along the way return ICMP Time Exceeded addressed to
# us; the ICMP payload echoes the original IP header plus the first 8 bytes of the
# TCP header, which carries our source port - that is how each reply is correlated
# back to the probe that caused it.
function Get-TcpPath {
    param(
        [string]$Target,
        [int]$TargetPort,
        [string]$LocalIp,
        [int]$MaxHops = 30,
        [int]$HopTimeoutMs = 2000
    )

    $out = [pscustomobject]@{
        Supported = $true
        Reason    = ''
        Hops      = @()
    }

    if (-not (Test-Elevated)) {
        $out.Supported = $false
        $out.Reason = 'Not elevated - a raw ICMP socket requires Administrator.'
        return $out
    }
    if (-not $LocalIp) {
        $out.Supported = $false
        $out.Reason = 'No egress source address known (Find-NetRoute did not return one).'
        return $out
    }

    $raw = $null
    try {
        $raw = New-Object System.Net.Sockets.Socket(
            [System.Net.Sockets.AddressFamily]::InterNetwork,
            [System.Net.Sockets.SocketType]::Raw,
            [System.Net.Sockets.ProtocolType]::Icmp)
        $raw.Bind((New-Object System.Net.IPEndPoint([ipaddress]$LocalIp, 0)))
        $raw.ReceiveTimeout = 250
    } catch {
        if ($raw) { try { $raw.Close() } catch { } }
        $out.Supported = $false
        $out.Reason = "Could not open raw ICMP socket: $($_.Exception.Message). Endpoint protection often blocks this; use -NoTcpPath, or run nmap --traceroute -sS -p $TargetPort $Target instead."
        return $out
    }

    $targetAddr = $null
    try { $targetAddr = [System.Net.Dns]::GetHostAddresses($Target) | Where-Object { $_.AddressFamily -eq 'InterNetwork' } | Select-Object -First 1 }
    catch { }
    if (-not $targetAddr) {
        try { $raw.Close() } catch { }
        $out.Supported = $false
        $out.Reason = "Could not resolve $Target to an IPv4 address."
        return $out
    }

    $hops = New-Object System.Collections.ArrayList
    $buf  = New-Object byte[] 512
    $rawFailed = $false
    $rawFailReason = ''

    for ($ttl = 1; $ttl -le $MaxHops; $ttl++) {

        $tcp = $null
        $srcPort = 0
        $hopAddr = ''
        $hopKind = 'Timeout'
        $rtt = $null

        try {
            $tcp = New-Object System.Net.Sockets.Socket(
                [System.Net.Sockets.AddressFamily]::InterNetwork,
                [System.Net.Sockets.SocketType]::Stream,
                [System.Net.Sockets.ProtocolType]::Tcp)
            $tcp.Ttl = [int16]$ttl
            # Bind to port 0 and let the stack pick, then read it back - we need the
            # source port to correlate the ICMP quotation.
            $tcp.Bind((New-Object System.Net.IPEndPoint([ipaddress]$LocalIp, 0)))
            $srcPort = ([System.Net.IPEndPoint]$tcp.LocalEndPoint).Port
            $tcp.Blocking = $false

            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            try { $tcp.Connect($targetAddr, $TargetPort) } catch { }

            $deadline = [DateTime]::UtcNow.AddMilliseconds($HopTimeoutMs)
            while ([DateTime]::UtcNow -lt $deadline) {

                # On Windows a FAILED non-blocking connect (RST / refused) is signalled in
                # exceptfds, not writefds. Check the error state first - otherwise a
                # destination that is reachable and actively refusing looks identical to a
                # black hole, which is the exact distinction this script exists to make.
                if ($tcp.Poll(0, [System.Net.Sockets.SelectMode]::SelectError)) {
                    $hopAddr = $targetAddr.ToString()
                    $hopKind = 'Destination (refused - RST returned, return path proven)'
                    $rtt = [int]$sw.ElapsedMilliseconds
                    break
                }

                # Did the handshake complete? Then this TTL reached the destination.
                if ($tcp.Poll(0, [System.Net.Sockets.SelectMode]::SelectWrite)) {
                    try {
                        if ($tcp.Connected) {
                            $hopAddr = $targetAddr.ToString()
                            $hopKind = 'Destination'
                            $rtt = [int]$sw.ElapsedMilliseconds
                            break
                        }
                    } catch { }
                }

                # Any ICMP addressed to us?
                try {
                    $n = $raw.Receive($buf)
                    if ($n -gt 0) {
                        $parsed = ConvertFrom-IcmpError -Buffer $buf -Length $n -ExpectSrcPort $srcPort -ExpectDstPort $TargetPort
                        if ($parsed) {
                            $hopAddr = $parsed.Router
                            $hopKind = $parsed.Kind
                            $rtt = [int]$sw.ElapsedMilliseconds
                            break
                        }
                    }
                } catch [System.Net.Sockets.SocketException] {
                    # TimedOut is the expected case - keep polling until the hop deadline.
                    # Anything else means the raw socket itself has failed, and continuing
                    # would silently produce 30 clean-looking Timeout hops.
                    if ($_.Exception.SocketErrorCode -ne [System.Net.Sockets.SocketError]::TimedOut) {
                        $rawFailed = $true
                        $rawFailReason = [string]$_.Exception.SocketErrorCode
                        break
                    }
                    Start-Sleep -Milliseconds 20
                } catch {
                    Start-Sleep -Milliseconds 20
                }
            }
            $sw.Stop()
        } catch {
            $hopKind = "Error: $($_.Exception.Message)"
        } finally {
            if ($tcp) { try { $tcp.Close() } catch { } }
        }

        $null = $hops.Add([pscustomobject]@{
            Ttl     = $ttl
            Address = $hopAddr
            Status  = $hopKind
            RttMs   = $rtt
        })

        if ($rawFailed) { break }
        # -like, not -eq: the Unreachable status carries the ICMP code text, so an
        # exact match never fires and the trace runs 20+ pointless TTLs past the
        # device that already told you it was dropping the packet.
        if ($hopKind -like 'Destination*' -or $hopKind -like 'Unreachable*') { break }
    }

    try { $raw.Close() } catch { }
    $out.Hops = @($hops)

    if ($rawFailed) {
        $out.Reason = "Raw ICMP socket failed mid-trace ($rawFailReason). The hops recorded before that point are valid; the trace is incomplete."
    } else {
        # If nothing at all answered, say so explicitly. Endpoint protection commonly
        # blocks inbound ICMP at the WFP layer while Get-IcmpPath still works, because
        # that uses IcmpSendEcho rather than a raw socket. Without this note an operator
        # sees a healthy ICMP trace beside a blank TCP trace and draws the wrong
        # conclusion about where the traffic is dying.
        $answered = @($out.Hops | Where-Object { $_.Address })
        if ($answered.Count -eq 0 -and $out.Hops.Count -gt 0) {
            $out.Reason = 'No hop answered. This often means inbound ICMP to this host is blocked locally (WFP / endpoint protection) rather than that the path is dead - compare against the ICMP trace, which uses a different mechanism.'
        }
    }

    return $out
}

# Parse a raw IPv4 frame carrying an ICMP error and confirm the quoted TCP header
# matches the probe we just sent. Returns $null for anything unrelated.
function ConvertFrom-IcmpError {
    param([byte[]]$Buffer, [int]$Length, [int]$ExpectSrcPort, [int]$ExpectDstPort)

    if ($Length -lt 28) { return $null }

    # Outer IPv4 header. Low nibble of byte 0 is the header length in 32-bit words.
    $ihl = ($Buffer[0] -band 0x0F) * 4
    if ($Length -lt ($ihl + 8)) { return $null }

    $router = '{0}.{1}.{2}.{3}' -f $Buffer[12], $Buffer[13], $Buffer[14], $Buffer[15]

    $icmpType = $Buffer[$ihl]
    $kind = $null
    if ($icmpType -eq 11) { $kind = 'TtlExceeded' }
    elseif ($icmpType -eq 3) { $kind = 'Unreachable' }
    else { return $null }

    # ICMP error payload: 8-byte ICMP header, then the original IP header,
    # then at least the first 8 bytes of the original transport header.
    $innerIpOffset = $ihl + 8
    if ($Length -lt ($innerIpOffset + 20)) { return $null }
    $innerIhl = ($Buffer[$innerIpOffset] -band 0x0F) * 4
    $innerProto = $Buffer[$innerIpOffset + 9]
    if ($innerProto -ne 6) { return $null }   # not TCP, not ours

    $tcpOffset = $innerIpOffset + $innerIhl
    if ($Length -lt ($tcpOffset + 4)) { return $null }

    $qSrcPort = ([int]$Buffer[$tcpOffset] -shl 8) -bor [int]$Buffer[$tcpOffset + 1]
    $qDstPort = ([int]$Buffer[$tcpOffset + 2] -shl 8) -bor [int]$Buffer[$tcpOffset + 3]

    if ($qSrcPort -ne $ExpectSrcPort -or $qDstPort -ne $ExpectDstPort) { return $null }

    if ($kind -eq 'Unreachable') {
        $code = $Buffer[$ihl + 1]
        $codeText = switch ($code) {
            0 { 'net unreachable' }
            1 { 'host unreachable' }
            2 { 'protocol unreachable' }
            3 { 'port unreachable' }
            9 { 'net administratively prohibited' }
            10 { 'host administratively prohibited' }
            13 { 'communication administratively prohibited (filtered)' }
            default { "code $code" }
        }
        return [pscustomobject]@{ Router = $router; Kind = "Unreachable ($codeText)" }
    }

    return [pscustomobject]@{ Router = $router; Kind = $kind }
}

# =============================================================================
#  TCP CONNECT  -  classified, not boolean
# =============================================================================

# Single source for the outcome prose. It lives here rather than in the report so
# the JSON carries only the machine-readable 'outcome' field - prose in JSON is
# bloat that rewords between versions and ruins diffs. The console and the .txt
# report both render it from this function.
function Get-OutcomeInterpretation {
    param([string]$Outcome)
    switch ($Outcome) {
        'Connected' {
            return 'Full three-way handshake completed. Forward AND return paths are both working for this 5-tuple at this moment. If the production failure persists, the difference is in the 5-tuple - a different source IP, source port range, or service port is taking a different path.'
        }
        'Refused' {
            return 'RST received. This is significant: a reset travelled the entire return path back to us, which PROVES the return path is intact. The problem is the listener or the policy on the destination, not the network path.'
        }
        'Timeout' {
            return 'No response of any kind within the timeout. The SYN may never have arrived, OR the SYN-ACK may have been lost on the way back. A connect test cannot separate these - this is exactly why the two-ended capture is required.'
        }
        'HostUnreachable' {
            return 'ICMP host unreachable. A router on the path has no route to the destination, or is administratively filtering. The ICMP source in the TCP trace identifies the device.'
        }
        'NetworkUnreachable' {
            return 'ICMP network unreachable - a routing problem on the forward path, usually local or first-hop.'
        }
        default { return '' }
    }
}

# The old Test-PortOpen returned $true/$false and threw away the only information
# that matters here. A timeout and a refusal are completely different diagnoses:
# a refusal is an RST that travelled all the way back, which PROVES the return
# path works. That single distinction can end this investigation.
function Test-TcpConnectDetailed {
    param([string]$Target, [int]$TargetPort, [int]$TimeoutMs = 5000)

    $r = [pscustomobject]@{
        Target         = $Target
        Port           = $TargetPort
        TimeoutMs      = $TimeoutMs
        Outcome        = 'Unknown'
        SocketError    = ''
        ElapsedMs      = 0
        LocalEndpoint  = ''
        ReturnPathProven = $false
        Interpretation = ''
    }

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $ar = $client.BeginConnect($Target, $TargetPort, $null, $null)
        if (-not $ar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) {
            $r.Outcome = 'Timeout'
        } else {
            $client.EndConnect($ar)
            $r.Outcome = 'Connected'
            $r.ReturnPathProven = $true
            try { $r.LocalEndpoint = $client.Client.LocalEndPoint.ToString() } catch { }
        }
    } catch [System.Net.Sockets.SocketException] {
        # PowerShell normally unwraps MethodInvocationException for typed catch, but be
        # explicit - if the wrapper leaks through, SocketErrorCode is absent and every
        # failure degrades to the generic 'Error' branch, losing the Refused/Timeout
        # distinction that this whole function exists to make.
        $se = $_.Exception
        if ($se -isnot [System.Net.Sockets.SocketException] -and $se.InnerException) { $se = $se.InnerException }
        $r.SocketError = [string]$se.SocketErrorCode
        switch ([string]$se.SocketErrorCode) {
            'ConnectionRefused'  { $r.Outcome = 'Refused'; $r.ReturnPathProven = $true }
            'HostUnreachable'    { $r.Outcome = 'HostUnreachable' }
            'NetworkUnreachable' { $r.Outcome = 'NetworkUnreachable' }
            'TimedOut'           { $r.Outcome = 'Timeout' }
            default {
                $r.Outcome = 'Error'
                $r.Interpretation = "Socket error $($se.SocketErrorCode): $($se.Message)"
            }
        }
    } catch {
        $r.Outcome = 'Error'
        # Populate SocketError too - it is the only error field the schema carried
        # before 'message' existed, and leaving it blank made a non-socket failure
        # indistinguishable from a clean one in the JSON.
        $r.SocketError = $_.Exception.GetType().Name
        $r.Interpretation = $_.Exception.Message
    } finally {
        $sw.Stop()
        $r.ElapsedMs = [int]$sw.ElapsedMilliseconds
        try { $client.Close() } catch { }
    }

    if (-not $r.Interpretation) { $r.Interpretation = Get-OutcomeInterpretation -Outcome $r.Outcome }
    return $r
}

# =============================================================================
#  PKTMON CAPTURE
# =============================================================================

function Test-PktmonAvailable {
    $cmd = Get-Command pktmon.exe -ErrorAction SilentlyContinue
    return [bool]$cmd
}

# pktmon's -i (IP) and -p (port) filters match the value in EITHER the source or
# the destination field, so one filter per port covers both directions. That is
# what lets the source end answer "did a SYN-ACK ever arrive here at all".
function Start-DiagCapture {
    param([string]$PeerIp, [int[]]$Ports, [string]$EtlPath)

    $state = [pscustomobject]@{
        Started   = $false
        EtlPath   = $EtlPath
        Syntax    = ''
        Messages  = @()
        PcapPath  = ''
        TxtPath   = ''
    }

    $msgs = New-Object System.Collections.ArrayList
    try { $null = & pktmon.exe filter remove 2>&1 } catch { }

    # Track whether ANY filter installed. If none did, starting the capture would
    # record every packet on the box - on a busy server that means a 300 MB circular
    # ETL and a multi-gigabyte conversion, so refuse to start instead.
    $filtersInstalled = 0
    foreach ($p in $Ports) {
        $o = & pktmon.exe filter add "PathDiag$p" -i $PeerIp -t TCP -p $p 2>&1
        $null = $msgs.Add("filter add $p (exit $LASTEXITCODE): " + ($o | Out-String).Trim())
        if ($LASTEXITCODE -eq 0) { $filtersInstalled++ }
    }
    # ICMP from anywhere: unreachables and TTL-exceeded are how transit devices
    # tell you they dropped something, and they do not match a TCP port filter.
    $o = & pktmon.exe filter add 'PathDiagIcmp' -t ICMP 2>&1
    $null = $msgs.Add("filter add icmp (exit $LASTEXITCODE): " + ($o | Out-String).Trim())

    if ($filtersInstalled -eq 0) {
        $null = $msgs.Add('No TCP filter installed - refusing to start an unfiltered capture.')
        $state.Messages = @($msgs)
        return $state
    }

    # Modern syntax first, then the 1809/1903-era flags.
    $o = & pktmon.exe start --capture --pkt-size 160 --file-name $EtlPath --file-size 300 2>&1
    $txt = ($o | Out-String)
    if ($LASTEXITCODE -eq 0 -and $txt -notmatch 'Unknown|Invalid|usage') {
        $state.Started = $true
        $state.Syntax = 'modern'
    } else {
        $null = $msgs.Add($txt.Trim())
        $o2 = & pktmon.exe start --etw -c -p 160 -f $EtlPath -s 300 2>&1
        $txt2 = ($o2 | Out-String)
        if ($LASTEXITCODE -eq 0 -and $txt2 -notmatch 'Unknown|Invalid|usage') {
            $state.Started = $true
            $state.Syntax = 'legacy'
        } else {
            $null = $msgs.Add($txt2.Trim())
        }
    }

    $state.Messages = @($msgs)
    return $state
}

function Stop-DiagCapture {
    param([pscustomobject]$State)

    if (-not $State.Started) { return $State }
    try { $null = & pktmon.exe stop 2>&1 } catch { }
    try { $null = & pktmon.exe filter remove 2>&1 } catch { }

    $base = [IO.Path]::ChangeExtension($State.EtlPath, $null).TrimEnd('.')
    $msgs = New-Object System.Collections.ArrayList
    foreach ($m in @($State.Messages)) { if ($m) { $null = $msgs.Add($m) } }

    # pcapng for Wireshark. Command name changed across releases, so try both.
    # Conversion output is RETAINED, not discarded - when both names fail, that
    # output is the only clue why the capture produced nothing readable.
    $pcap = "$base.pcapng"
    try {
        $o = & pktmon.exe etl2pcap $State.EtlPath --out $pcap 2>&1
        if (-not (Test-Path $pcap)) {
            $null = $msgs.Add("etl2pcap: " + ($o | Out-String).Trim())
            $o = & pktmon.exe pcapng $State.EtlPath -o $pcap 2>&1
            if (-not (Test-Path $pcap)) { $null = $msgs.Add("pcapng: " + ($o | Out-String).Trim()) }
        }
        if (Test-Path $pcap) { $State.PcapPath = $pcap }
    } catch { $null = $msgs.Add("pcap conversion threw: $($_.Exception.Message)") }

    # Text for the automated read below, and for drop reasons - pktmon names the
    # component that dropped a packet and why, which no pcap can tell you.
    #
    # etl2txt was renamed to 'pktmon format' on Server 2022 / Win11. Trying only the
    # old name means that on a modern build TxtPath stays empty, Get-CaptureObservations
    # returns Parsed=$false, and every automated capture conclusion - including the
    # DECISIVE return-path finding in -Compare - becomes silently unreachable.
    $txt = "$base.txt"
    try {
        $o = & pktmon.exe format $State.EtlPath -o $txt 2>&1
        if (-not (Test-Path $txt)) {
            $null = $msgs.Add("format: " + ($o | Out-String).Trim())
            $o = & pktmon.exe etl2txt $State.EtlPath -o $txt 2>&1
            if (-not (Test-Path $txt)) { $null = $msgs.Add("etl2txt: " + ($o | Out-String).Trim()) }
        }
        if (Test-Path $txt) { $State.TxtPath = $txt }
    } catch { $null = $msgs.Add("text conversion threw: $($_.Exception.Message)") }

    $State.Messages = @($msgs)
    return $State
}

# Read the capture text back and answer the two questions that matter per end:
#   Source end:      did ANY packet arrive from the peer on the service port?
#   Destination end: what source IP did the inbound SYN actually carry? (NAT check)
function Get-CaptureObservations {
    param([string]$TxtPath, [string]$PeerIp, [int[]]$Ports)

    $obs = [pscustomobject]@{
        Parsed            = $false
        ParserMatchedTcp  = $false
        TotalPackets      = 0
        ToServicePort     = 0
        FromServicePort   = 0
        IcmpPackets       = 0
        DropEvents        = @()
        ObservedPeers     = @()
        ObservedLocals    = @()
    }

    if (-not $TxtPath -or -not (Test-Path $TxtPath)) { return $obs }

    $drops   = New-Object System.Collections.ArrayList
    $srcIps  = @{}
    $dstIps  = @{}
    $portSet = @{}
    foreach ($p in $Ports) { $portSet["$p"] = $true }

    # pktmon logs the SAME packet once per component/edge it traverses, tagged with an
    # Appearance number. Counting every line inflates the totals several-fold, so only
    # Appearance 1 is counted and later appearances are skipped wholesale.
    $skipBlock = $false
    $curSrc = ''; $curDst = ''

    try {
        $reader = [IO.File]::OpenText($TxtPath)
        try {
            while ($null -ne ($line = $reader.ReadLine())) {

                if ($line -match 'PktNumber\s+\d+') {
                    $m = [regex]::Match($line, 'Appearance\s+(\d+)')
                    $skipBlock = ($m.Success -and [int]$m.Groups[1].Value -ne 1)
                    $curSrc = ''; $curDst = ''
                }

                # Drop reasons appear on the packet header line with no delimiter on some
                # builds and with a colon on others. Require a non-empty reason token so a
                # bare 'DropReason' on every packet cannot manufacture a false Critical.
                $dm = [regex]::Match($line, 'Drop\s*Reason\s*[:=]?\s*([A-Za-z][\w .()/-]{2,})')
                if ($dm.Success) {
                    $reason = $dm.Groups[1].Value.Trim()
                    if ($reason -and $reason -notmatch '^(None|NotDropped|0)$') { $null = $drops.Add($reason) }
                }

                if ($skipBlock) { continue }

                if ($line -match '(?:IPv4|ipv4)\s*:?\s*(\d{1,3}(?:\.\d{1,3}){3})\s*->\s*(\d{1,3}(?:\.\d{1,3}){3})') {
                    $obs.TotalPackets++
                    $curSrc = $Matches[1]; $curDst = $Matches[2]
                    if (-not $srcIps.ContainsKey($curSrc)) { $srcIps[$curSrc] = 0 }
                    if (-not $dstIps.ContainsKey($curDst)) { $dstIps[$curDst] = 0 }
                    $srcIps[$curSrc]++
                    $dstIps[$curDst]++
                }

                # pktmon spells the ports differently across builds: 'sport N, dport N'
                # on newer ones, 'SrcPort N ... DstPort N' on older, and a bare
                # 'TCP: 51234 -> 6162' in some summaries. Try all three.
                $sp = $null; $dp = $null
                $m1 = [regex]::Match($line, '(?:sport|SrcPort|Src\s*Port)\s*[:=]?\s*(\d+)[\s,]+.{0,60}?(?:dport|DstPort|Dst\s*Port)\s*[:=]?\s*(\d+)')
                if ($m1.Success) { $sp = $m1.Groups[1].Value; $dp = $m1.Groups[2].Value }
                else {
                    $m2 = [regex]::Match($line, '(?:^|\s)(?:TCP|tcp)\s*:?\s*(\d{1,5})\s*->\s*(\d{1,5})')
                    if ($m2.Success) { $sp = $m2.Groups[1].Value; $dp = $m2.Groups[2].Value }
                }
                if ($sp -and $dp) {
                    $obs.ParserMatchedTcp = $true
                    if ($portSet.ContainsKey($dp)) {
                        $obs.ToServicePort++
                        # Who connected TO the service port is exactly the NAT question.
                        if ($curSrc) { $srcIps["svc:$curSrc"] = 1 }
                    }
                    if ($portSet.ContainsKey($sp)) { $obs.FromServicePort++ }
                }

                if ($line -match '(?:^|\s)(?:ICMP|icmp)(?:\s|:)' -and $line -notmatch 'ICMPv6') { $obs.IcmpPackets++ }
            }
        } finally { $reader.Close() }
        $obs.Parsed = $true
    } catch {
        return $obs
    }

    $obs.DropEvents = @($drops | Group-Object | Sort-Object Count -Descending |
        ForEach-Object { [pscustomobject]@{ Reason = $_.Name; Count = $_.Count } })
    # Only addresses that actually sent to the service port - not every source in the
    # capture, which would include this host and all the ICMP noise.
    $obs.ObservedPeers  = @($srcIps.Keys | Where-Object { $_ -like 'svc:*' } | ForEach-Object { $_.Substring(4) } | Sort-Object)
    $obs.ObservedLocals = @($dstIps.Keys | Sort-Object)

    if ($obs.Parsed -and $obs.TotalPackets -gt 0 -and -not $obs.ParserMatchedTcp) {
        Add-Finding -Severity Warning -Area Capture -Message "Parsed $($obs.TotalPackets) packet(s) from the capture but recognised no TCP port lines - this build's pktmon text format differs from what the parser expects. The per-port counts below are NOT trustworthy; read the pcapng in Wireshark instead."
    }

    if ($obs.Parsed -and $obs.ParserMatchedTcp -and $obs.FromServicePort -eq 0 -and $obs.ToServicePort -gt 0) {
        Add-Finding -Severity Critical -Area Capture -Message "This host sent $($obs.ToServicePort) packet(s) TO the service port and received ZERO back FROM it. The return traffic is not reaching this host. Combined with the far end's capture, that localises the drop to the transit path."
    }
    if ($obs.DropEvents.Count -gt 0) {
        Add-Finding -Severity Critical -Area Capture -Message "pktmon recorded $($obs.DropEvents.Count) distinct drop reason(s) - see the report. A drop logged here means the packet died on THIS host (filter driver, firewall, or stack), not in transit."
    }

    return $obs
}

# =============================================================================
#  COLLECT
# =============================================================================

function Invoke-Collect {
    param(
        [string]$PeerName, [int[]]$Ports, [string]$RoleLabel,
        [int]$ConnectTimeoutMs, [bool]$DoCapture, [bool]$SkipTcpPath,
        [int]$Hops, [string]$Destination, [int]$MaxTracePorts = 2
    )

    Write-Rule "Path diagnostic : $RoleLabel  ->  $PeerName"
    Write-Info "Started $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') local / $((Get-Date).ToUniversalTime().ToString('HH:mm:ss')) UTC"
    Write-Info "Ports: $($Ports -join ', ')    Connect timeout: ${ConnectTimeoutMs} ms"

    if (-not (Test-Elevated)) {
        Add-Finding -Severity Warning -Area Privilege -Message 'Not running elevated. The TCP traceroute and pktmon capture will be skipped or incomplete.'
    }

    Write-Rule 'Identity'
    $identity = Get-LocalIdentity
    Write-Info "$($identity.ComputerName)  ($($identity.Fqdn))"
    foreach ($a in $identity.Addresses) {
        Write-Info ("  {0}/{1}  on {2} (ifIndex {3})" -f $a.IPAddress, $a.PrefixLength, $a.InterfaceAlias, $a.InterfaceIndex)
    }

    Write-Rule 'DNS'
    $dns = Resolve-PeerDns -Name $PeerName
    if ($dns.Error) { Write-Bad "Resolution error: $($dns.Error)" }
    Write-Info "Forward : $($dns.ForwardAddresses -join ', ')"
    Write-Info "Reverse : $($dns.ReverseName)"
    foreach ($s in $dns.DnsServers) { Write-Info "Servers : $s" }

    if ($dns.ForwardAddresses.Count -eq 0) {
        Add-Finding -Severity Critical -Area Dns -Message "$PeerName does not resolve to an IPv4 address. Every port result below would be meaningless, so collection stops here."
        return $null
    }
    if ($dns.ForwardAddresses.Count -gt 1) {
        Add-Finding -Severity Warning -Area Dns -Message "$PeerName resolves to $($dns.ForwardAddresses.Count) addresses ($($dns.ForwardAddresses -join ', ')). Successive connections may land on different hosts or paths, which produces exactly this kind of intermittent half-open behaviour."
    }
    if ($dns.ReverseName -and $dns.ForwardOfReverse.Count -gt 0) {
        if ($dns.ForwardOfReverse -notcontains $dns.ForwardAddresses[0]) {
            Add-Finding -Severity Warning -Area Dns -Message "Forward/reverse mismatch: $PeerName -> $($dns.ForwardAddresses[0]) -> $($dns.ReverseName) -> $($dns.ForwardOfReverse -join ', '). Stale DNS is a common reason traffic is aimed at the wrong host."
        }
    }

    $peerIp = $dns.ForwardAddresses[0]

    Write-Rule 'Routing'
    $route = Get-RouteFacts -PeerIp $peerIp
    Write-Info "Egress source   : $($route.SelectedSourceIp)"
    Write-Info "Interface       : $($route.InterfaceAlias) (index $($route.InterfaceIndex), metric $($route.InterfaceMetric))"
    Write-Info "Next hop        : $($route.NextHop)"
    Write-Info "Matched prefix  : $($route.DestinationPrefix)"
    if ($route.MatchingRoutes.Count -gt 1) {
        Write-Info "Other candidate routes to this destination:"
        foreach ($mr in $route.MatchingRoutes) {
            Write-Info ("  {0,-20} via {1,-15} on {2}" -f $mr.DestinationPrefix, $mr.NextHop, $mr.InterfaceAlias)
        }
    }

    Write-Rule 'Ephemeral port range'
    $ephemeral = Get-EphemeralRange
    if ($ephemeral.StartPort) { Write-Info "$($ephemeral.StartPort) - $($ephemeral.EndPort)  ($($ephemeral.NumberOfPorts) ports)" }

    Write-Rule 'Local firewall'
    $fw = Get-FirewallFacts -Ports $Ports
    foreach ($p in $fw.Profiles) {
        Write-Info ("{0,-8} enabled={1}  inbound={2}  outbound={3}" -f $p.Name, $p.Enabled, $p.DefaultInboundAction, $p.DefaultOutboundAction)
    }
    if ($fw.MatchingRules.Count -eq 0) { Write-Info 'No rules reference the service port(s).' }
    foreach ($r in $fw.MatchingRules) {
        Write-Info ("{0,-9} {1,-6} {2,-6} {3}" -f $r.Direction, $r.Action, $r.Enabled, $r.DisplayName)
    }

    # ---- capture wraps the active tests ------------------------------------
    $capture = $null
    $capState = $null
    if ($DoCapture) {
        Write-Rule 'Starting pktmon capture'
        if (-not (Test-PktmonAvailable)) {
            Add-Finding -Severity Warning -Area Capture -Message 'pktmon.exe not found. Capture skipped. On older builds use: netsh trace start capture=yes'
        } elseif (-not (Test-Elevated)) {
            Add-Finding -Severity Warning -Area Capture -Message 'pktmon requires elevation. Capture skipped.'
        } else {
            $etl = Join-Path $Destination ("capture-{0}-{1}.etl" -f $RoleLabel, (Get-Date -Format 'yyyyMMdd-HHmmss'))
            $capState = Start-DiagCapture -PeerIp $peerIp -Ports $Ports -EtlPath $etl
            if ($capState.Started) { Write-Good "Capturing to $etl ($($capState.Syntax) syntax)" }
            else { Add-Finding -Severity Warning -Area Capture -Message 'pktmon failed to start - see Messages in the JSON report.' }
        }
    }

    Write-Rule 'ICMP path'
    $icmpPath = Get-IcmpPath -Target $peerIp -MaxHops $Hops
    foreach ($h in $icmpPath) {
        $disp = $h.Address
        if (-not $disp) { $disp = '*' }
        Write-Info ("{0,3}  {1,-16} {2}" -f $h.Ttl, $disp, $h.Status)
    }

    # Connects run BEFORE the traces now. Two reasons: the result is what decides
    # which ports are worth tracing, and a trace can take a minute per port while a
    # connect takes at most the timeout.
    Write-Rule 'TCP connect'
    $connects = @()
    foreach ($p in $Ports) {
        $c = Test-TcpConnectDetailed -Target $peerIp -TargetPort $p -TimeoutMs $ConnectTimeoutMs
        $connects += $c
        $desc = Get-PortDescription -PortNumber $p
        $label = ('port {0,-6} {1,-20} {2} ms   {3}' -f $p, $c.Outcome, $c.ElapsedMs, $desc)
        if ($c.Outcome -eq 'Connected') { Write-Good $label }
        elseif ($c.ReturnPathProven) { Write-Warn $label }
        else { Write-Bad $label }
        if ($c.ReturnPathProven) {
            Add-Finding -Severity Info -Area Connect -Message "Port $p proved the return path is intact (outcome: $($c.Outcome))."
        }
    }
    Write-Info ''
    Write-Info 'Refused is NOT a failure - it means an RST came all the way back, which proves'
    Write-Info 'the return path works. Timeout is the ambiguous one the two-ended capture solves.'

    # Choose what to trace: failures first, since that is where the path matters.
    # Tracing a 12-port Core set at up to 60 s per port would run for minutes.
    $tcpPaths = @{}
    if (-not $SkipTcpPath -and $MaxTracePorts -gt 0) {
        $failedPorts = @($connects | Where-Object { -not $_.ReturnPathProven } | ForEach-Object { [int]$_.Port })
        $otherPorts  = @($connects | Where-Object { $_.ReturnPathProven }      | ForEach-Object { [int]$_.Port })
        $traceList   = @(@($failedPorts + $otherPorts) | Select-Object -First $MaxTracePorts)

        $skipped = @($Ports | Where-Object { $traceList -notcontains $_ })
        if ($skipped.Count -gt 0) {
            Write-Info ''
            Write-Info "Tracing $($traceList -join ', ') only. Not traced: $($skipped -join ', '). Raise -TraceLimit to cover more."
        }

        foreach ($p in $traceList) {
            Write-Rule "TCP path on port $p"
            $tp = Get-TcpPath -Target $peerIp -TargetPort $p -LocalIp $route.SelectedSourceIp -MaxHops $Hops
            if (-not $tp.Supported) {
                Write-Warn $tp.Reason
            } else {
                foreach ($h in $tp.Hops) {
                    $disp = $h.Address
                    if (-not $disp) { $disp = '*' }
                    Write-Info ("{0,3}  {1,-16} {2}" -f $h.Ttl, $disp, $h.Status)
                }
                if ($tp.Reason) { Write-Warn $tp.Reason }
                $filtered = @($tp.Hops | Where-Object { $_.Status -like 'Unreachable*' })
                foreach ($f in $filtered) {
                    Add-Finding -Severity Critical -Area TcpPath -Message "Hop $($f.Ttl) ($($f.Address)) returned '$($f.Status)' for TCP port $p. That device is the one rejecting this traffic."
                }
            }
            $tcpPaths["$p"] = $tp
        }
    }

    if ($capState -and $capState.Started) {
        Write-Rule 'Stopping capture'
        Start-Sleep -Seconds 2
        $capState = Stop-DiagCapture -State $capState
        if ($capState.PcapPath) { Write-Good "pcapng: $($capState.PcapPath)" }
        if ($capState.TxtPath)  { Write-Good "text  : $($capState.TxtPath)" }
        $capture = Get-CaptureObservations -TxtPath $capState.TxtPath -PeerIp $peerIp -Ports $Ports
        if ($capture.Parsed) {
            Write-Info "Packets seen: $($capture.TotalPackets)   to service port: $($capture.ToServicePort)   from service port: $($capture.FromServicePort)"
            if ($capture.ObservedPeers.Count -gt 0) { Write-Info "Source IPs observed: $($capture.ObservedPeers -join ', ')" }
        }
    }

    return (New-PathDiagReport -RoleLabel $RoleLabel -PeerName $PeerName -PeerIp $peerIp `
                -Ports $Ports -Identity $identity -Dns $dns -Route $route -Ephemeral $ephemeral `
                -Firewall $fw -IcmpPath $icmpPath -TcpPaths $tcpPaths -Connects $connects `
                -CapState $capState -CapObs $capture -CaptureRequested $DoCapture)
}

# =============================================================================
#  REPORT SCHEMA
# =============================================================================

# Everything above collects in whatever shape was convenient. This is the single
# place that decides what lands on disk, and it is a deliberate projection rather
# than a dump of internal state. Rules it follows:
#   - every leaf is a scalar; every collection is an array of FLAT objects, so
#     ConvertTo-Json -Depth can never silently truncate a branch to a type name
#   - lists are arrays, never hashtables keyed by a number: numeric keys survive
#     the round-trip but come back as property names a caller must discover by
#     reflection, which is why -Compare previously needed PSObject.Properties
#   - no console prose. Interpretation strings belong in the .txt report; in JSON
#     they are bloat that changes wording between versions and breaks diffs
#   - no raw command output, no empty internal bookkeeping
#   - one timestamp format: ISO-8601 UTC with Z
function ConvertTo-HopArray {
    param($Hops)
    return @(@($Hops) | Where-Object { $_ } | ForEach-Object {
        $rtt = $null
        if ($null -ne $_.RttMs -and $_.RttMs -ne '') { $rtt = [int]$_.RttMs }
        [pscustomobject]@{
            ttl     = [int]$_.Ttl
            address = [string]$_.Address
            status  = [string]$_.Status
            rttMs   = $rtt
        }
    })
}

function Get-MaxTtl {
    param($Hops)
    # Filter nulls BEFORE counting. @($null).Count is 1, not 0, so a plain
    # count guard sails past an empty/null input and then hands Measure-Object a
    # null object, which writes a red error to the console mid-report.
    $h = @(@($Hops) | Where-Object { $_ })
    if ($h.Count -eq 0) { return 0 }
    return [int](($h | Measure-Object -Property ttl -Maximum).Maximum)
}

function New-PathDiagReport {
    param(
        $RoleLabel, $PeerName, $PeerIp, $Ports, $Identity, $Dns, $Route,
        $Ephemeral, $Firewall, $IcmpPath, $TcpPaths, $Connects,
        $CapState, $CapObs, [bool]$CaptureRequested
    )

    # @() at the CALL SITE is mandatory. 'return @(...)' inside a function writes to
    # the pipeline, which enumerates the collection and undoes the wrapper: an empty
    # result arrives as $null and a single hop arrives as a bare object. Both then
    # serialise as "hops": null / "hops": {...} instead of an array, breaking the
    # documented contract for every external consumer. Zero hops is the normal case
    # on an EDR-protected host, and one hop is the normal case for an adjacent peer,
    # so neither is exotic.
    $icmpHops = @(ConvertTo-HopArray -Hops $IcmpPath)

    $tcpArr = @()
    if ($TcpPaths) {
        foreach ($k in @($TcpPaths.Keys | Sort-Object { [int]$_ })) {
            $tp = $TcpPaths[$k]
            $hops = @(ConvertTo-HopArray -Hops $tp.Hops)
            $tcpArr += [pscustomobject]@{
                port               = [int]$k
                supported          = [bool]$tp.Supported
                reason             = [string]$tp.Reason
                reachedDestination = (@($hops | Where-Object { $_.status -like 'Destination*' }).Count -gt 0)
                maxTtl             = (Get-MaxTtl -Hops $hops)
                respondingHops     = @($hops | Where-Object { $_.address }).Count
                hops               = @($hops)
            }
        }
    }

    # pktmon diagnostics are kept only when something actually went wrong - a
    # successful run has nothing useful to say and the messages are multi-line
    # console noise that makes the JSON unreadable.
    # Kept when the capture failed to START **or** failed to produce readable text.
    # The common silent failure is a capture that starts fine and then fails to
    # convert, which previously reported started:true, parsed:false, diagnostics:[]
    # - i.e. "something went wrong" with nothing to act on.
    $capDiag = @()
    $capUnusable = ($CapState -and -not $CapState.Started) -or
                   ($CapState -and $CapState.Started -and -not ($CapObs -and $CapObs.Parsed))
    if ($capUnusable) {
        $capDiag = @(@($CapState.Messages) | Where-Object { $_ } | ForEach-Object {
            ($_ -replace '\s*\r?\n\s*', ' ').Trim()
        } | Where-Object { $_ })
    }

    # Named captureBlock, not $capture: a local called $capture would shadow the
    # script's [switch]$Capture parameter by name and silently mislead anyone who
    # later adds an "if ($Capture)" test inside this function.
    $captureBlock = [pscustomobject]@{
        requested        = $CaptureRequested
        started          = [bool]($CapState -and $CapState.Started)
        syntax           = [string]$(if ($CapState) { $CapState.Syntax } else { '' })
        files            = [pscustomobject]@{
            etl    = [string]$(if ($CapState) { $CapState.EtlPath }  else { '' })
            pcapng = [string]$(if ($CapState) { $CapState.PcapPath } else { '' })
            text   = [string]$(if ($CapState) { $CapState.TxtPath }  else { '' })
        }
        parsed           = [bool]($CapObs -and $CapObs.Parsed)
        parserMatchedTcp = [bool]($CapObs -and $CapObs.ParserMatchedTcp)
        totalPackets     = [int]$(if ($CapObs) { $CapObs.TotalPackets }    else { 0 })
        toServicePort    = [int]$(if ($CapObs) { $CapObs.ToServicePort }   else { 0 })
        fromServicePort  = [int]$(if ($CapObs) { $CapObs.FromServicePort } else { 0 })
        icmpPackets      = [int]$(if ($CapObs) { $CapObs.IcmpPackets }     else { 0 })
        observedSources  = @(if ($CapObs) { @($CapObs.ObservedPeers) } else { @() })
        drops            = @(if ($CapObs) {
                                @($CapObs.DropEvents) | Where-Object { $_ } | ForEach-Object {
                                    [pscustomobject]@{ reason = [string]$_.Reason; count = [int]$_.Count }
                                }
                             } else { @() })
        diagnostics      = $capDiag
    }

    return [pscustomobject]@{
        schema       = 'pathdiag/2'
        generatedUtc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        role         = [string]$RoleLabel
        ports        = @(@($Ports) | ForEach-Object { [int]$_ })

        host = [pscustomobject]@{
            name      = [string]$Identity.ComputerName
            fqdn      = [string]$Identity.Fqdn
            os        = [string]$Identity.OperatingSystem
            timeZone  = [string]$Identity.TimeZone
            addresses = @(@($Identity.Addresses) | Where-Object { $_ } | ForEach-Object {
                [pscustomobject]@{
                    ip             = [string]$_.IPAddress
                    prefixLength   = [int]$_.PrefixLength
                    interfaceAlias = [string]$_.InterfaceAlias
                    interfaceIndex = [int]$_.InterfaceIndex
                    prefixOrigin   = [string]$_.PrefixOrigin
                    skipAsSource   = [bool]$_.SkipAsSource
                }
            })
        }

        peer = [pscustomobject]@{
            query            = [string]$PeerName
            ip               = [string]$PeerIp
            isLiteralIp      = [bool]$Dns.IsLiteralIp
            forwardAddresses = @(@($Dns.ForwardAddresses) | ForEach-Object { [string]$_ })
            reverseName      = [string]$Dns.ReverseName
            forwardOfReverse = @(@($Dns.ForwardOfReverse) | ForEach-Object { [string]$_ })
            dnsServers       = @(@($Dns.DnsServers) | ForEach-Object { [string]$_ })
            resolveError     = [string]$Dns.Error
        }

        egress = [pscustomobject]@{
            sourceIp        = [string]$Route.SelectedSourceIp
            interfaceAlias  = [string]$Route.InterfaceAlias
            interfaceIndex  = [int]$(if ($null -ne $Route.InterfaceIndex) { $Route.InterfaceIndex } else { 0 })
            interfaceMetric = [int]$(if ($null -ne $Route.InterfaceMetric) { $Route.InterfaceMetric } else { 0 })
            nextHop         = [string]$Route.NextHop
            matchedPrefix   = [string]$Route.DestinationPrefix
            routeMetric     = [int]$(if ($null -ne $Route.RouteMetric) { $Route.RouteMetric } else { 0 })
            ecmp            = [bool]$Route.EcmpDetected
            lookupError     = [string]$Route.Error
            defaultRoutes   = @(@($Route.DefaultRoutes) | Where-Object { $_ } | ForEach-Object {
                [pscustomobject]@{
                    nextHop        = [string]$_.NextHop
                    interfaceAlias = [string]$_.InterfaceAlias
                    interfaceIndex = [int]$_.InterfaceIndex
                    routeMetric    = [int]$_.RouteMetric
                }
            })
            candidateRoutes = @(@($Route.MatchingRoutes) | Where-Object { $_ } | ForEach-Object {
                [pscustomobject]@{
                    prefix         = [string]$_.DestinationPrefix
                    nextHop        = [string]$_.NextHop
                    interfaceAlias = [string]$_.InterfaceAlias
                    interfaceIndex = [int]$_.InterfaceIndex
                    routeMetric    = [int]$_.RouteMetric
                }
            })
        }

        # Raw netsh output deliberately dropped - it is a localised console blob
        # that bloats the file and carries nothing the parsed fields do not.
        ephemeral = [pscustomobject]@{
            start  = [int]$(if ($null -ne $Ephemeral.StartPort) { $Ephemeral.StartPort } else { 0 })
            end    = [int]$(if ($null -ne $Ephemeral.EndPort)   { $Ephemeral.EndPort }   else { 0 })
            count  = [int]$(if ($null -ne $Ephemeral.NumberOfPorts) { $Ephemeral.NumberOfPorts } else { 0 })
            source = [string]$Ephemeral.Source
        }

        firewall = [pscustomobject]@{
            queryError = [string]$Firewall.Error
            profiles   = @(@($Firewall.Profiles) | Where-Object { $_ } | ForEach-Object {
                [pscustomobject]@{
                    name           = [string]$_.Name
                    enabled        = [bool]$_.Enabled
                    defaultInbound = [string]$_.DefaultInboundAction
                    defaultOutbound= [string]$_.DefaultOutboundAction
                }
            })
            rules      = @(@($Firewall.MatchingRules) | Where-Object { $_ } | ForEach-Object {
                [pscustomobject]@{
                    displayName = [string]$_.DisplayName
                    direction   = [string]$_.Direction
                    action      = [string]$_.Action
                    enabled     = ([string]$_.Enabled -eq 'True')
                    profile     = [string]$_.Profile
                    protocol    = [string]$_.Protocol
                    localPort   = [string]$_.LocalPort
                    remotePort  = [string]$_.RemotePort
                }
            })
        }

        paths = [pscustomobject]@{
            icmp = [pscustomobject]@{
                reachedDestination = (@($icmpHops | Where-Object { $_.status -eq 'Success' }).Count -gt 0)
                maxTtl             = (Get-MaxTtl -Hops $icmpHops)
                respondingHops     = @($icmpHops | Where-Object { $_.address }).Count
                hops               = @($icmpHops)
            }
            tcp = @($tcpArr)
        }

        # 'message' carries the per-instance detail for the Error outcome only. The
        # five enumerated outcomes have fixed prose that Get-OutcomeInterpretation
        # regenerates, so repeating it here would be bloat - but an Error's text is
        # unique and would otherwise survive nowhere except the console of the
        # machine that ran the test.
        connects = @(@($Connects) | Where-Object { $_ } | ForEach-Object {
            $msg = ''
            if ($_.Outcome -eq 'Error' -or $_.Outcome -eq 'Unknown') { $msg = [string]$_.Interpretation }
            [pscustomobject]@{
                port             = [int]$_.Port
                component        = [string](Get-PortDescription -PortNumber ([int]$_.Port))
                outcome          = [string]$_.Outcome
                socketError      = [string]$_.SocketError
                message          = $msg
                elapsedMs        = [int]$_.ElapsedMs
                timeoutMs        = [int]$_.TimeoutMs
                localEndpoint    = [string]$_.LocalEndpoint
                returnPathProven = [bool]$_.ReturnPathProven
            }
        })

        capture = $captureBlock

        findings = @(@($script:Findings) | Where-Object { $_ } | ForEach-Object {
            [pscustomobject]@{
                severity = [string]$_.Severity
                area     = [string]$_.Area
                message  = [string]$_.Message
            }
        })
    }
}

# =============================================================================
#  COMPARE
# =============================================================================

# All three accessors below read the pathdiag/2 schema, where paths.tcp is an
# ARRAY of per-port objects. The previous schema keyed it by port number, which
# forced these helpers to reflect over PSObject.Properties to find the ports.
# Every read is wrapped in @() because ConvertTo-Json in PS 5.1 can collapse a
# single-element array to a scalar on the way out.
function Get-PathAddresses {
    # -ForPort is typed with a sentinel rather than left loose: an untyped parameter
    # cast with [int] at the comparison throws on '' or a non-numeric value.
    param($Report, [string]$Which, [int]$ForPort = -1)
    if ($Which -eq 'icmp') {
        return @(@($Report.paths.icmp.hops) | Where-Object { $_.address } | ForEach-Object { $_.address })
    }
    $out = New-Object System.Collections.ArrayList
    foreach ($tp in @($Report.paths.tcp)) {
        if (-not $tp) { continue }
        if ($ForPort -ge 0 -and [int]$tp.port -ne $ForPort) { continue }
        foreach ($h in @($tp.hops)) { if ($h.address) { $null = $out.Add($h.address) } }
    }
    return @($out)
}

# Which ports actually have a usable TCP trace in this report.
function Get-TracedPorts {
    param($Report)
    return @(@($Report.paths.tcp) |
        Where-Object { $_ -and @(@($_.hops) | Where-Object { $_.address }).Count -gt 0 } |
        ForEach-Object { [int]$_.port })
}

# maxTtl is the number of probes SENT, not the number that answered. Get-IcmpPath
# runs to MaxHops when the destination never replies, so counting only responding
# hops makes an ICMP-silent path look short and manufactures a confident, wrong
# "hop count differs" verdict in exactly the scenario this tool is built for.
function Get-PathReach {
    param($Report)
    return [pscustomobject]@{
        ReachedDestination = [bool]$Report.paths.icmp.reachedDestination
        MaxTtl             = [int]$Report.paths.icmp.maxTtl
        Responding         = [int]$Report.paths.icmp.respondingHops
    }
}

function Invoke-Compare {
    param([string[]]$Paths)

    # Expand wildcards FIRST, then check the count. Checking $Paths.Count before
    # expansion lets a glob matching three reports through, and the old code then
    # silently took [0].
    $expanded = New-Object System.Collections.ArrayList
    foreach ($p in $Paths) {
        $resolved = @(Resolve-Path -Path $p -ErrorAction SilentlyContinue)
        if ($resolved.Count -eq 0) { Write-Bad "Not found: $p"; return 2 }
        foreach ($rp in $resolved) { $null = $expanded.Add($rp.Path) }
    }
    if ($expanded.Count -ne 2) {
        Write-Bad "Compare needs exactly two report files; the paths given resolved to $($expanded.Count):"
        foreach ($e in $expanded) { Write-Info "  $e" }
        return 2
    }

    $reports = @()
    foreach ($p in $expanded) {
        try {
            $reports += (Get-Content -Raw -Path $p | ConvertFrom-Json)
        } catch {
            Write-Bad "Could not parse $p : $($_.Exception.Message)"
            return 2
        }
    }

    $a = $reports[0]
    $b = $reports[1]
    $issues = New-Object System.Collections.ArrayList

    # Fail loudly on an unexpected schema rather than silently comparing $null to
    # $null and reporting "no problem detected", which is the worst possible output
    # this tool could produce.
    foreach ($i in 0, 1) {
        $sv = [string]$reports[$i].schema
        if ($sv -ne 'pathdiag/2') {
            Write-Bad "$($expanded[$i]) has schema '$sv'; this build expects 'pathdiag/2'."
            if (-not $sv) { Write-Info '  Reports written by an earlier build have no schema field. Re-collect both ends.' }
            return 2
        }
    }

    Write-Rule "Comparing  $($a.role)  <->  $($b.role)"
    Write-Info "A: $($a.role) ($($a.host.name)) collected $($a.generatedUtc)"
    Write-Info "B: $($b.role) ($($b.host.name)) collected $($b.generatedUtc)"

    try {
        $skew = [Math]::Abs((([datetime]$a.generatedUtc) - ([datetime]$b.generatedUtc)).TotalSeconds)
        if ($skew -gt 300) {
            $null = $issues.Add("The two reports were collected $([int]$skew)s apart. Correlating them is unsafe - re-run both with -StartAt.")
        }
    } catch { }

    # ---- 1. Does each end agree about the other's address? -----------------
    Write-Rule '1. Address agreement'
    $aSays = $a.egress.sourceIp
    $bSays = $b.egress.sourceIp
    Write-Info "$($a.role) will egress as : $aSays   (targeting $($a.peer.ip))"
    Write-Info "$($b.role) will egress as : $bSays   (targeting $($b.peer.ip))"

    if ($aSays -and $b.peer.ip -and $aSays -ne $b.peer.ip) {
        $null = $issues.Add("$($a.role) sources traffic from $aSays, but $($b.role) is aiming its return traffic at $($b.peer.ip). Those differ - either there is NAT in the path, or $($b.role) has been told the wrong peer address. If it is NAT, the server's replies go to the NAT address and whatever holds that translation must still have state for the flow.")
    }
    if ($bSays -and $a.peer.ip -and $bSays -ne $a.peer.ip) {
        $null = $issues.Add("$($b.role) sources traffic from $bSays, but $($a.role) is aiming at $($a.peer.ip). Same NAT / wrong-address question in the other direction.")
    }

    # ---- 2. NAT, proven from the captures ----------------------------------
    # Checked in BOTH directions. A one-sided test makes the verdict depend on the
    # order the two filenames happened to be typed, and silently assumes the second
    # report is the listening end - which nothing enforces.
    Write-Rule '2. NAT detection from capture'
    # Hashtables, not nested arrays - @(@(x,y),@(y,x)) is a flattening hazard.
    foreach ($pair in @(@{From=$a; To=$b}, @{From=$b; To=$a})) {
        $from = $pair.From; $to = $pair.To
        $fromSays = $from.egress.sourceIp
        $observed = @()
        if ($to.capture.parsed) { $observed = @($to.capture.observedSources) }
        if ($observed.Count -eq 0) {
            Write-Info "$($to.role): no capture observations - re-run that end with -Capture to test this automatically."
            continue
        }
        Write-Info "$($to.role) saw service-port traffic from: $($observed -join ', ')"
        if ($fromSays -and ($observed -notcontains $fromSays)) {
            $null = $issues.Add("CONFIRMED NAT or redirection: $($from.role) believes it egresses as $fromSays, but $($to.role) never saw that address - it saw $($observed -join ', '). $($to.role) replies to whatever address it saw, so THAT is the address the return path must carry state for, and whatever holds the translation must still have the flow.")
        } elseif ($fromSays) {
            Write-Good "$($to.role) saw $fromSays - no NAT between them in this direction."
        }
    }

    # ---- 3. Path asymmetry -------------------------------------------------
    Write-Rule '3. Path asymmetry'
    $aIcmp = @(Get-PathAddresses -Report $a -Which 'icmp')
    $bIcmp = @(Get-PathAddresses -Report $b -Which 'icmp')
    Write-Info "$($a.role) -> $($a.peer.ip):"
    if ($aIcmp.Count -eq 0) { Write-Info '  (no hops recorded)' } else { Write-Info "  $($aIcmp -join '  ->  ')" }
    Write-Info "$($b.role) -> $($b.peer.ip):"
    if ($bIcmp.Count -eq 0) { Write-Info '  (no hops recorded)' } else { Write-Info "  $($bIcmp -join '  ->  ')" }

    if ($aIcmp.Count -gt 0 -and $bIcmp.Count -gt 0) {
        $onlyA = @($aIcmp | Where-Object { $bIcmp -notcontains $_ })
        $onlyB = @($bIcmp | Where-Object { $aIcmp -notcontains $_ })
        # Note: a hop legitimately appears on one side only when a router replies
        # from a different interface in each direction, so treat this as a lead,
        # not a verdict. A difference in HOP COUNT is the stronger signal.
        if ($onlyA.Count -gt 0 -or $onlyB.Count -gt 0) {
            $null = $issues.Add("Path asymmetry indicated. Hops seen only from $($a.role): $($onlyA -join ', '). Hops seen only from $($b.role): $($onlyB -join ', '). Some of this is normal (routers reply from the ingress interface), but any device appearing in ONE direction only is a candidate for the stateful drop - check it for a session matching the reverse 5-tuple.")
        } else {
            Write-Good 'Both traces traverse the same set of router addresses.'
        }
        # Only claim a length difference when BOTH traces actually reached the far
        # end. Otherwise the "short" side is just a run of ICMP-silent routers.
        $aReach = Get-PathReach -Report $a
        $bReach = Get-PathReach -Report $b
        if ($aReach.ReachedDestination -and $bReach.ReachedDestination) {
            $delta = [Math]::Abs($aReach.MaxTtl - $bReach.MaxTtl)
            if ($delta -ge 2) {
                $null = $issues.Add("Path length differs by $delta hops ($($aReach.MaxTtl) out vs $($bReach.MaxTtl) back), measured to the destination in both directions. That is strong evidence the return traffic takes a different physical path than the outbound.")
            }
        } else {
            $silent = @()
            if (-not $aReach.ReachedDestination) { $silent += $a.role }
            if (-not $bReach.ReachedDestination) { $silent += $b.role }
            Write-Info "Not comparing path lengths: the trace from $($silent -join ' and ') never reached the destination, so hop counts are not comparable."
        }
    }

    # ICMP and TCP can diverge under ECMP or policy-based routing, so a clean ICMP
    # comparison above does not settle it. This is the comparison that counts.
    # Compared per port - flattening every port's trace into one list prints a
    # nonsense zig-zag chain that an operator will try to read as a path.
    $aPorts = @(Get-TracedPorts -Report $a)
    $bPorts = @(Get-TracedPorts -Report $b)
    foreach ($r in @(@{R=$a;P=$aPorts;Icmp=$aIcmp}, @{R=$b;P=$bPorts;Icmp=$bIcmp})) {
        foreach ($pt in $r.P) {
            $tp = @(Get-PathAddresses -Report $r.R -Which 'tcp' -ForPort $pt)
            Write-Info "TCP path $($r.R.role) -> $($r.R.peer.ip):$pt   $($tp -join '  ->  ')"
            $drift = @($tp | Where-Object { $r.Icmp -notcontains $_ })
            if ($tp.Count -gt 0 -and $r.Icmp.Count -gt 0 -and $drift.Count -gt 0) {
                $null = $issues.Add("On $($r.R.role) the TCP path to port $pt differs from the ICMP path (TCP-only hops: $($drift -join ', ')). The ICMP traceroute is therefore NOT representative of where your TCP session goes - trust the TCP trace and disregard any conclusion drawn from tracert alone.")
            }
        }
    }

    # Per-port TCP asymmetry, for ports traced from both ends.
    foreach ($pt in @($aPorts | Where-Object { $bPorts -contains $_ })) {
        $onlyATcp = @()
        $onlyBTcp = @()
        $at = @(Get-PathAddresses -Report $a -Which 'tcp' -ForPort $pt)
        $bt = @(Get-PathAddresses -Report $b -Which 'tcp' -ForPort $pt)
        $onlyATcp = @($at | Where-Object { $bt -notcontains $_ })
        $onlyBTcp = @($bt | Where-Object { $at -notcontains $_ })
        if ($onlyATcp.Count -gt 0 -or $onlyBTcp.Count -gt 0) {
            $null = $issues.Add("TCP path asymmetry on port $pt. Only on the $($a.role) side: $($onlyATcp -join ', '). Only on the $($b.role) side: $($onlyBTcp -join ', '). These are the devices to interrogate first - a stateful device that only ever sees one direction of a flow drops the other as out-of-state.")
        } else {
            Write-Good "Port ${pt}: both TCP traces traverse the same router addresses."
        }
    }

    # ---- 4. ECMP -----------------------------------------------------------
    Write-Rule '4. ECMP / multiple default routes'
    foreach ($r in @($a, $b)) {
        if ($r.egress.ecmp) {
            $null = $issues.Add("$($r.role) has multiple default routes with different next hops. Flows are hashed across them, so this failure can be intermittent and 5-tuple dependent - which matches a case where some sessions work and some age out.")
        } else {
            $dh = ''
            $dr = @($r.egress.defaultRoutes)
            if ($dr.Count -gt 0) { $dh = $dr[0].nextHop }
            Write-Good "$($r.role): single default next hop ($dh)."
        }
    }

    # ---- 5. Ephemeral range vs return-path ACL scope ------------------------
    # An observation, not a finding. Every default-configured modern Windows host
    # starts at 49152, so treating it as an issue guarantees the findings list is
    # never empty and makes exit code 1 meaningless.
    Write-Rule '5. Ephemeral range'
    foreach ($r in @($a, $b)) {
        if ($r.ephemeral.start -gt 0) {
            Write-Info "$($r.role): $($r.ephemeral.start)-$($r.ephemeral.end)"
            if ($r.ephemeral.start -ge 49152) {
                Write-Info "  -> Return traffic to $($r.role) is destined to ports in this range. Any reverse ACL scoped to the legacy 1024-5000 range permits nothing this host originates. Worth checking on every stateless device in the path."
            }
        } else {
            Write-Warn "$($r.role): dynamic port range unknown - check by hand."
        }
    }

    # ---- 6. Connect outcome correlation ------------------------------------
    Write-Rule '6. Connect outcomes'
    foreach ($r in @($a, $b)) {
        foreach ($c in @($r.connects)) {
            Write-Info ("{0} -> {1}:{2,-6} {3,-20} {4} ms   {5}" -f $r.role, $r.peer.ip, $c.port, $c.outcome, $c.elapsedMs, $c.component)
            # A proven return path is good news, so it is reported as such rather
            # than added to the issue list.
            if ($c.returnPathProven) {
                Write-Good "  Return path from $($r.peer.ip) back to $($r.role) is PROVEN intact for that 5-tuple (outcome: $($c.outcome))."
                Write-Info "  If production traffic on the same port still fails, the difference is in the 5-tuple - source address or source port. Compare against the ephemeral range above."
            }
        }
    }

    # ---- 7. One-way capture evidence ---------------------------------------
    Write-Rule '7. Capture evidence'
    foreach ($r in @($a, $b)) {
        if ($r.capture.parsed) {
            Write-Info "$($r.role): total=$($r.capture.totalPackets)  to-service-port=$($r.capture.toServicePort)  from-service-port=$($r.capture.fromServicePort)"
            foreach ($d in @($r.capture.drops)) {
                $null = $issues.Add("$($r.role) logged a local pktmon drop: '$($d.reason)' x$($d.count). A drop recorded here means the packet died ON THAT HOST, not in transit - that is your answer.")
            }
        } elseif ($r.capture.requested) {
            Write-Warn "$($r.role): capture was requested but produced nothing readable."
            foreach ($d in @($r.capture.diagnostics)) { Write-Info "  $d" }
        } else {
            Write-Info "$($r.role): no capture requested."
        }
    }

    # Evaluated in both directions, for the same reason as section 2: which report
    # is the "server" end is not something the script can assume.
    foreach ($pair in @(@{Client=$a; Server=$b}, @{Client=$b; Server=$a})) {
        $client = $pair.Client; $server = $pair.Server
        if (-not ($client.capture.parsed -and $client.capture.parserMatchedTcp)) { continue }
        if (-not ($server.capture.parsed -and $server.capture.parserMatchedTcp)) { continue }

        $serverSentBack = [int]$server.capture.fromServicePort
        $clientGotBack  = [int]$client.capture.fromServicePort
        if ($serverSentBack -gt 0 -and $clientGotBack -eq 0) {
            $null = $issues.Add("DECISIVE: $($server.role) transmitted $serverSentBack packet(s) FROM the service port, and $($client.role) received NONE. The return traffic leaves $($server.role) and dies before reaching $($client.role). Every device listed in section 3 is a suspect - search each for a DENY on the REVERSED 5-tuple: source $($server.egress.sourceIp):<service port>, destination $($client.egress.sourceIp):<ephemeral>. Searching the forward tuple will not show it.")
        }
    }

    # ---- 8. Findings raised during collection -------------------------------
    # Without this, Critical findings recorded by either end - a filtering hop
    # named by the TCP trace, a DNS failure, an inbound BLOCK rule - sit in both
    # JSON files and never appear in the compare output, which is the only thing
    # most people read.
    Write-Rule '8. Findings raised on each end'
    foreach ($r in @($a, $b)) {
        $crit = @(@($r.findings) | Where-Object { $_.severity -eq 'Critical' })
        $warn = @(@($r.findings) | Where-Object { $_.severity -eq 'Warning' })
        if ($crit.Count -eq 0 -and $warn.Count -eq 0) {
            Write-Good "$($r.role): nothing raised during collection."
            continue
        }
        foreach ($f in $crit) {
            $null = $issues.Add("$($r.role) raised a CRITICAL finding during collection [$($f.area)]: $($f.message)")
        }
        foreach ($f in $warn) { Write-Warn "$($r.role) [$($f.area)]: $($f.message)" }
    }

    # ---- verdict -----------------------------------------------------------
    Write-Rule 'Findings'
    if ($issues.Count -eq 0) {
        Write-Good 'No asymmetry or return-path problem detected from these two reports.'
        return 0
    }
    $n = 1
    foreach ($i in $issues) {
        Write-Host ''
        Write-Host "  [$n] $i" -ForegroundColor Yellow
        $n++
    }
    Write-Host ''
    return 1
}

# =============================================================================
#  MAIN
# =============================================================================

# Everything below runs inside try/finally so the caller's preferences are restored
# even on Ctrl-C or an unhandled terminating error. Complete-PathDiag does the same
# restore on the normal paths; the function is idempotent, so both can run.
# (Deliberately not re-indented - the brace is the only change.)
try {

if ($PSCmdlet.ParameterSetName -eq 'Compare') {
    # Capture first rather than inlining the call into the parameter. If anything
    # inside Invoke-Compare ever leaks an extra object onto the pipeline, inlining
    # would fail to bind [int]$Code and take the whole run down with it.
    $cmpResult = Invoke-Compare -Paths $Compare
    if ($cmpResult -is [array]) { $cmpResult = $cmpResult[-1] }
    Complete-PathDiag -Code ([int]$cmpResult)
    return
}

if (-not $OutDir) {
    if ($PSScriptRoot) { $OutDir = $PSScriptRoot } else { $OutDir = (Get-Location).Path }
}
if (-not (Test-Path $OutDir)) { $null = New-Item -ItemType Directory -Path $OutDir -Force }
# pktmon.exe resolves relative paths against the process CWD, not the PowerShell
# location, so hand it an absolute path only.
$OutDir = (Resolve-Path -Path $OutDir).Path

if ($StartAt) {
    $target = $null
    try {
        # InvariantCulture: on a non-en-US server the current culture can reject or
        # misread a full datetime string. 'HH:mm:ss' is safe either way.
        $target = [datetime]::Parse($StartAt, [System.Globalization.CultureInfo]::InvariantCulture)
        if ($target -lt (Get-Date)) { $target = $target.AddDays(1) }
    } catch {
        Write-Bad "Could not parse -StartAt '$StartAt'. Use 'HH:mm:ss' or a full datetime."
        Complete-PathDiag -Code 2
        return
    }
    $wait = ($target - (Get-Date)).TotalSeconds
    # A fat-fingered time that has just passed rolls to tomorrow and would otherwise
    # sit on a progress bar for ~24 hours, which on a production server reads as a hang.
    if ($wait -gt 14400) {
        Write-Bad ("-StartAt '{0}' resolves to {1}, which is {2:N1} hours away. That is almost certainly a typo for a time that has already passed. Re-run with a future time, or omit -StartAt to begin now." -f $StartAt, $target.ToString('yyyy-MM-dd HH:mm:ss'), ($wait / 3600))
        Complete-PathDiag -Code 2
        return
    }
    if ($wait -gt 0) {
        Write-Rule "Waiting until $($target.ToString('HH:mm:ss')) local ($([int]$wait)s)"
        Write-Info 'Start the other end with the same -StartAt value so both captures cover the same window.'
        while ((Get-Date) -lt $target) {
            $remaining = [int](($target - (Get-Date)).TotalSeconds)
            Write-Progress -Activity 'Synchronised start' -Status "$remaining s" -PercentComplete ([Math]::Max(0, 100 - [Math]::Min(100, $remaining)))
            Start-Sleep -Milliseconds 200
        }
        Write-Progress -Activity 'Synchronised start' -Completed
    }
}

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$safeRole = ($Role -replace '[^A-Za-z0-9._-]', '-')

# Resolve the port list: explicit -Port plus every -PortSet, de-duplicated.
# Neither given falls back to Core rather than to a hardcoded pair, so the default
# run covers the whole backup-server-to-component surface.
$resolvedPorts = @()
if ($Port)    { $resolvedPorts += @($Port) }
if ($PortSet) { $resolvedPorts += @(Get-VeeamPortSet -SetNames $PortSet) }
if ($resolvedPorts.Count -eq 0) {
    $resolvedPorts = @(Get-VeeamPortSet -SetNames @('Core'))
    Write-Rule 'No -Port or -PortSet given - defaulting to the Core set'
}
$resolvedPorts = @($resolvedPorts | Sort-Object -Unique)

Write-Rule "Ports under test ($($resolvedPorts.Count))"
foreach ($p in $resolvedPorts) {
    $desc = Get-PortDescription -PortNumber $p
    if (-not $desc) { $desc = '(not in the Veeam catalog)' }
    Write-Info ('{0,-6} {1}' -f $p, $desc)
}
Write-Info ''
Write-Info '~ marks a port documented but not confirmed by service name - treat as indicative.'
if ($resolvedPorts.Count -gt 6 -and $TraceLimit -gt 0) {
    Write-Info "TCP tracing is limited to $TraceLimit port(s); failing ports are traced first. Use -TraceLimit to change, 0 to disable."
}

# The finally block is not optional. Without it, a Ctrl-C or a terminating error
# between capture start and stop leaves pktmon running indefinitely on a production
# server with filters installed, writing into a 300 MB circular ETL.
$report = $null
try {
    $report = Invoke-Collect -PeerName $Peer -Ports $resolvedPorts -RoleLabel $safeRole `
                             -ConnectTimeoutMs $TimeoutMs -DoCapture ([bool]$Capture) `
                             -SkipTcpPath ([bool]$NoTcpPath) -Hops $MaxHops -Destination $OutDir `
                             -MaxTracePorts $TraceLimit
} finally {
    if ($Capture -and (Test-PktmonAvailable)) {
        try { $null = & pktmon.exe stop 2>&1 } catch { }
        try { $null = & pktmon.exe filter remove 2>&1 } catch { }
    }
}

if (-not $report) {
    Write-Rule 'Collection aborted'
    Complete-PathDiag -Code 2
    return
}

$jsonPath = Join-Path $OutDir "pathdiag-$safeRole-$stamp.json"
$txtPath  = Join-Path $OutDir "pathdiag-$safeRole-$stamp.txt"

# Depth 12 against a schema whose deepest branch is 5 levels, so there is headroom
# and ConvertTo-Json can never quietly replace a nested object with its type name.
$jsonOk = $false
try {
    $json = $report | ConvertTo-Json -Depth 12
    # WriteAllText with an explicit BOM-less encoder. Set-Content -Encoding UTF8 on
    # Windows PowerShell 5.1 means UTF-8 WITH BOM, and a leading U+FEFF is rejected
    # by jq, Python's json module and most other readers. Get-Content strips it, so
    # this script's own round-trip would never have caught it - but the whole point
    # of the file is to be copied to another machine and consumed there.
    [IO.File]::WriteAllText($jsonPath, $json, (New-Object System.Text.UTF8Encoding $false))
    $jsonOk = $true
} catch {
    Write-Bad "Could not write JSON report: $($_.Exception.Message)"
}

# Read it straight back. A report that does not round-trip is worse than no report
# at all, because -Compare would silently read $null for the missing branches and
# conclude there was no problem.
if ($jsonOk) {
    try {
        $verify = Get-Content -Raw -Path $jsonPath | ConvertFrom-Json
        $missing = @()
        foreach ($k in 'schema', 'role', 'host', 'peer', 'egress', 'paths', 'connects', 'capture', 'findings') {
            if ($null -eq $verify.$k) { $missing += $k }
        }
        if ($verify.schema -ne 'pathdiag/2') { $missing += "schema was '$($verify.schema)'" }
        if ($missing.Count -gt 0) {
            Write-Bad "JSON round-trip check FAILED - missing or wrong: $($missing -join ', '). Do not rely on -Compare with this file."
            $jsonOk = $false
        }
    } catch {
        Write-Bad "JSON round-trip check FAILED: $($_.Exception.Message)"
        $jsonOk = $false
    }
}

# The .txt is the human read: same facts, plus the prose that is deliberately kept
# out of the JSON.
$lines = New-Object System.Collections.ArrayList
$null = $lines.Add("Path diagnostic - $($report.role) -> $($report.peer.query) ($($report.peer.ip))")
$null = $lines.Add("Collected $($report.generatedUtc) on $($report.host.name) ($($report.host.os))")
$null = $lines.Add("Ports: $($report.ports -join ', ')")
$null = $lines.Add('')
$null = $lines.Add("Egress source : $($report.egress.sourceIp)")
$null = $lines.Add("Interface     : $($report.egress.interfaceAlias) (index $($report.egress.interfaceIndex), metric $($report.egress.interfaceMetric))")
$null = $lines.Add("Next hop      : $($report.egress.nextHop)")
$null = $lines.Add("Matched route : $($report.egress.matchedPrefix)")
$null = $lines.Add("ECMP          : $($report.egress.ecmp)")
$null = $lines.Add("Ephemeral     : $($report.ephemeral.start)-$($report.ephemeral.end)")
$null = $lines.Add('')
$null = $lines.Add("ICMP path (reached destination: $($report.paths.icmp.reachedDestination)):")
foreach ($h in @($report.paths.icmp.hops)) {
    $d = $h.address; if (-not $d) { $d = '*' }
    $null = $lines.Add(('  {0,3}  {1,-16} {2}' -f $h.ttl, $d, $h.status))
}
foreach ($tp in @($report.paths.tcp)) {
    $null = $lines.Add('')
    if (-not $tp.supported) {
        $null = $lines.Add("TCP path port $($tp.port): not available - $($tp.reason)")
        continue
    }
    $null = $lines.Add("TCP path port $($tp.port) (reached destination: $($tp.reachedDestination)):")
    if ($tp.reason) { $null = $lines.Add("  note: $($tp.reason)") }
    foreach ($h in @($tp.hops)) {
        $d = $h.address; if (-not $d) { $d = '*' }
        $null = $lines.Add(('  {0,3}  {1,-16} {2}' -f $h.ttl, $d, $h.status))
    }
}
$null = $lines.Add('')
$null = $lines.Add('Connect results:')
foreach ($c in @($report.connects)) {
    $null = $lines.Add(("  port {0,-6} {1,-20} {2} ms   {3}" -f $c.port, $c.outcome, $c.elapsedMs, $c.component))
    if ($c.message) { $null = $lines.Add("    error: $($c.message)") }
    $prose = Get-OutcomeInterpretation -Outcome $c.outcome
    if ($prose) { $null = $lines.Add("    $prose") }
}
if ($report.capture.requested) {
    $null = $lines.Add('')
    $null = $lines.Add('Capture:')
    $null = $lines.Add("  started=$($report.capture.started)  parsed=$($report.capture.parsed)  tcpLinesRecognised=$($report.capture.parserMatchedTcp)")
    $null = $lines.Add("  packets=$($report.capture.totalPackets)  toServicePort=$($report.capture.toServicePort)  fromServicePort=$($report.capture.fromServicePort)")
    if (@($report.capture.observedSources).Count -gt 0) {
        $null = $lines.Add("  sources seen on the service port: $(@($report.capture.observedSources) -join ', ')")
    }
    foreach ($d in @($report.capture.drops)) { $null = $lines.Add("  DROP: $($d.reason) x$($d.count)") }
    foreach ($d in @($report.capture.diagnostics)) { $null = $lines.Add("  pktmon: $d") }
}
$null = $lines.Add('')
$null = $lines.Add('Findings:')
foreach ($f in @($report.findings)) {
    $null = $lines.Add(("  [{0}] {1}: {2}" -f $f.severity, $f.area, $f.message))
}
try { $lines | Set-Content -Path $txtPath -Encoding UTF8 } catch { }

Write-Rule 'Done'
if ($jsonOk) { Write-Good "JSON : $jsonPath" } else { Write-Bad "JSON : $jsonPath  (failed verification)" }
Write-Good "Text : $txtPath"
Write-Host ''
Write-Host '  Next: copy both ends'' JSON files to one machine and run' -ForegroundColor Cyan
Write-Host "    .\Invoke-PathDiag.ps1 -Compare .\pathdiag-A-*.json,.\pathdiag-B-*.json" -ForegroundColor Cyan
Write-Host ''
Write-Host '  This run left your session open. The report object is still here as' -ForegroundColor DarkCyan
Write-Host '    $PathDiagLastReport        e.g. $PathDiagLastReport.paths.tcp[0].hops' -ForegroundColor DarkCyan
Write-Host '  Result code is in $LASTEXITCODE (0 clean, 1 something flagged, 2 could not run).' -ForegroundColor DarkCyan
Write-Host ''

# Keep the report reachable from the caller's session without forcing it onto the
# pipeline, where it would dump a wall of object output over the console report.
$global:PathDiagLastReport = $report

# Emit BEFORE Complete-PathDiag: under -ExitWithCode that function calls exit, and
# anything after it would never run.
if ($PassThru) { $report }

$critical = @(@($report.findings) | Where-Object { $_.severity -eq 'Critical' })
if ($critical.Count -gt 0) { Complete-PathDiag -Code 1 } else { Complete-PathDiag -Code 0 }

} finally {
    Restore-PathDiagPreference

    # In the finally so it covers every path - a clean run, an early return, an
    # unhandled error. Losing the console output on the failure cases is exactly
    # when it hurts most.
    if (-not $ExitWithCode -and -not $NoPause) {
        if ($KeepOpen) {
            Suspend-ForOperator -Reason 'Holding the window open (-KeepOpen).'
        } elseif (Test-HostWillClose) {
            Suspend-ForOperator -Reason 'This host was started with -File or -Command, so it closes as soon as the script returns. Launch with "powershell.exe -NoExit -File ..." (or run from an already-open prompt) to avoid this pause.'
        }
    }
}
