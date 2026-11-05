# Invoke-PathDiag.ps1

Two-ended TCP path diagnostic. Built for one specific failure: the server receives SYNs and generates SYN-ACKs, but the client-side firewall sessions age out having never recorded a returning packet.

## Why a one-ended test cannot solve this

A plain TCP connect test returns `FAILED` in two completely different situations — the SYN never arrived, or the SYN-ACK never came back. Those have different root causes and different fixes, and a connect test collapses them into one result. That is why this script is designed to be run on **both** ends and the two reports compared. `Test-PortOpen` in the older `veeam-portcheck` toolkit cannot tell you anything here beyond what you already know.

Two related corrections worth internalising before you start:

**`tracert` does not show you the return path.** It shows the forward path from wherever you run it. The TTL-exceeded replies do travel back over the reverse path, but you never see its hops — each line is the forward-facing interface of a router on the way out. The only way to see the return path is to trace from the far end back. That is what `-Compare` is for.

**ICMP and TCP do not necessarily take the same path.** ECMP hashes on the 5-tuple and policy-based routing can match on protocol, so a clean `tracert` proves nothing about your TCP session. This script traces the real service port with TTL-limited SYNs and flags it when the two paths diverge.

## Quick start

Elevated PowerShell on both ends, at the same moment:

```powershell
# On the source proxy
.\Invoke-PathDiag.ps1 -Peer 10.201.21.10 -PortSet DataMover -Role source-proxy -Capture -StartAt '14:30:00'

# On 10.201.21.10
.\Invoke-PathDiag.ps1 -Peer 10.10.5.20 -PortSet DataMover -Role dest-server -Capture -StartAt '14:30:00'
```

Then copy both `.json` files to one machine:

```powershell
.\Invoke-PathDiag.ps1 -Compare .\pathdiag-source-proxy-*.json,.\pathdiag-dest-server-*.json
```

`-StartAt` takes a local wall-clock time and blocks until it arrives, so both captures cover the same window. Use it — `-Compare` warns and refuses to draw conclusions if the two reports are more than five minutes apart.

## Parameters

| Parameter | Notes |
|---|---|
| `-Peer <host>` | The other end. Hostname or IP. |
| `-Port <int[]>` | Explicit port(s). Combined with `-PortSet`. |
| `-PortSet <name[]>` | Named groups from the Veeam catalog below. Defaults to `Core` when neither is given. |
| `-TraceLimit <int>` | How many ports get a TCP traceroute. Default 2. `0` disables tracing. |
| `-Role <label>` | Free-text label used in filenames and compare output, e.g. `source-proxy`. |
| `-TimeoutMs <int>` | Connect timeout, default **5000**. See the warning below. |
| `-Capture` | Wrap the tests in a pktmon capture, convert to pcapng, and extract drop reasons. |
| `-StartAt <time>` | Block until this local time before starting. `'HH:mm:ss'` or a full datetime. |
| `-NoTcpPath` | Skip the TCP traceroute (which needs a raw socket). ICMP trace still runs. |
| `-MaxHops <int>` | Traceroute hop limit, default 30. |
| `-OutDir <path>` | Where reports land. Defaults to the script directory. |
| `-Compare <a.json>,<b.json>` | Analysis only. Collects nothing. |
| `-PassThru` | Emit the report object to the pipeline: `$r = .\Invoke-PathDiag.ps1 -Peer x -PassThru` |
| `-ExitWithCode` | Call `exit` and terminate the host process. **Off by default** — see below. |
| `-KeepOpen` | Always pause before returning. |
| `-NoPause` | Never pause, even when the window is about to close. |

## Port sets

`-PortSet` takes any combination of these, drawn from `veeam-portcheck/functions/PortTables.ps1`:

| Set | Ports |
|---|---|
| `Core` *(default)* | 443, 6160, 6162, 6172, 9380, 9392, 9393, 9401, 9405, 9419, 10006, 10443 |
| `DataMover` | 6160, 6162, 2500, 2501, 3300 |
| `VPowerNfs` | 111, 1058, 2049, 6161 |
| `EnterpriseManager` | 9080, 9394, 9398, 9399, 9443, 10443 |
| `CloudConnect` | 443, 6180, 10003 |
| `WanAccelerator` | 6164, 6165 |
| `Database` | 1433, 5432 |
| `VeeamOne` | 50001 |
| `Os` | 135, 139, 445 |
| `GuestProcessing` | 135, 445, 49152, 65535 |
| `Dependencies` | 53, 80, 389, 443, 636, 3268, 3269 |
| `All` | every port above |

```powershell
.\Invoke-PathDiag.ps1 -Peer 10.201.21.10 -PortSet DataMover,VPowerNfs -Role source-proxy
.\Invoke-PathDiag.ps1 -Peer 10.201.21.10 -PortSet Core -Port 6162,9392
```

Each result is labelled with the component that owns the port. A `~` suffix means the port is documented but not confirmed by service name against v13 docs — treat those as indicative.

Two of these are range samples rather than real ports. `DataMover` tests 2500, 2501 and 3300 as probes into the 2500–3300 transfer range, and `GuestProcessing` tests 49152 and 65535 as probes into the dynamic RPC range. Both tell you whether the range is open at all; neither proves every port in it is.

**Connects run on every port; tracing does not.** A TCP traceroute can take up to `MaxHops × HopTimeout` per port, so a 12-port `Core` run would spend minutes tracing. `-TraceLimit` caps it at 2 by default, and the ports whose connect *failed* are traced first, since that is where the path actually matters. Raise it when you want more, or set `0` to skip tracing.

## It will not close your session

The script never calls `exit` unless you ask for it with `-ExitWithCode`. Instead:

- the result code is published as `$LASTEXITCODE` — `0` clean, `1` something flagged, `2` could not run;
- the full report object stays reachable afterwards as `$PathDiagLastReport`, so you can keep poking at it (`$PathDiagLastReport.paths.tcp[0].hops`) without re-reading the JSON;
- `$ErrorActionPreference` and `$ProgressPreference` are saved on entry and restored on exit, so a dot-sourced run leaves your shell configured the way it found it;
- the capture is wrapped in `try/finally`, so Ctrl-C still stops pktmon and clears the filters.

**If the window still closes, the script is not what is closing it.** When `powershell.exe` is started with `-File` or `-Command`, the *host process* terminates the moment the script returns. That is the host's behaviour and no amount of removing `exit` from the script can change it. "Run with PowerShell" from Explorer, a desktop shortcut, a `.bat` wrapper and most scheduled-task definitions all launch that way.

The script now detects this and pauses before returning, so you keep the output. It only does so when the console is interactive, the host is `ConsoleHost`, and the command line contains `-File` or `-Command` without `-NoExit` — so a scheduled run never blocks. Force it with `-KeepOpen`, suppress it with `-NoPause`.

The cleaner fix is to not launch that way:

```powershell
powershell.exe -NoExit -File .\Invoke-PathDiag.ps1 -Peer 10.201.21.10
```

or just run it from a prompt you already have open, where nothing closes in the first place.

Use `-ExitWithCode` for CI or a scheduled task that reads `%ERRORLEVEL%`; that path never pauses.

## JSON schema (`pathdiag/2`)

The JSON is a deliberate projection, not a dump of internal state. Every leaf is a scalar and every collection is an array of flat objects, so it diffs cleanly between runs and `ConvertTo-Json -Depth` can never silently truncate a branch into a type name. Console prose is kept out of it — `connects[].outcome` is the machine-readable fact, and the matching explanation lives in the `.txt` report. After writing, the script reads the file straight back and verifies the top-level branches survived; a report that fails that check is reported as failed rather than quietly handed to `-Compare`.

```json
{
  "schema": "pathdiag/2",
  "generatedUtc": "2026-11-05T14:30:02Z",
  "role": "source-proxy",
  "ports": [6162],
  "host":   { "name": "", "fqdn": "", "os": "", "timeZone": "",
              "addresses": [ { "ip": "", "prefixLength": 24, "interfaceAlias": "",
                               "interfaceIndex": 12, "prefixOrigin": "", "skipAsSource": false } ] },
  "peer":   { "query": "", "ip": "", "isLiteralIp": false, "forwardAddresses": [],
              "reverseName": "", "forwardOfReverse": [], "dnsServers": [], "resolveError": "" },
  "egress": { "sourceIp": "", "interfaceAlias": "", "interfaceIndex": 12, "interfaceMetric": 25,
              "nextHop": "", "matchedPrefix": "", "routeMetric": 0, "ecmp": false, "lookupError": "",
              "defaultRoutes":   [ { "nextHop": "", "interfaceAlias": "", "interfaceIndex": 12, "routeMetric": 0 } ],
              "candidateRoutes": [ { "prefix": "", "nextHop": "", "interfaceAlias": "", "interfaceIndex": 12, "routeMetric": 0 } ] },
  "ephemeral": { "start": 49152, "end": 65535, "count": 16384, "source": "Get-NetTCPSetting" },
  "firewall":  { "queryError": "",
                 "profiles": [ { "name": "Domain", "enabled": true, "defaultInbound": "", "defaultOutbound": "" } ],
                 "rules":    [ { "displayName": "", "direction": "Inbound", "action": "Allow", "enabled": true,
                                 "profile": "", "protocol": "TCP", "localPort": "", "remotePort": "" } ] },
  "paths": {
    "icmp": { "reachedDestination": true, "maxTtl": 8, "respondingHops": 6,
              "hops": [ { "ttl": 1, "address": "", "status": "TtlExpired", "rttMs": 1 } ] },
    "tcp":  [ { "port": 6162, "supported": true, "reason": "", "reachedDestination": false,
                "maxTtl": 30, "respondingHops": 4,
                "hops": [ { "ttl": 1, "address": "", "status": "TtlExceeded", "rttMs": 1 } ] } ]
  },
  "connects": [ { "port": 6162, "component": "Veeam Data Mover / Transport Service",
                  "outcome": "Timeout", "socketError": "", "message": "",
                  "elapsedMs": 5003, "timeoutMs": 5000, "localEndpoint": "", "returnPathProven": false } ],
  "capture":  { "requested": true, "started": true, "syntax": "modern",
                "files": { "etl": "", "pcapng": "", "text": "" },
                "parsed": true, "parserMatchedTcp": true,
                "totalPackets": 11, "toServicePort": 5, "fromServicePort": 0, "icmpPackets": 0,
                "observedSources": [], "drops": [ { "reason": "", "count": 0 } ], "diagnostics": [] },
  "findings": [ { "severity": "Critical", "area": "Capture", "message": "" } ]
}
```

Three fields carry most of the diagnostic weight. `egress.sourceIp` is the address the stack will actually use, which is what you compare against the far end's `capture.observedSources` to prove NAT. `capture.fromServicePort` is the count of packets seen coming *back* from the service port — zero on the client while the server shows a positive count is the decisive return-path result. And `paths.tcp[].hops` is the real TCP path, which is the one to trust when it disagrees with `paths.icmp`.

`connects[].message` is populated only for the `Error` outcome, where the text is per-instance and exists nowhere else. The five enumerated outcomes (`Connected`, `Refused`, `Timeout`, `HostUnreachable`, `NetworkUnreachable`) have fixed prose that the `.txt` report regenerates from `outcome`, so it is not duplicated into the JSON.

`capture.diagnostics` is populated when pktmon either failed to start *or* produced nothing readable — the second case is the common silent failure, where the capture runs fine and the ETL conversion fails. A healthy run leaves it empty rather than filling the file with console noise. Raw `netsh` output is not included at all; the parsed `ephemeral` fields carry everything it had.

Arrays are always arrays. `paths.icmp.hops` and `paths.tcp[].hops` are `[]` when empty and a one-element list when a single hop answered — never `null` and never a bare object. That matters more than it sounds: zero hops is the normal result on an EDR-protected host that blocks the raw ICMP socket, and one hop is the normal result for a peer on the same VLAN.

The file is written as UTF-8 **without** a BOM, so `jq` and `python -m json.tool` read it directly. (`Set-Content -Encoding UTF8` on PS 5.1 would have added one.)

`-Compare` rejects any file whose `schema` is not `pathdiag/2`, rather than reading `null` from the missing branches and reporting "no problem detected". It also surfaces, in section 8, any Critical or Warning finding either end recorded during collection — those used to exist only in the JSON.

> **Do not lower `-TimeoutMs` for a WAN target.** The 500 ms hardcoded timeout in the older `portest3` / `Reachability.ps1` is already documented as a known limitation there: any WAN-latency target reports every port blocked. Against a cross-site destination that produces a clean-looking false positive for exactly the failure you are chasing.

## What it collects per end

Interface identity and the **egress source address the stack will actually choose** for the peer, via `Find-NetRoute` — this asks the stack the same question the TCP connect will ask. DNS forward and reverse, with multi-A-record and forward/reverse-mismatch detection. Route selection, next hop, every route that could match the peer, and ECMP detection. The dynamic port range. Windows Firewall profile state and any rule touching the service port. ICMP traceroute. TCP traceroute on the service port. A classified TCP connect. Optionally a pktmon capture.

## Reading the output

**The connect outcome is the first thing to read, and `Refused` is not a failure.**

| Outcome | What it means |
|---|---|
| `Connected` | Handshake completed. Forward *and* return path work for this 5-tuple right now. If production still fails, the difference is in the 5-tuple — a different source address or source port taking a different path. |
| `Refused` | An RST travelled the **entire return path** back to you. This proves the return path is intact. The problem is the listener or destination policy, not the network. This single result can end the investigation. |
| `Timeout` | No response. Ambiguous by design — forward or return loss, indistinguishable from one end. This is the case that needs the two-ended capture. |
| `HostUnreachable` / `NetworkUnreachable` | A router answered with ICMP. The TCP trace names the device. |

**pktmon drop events are decisive.** If pktmon logs a drop, the packet died *on that host* — in a filter driver, the firewall, or the stack — not in transit. pktmon names the component and the reason, which no pcap can tell you.

**In the TCP trace, `Unreachable (communication administratively prohibited)` is a filtering device announcing itself.** That hop is your answer.

## Decision tree

- Destination capture shows **no inbound SYN at all** → forward path problem. Stop looking at the return path.
- Destination capture shows the SYN arriving **from an address that is not the source's egress address** → NAT in the path. The server replies to the NAT address, and whatever holds that translation must still have state for the flow. `-Compare` section 2 detects this automatically.
- Destination transmits SYN-ACKs, source capture receives **nothing** → return-path drop, between the two. `-Compare` calls this out as DECISIVE. Go to the next bullet.
- TCP paths differ between the two directions → any device appearing in **one direction only** is a stateful device seeing half a flow. Search each one for a **DENY on the reversed 5-tuple** — source `<server IP>:<service port>`, destination `<client IP>:<ephemeral port>`. Almost everyone searches logs for the forward tuple only and never sees the deny. Out-of-state drops log distinctly: Palo Alto records a `non-syn-tcp` session end reason, FortiGate logs the deny with no matching session, ASA emits `%ASA-6-106015 Deny TCP (no connection)`.
- ECMP detected → the failure will be intermittent and 5-tuple dependent, which matches a case where some sessions complete and some age out. Test repeatedly from different source ports before concluding anything.
- Ephemeral range starts at 49152 and a return ACL exists → check its destination port range. A reverse rule scoped to the legacy 1024–5000 range exists, passes review, and silently drops everything modern Windows originates.
- IPsec tunnel anywhere in the path → check traffic selectors and proxy IDs. They are directional. A mismatch lets the SYN encrypt outbound cleanly while the SYN-ACK has no matching SA at the far end. Produces this exact signature.

## A note on stateful vs stateless

On a stateful firewall a unidirectional rule is normal and harmless — the session table permits the reply, and there is no second rule to be missing. The failure happens when return traffic meets a device that has **no session for it**: a stateless ACL on a router or L3 switch, a second stateful firewall reached through asymmetric routing, an HA peer without session sync, a cloud NACL (stateless by design), or a host firewall where inbound and outbound are separate rulesets.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Completed, nothing critical flagged |
| 1 | Completed, a likely root cause was flagged |
| 2 | Could not run — not elevated, bad parameters, or the peer did not resolve |

## Known limitations

The TCP traceroute opens a raw ICMP socket, which requires Administrator and is frequently blocked by endpoint protection. It degrades gracefully and tells you why; `nmap --traceroute -sS -p <port> <target>` is the fallback. If inbound ICMP is blocked locally by WFP the socket opens fine but receives nothing, so every hop reads `Timeout` while the ICMP trace works perfectly — that combination is reported explicitly, because it looks like a dead path and is not one. ICMP traceroute depends on routers returning TTL-exceeded; a hop that does not is reported as `TimedOut`, which is silence, not a failure.

pktmon command syntax changed across Windows releases, and the script tries both generations: `start --capture --pkt-size` then the 1809/1903-era `start --etw -c -p`, `pktmon format` then the older `etl2txt`, `etl2pcap` then `pcapng`. It records every attempt in the JSON. On builds without pktmon, use `netsh trace start capture=yes`.

Capture text parsing is regex-based and port-line formats differ across builds. If the parser recognises IP lines but no TCP port lines, it says so and tells you not to trust the counts — read the pcapng instead. The pcapng is the source of truth; the parsed counts are a fast first read. Because pktmon logs each packet once per component it traverses, only the first appearance is counted.

Path asymmetry detection flags hops seen in one direction only. Some of this is normal, because routers reply from the ingress interface. Treat it as a lead rather than a verdict. Path **length** is only compared when both traces actually reached the destination — otherwise a run of ICMP-silent routers makes one side look artificially short.

Firewall queries use `ActiveStore`, so GPO-delivered rules are visible. Rules scoped to `LocalPort = Any` are included, since a blanket inbound Block is the most likely local cause and would otherwise never appear.

DNS calls have no timeout and will block for the OS resolver timeout if DNS is sick — which is one of the conditions you may be investigating. Nothing crashes, but startup can stall for tens of seconds.

`-Compare` reasons only from what the two reports contain. Run both ends with `-Capture` or sections 2 and 7 have nothing to work with. All of its directional checks run both ways, so the order you pass the two filenames does not change the verdict.

`-StartAt` refuses anything more than four hours out, since a time that has just passed rolls to tomorrow and would otherwise look like a hang. The capture is wrapped in `try/finally`, so Ctrl-C still stops pktmon and removes the filters. Note that `pktmon filter remove` clears *all* filters on the box, including any a colleague had in place.
