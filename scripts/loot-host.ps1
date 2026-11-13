# loot-host.ps1 -- loot-host.sh for Windows: listening sockets, the services
# behind them, addresses, and the firewall the host is actually enforcing.
#
# Run elevated. Unelevated it still runs, but Win32_Process hides other users'
# executable paths and command lines, so listeners lose their attribution
# quietly. That is recorded in `errors.txt` rather than guessed around.
#
# Local only, on purpose. Remote collection (WinRM, remote WMI) opens 5985/135
# and adds firewall rules, which changes the footprint being measured. Copy the
# script over, run it, and bring the directory back as
# hosts/<hostname>/loot-host/:
#
#     powershell -ExecutionPolicy Bypass -File loot-host.ps1 [outdir]
#
# That is read-only and quick: listening sockets only. Which process talked
# where is conn-audit.ps1's job, the counterpart for connections.
#
# Windows PowerShell 5.1 is the floor (stock on Server 2016+ and Windows 10+).
#
# Output files:
#   collected-at     -- when netstat ran, UTC (ISO 8601); a copy keeps it
#   connections.csv  -- netstat -ano listeners (TCP) and endpoints (UDP),
#                       joined with Win32_Process on the pid: ProcessName,
#                       ProcessPath, CommandLine. netstat, as PoSh-R2 used,
#                       because the Get-Net*Connection cmdlets hide the IPv4
#                       half of dual-mode sockets (see 'connections' below).
#   http-urls.csv    -- HTTP.sys URL registrations with their processes (Port,
#                       Url, ProcessId, Image): what a System-owned port really
#                       is; raw netsh text beside it (http-servicestate.txt,
#                       http-urlacl.txt).
#   Services.csv     -- Win32_Service, ProcessId included: the services hosted
#                       in each svchost. The name is PoSh-R2's, so the reader's
#                       filename hint picks it.
#   ipaddr.json      -- Get-NetIPAddress in `ip -j addr show` shape (ifname,
#                       addr_info[].local/prefixlen), so the prefix length
#                       reaches firru by the same path as on Linux.
#   firewall.json    -- profiles (enabled, default actions) and every rule in
#                       the ActiveStore -- local and GPO merged, i.e. what is
#                       enforced -- joined with its port, address, application
#                       and service filters. Get-NetFirewallRule alone, which
#                       is what PoSh-R2 exports, carries none of those: no
#                       ports, no addresses, no program. Plus the count of
#                       IPsec connection security / main mode rules.
#   hostname         -- the FQDN, or the bare name off a domain.
#   errors.txt       -- whatever failed. Absent means nothing did.
#   manifest.sha256  -- sha256 of the sorted (proto, scope, port, process)
#                       tuples: drift detection without pid churn. Scope is
#                       the wildcard or loopback, else just "host", so a new
#                       DHCP lease is not drift; dynamic-range UDP ports, which
#                       are new on every boot, count once per process.
#
# Every file is UTF-8 without a BOM. Windows PowerShell 5.1 writes ASCII from
# Export-Csv (localized service descriptions become '?') and UTF-16 from
# Out-File; with a BOM, the first CSV column name comes back as '﻿Protocol'.

param(
    [string]$OutDir
)

$ErrorActionPreference = 'Stop'
$utf8 = New-Object System.Text.UTF8Encoding $false

$cs = Get-CimInstance Win32_ComputerSystem
$fqdn = if ($cs.PartOfDomain) { "$($cs.DNSHostName).$($cs.Domain)" } else { $cs.DNSHostName }
$fqdn = $fqdn.ToLower()
if (-not $OutDir) { $OutDir = Join-Path $env:TEMP "loot-$fqdn" }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$OutDir = (Resolve-Path $OutDir).Path
Write-Host "Collecting $fqdn -> $OutDir"

$errors = New-Object System.Collections.Generic.List[string]

function Save-Lines([string]$name, [string[]]$lines) {
    [System.IO.File]::WriteAllLines((Join-Path $OutDir $name), $lines, $utf8)
}
function Save-Csv([string]$name, $rows) {
    # No rows still writes the (empty) file: present-and-empty is an answer,
    # absent is a failure.
    # @(...) around the whole if: an if that yields @() assigns $null, not an empty array.
    [string[]]$lines = @(if ($rows) { $rows | ConvertTo-Csv -NoTypeInformation })
    Save-Lines $name $lines
}
function Save-Json([string]$name, $obj) {
    Save-Lines $name @(ConvertTo-Json -InputObject $obj -Depth 6)
}
function Step([string]$what, [scriptblock]$body) {
    try { & $body }
    catch { $errors.Add("${what}: $($_.Exception.Message)"); Write-Warning "${what}: $_" }
}

$elevated = $false
Step 'elevation check' {
    $script:elevated = ([Security.Principal.WindowsPrincipal] `
        [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
if (-not $elevated) {
    $errors.Add('not elevated: process paths and command lines may be missing')
}

Save-Lines 'hostname' @($fqdn)
# The dynamic (ephemeral) port ranges, as this host has them: not always the
# default 49152-65535 (Exchange Setup moves TCP's to 6005-65535).
# The release (which baseline it compares with).
$os = Get-CimInstance Win32_OperatingSystem
Save-Lines 'os-release' @("NAME=$($os.Caption)", "BUILD=$($os.BuildNumber)")
Save-Lines 'dynamicport.txt' @(foreach ($p in 'tcp', 'udp') { & netsh.exe int ipv4 show dynamicport $p })

# ---------------------------------------------------------------------------
# Sockets
# ---------------------------------------------------------------------------

$procs = @{}
Step 'Win32_Process' {
    foreach ($p in Get-CimInstance Win32_Process) {
        $procs[[int]$p.ProcessId] = $p
    }
}

function Socket-Row([string]$proto, $s, [string]$state) {
    $p = $procs[[int]$s.OwningProcess]
    [PSCustomObject]@{
        Protocol      = $proto
        LocalAddress  = $s.LocalAddress
        LocalPort     = $s.LocalPort
        State         = $state
        OwningProcess = $s.OwningProcess
        ProcessName   = if ($p) { $p.Name -replace '\.exe$', '' } else { '' }
        ProcessPath   = if ($p) { $p.ExecutablePath } else { '' }
        CommandLine   = if ($p) { $p.CommandLine } else { '' }
    }
}

$sockets = @()
# netstat, not Get-NetTCPConnection / Get-NetUDPEndpoint: the cmdlets report a
# dual-mode socket once, on ::, so SMB 445, http.sys 80 and WinRM 47001 look
# IPv6-only; netstat reads the IPv4 and IPv6 tables separately and lists them
# in both, as PoSh-R2's netstat-based loot always did. Parsed by position, not
# by word: the state column is localized (LISTENING is KUUNTELEE on Finnish
# Windows), so a TCP listener is recognized by its foreign address, which is
# 0.0.0.0:0 or [::]:0 only while listening.
function Split-Endpoint([string]$ep) {
    $i = $ep.LastIndexOf(':')
    [PSCustomObject]@{ Address = $ep.Substring(0, $i).Trim('[', ']'); Port = [int]$ep.Substring($i + 1) }
}
Step 'connections' {
    Save-Lines 'collected-at' @((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
    $rows = foreach ($line in (& netstat.exe -ano)) {
        $t = -split $line
        if ($t.Count -lt 4) { continue }
        if ($t[0] -eq 'TCP' -and $t.Count -ge 5 -and $t[2] -in '0.0.0.0:0', '[::]:0') {
            $l = Split-Endpoint $t[1]
            Socket-Row 'TCP' ([PSCustomObject]@{ LocalAddress = $l.Address; LocalPort = $l.Port; OwningProcess = $t[4] }) 'Listen'
        } elseif ($t[0] -eq 'UDP') {
            $l = Split-Endpoint $t[1]
            Socket-Row 'UDP' ([PSCustomObject]@{ LocalAddress = $l.Address; LocalPort = $l.Port; OwningProcess = $t[3] }) ''
        }
    }
    $script:sockets = @($rows)
    Save-Csv 'connections.csv' $script:sockets
}

# ---------------------------------------------------------------------------
# HTTP.sys: which process and URL path sits behind a System-owned port
# ---------------------------------------------------------------------------
# Ports served through HTTP.sys (WinRM 5985/47001, RDP WebSocket 3387, IIS,
# WSUS ...) belong to System (pid 4) in the socket table, and several
# processes can share one port by URL path; a firewall rule sees only the
# port. The request queues name the real process and paths. Raw text is kept
# next to the parse; the labels are localized, so the parse goes by shape.
Step 'http.sys' {
    $raw = @(& netsh.exe http show servicestate view=requestq verbose=no)
    Save-Lines 'http-servicestate.txt' $raw
    Save-Lines 'http-urlacl.txt' @(& netsh.exe http show urlacl)
    $rows = New-Object System.Collections.Generic.List[object]
    $queue = 0; $procs = @()
    foreach ($line in $raw) {
        if ($line -match '^\S' -and $line -match ':') { $queue++; $procs = @(); continue }
        if ($line -match '(\d+),\s*\S+:\s*([A-Za-z]:\\.+?)\s*$') {
            $procs += [PSCustomObject]@{ Id = $Matches[1]; Image = $Matches[2] }; continue }
        if ($line -match '^\s*(https?://\S+)\s*$') {
            $url = $Matches[1]
            $port = if ($url -match '://[^/]*:(\d+)/') { $Matches[1] } elseif ($url -match '^https') { '443' } else { '80' }
            if ($procs.Count -eq 0) { $rows.Add([PSCustomObject]@{ Queue = $queue; Port = $port; Url = $url; ProcessId = ''; Image = '' }) }
            foreach ($pr in $procs) { $rows.Add([PSCustomObject]@{ Queue = $queue; Port = $port; Url = $url; ProcessId = $pr.Id; Image = $pr.Image }) }
        }
    }
    Save-Csv 'http-urls.csv' $rows
}

# ---------------------------------------------------------------------------
# Services: which service names sit behind each pid
# ---------------------------------------------------------------------------

Step 'Services' {
    $rows = Get-CimInstance Win32_Service | ForEach-Object {
        [PSCustomObject]@{
            Name             = $_.Name
            DisplayName      = $_.DisplayName
            ProcessId        = $_.ProcessId
            State            = $_.State
            StartMode        = $_.StartMode
            DelayedAutoStart = $_.DelayedAutoStart
            ServiceType      = $_.ServiceType
            StartName        = $_.StartName
            PathName         = $_.PathName
            Description      = $_.Description
        }
    }
    Save-Csv 'Services.csv' $rows
}

# ---------------------------------------------------------------------------
# Addresses, in `ip -j addr show` shape
# ---------------------------------------------------------------------------

Step 'ipaddr' {
    $ifaces = Get-NetIPAddress | Group-Object InterfaceIndex | ForEach-Object {
        $first = $_.Group[0]
        [ordered]@{
            ifindex   = [int]$first.InterfaceIndex
            ifname    = $first.InterfaceAlias
            addr_info = @($_.Group | ForEach-Object {
                [ordered]@{
                    family    = if ($_.AddressFamily -eq 'IPv6') { 'inet6' } else { 'inet' }
                    local     = ($_.IPAddress -split '%')[0]
                    prefixlen = [int]$_.PrefixLength
                    origin    = [string]$_.PrefixOrigin
                }
            })
        }
    }
    Save-Json 'ipaddr.json' @($ifaces)
}

# ---------------------------------------------------------------------------
# Firewall: what is enforced, with the filters that say what each rule matches
# ---------------------------------------------------------------------------

Step 'firewall' {
    $store = 'ActiveStore'
    # One bulk query per filter type, indexed by the rule's InstanceID. Asking
    # per rule is several hundred CIM round trips on a stock host.
    $index = {
        param($items)
        $h = @{}
        foreach ($i in $items) { $h[$i.InstanceID] = $i }
        $h
    }
    $ports = & $index (Get-NetFirewallPortFilter -All -PolicyStore $store)
    $addrs = & $index (Get-NetFirewallAddressFilter -All -PolicyStore $store)
    $apps  = & $index (Get-NetFirewallApplicationFilter -All -PolicyStore $store)
    $svcs  = & $index (Get-NetFirewallServiceFilter -All -PolicyStore $store)
    # Interface scoping: a rule for Wi-Fi Direct or one adapter only reads as
    # "any interface" without these (Server 2025 enables WFD driver rules for
    # System on every port).
    $ifs   = & $index (Get-NetFirewallInterfaceFilter -All -PolicyStore $store -ErrorAction SilentlyContinue)
    $iftys = & $index (Get-NetFirewallInterfaceTypeFilter -All -PolicyStore $store -ErrorAction SilentlyContinue)

    # The comma keeps a one-element list a list: PowerShell unrolls arrays
    # out of an `if` or a function, and ConvertTo-Json then writes "3389"
    # where every other rule has ["80", "443"].
    function List-Of($filter, [string]$field) {
        if ($filter) { , @($filter.$field) } else { , @() }
    }

    $rules = Get-NetFirewallRule -PolicyStore $store | ForEach-Object {
        $id = $_.InstanceID
        $pf = $ports[$id]; $af = $addrs[$id]; $ap = $apps[$id]; $sf = $svcs[$id]
        $if = $ifs[$id]; $it = $iftys[$id]
        [ordered]@{
            Name          = $_.Name
            DisplayName   = $_.DisplayName
            Group         = $_.Group
            DisplayGroup  = $_.DisplayGroup
            Enabled       = [string]$_.Enabled -eq 'True'
            # Whether Windows actually plumbed the rule into WFP. Enabled rules
            # can still be inert: Server 2025's Wi-Fi Direct rules (System,
            # every port) are 'ProfileInactive NoDynamicTransport' and have no
            # filter until a WFD link exists; keyword rules whose keyword
            # resolves to nothing are NoRemoteAddress / NoLocalPort.
            Enforcement   = [string]$_.EnforcementStatus
            Status        = [string]$_.PrimaryStatus
            Direction     = [string]$_.Direction
            Action        = [string]$_.Action
            Profile       = [string]$_.Profile
            EdgeTraversal = [string]$_.EdgeTraversalPolicy
            Source        = [string]$_.PolicyStoreSourceType
            Protocol      = if ($pf) { [string]$pf.Protocol } else { $null }
            LocalPort     = List-Of $pf 'LocalPort'
            RemotePort    = List-Of $pf 'RemotePort'
            IcmpType      = List-Of $pf 'IcmpType'
            LocalAddress  = List-Of $af 'LocalAddress'
            RemoteAddress = List-Of $af 'RemoteAddress'
            Program       = if ($ap) { $ap.Program } else { $null }
            Package       = if ($ap) { $ap.Package } else { $null }
            Service       = if ($sf) { $sf.Service } else { $null }
            # Store-app rules: the AppContainer SID that owns the rule, when
            # the application filter does not carry it as Package.
            Owner         = if ($_.Owner) { [string]$_.Owner } else { $null }
            InterfaceAlias = List-Of $if 'InterfaceAlias'
            InterfaceType = if ($it) { [string]$it.InterfaceType } else { $null }
        }
    }

    $profiles = Get-NetFirewallProfile -PolicyStore $store | ForEach-Object {
        [ordered]@{
            Name                  = $_.Name
            Enabled               = [string]$_.Enabled
            DefaultInboundAction  = [string]$_.DefaultInboundAction
            DefaultOutboundAction = [string]$_.DefaultOutboundAction
            AllowLocalFirewallRules = [string]$_.AllowLocalFirewallRules
        }
    }
    # Which profile each interface is in decides which rules apply to it.
    $nets = Get-NetConnectionProfile -ErrorAction SilentlyContinue | ForEach-Object {
        [ordered]@{
            ifname   = $_.InterfaceAlias
            ifindex  = [int]$_.InterfaceIndex
            category = [string]$_.NetworkCategory
        }
    }

    # IPsec connection security and main mode rules, counted. Legacy
    # `netsh ipsec static` policies are not.
    $ipsec = [ordered]@{
        connection_security_rules = @(Get-NetIPsecRule -PolicyStore ActiveStore -ErrorAction SilentlyContinue).Count
        main_mode_rules           = @(Get-NetIPsecMainModeRule -PolicyStore ActiveStore -ErrorAction SilentlyContinue).Count
    }

    Save-Json 'firewall.json' ([ordered]@{
        profiles   = @($profiles)
        interfaces = @($nets)
        rules      = @($rules)
        ipsec      = $ipsec
    })
}

# ---------------------------------------------------------------------------
# Drift manifest: pid-free, order-free
# ---------------------------------------------------------------------------

Step 'manifest' {
    $tuples = $sockets | ForEach-Object {
        $scope = if ($_.LocalAddress -in @('0.0.0.0', '::')) { $_.LocalAddress }
                 elseif ($_.LocalAddress -match '^(127\.|::1$)') { 'loopback' }
                 else { 'host' }
        $port = if ($_.Protocol -eq 'UDP' -and [int]$_.LocalPort -ge 49152) { 'dynamic' } else { $_.LocalPort }
        "$($_.Protocol) $scope $port $($_.ProcessName)"
    } | Sort-Object -Unique
    $bytes = $utf8.GetBytes(($tuples -join "`n") + "`n")
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $hex = -join ($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') })
    Save-Lines 'manifest.sha256' @("$hex  connections.csv")
}

if ($errors.Count) {
    Save-Lines 'errors.txt' $errors.ToArray()
    Write-Warning "$($errors.Count) step(s) failed; see errors.txt"
}
Write-Host "Done: $OutDir ($(@($sockets).Count) sockets)"
