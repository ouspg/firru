# conn-audit.ps1 -- which process talked where: the connection counterpart of
# loot-host.ps1, which stays a quick listening-socket snapshot. Linux has
# conn-audit.sh.
#
# Run elevated (auditpol and the Security log need it). Local only, for the
# same reason as loot-host.ps1.
#
# Which process talked where is only on record if the host audits it: WFP
# connection events (Security 5156-5159), or Sysmon. Export reads what is
# there; to record it on a host that does not, bracket a window:
#
#     conn-audit.ps1 Start            # saves the current setting, enables the audit
#     ... wait, or provoke what you want to see:
#         UsoClient.exe StartScan     # update scan, no install (Win10 / Server 2019+)
#         Update-MpSignature          # Defender definitions (downloads them)
#     conn-audit.ps1 Export [outdir]  # what is recorded so far; the audit stays on
#     conn-audit.ps1 Stop [outdir]    # exports, then restores the saved setting
#
# Bring the directory back as hosts/<hostname>/conn-audit/. A scan shows the
# first hop only: download endpoints appear when something is pending. Under
# an egress firewall the attempt still shows, as blocked (5157).
#
# Output files:
#   egress-config.json -- what decides where update traffic goes: the Windows
#                       Update (WSUS), Delivery Optimization and Defender
#                       signature-source policy keys, the WinHTTP proxy, and
#                       the connection-audit setting. A null key is unset, i.e.
#                       Microsoft's defaults; a WSUS host needs none of them.
#   wfp-connections.csv -- Security events 5156/5157 (connection permitted /
#                       blocked) and 5158/5159 (bind) from the last -Hours,
#                       with the services behind each pid. Empty when the
#                       audit is off: egress-config.json says which.
#   dns-client.csv  -- the DNS Client operational log (Start turns it on):
#                       every query with the header's process and thread, the
#                       services behind the process, the query fields and the
#                       event's data as recorded (Fields). Which process asked
#                       is what the header says; the analysis decides how far
#                       that goes (the DNS Client service asks on behalf of
#                       others).
#   sysmon-network.csv, sysmon-dns.csv -- Sysmon events 3 and 22, when Sysmon
#                       is installed: the same, plus which process resolved
#                       which name.
#   hostname, errors.txt -- as in loot-host.ps1.
#
# Every file is UTF-8 without a BOM.

param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet('Start', 'Export', 'Stop')]
    [string]$Action,
    [Parameter(Position = 1)]
    [string]$OutDir,
    [int]$Hours = 24
)

$ErrorActionPreference = 'Stop'
$utf8 = New-Object System.Text.UTF8Encoding $false

$cs = Get-CimInstance Win32_ComputerSystem
$fqdn = if ($cs.PartOfDomain) { "$($cs.DNSHostName).$($cs.Domain)" } else { $cs.DNSHostName }
$fqdn = $fqdn.ToLower()
# Start writes nothing but the saved setting; Export and Stop write OutDir.
if ($Action -ne 'Start') {
    if (-not $OutDir) { $OutDir = Join-Path $env:TEMP "conn-audit-$fqdn" }
    New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
    $OutDir = (Resolve-Path $OutDir).Path
    Write-Host "Exporting $fqdn -> $OutDir"
}

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
    # auditpol and the Security log both need it.
    Write-Error 'conn-audit.ps1 needs an elevated shell'
    exit 1
}

if ($Action -ne 'Start') { Save-Lines 'hostname' @($fqdn) }

# ---------------------------------------------------------------------------
# Connection audit: opt-in, and always restorable
# ---------------------------------------------------------------------------

# "Filtering Platform Connection", by GUID: the subcategory name is localized.
$auditGuid  = '{0CCE9226-69AE-11D9-BED3-505054503030}'
# Outside OutDir on purpose: Stop may write to a different directory than
# Start did, and the setting to restore must not depend on which.
$auditState = Join-Path $env:ProgramData 'firru\connection-audit.json'
$dnsLog     = 'Microsoft-Windows-DNS-Client/Operational'

function Get-AuditSetting {
    $row = & auditpol.exe /get /subcategory:$auditGuid /r | Where-Object { $_ } | ConvertFrom-Csv
    [string]$row[0].'Inclusion Setting'
}

if ($Action -eq 'Start') {
    Step 'connection audit start' {
        # A second Start would save "enabled" as the setting to go back to.
        if (Test-Path $auditState) { throw "already started; $auditState holds the setting to restore" }
        $dl = Get-WinEvent -ListLog $dnsLog
        $state = [ordered]@{
            setting            = Get-AuditSetting
            security_log_bytes = [long](Get-WinEvent -ListLog Security).MaximumSizeInBytes
            dns_log_enabled    = [bool]$dl.IsEnabled
            dns_log_bytes      = [long]$dl.MaximumSizeInBytes
            started            = (Get-Date).ToUniversalTime().ToString('o')
        }
        New-Item -ItemType Directory -Force -Path (Split-Path $auditState) | Out-Null
        [System.IO.File]::WriteAllText($auditState, (ConvertTo-Json $state), $utf8)
        # Failure too: under an egress firewall the blocked attempt (5157) is
        # the record of what the host wanted.
        & auditpol.exe /set /subcategory:$auditGuid /success:enable /failure:enable | Out-Null
        if ($LASTEXITCODE) { throw "auditpol /set exited $LASTEXITCODE" }
        # Every inbound connection is logged too; the 20 MB default wraps in
        # minutes on a busy server.
        if ($state.security_log_bytes -lt 256MB) { & wevtutil.exe sl Security /ms:$(256MB) }
        # The DNS Client's own log, off by default: which names were asked
        # for, by which process (the header's).
        if ($state.dns_log_bytes -lt 64MB) { & wevtutil.exe sl $dnsLog /ms:$(64MB) }
        & wevtutil.exe sl $dnsLog /e:true
        if ($LASTEXITCODE) { throw "wevtutil sl $dnsLog /e:true exited $LASTEXITCODE" }
        Write-Host "Connection audit and DNS Client log on; conn-audit.ps1 Stop [outdir] exports and restores."
    }
}

if ($Action -ne 'Start') {
    # ---------------------------------------------------------------------------
    # Egress configuration: what decides where update traffic goes
    # ---------------------------------------------------------------------------

    Step 'egress-config' {
        function Reg-Values([string]$path) {
            if (-not (Test-Path $path)) { return $null }
            $o = [ordered]@{}
            foreach ($p in (Get-ItemProperty -Path $path).PSObject.Properties) {
                if ($p.Name -notmatch '^PS(Path|ParentPath|ChildName|Drive|Provider)$') {
                    $o[$p.Name] = [string]$p.Value
                }
            }
            $o
        }
        Step 'audit setting' { $script:auditNow = Get-AuditSetting }
        Save-Json 'egress-config.json' ([ordered]@{
            windows_update        = Reg-Values 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
            windows_update_au     = Reg-Values 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
            delivery_optimization = Reg-Values 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization'
            defender_signatures   = Reg-Values 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates'
            winhttp_proxy         = @(& netsh.exe winhttp show proxy | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
            connection_audit      = $script:auditNow
        })
    }

    # ---------------------------------------------------------------------------
    # Connection events: which process talked where, when the host recorded it
    # ---------------------------------------------------------------------------

    $since = (Get-Date).AddHours(-$Hours)
    $boot  = $null
    $svcByPid = @{}
    Step 'pid to service' {
        $script:boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
        foreach ($s in Get-CimInstance Win32_Service) {
            if ($s.ProcessId) { $script:svcByPid[[int]$s.ProcessId] += @($s.Name) }
        }
    }

    function Read-Events([string]$log, [int[]]$ids) {
        try {
            $f = @{ LogName = $log; StartTime = $since }
            if ($ids) { $f.Id = $ids }      # none: every event of the log
            @(Get-WinEvent -FilterHashtable $f -ErrorAction Stop)
        } catch {
            # No such log (no Sysmon) or no such events: an answer, not a failure.
            if ($_.FullyQualifiedErrorId -match 'NoMatching') { @() } else { throw }
        }
    }
    function Event-Data($e) {
        $d = @{}
        foreach ($x in ([xml]$e.ToXml()).Event.EventData.Data) { $d[$x.Name] = $x.'#text' }
        $d
    }
    # Pids are per boot: an event from before the last boot names some other
    # process, so it gets no service rather than a wrong one.
    function Services-Of($procId, $time) {
        if ($boot -and $time -ge $boot -and $svcByPid.ContainsKey([int]$procId)) {
            $svcByPid[[int]$procId] -join ';'
        } else { '' }
    }

    Step 'wfp events' {
        $kind = @{ 5156 = 'permitted'; 5157 = 'blocked'; 5158 = 'bind'; 5159 = 'bind-blocked' }
        $dir  = @{ '%%14592' = 'inbound'; '%%14593' = 'outbound' }
        $loop = '^(127\.|::1$)'
        $rows = foreach ($e in Read-Events 'Security' @(5156, 5157, 5158, 5159)) {
            $d = Event-Data $e
            if ($d.SourceAddress -match $loop -and $d.DestAddress -match $loop) { continue }
            [PSCustomObject]@{
                Time          = $e.TimeCreated.ToUniversalTime().ToString('o')
                Event         = $kind[$e.Id]
                ProcessId     = $d.ProcessId
                Application   = $d.Application
                Services      = Services-Of $d.ProcessId $e.TimeCreated
                Direction     = if ($dir.ContainsKey("$($d.Direction)")) { $dir["$($d.Direction)"] } else { $d.Direction }
                Protocol      = $d.Protocol
                SourceAddress = $d.SourceAddress
                SourcePort    = $d.SourcePort
                DestAddress   = $d.DestAddress
                DestPort      = $d.DestPort
            }
        }
        Save-Csv 'wfp-connections.csv' $rows
    }

    Step 'dns client events' {
        $rows = foreach ($e in Read-Events $dnsLog @()) {
            $d = Event-Data $e
            [PSCustomObject]@{
                Time         = $e.TimeCreated.ToUniversalTime().ToString('o')
                Id           = $e.Id
                ProcessId    = $e.ProcessId
                ThreadId     = $e.ThreadId
                Services     = Services-Of $e.ProcessId $e.TimeCreated
                QueryName    = $d.QueryName
                QueryType    = $d.QueryType
                QueryOptions = $d.QueryOptions
                QueryStatus  = $d.QueryStatus
                QueryResults = $d.QueryResults
                Fields       = (@($d.Keys | Sort-Object | ForEach-Object { "$_=$($d[$_])" }) -join '; ')
            }
        }
        Save-Csv 'dns-client.csv' $rows
    }

    Step 'sysmon events' {
        $log = 'Microsoft-Windows-Sysmon/Operational'
        if (-not (Get-WinEvent -ListLog $log -ErrorAction SilentlyContinue)) { return }
        $net = foreach ($e in Read-Events $log @(3)) {
            $d = Event-Data $e
            [PSCustomObject]@{
                Time = $e.TimeCreated.ToUniversalTime().ToString('o')
                ProcessId = $d.ProcessId; Image = $d.Image; User = $d.User
                Services = Services-Of $d.ProcessId $e.TimeCreated
                Protocol = $d.Protocol; Initiated = $d.Initiated
                SourceIp = $d.SourceIp; SourcePort = $d.SourcePort
                DestinationIp = $d.DestinationIp; DestinationHostname = $d.DestinationHostname
                DestinationPort = $d.DestinationPort
            }
        }
        Save-Csv 'sysmon-network.csv' $net
        $dns = foreach ($e in Read-Events $log @(22)) {
            $d = Event-Data $e
            [PSCustomObject]@{
                Time = $e.TimeCreated.ToUniversalTime().ToString('o')
                ProcessId = $d.ProcessId; Image = $d.Image
                Services = Services-Of $d.ProcessId $e.TimeCreated
                QueryName = $d.QueryName; QueryStatus = $d.QueryStatus; QueryResults = $d.QueryResults
            }
        }
        Save-Csv 'sysmon-dns.csv' $dns
    }
}

if ($Action -eq 'Stop') {
    Step 'connection audit stop' {
        if (-not (Test-Path $auditState)) { throw "no ${auditState}: nothing was started, nothing restored" }
        $st = Get-Content $auditState -Raw | ConvertFrom-Json
        $succ = if ($st.setting -match 'Success') { 'enable' } else { 'disable' }
        $fail = if ($st.setting -match 'Failure') { 'enable' } else { 'disable' }
        & auditpol.exe /set /subcategory:$auditGuid /success:$succ /failure:$fail | Out-Null
        if ($LASTEXITCODE) { throw "auditpol /set exited $LASTEXITCODE; settings kept in $auditState" }
        & wevtutil.exe sl Security /ms:$($st.security_log_bytes)
        if ($null -ne $st.dns_log_enabled) {
            & wevtutil.exe sl $dnsLog /e:$(if ($st.dns_log_enabled) { 'true' } else { 'false' }) /ms:$($st.dns_log_bytes)
        }
        Remove-Item $auditState
        Write-Host "Connection audit restored to: $($st.setting)"
    }
}

if ($errors.Count) {
    if ($Action -eq 'Start') {
        Write-Warning "$($errors.Count) step(s) failed"
        exit 1
    }
    Save-Lines 'errors.txt' $errors.ToArray()
    Write-Warning "$($errors.Count) step(s) failed; see errors.txt"
}
if ($Action -ne 'Start') { Write-Host "Done: $OutDir" }
