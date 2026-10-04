<#
.SYNOPSIS
  Snapshot of what this machine has, as JSON. Collection only — no verdicts.

.DESCRIPTION
  The collector half of the idea in BACKLOG.new.md. It reads and writes nothing
  but its own output file, so it is safe on a machine under diagnosis.

  Why JSON and why a separate script: with a file boundary in the middle, the
  analysis is written in Python, tested against recorded snapshots, and runs on a
  machine that never saw the one being examined. Without it, nothing about this
  feature could be tested in CI at all.

  The four sources are here because each one finds what the others miss,
  measured on 2026-09-24:
    - device state saw three chipset devices with no driver, and NOT the
      Logitech HID collection whose UMDF driver fails to load;
    - the event log saw that, and not the unsigned binaries;
    - the driver store told a stale orphan from a tampered file, which neither
      of the other two could;
    - the crash and install logs are what put a 19:23 watchdog dump and a 19:47
      driver install on the same line.

  Version 1 closes two gaps that version 0 only revealed once its output was
  used in anger: it recorded the symptoms of both worked cases and not the
  evidence that resolved either of them.

    - the `cmd:` line of each install section, which is what traced a
      firmware-flash driver that no longer exists back to a file still on disk;
    - the DriverStore copies of the binaries in System32\drivers, without which
      a stale orphan cannot be told from a replaced file.

  A fixture recorder, not a product. It produces no verdicts: every judgement
  belongs on the other side of the JSON, where it can be tested.
#>
[CmdletBinding()]
param(
    [string] $OutFile = "inventory-$(Get-Date -Format 'yyyyMMdd-HHmmss').json",
    [int]    $EventDays = 90
)

$ErrorActionPreference = 'Stop'
$started = Get-Date

function Safe {
    <# A source that fails must not cost the whole snapshot. #>
    param([string] $Name, [scriptblock] $Body)
    try { & $Body }
    catch {
        Write-Warning "$Name : $($_.Exception.Message)"
        [pscustomobject]@{ error = $_.Exception.Message }
    }
}

# ── who is reading, and with what rights ────────────────────────────────────
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$elevated = (New-Object Security.Principal.WindowsPrincipal($identity)).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)

$snapshot = [ordered]@{
    schema      = 'radar.inventory/1'
    takenAt     = $started.ToString('o')
    elevated    = $elevated
    # Every comparison against an inbox driver set is valid only for this build.
    system      = Safe 'system' {
        $os = Get-CimInstance Win32_OperatingSystem
        $cs = Get-CimInstance Win32_ComputerSystem
        $bb = Get-CimInstance Win32_BaseBoard
        [ordered]@{
            caption        = $os.Caption
            version        = $os.Version
            build          = $os.BuildNumber
            displayVersion = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').DisplayVersion
            installDate    = $os.InstallDate.ToString('o')
            lastBoot       = $os.LastBootUpTime.ToString('o')
            # "To Be Filled By O.E.M." is a real value, and it means the board
            # never filled SMBIOS. The PCI subsystem id is the fallback.
            manufacturer   = $cs.Manufacturer
            model          = $cs.Model
            board          = "$($bb.Manufacturer) $($bb.Product)"
        }
    }
    firmware    = Safe 'firmware' {
        $b = Get-CimInstance Win32_BIOS
        [ordered]@{
            manufacturer = $b.Manufacturer
            version      = $b.SMBIOSBIOSVersion
            releaseDate  = $b.ReleaseDate.ToString('o')
            # Firmware CVEs are not in NVD under a consistent CPE. Reported, not judged.
            assessed     = $false
        }
    }
    posture     = Safe 'posture' {
        $bcd = (bcdedit /enum '{current}' 2>$null) -join "`n"
        $dg  = Get-CimInstance -ClassName Win32_DeviceGuard `
                 -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
        # Computed before the literal: Windows PowerShell 5.1 does not accept
        # try/catch as an expression inside a hashtable, and Confirm-SecureBootUEFI
        # throws rather than returning false on a machine booted in legacy mode.
        $secureBoot = $null
        try { $secureBoot = [bool](Confirm-SecureBootUEFI) } catch { $secureBoot = $null }
        # The antivirus half. Its purpose is not to find threats: it is so that
        # "no detections" becomes a measured fact with a date and a signature
        # version beside it, instead of a silent absence. On 26/09/2026 an
        # installer was refused by Windows and Defender had recorded nothing --
        # knowing that its signatures were current at the time is what turned
        # that from a gap into a finding.
        $mp  = Get-MpComputerStatus -ErrorAction SilentlyContinue
        $pref = Get-MpPreference -ErrorAction SilentlyContinue
        $since = (Get-Date).AddDays(-30)
        $det = @(Get-MpThreatDetection -ErrorAction SilentlyContinue |
                 Where-Object { $_.InitialDetectionTime -gt $since } |
                 ForEach-Object {
                     [ordered]@{
                         at        = $_.InitialDetectionTime.ToString('o')
                         threatId  = "$($_.ThreatID)"
                         succeeded = $_.ActionSuccess
                         resources = @($_.Resources)
                     }
                 })
        # Present on disk is not the same as in force: this machine carries
        # driversipolicy.p7b while CodeIntegrityPolicyEnforcementStatus is 0.
        $ciPolicy = 'C:\Windows\System32\CodeIntegrity\driversipolicy.p7b'
        [ordered]@{
            secureBoot        = $secureBoot
            testSigning       = [bool]($bcd -match '(?m)^testsigning\s+Yes')
            noIntegrityChecks = [bool]($bcd -match '(?m)^nointegritychecks\s+Yes')
            vbsStatus         = if ($dg) { $dg.VirtualizationBasedSecurityStatus } else { $null }
            servicesRunning   = if ($dg) { @($dg.SecurityServicesRunning) } else { @() }
            ciEnforcement     = if ($dg) { $dg.CodeIntegrityPolicyEnforcementStatus } else { $null }
            driverBlocklist   = [ordered]@{
                filePresent = Test-Path $ciPolicy
                enableFlag  = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config' `
                                 -ErrorAction SilentlyContinue).VulnerableDriverBlocklistEnable
            }
            antivirus         = [ordered]@{
                realTime          = if ($mp) { $mp.RealTimeProtectionEnabled } else { $null }
                signatureVersion  = if ($mp) { $mp.AntivirusSignatureVersion } else { $null }
                signatureUpdated  = if ($mp -and $mp.AntivirusSignatureLastUpdated) {
                                        $mp.AntivirusSignatureLastUpdated.ToString('o') } else { $null }
                puaProtection     = if ($pref) { "$($pref.PUAProtection)" } else { $null }
                detectionsWindowDays = 30
                detections        = $det
            }
        }
    }
    # ── devices: what is attached and what state it is in ───────────────────
    devices     = @(Safe 'devices' {
        Get-PnpDevice | ForEach-Object {
            [ordered]@{
                instanceId   = $_.InstanceId
                friendlyName = $_.FriendlyName
                class        = $_.Class
                status       = $_.Status
                problem      = "$($_.Problem)"
                problemCode  = $_.ProblemCode
                # A device unplugged long ago is not a fault. Kept, and marked,
                # so the analysis can drop it without having to guess.
                phantom      = ("$($_.Problem)" -eq 'CM_PROB_PHANTOM')
            }
        }
    })
    # ── drivers bound to a device ───────────────────────────────────────────
    drivers     = @(Safe 'drivers' {
        Get-CimInstance Win32_PnPSignedDriver | ForEach-Object {
            [ordered]@{
                deviceId     = $_.DeviceID
                deviceName   = $_.DeviceName
                deviceClass  = $_.DeviceClass
                infName      = $_.InfName
                version      = $_.DriverVersion
                date         = if ($_.DriverDate) { $_.DriverDate.ToString('o') } else { $null }
                # An empty provider is not missing data: on 2026-09-24 three of
                # the seven empty ones were exactly the three devices with no
                # driver at all. The blank is the finding.
                provider     = $_.DriverProviderName
                signer       = $_.Signer
                isSigned     = $_.IsSigned
                # oemNN.inf is how Windows publishes a third-party package. It
                # is the reliable marker, and it needs no reference image.
                thirdParty   = [bool]($_.InfName -match '^oem\d+\.inf$')
            }
        }
    })
    # ── the driver store: the authority, which drivers\ is not ──────────────
    driverStore = @(Safe 'driverStore' {
        $text = (pnputil /enum-drivers) -join "`n"
        ($text -split "(?m)^\s*$") | ForEach-Object {
            $b = $_
            if ($b -notmatch ':') { return }
            $get = {
                param($labels)
                foreach ($l in $labels) {
                    $m = [regex]::Match($b, "(?m)^\s*$l\s*:\s*(.+?)\s*$")
                    if ($m.Success) { return $m.Groups[1].Value }
                }
                $null
            }
            $published = & $get @('Published Name', 'Nome pubblicato')
            if (-not $published) { return }
            [ordered]@{
                published = $published
                original  = & $get @('Original Name', 'Nome originale')
                provider  = & $get @('Provider Name', 'Nome provider')
                class     = & $get @('Class Name', 'Nome classe')
                version   = & $get @('Driver Version', 'Versione driver')
                signer    = & $get @('Signer Name', 'Nome firmatario')
            }
        }
    })
    # ── the binaries, and whether their signature can be verified ───────────
    driverFiles = @(Safe 'driverFiles' {
        Get-ChildItem 'C:\Windows\System32\drivers' -Filter *.sys -File -ErrorAction SilentlyContinue |
          ForEach-Object {
            $sig = Get-AuthenticodeSignature -LiteralPath $_.FullName
            [ordered]@{
                name          = $_.Name
                sizeBytes     = $_.Length
                modified      = $_.LastWriteTime.ToString('o')
                status        = "$($sig.Status)"
                # Catalog, not Embedded, is the normal case for a driver: a file
                # reported unsigned may simply be signed elsewhere.
                signatureType = "$($sig.SignatureType)"
                signer        = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { $null }
                sha256        = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash
            }
        }
    })
    # ── the same binaries as the DriverStore holds them ─────────────────────
    #
    # The DriverStore is the authority; System32\drivers holds copies placed at
    # install time. Telling a stale orphan from a replaced file needs both, and
    # version 0 captured only one — so the case that demonstrated the whole idea
    # could not be reproduced from its own output:
    #
    #   BthA2dp.sys in System32\drivers  -> unsigned, dated 2019
    #   the same file in the DriverStore -> validly catalog-signed
    #   the two hashes                   -> different
    #   the service                      -> never started, no Bluetooth hardware
    #   verdict                          -> stale orphan, not tampering
    #
    # Only the files that share a name with one in System32\drivers are hashed:
    # 209 of 371 on the machine this was written on, about 2.6 seconds. Hashing
    # the whole repository would cost more and answer nothing extra.
    driverStoreFiles = @(Safe 'driverStoreFiles' {
        $repository = 'C:\Windows\System32\DriverStore\FileRepository'
        if (-not (Test-Path $repository)) { return }
        $inSystem32 = @{}
        Get-ChildItem 'C:\Windows\System32\drivers' -Filter *.sys -File -ErrorAction SilentlyContinue |
          ForEach-Object { $inSystem32[$_.Name] = $true }
        Get-ChildItem $repository -Recurse -Filter *.sys -File -ErrorAction SilentlyContinue |
          Where-Object { $inSystem32.ContainsKey($_.Name) } |
          ForEach-Object {
            $sig = Get-AuthenticodeSignature -LiteralPath $_.FullName
            [ordered]@{
                name          = $_.Name
                # The package directory is the version: two packages can hold the
                # same file name with different contents.
                package       = $_.Directory.Name
                sizeBytes     = $_.Length
                modified      = $_.LastWriteTime.ToString('o')
                status        = "$($sig.Status)"
                signatureType = "$($sig.SignatureType)"
                sha256        = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash
            }
        }
    })
    installedSoftware = @(Safe 'installedSoftware' {
        # Win32_Product is deliberately not used: enumerating it triggers an MSI
        # reconfiguration of every installed product.
        $keys = @(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
            'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
        )
        foreach ($k in $keys) {
            Get-ItemProperty $k -ErrorAction SilentlyContinue |
              Where-Object { $_.DisplayName } | ForEach-Object {
                [ordered]@{
                    name      = $_.DisplayName
                    version   = $_.DisplayVersion
                    publisher = $_.Publisher
                    installed = $_.InstallDate
                    scope     = if ($k -like 'HKCU*') { 'user' } else { 'machine' }
                    # The hive itself, not an inferred architecture: on a 32-bit
                    # OS the native key is x86 too, and HKCU says nothing either
                    # way. Recording which key answered keeps the derivation on
                    # the Python side, where it can be tested.
                    hive      = if ($k -like '*WOW6432Node*') { 'HKLM\WOW6432Node' }
                                elseif ($k -like 'HKCU*')     { 'HKCU' }
                                else                          { 'HKLM' }
                    # The three routes to the product's own binaries, needed by
                    # the signature cascade: without a path, "this executable is
                    # unsigned" has nothing to point at. Old installers very
                    # often leave InstallLocation empty, and then DisplayIcon or
                    # the uninstall command are the only pointers left.
                    location  = $_.InstallLocation
                    icon      = $_.DisplayIcon
                    uninstall = $_.UninstallString
                }
              }
        }
    })
    # ── the timeline: crashes, hangs and what was installed around them ─────
    crashArtefacts = @(Safe 'crashArtefacts' {
        $out = @()
        # %LOCALAPPDATA%\CrashDumps is where user-mode crashes land, and the
        # first three directories only hold kernel ones. On 26/09/2026 this
        # collector ran twice around a session in which Explorer.EXE and an
        # installer both crashed, and reported crashArtefacts=1 both times: the
        # two dumps were sitting in a directory it did not read.
        foreach ($dir in 'C:\Windows\Minidump', 'C:\Windows\LiveKernelReports',
                         "$env:LOCALAPPDATA\CrashDumps",
                         "$env:ProgramData\Microsoft\Windows\WER\ReportArchive") {
            if (Test-Path $dir) {
                $out += Get-ChildItem $dir -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
                    [ordered]@{ path = $_.FullName; sizeBytes = $_.Length; written = $_.LastWriteTime.ToString('o') }
                }
            }
        }
        if (Test-Path 'C:\Windows\MEMORY.DMP') {
            $f = Get-Item 'C:\Windows\MEMORY.DMP'
            $out += [ordered]@{ path = $f.FullName; sizeBytes = $f.Length; written = $f.LastWriteTime.ToString('o') }
        }
        $out
    })
    events = @(Safe 'events' {
        $since = (Get-Date).AddDays(-$EventDays)
        $logs  = 'System', 'Microsoft-Windows-CodeIntegrity/Operational', 'Microsoft-Windows-Kernel-PnP/Configuration'
        foreach ($log in $logs) {
            Get-WinEvent -FilterHashtable @{ LogName = $log; StartTime = $since } -ErrorAction SilentlyContinue |
              Where-Object { $_.LevelDisplayName -in 'Errore', 'Error', 'Critico', 'Critical', 'Avviso', 'Warning' } |
              ForEach-Object {
                [ordered]@{
                    log      = $log
                    # The id alone is ambiguous: Netwtw04 emits 7000 and 7001 as
                    # information while those same numbers mean "service failed
                    # to start" for the Service Control Manager. Always paired.
                    provider = $_.ProviderName
                    id       = $_.Id
                    level    = $_.LevelDisplayName
                    time     = $_.TimeCreated.ToString('o')
                    message  = ($_.Message -replace "`r?`n", ' ' -replace '\s+', ' ')
                }
              }
        }
    })
    driverInstallLog = Safe 'driverInstallLog' {
        $p = 'C:\Windows\INF\setupapi.dev.log'
        if (-not (Test-Path $p)) { return $null }
        $lines = Get-Content $p -ErrorAction SilentlyContinue
        # Headers, timestamps, and the two lines that name what did the installing.
        #
        # `cmd:` was missing from version 0, and it is the field that resolved the
        # one case this whole idea was tested on: an Insyde firmware-flash driver
        # appeared on a machine with an AMI BIOS, was gone by the time anyone
        # looked, and the only thing that explained it was
        #   cmd: .\HPFlashWinx64.exe -sfx7z "c:\SWSetup\SP143731"
        # which led to a file still on disk. Recording the section header alone
        # says a driver was installed; it does not say by what.
        #
        # The body is megabytes, so only these lines are kept and the analysis
        # re-reads the file when it wants the rest.
        $out = @()
        for ($i = 0; $i -lt $lines.Count; $i++) {
            if ($lines[$i] -notmatch '^>>>\s+\[(.+)\]\s*$') { continue }
            $what = $matches[1]
            $when = $null; $cmd = $null; $infPath = $null
            for ($j = $i + 1; $j -lt [Math]::Min($i + 40, $lines.Count); $j++) {
                if ($lines[$j] -match '^>>>\s+\[') { break }
                if (-not $when    -and $lines[$j] -match 'Section start\s+(.+)$')      { $when = $matches[1].Trim(); continue }
                if (-not $cmd     -and $lines[$j] -match '^\s*cmd:\s*(.+?)\s*$')       { $cmd = $matches[1]; continue }
                if (-not $infPath -and $lines[$j] -match 'INF path:\s*(.+?)\s*$')      { $infPath = $matches[1]; continue }
            }
            $out += [ordered]@{ section = $what; start = $when; cmd = $cmd; infPath = $infPath }
        }
        [ordered]@{ path = $p; sizeBytes = (Get-Item $p).Length; sections = @($out) }
    }
}

$snapshot.durationSeconds = [math]::Round(((Get-Date) - $started).TotalSeconds, 1)

# -Depth matters: the default of 2 would silently flatten every nested object.
$json = $snapshot | ConvertTo-Json -Depth 8 -Compress:$false

# UTF-8 without a BOM. Set-Content -Encoding utf8 writes one on Windows
# PowerShell 5.1, and a BOM in front of a JSON document makes a strict parser
# refuse the file — Python's json.loads says "Unexpected UTF-8 BOM" and stops.
# The whole point of this file is that something else reads it.
# Resolved by hand: .NET resolves a relative path against the process directory,
# which is not always where PowerShell thinks it is. No null-coalescing either —
# Windows PowerShell 5.1 does not have it.
if ([System.IO.Path]::IsPathRooted($OutFile)) {
    $full = $OutFile
} else {
    $full = Join-Path (Get-Location).Path $OutFile
}
[System.IO.File]::WriteAllText($full, $json, (New-Object System.Text.UTF8Encoding($false)))
$OutFile = $full

$size = [math]::Round((Get-Item $OutFile).Length / 1MB, 2)
Write-Output "scritto: $OutFile ($size MB, $($snapshot.durationSeconds)s, elevato=$elevated)"
foreach ($k in 'devices', 'drivers', 'driverStore', 'driverFiles', 'driverStoreFiles', 'installedSoftware', 'events', 'crashArtefacts') {
    $v = $snapshot[$k]
    $n = if ($v -is [array]) { $v.Count } elseif ($v) { 1 } else { 0 }
    Write-Output ("  {0,-18} {1}" -f $k, $n)
}
