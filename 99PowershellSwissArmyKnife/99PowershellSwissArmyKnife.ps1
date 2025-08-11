
<#
.SYNOPSIS
99PowershellSwissArmyKnife - Expanded portable admin toolkit (99 commands)

Use the provided .bat launcher to run as admin by double-clicking.
WARNING: many actions are disruptive. Confirm prompts are required.
#>

# Helpers
function Is-Admin {
    $current = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $current.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Write-Option {
    param(
        [string]$Key,
        [string]$Description,
        [ConsoleColor]$KeyColor = [ConsoleColor]::Yellow,
        [ConsoleColor]$DescColor = [ConsoleColor]::Gray
    )
    Write-Host "[" -NoNewline -ForegroundColor DarkGray
    Write-Host $Key -NoNewline -ForegroundColor $KeyColor
    Write-Host "] " -NoNewline -ForegroundColor DarkGray
    Write-Host $Description -ForegroundColor $DescColor
}

function Write-InfoLine {
    param(
        [string]$Label,
        [string]$Value
    )
    Write-Host (" {0,-9}: " -f $Label) -NoNewline -ForegroundColor DarkGray
    Write-Host $Value -ForegroundColor Green
}

# Read input with Boss Key support (Ctrl+B to exit immediately)
function Read-InputWithBossKey {
    param([string]$Prompt = "")
    if ($Prompt) { Write-Host -NoNewline ($Prompt + " ") }
    try {
        $builder = New-Object System.Text.StringBuilder
        while ($true) {
            $key = [System.Console]::ReadKey($true)
            if (($key.Modifiers -band [ConsoleModifiers]::Control) -and $key.Key -eq [ConsoleKey]::B) {
                exit
            }
            switch ($key.Key) {
                'Enter' { Write-Host ''; return $builder.ToString() }
                'Backspace' {
                    if ($builder.Length -gt 0) {
                        $null = $builder.Remove($builder.Length - 1, 1)
                        Write-Host "`b `b" -NoNewline
                    }
                }
                default {
                    if ($key.KeyChar -ne [char]0) {
                        $null = $builder.Append($key.KeyChar)
                        Write-Host $key.KeyChar -NoNewline
                    }
                }
            }
        }
    } catch {
        # Fallback to Read-Host if console key read fails
        return (Read-Host $Prompt)
    }
}

# Global state
$script:TaskCount = 0
$script:ConsecutiveInvalidCount = 0
$script:CommandHistory = @()

function Add-CommandHistory {
    param([string]$Entry)
    if (-not $Entry) { return }
    $script:CommandHistory = @($Entry) + $script:CommandHistory
    if ($script:CommandHistory.Count -gt 5) {
        $script:CommandHistory = $script:CommandHistory[0..4]
    }
}

function Show-CommandHistory {
    Write-Host ""; Write-Host "Recent commands (last 5):" -ForegroundColor White
    if (-not $script:CommandHistory -or $script:CommandHistory.Count -eq 0) {
        Write-Host "(none yet)" -ForegroundColor DarkGray
        return
    }
    $script:CommandHistory | ForEach-Object { Write-Host " - $_" -ForegroundColor Gray }
    Write-Host ""
    Read-Host "Press Enter to return"
}

function Show-RandomQuote {
    $quotes = @(
        'It works on my machine.',
        'Never underestimate the bandwidth of a station wagon full of tapes.',
        'There is no place like 127.0.0.1.',
        'To err is human; to really foul things up you need a computer.',
        'Have you tried turning it off and on again?',
        'DNS: The root of all problems.',
        'There are two hard things in computer science: cache invalidation and naming things.',
        ' rm -rf / laughter in the distance ',
        'Out of memory? Just add more RAM.',
        'Works in prod? Ship it!'
    )
    $q = Get-Random -InputObject $quotes
    Write-Host ""; Write-Host ('Quote: "{0}"' -f $q) -ForegroundColor DarkCyan; Write-Host ""
}

function Show-FakeProgressBar {
    Clear-Host
    Write-Host 'Deleting C:\Windows…' -ForegroundColor Red
    for ($i=0; $i -le 100; $i+=7) {
        Write-Progress -Activity 'System Cleanup' -Status ("Removing critical files... {0}%" -f $i) -PercentComplete $i
        Start-Sleep -Milliseconds (Get-Random -Minimum 50 -Maximum 200)
    }
    Write-Progress -Activity 'System Cleanup' -Completed -Status 'Done'
    Write-Host ''
    Write-Host 'Just kidding!' -ForegroundColor Green
    Write-Host ''
    Read-Host 'Press Enter to return'
}

function Handle-InvalidChoice {
    $script:ConsecutiveInvalidCount++
    Show-InvalidChoiceMessage
    if ($script:ConsecutiveInvalidCount -ge 2) {
        $script:ConsecutiveInvalidCount = 0
        Show-FakeProgressBar
    }
}

function Handle-PostTask {
    param(
        [string]$Category,
        [string]$Choice,
        [string[]]$ValidChoices
    )
    if ($null -eq $Choice) { return }
    $c = $Choice.ToUpper()
    if ($ValidChoices -and ($ValidChoices -contains $c) -and $c -ne 'B') {
        $script:TaskCount++
        $script:ConsecutiveInvalidCount = 0
        Add-CommandHistory ("{0}: {1}" -f $Category, $c)
        if (($script:TaskCount % 2) -eq 0) { Show-RandomQuote }
    }
}

function Show-InvalidChoiceMessage {
    Clear-Host
    try {
        $raw = $Host.UI.RawUI
        $width = $raw.WindowSize.Width
        $height = $raw.WindowSize.Height
        if (-not $width -or $width -le 0) { $width = 80 }
        if (-not $height -or $height -le 0) { $height = 25 }
    } catch {
        $raw = $null
        $width = 80
        $height = 25
    }

    $lines = @(
        " ______________________________",
        "|                              |",
        "|    Achievement Unlocked!     |",
        "|  You found 99 ways to break  |",
        "|  ...I mean, fix your system. |",
        "|______________________________|"
    )

    $topPad = [Math]::Max(0, [Math]::Floor(($height - $lines.Count - 2) / 2))
    for ($i = 0; $i -lt $topPad; $i++) { Write-Host "" }

    foreach ($line in $lines) {
        $pad = [Math]::Max(0, [Math]::Floor(($width - $line.Length) / 2))
        Write-Host (' ' * $pad) -NoNewline
        Write-Host $line
    }

    $footer = "click any button to return ...."
    $footerPad = [Math]::Max(0, [Math]::Floor(($width - $footer.Length) / 2))
    try {
        if ($raw) {
            $raw.CursorPosition = New-Object System.Management.Automation.Host.Coordinates(0, [Math]::Max(0, $height - 1))
        }
    } catch {}
    Write-Host ((' ' * $footerPad) + $footer) -ForegroundColor DarkGray

    try {
        if ($raw) { $null = $raw.ReadKey('NoEcho,IncludeKeyDown') }
        else { $null = [System.Console]::ReadKey($true) }
    } catch { Start-Sleep -Milliseconds 500 }
}

function Ensure-Admin {
    if (-not (Is-Admin)) {
        Write-Host "This tool requires Administrator privileges. Attempting to relaunch as Administrator..." -ForegroundColor Yellow
        Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
        exit
    }
}

function Log-Event {
    param([string]$Message, [string]$Level = "INFO")
    try {
        $logDir = Join-Path -Path $PSScriptRoot -ChildPath "Logs"
        if (-not (Test-Path $logDir)) { New-Item -Path $logDir -ItemType Directory | Out-Null }
        $logFile = Join-Path -Path $logDir -ChildPath ((Get-Date).ToString("yyyy-MM-dd") + ".log")
        $entry = ("{0} [{1}] {2} (User:{3} Host:{4})" -f (Get-Date), $Level, $Message, $env:USERNAME, $env:COMPUTERNAME)
        Add-Content -Path $logFile -Value $entry
    } catch {
        Write-Host ("Logging failed: {0}" -f $_) -ForegroundColor Red
    }
}

function Confirm-Action {
    param([string]$Message = "Are you sure? This action is potentially disruptive.")
    Write-Host ""
    Write-Host $Message -ForegroundColor Yellow
    $ans = Read-Host "Type YES to confirm, anything else to cancel"
    if ($ans -eq "YES") { return $true } else { Write-Host "Action cancelled." -ForegroundColor Cyan; return $false }
}

function Create-RestorePoint {
    param([string]$Description = "99PowershellSwissArmyKnife checkpoint")
    try {
        $sr = Get-ComputerRestorePoint -ErrorAction SilentlyContinue
        if ($null -ne $sr) {
            Write-Host ("Creating System Restore Point: {0}" -f $Description) -ForegroundColor Green
            Checkpoint-Computer -Description $Description -RestorePointType "MODIFY_SETTINGS" -ErrorAction Stop
            Log-Event ("Created restore point: {0}" -f $Description)
            return $true
        } else {
            Write-Host "System Restore not available on this system." -ForegroundColor Yellow
            Log-Event "System Restore not available"
            return $false
        }
    } catch {
        Write-Host ("Failed to create restore point: {0}" -f $_) -ForegroundColor Red
        Log-Event ("Failed to create restore point: {0}" -f $_) "ERROR"
        return $false
    }
}


# Networking functions (1-20)
function Show-ActiveAdapters { Get-NetAdapter | Format-Table -AutoSize; Log-Event "Viewed adapters" }
function Enable-Adapter { param($name); Enable-NetAdapter -Name $name -Confirm:$false; Log-Event ("Enabled adapter {0}" -f $name) }
function Disable-Adapter { param($name); Disable-NetAdapter -Name $name -Confirm:$false; Log-Event ("Disabled adapter {0}" -f $name) }
function Restart-NetworkAdapterByName { param($name); Restart-NetAdapter -Name $name -Confirm:$false; Log-Event ("Restarted adapter {0}" -f $name) }
function Show-IPConfig { ipconfig /all }
function Release-Renew { ipconfig /release; Start-Sleep -Seconds 1; ipconfig /renew; Log-Event "Released and renewed IP" }
function Flush-DNS { ipconfig /flushdns | Out-Null; Write-Host "Flushed DNS" -ForegroundColor Green; Log-Event "Flushed DNS" }
function Set-DNS-Google { param($iface); if (-not $iface) { $iface=(Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | Select-Object -First 1).Name }; Set-DnsClientServerAddress -InterfaceAlias $iface -ServerAddresses ("8.8.8.8","8.8.4.4") -ErrorAction SilentlyContinue; Log-Event ("Set DNS Google on {0}" -f $iface) }
function Set-DNS-Cloudflare { param($iface); if (-not $iface) { $iface=(Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | Select-Object -First 1).Name }; Set-DnsClientServerAddress -InterfaceAlias $iface -ServerAddresses ("1.1.1.1","1.0.0.1") -ErrorAction SilentlyContinue; Log-Event ("Set DNS Cloudflare on {0}" -f $iface) }
function Show-ActiveConnections { Get-NetTCPConnection | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State | Format-Table -AutoSize; Log-Event "Listed active TCP connections" }
function Show-ListeningPorts { Get-NetTCPConnection -State Listen | Select-Object LocalAddress,LocalPort,OwningProcess | Format-Table -AutoSize; Log-Event "Listed listening ports" }
function Test-Conn { param($t); if (-not $t) { $t=Read-Host 'Target' }; Test-Connection -ComputerName $t -Count 4 | Select-Object Address, ResponseTime; Log-Event ("Test-Connection {0}" -f $t) }
function Traceroute-Host { param($t); if (-not $t) { $t=Read-Host 'Target' }; tracert $t; Log-Event ("Traceroute {0}" -f $t) }
function Scan-CommonPorts { param($t); if (-not $t) { $t=Read-Host 'Target' }; $ports = @(21,22,23,80,443,3389,5900); foreach ($p in $ports) { $res = Test-NetConnection -ComputerName $t -Port $p -WarningAction SilentlyContinue; Write-Host ($p + ':' + $res.TcpTestSucceeded) } ; Log-Event ("Scanned common ports {0}" -f $t) }
function Reset-TCPIP { netsh int ip reset; Log-Event "Reset TCP/IP" }
function Show-ARP { arp -a }
function Show-Routes { route print }
function Add-StaticRoute { param($dest,$mask,$gateway); route add $dest mask $mask $gateway; Log-Event ("Added route {0}->{1}" -f $dest,$gateway) }
function Remove-StaticRoute { param($dest); route delete $dest; Log-Event ("Removed route {0}" -f $dest) }
function Show-WiFiProfiles { netsh wlan show profiles }
function Show-WiFiPasswords {
    netsh wlan show profiles | Select-String "\:(.*)$" | ForEach-Object { $_.ToString().Split(":")[1].Trim() } | ForEach-Object {
        $p = $_
        Write-Host "Profile: $p"
        try { netsh wlan show profile name="$p" key=clear } catch {}
    }
    Log-Event "Displayed wifi profiles"
}


# System Maintenance functions (21-40)
function Show-SystemInfo { Get-ComputerInfo | Select-Object CsName, WindowsProductName, WindowsVersion, OsHardwareAbstractionLayer | Format-List; Log-Event "Viewed system info" }
function Show-DiskUsage { Get-PSDrive -PSProvider FileSystem | Select-Object Name,Used,Free, @{Name='FreeGB';Expression={[math]::round($_.Free/1GB,2)}}, @{Name='UsedGB';Expression={[math]::round($_.Used/1GB,2)}} | Format-Table -AutoSize; Log-Event "Viewed disk usage" }
function Clean-UserTemp { $temp=$env:TEMP; Get-ChildItem -Path $temp -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue; Write-Host "Cleaned user temp"; Log-Event "Cleaned user temp" }
function Clean-SystemTemp { $sys = $env:windir + "\Temp"; Get-ChildItem -Path $sys -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue; Write-Host "Cleaned system temp"; Log-Event "Cleaned system temp" }
function Empty-RecycleBin { Clear-RecycleBin -Force -ErrorAction SilentlyContinue; Write-Host "Recycle Bin emptied"; Log-Event "Emptied recycle bin" }
function Chk-Disk { param($drive='C:' ); chkdsk $drive; Log-Event ("Checked disk {0}" -f $drive) }
function Run-SFC { sfc /scannow; Log-Event "Ran sfc /scannow" }
function Run-DISM { DISM /Online /Cleanup-Image /RestoreHealth; Log-Event "Ran DISM RestoreHealth" }
function Defrag-Drive { param($drive='C:' ); Optimize-Volume -DriveLetter ($drive.TrimEnd(':')) -Defrag -Verbose; Log-Event ("Defragged {0}" -f $drive) }
function List-Services { Get-Service | Where-Object {$_.Status -eq 'Running'} | Select-Object Name,Status | Format-Table -AutoSize; Log-Event "Listed running services" }
function Restart-ServiceByName { param($name); Restart-Service -Name $name -Force; Log-Event ("Restarted service {0}" -f $name) }
function Stop-ServiceByName { param($name); Stop-Service -Name $name -Force; Log-Event ("Stopped service {0}" -f $name) }
function Start-ServiceByName { param($name); Start-Service -Name $name -Force; Log-Event ("Started service {0}" -f $name) }
function Disable-StartupApp { param($name); Get-CimInstance -ClassName Win32_StartupCommand | Where-Object {$_.Name -like "*$name*"} | ForEach-Object { $_ } ; Log-Event ("Searched startup for {0}" -f $name) }
function List-ScheduledTasks { schtasks /Query /FO LIST /V }
function Create-Restore { Create-RestorePoint -Description "ManualCheckpoint" }
function Toggle-WindowsUpdate { param($action='status'); if ($action -eq 'status') { Get-Service -Name wuauserv | Select-Object Name,Status } elseif ($action -eq 'stop') { Stop-Service -Name wuauserv -Force } elseif ($action -eq 'start') { Start-Service -Name wuauserv -Force }; Log-Event ("Toggled Windows Update {0}" -f $action) }
function Reboot-System { if (Confirm-Action "Reboot the system now?") { Restart-Computer -Force } }
function Shutdown-System { if (Confirm-Action "Shutdown the system now?") { Stop-Computer -Force } }


# Security & Privacy functions (41-60)
function Enable-Firewall { Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True; Log-Event "Enabled firewall" }
function Disable-Firewall { Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False; Log-Event "Disabled firewall" }
function Show-FirewallRules { Get-NetFirewallRule | Select-Object Name,Enabled,Direction,Action | Format-Table -AutoSize; Log-Event "Listed firewall rules" }
function Block-HostsFile {
    param([Alias('host')][string]$TargetHost)
    if (-not $TargetHost) { $TargetHost = Read-Host 'Host to block' }
    Add-Content -Path (Join-Path $env:SystemRoot 'System32\drivers\etc\hosts') -Value ('0.0.0.0 ' + $TargetHost)
    Log-Event ("Blocked host {0}" -f $TargetHost)
}
function Unblock-HostsFile {
    param([Alias('host')][string]$TargetHost)
    $path = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
    (Get-Content $path) | Where-Object { $_ -notlike "*$TargetHost*" } | Set-Content $path
    Log-Event ("Unblocked host {0}" -f $TargetHost)
}
function Disable-DiagTrack { if (Confirm-Action "Disable Diagnostics Tracking Service (DiagTrack)?") { Stop-Service -Name "DiagTrack" -ErrorAction SilentlyContinue; Set-Service -Name "DiagTrack" -StartupType Disabled -ErrorAction SilentlyContinue; Log-Event "Disabled DiagTrack" } }
function Show-DefenderStatus { try { Get-MpComputerStatus | Format-List } catch { Write-Host "Defender not available on this system." -ForegroundColor Yellow } ; Log-Event "Viewed Defender status" }
function Defender-QuickScan { try { Start-MpScan -ScanType QuickScan -ErrorAction Stop } catch { Write-Host "Defender scan failed or not available." -ForegroundColor Yellow } ; Log-Event "Ran Defender quick scan" }
function Defender-FullScan { try { Start-MpScan -ScanType FullScan -ErrorAction Stop } catch { Write-Host "Defender full scan failed or not available." -ForegroundColor Yellow } ; Log-Event "Ran Defender full scan" }
function Update-DefenderSignatures { try { Update-MpSignature -ErrorAction Stop } catch { Write-Host "Update failed or Defender not available." -ForegroundColor Yellow } ; Log-Event "Updated defender signatures" }
function Show-Users { Get-LocalUser | Select-Object Name,Enabled | Format-Table -AutoSize; Log-Event "Listed local users" }
function Lock-Workstation { rundll32.exe user32.dll,LockWorkStation }
function Clear-RecentFiles { $path = Join-Path $env:APPDATA "Microsoft\Windows\Recent"; Get-ChildItem $path -Recurse -Force | Remove-Item -Force -ErrorAction SilentlyContinue; Log-Event "Cleared recent files" }
function Clear-ClipboardHistory { cmd /c "echo off | clip"; Log-Event "Cleared clipboard" }


# Utilities functions (61-80)
function Take-Screenshot {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    $desktop = [Environment]::GetFolderPath("Desktop")
    $file = Join-Path $desktop ("screenshot_{0}.png" -f (Get-Date -Format "yyyyMMdd_HHmmss"))
    $bmp = New-Object System.Drawing.Bitmap([System.Windows.Forms.Screen]::PrimaryScreen.Bounds.Width, [System.Windows.Forms.Screen]::PrimaryScreen.Bounds.Height)
    $gfx = [System.Drawing.Graphics]::FromImage($bmp)
    $gfx.CopyFromScreen(0,0,0,0,$bmp.Size)
    $bmp.Save($file,[System.Drawing.Imaging.ImageFormat]::Png)
    $gfx.Dispose(); $bmp.Dispose()
    Write-Host ("Screenshot saved to {0}" -f $file) -ForegroundColor Green
    Log-Event ("Screenshot saved {0}" -f $file)
}
function List-InstalledPrograms {
    Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher | Where-Object { $_.DisplayName } | Format-Table -AutoSize
    Log-Event "Listed installed programs (wow6432)"
}
function Create-LocalAdmin { param($name); if (-not $name){ $name=Read-Host 'New username' }; $securePassword = Read-Host -AsSecureString 'Password'; New-LocalUser -Name $name -Password $securePassword -PasswordNeverExpires:$true; Add-LocalGroupMember -Group 'Administrators' -Member $name; Write-Host ("Created local admin {0}" -f $name); Log-Event ("Created local admin {0}" -f $name) }
function Remove-LocalUser { param($name); if (-not $name){ $name=Read-Host 'Username to remove' }; Remove-LocalUser -Name $name -ErrorAction SilentlyContinue; Log-Event ("Removed user {0}" -f $name) }
function Change-UserPassword { param($name); if (-not $name){ $name=Read-Host 'Username' }; $newPasswordSecure=Read-Host -AsSecureString 'New password'; Set-LocalUser -Name $name -Password $newPasswordSecure; Log-Event ("Changed password for {0}" -f $name) }
function List-TopProcesses { Get-Process | Sort-Object CPU -Descending | Select-Object -First 30 | Format-Table -AutoSize; Log-Event "Listed top processes" }
function Kill-Process { param($name); if (-not $name){ $name=Read-Host 'Process name' }; Get-Process -Name $name -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue; Log-Event ("Killed process {0}" -f $name) }
function Restart-Explorer { Stop-Process -Name explorer -Force; Start-Sleep -Seconds 1; Start-Process explorer; Log-Event "Restarted explorer" }
function Set-TimeZone { param($tz); if (-not $tz){ tzutil /l; $tz = Read-Host 'Enter TimeZoneId from list' }; tzutil /s $tz; Log-Event ("Set timezone {0}" -f $tz) }
function Show-EventLogs { Get-EventLog -LogName System -Newest 50 | Format-Table -AutoSize; Log-Event "Viewed event logs" }
function Export-SystemInfo { param($out); if (-not $out){ $out = Join-Path $env:USERPROFILE 'Desktop\systeminfo.txt' }; Get-ComputerInfo | Out-File $out; Write-Host ("Saved system info to {0}" -f $out); Log-Event ("Exported system info {0}" -f $out) }
function Disable-PnPDevice { param($dev); if (-not $dev){ Write-Host 'Listing PnP devices...'; Get-PnpDevice | Select-Object -First 20 | Format-Table -AutoSize; $dev=Read-Host 'Enter Device InstanceId or Name' }; Disable-PnpDevice -InstanceId $dev -Confirm:$false -ErrorAction SilentlyContinue; Log-Event ("Disabled device {0}" -f $dev) }
function Eject-CD { (New-Object -comObject WMPlayer.OCX).cdromCollection.Item(0).Eject() ; Log-Event "Ejected CD/DVD" }
function Mount-ISO { param($path); if (-not $path){ $path=Read-Host 'Path to ISO' }; Mount-DiskImage -ImagePath $path; Log-Event ("Mounted ISO {0}" -f $path) }
function Dismount-ISO { param($path); if (-not $path){ $path=Read-Host 'Path to ISO' }; Dismount-DiskImage -ImagePath $path; Log-Event ("Dismounted ISO {0}" -f $path) }


# Misc functions (81-99)
function Show-TempSizes { $temp = $env:TEMP; $size = (Get-ChildItem -Path $temp -Recurse -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum; Write-Host ("Temp size (bytes): {0}" -f $size); Log-Event "Checked temp size" }
function Clear-WindowsUpdateCache { if (Confirm-Action "Clear Windows Update cache?") { Stop-Service wuauserv -ErrorAction SilentlyContinue; Remove-Item -Path "$env:SystemRoot\SoftwareDistribution\Download\*" -Recurse -Force -ErrorAction SilentlyContinue; Start-Service wuauserv -ErrorAction SilentlyContinue; Log-Event "Cleared Windows Update cache" } }
function Show-SmbShares { Get-SmbShare | Format-Table -AutoSize; Log-Event "Listed SMB shares" }
function New-SmbShare { param($name,$path); if (-not $name){ $name=Read-Host 'Share name' }; if (-not $path){ $path=Read-Host 'Path to share' }; New-SmbShare -Name $name -Path $path -FullAccess Everyone -ErrorAction SilentlyContinue; Log-Event ("Created share {0}" -f $name) }
function Remove-SmbShare { param($name); if (-not $name){ $name=Read-Host 'Share name to remove' }; Remove-SmbShare -Name $name -Force -ErrorAction SilentlyContinue; Log-Event ("Removed share {0}" -f $name) }
function Map-NetworkDrive { param($letter,$path); if (-not $letter){ $letter=Read-Host 'Drive letter (e.g. Z:)' }; if (-not $path){ $path=Read-Host 'Network path (\\\\server\\share)' }; New-PSDrive -Name $letter.TrimEnd(':') -PSProvider FileSystem -Root $path -Persist -ErrorAction SilentlyContinue; Log-Event ("Mapped drive {0} to {1}" -f $letter,$path) }
function Unmap-NetworkDrive { param($letter); if (-not $letter){ $letter=Read-Host 'Drive letter to remove (e.g. Z:)' }; Remove-PSDrive -Name $letter.TrimEnd(':') -Force -ErrorAction SilentlyContinue; Log-Event ("Removed drive {0}" -f $letter) }
function Sync-Time { w32tm /resync; Log-Event "Synced time" }
function Show-ActivationStatus { slmgr /xpr; Log-Event "Checked activation status" }
function Mute-Unmute { param($action='toggle'); Add-Type -AssemblyName presentationCore; Write-Host 'Use OS volume controls' ; Log-Event "Toggled mute (placeholder)" }
function Open-RegistryEditor { Start-Process regedit; Log-Event "Opened registry editor" }
function Backup-Registry { param($out); if (-not $out){ $out = Join-Path $env:USERPROFILE 'Desktop\registry_backup.reg' }; reg export HKLM $out /y; Log-Event ("Exported registry to {0}" -f $out) }
function Restore-Registry { param($file); if (-not $file){ $file=Read-Host 'Path to .reg file' }; reg import $file; Log-Event ("Imported registry {0}" -f $file) }
function Export-ARP { arp -a > (Join-Path $env:USERPROFILE 'Desktop\arp_cache.txt'); Write-Host 'ARP exported to Desktop' ; Log-Event "Exported ARP" }
function Toggle-Hibernate { param($on='status'); if ($on -eq 'status'){ powercfg /availablesleepstates } elseif ($on -eq 'off'){ powercfg -h off } elseif ($on -eq 'on'){ powercfg -h on }; Log-Event ("Toggled hibernate {0}" -f $on) }
function Toggle-RDP-Port { param($port=3389); Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'PortNumber' -Value $port -ErrorAction SilentlyContinue; Log-Event ("Set RDP port to {0}" -f $port) }
function Toggle-RemoteDesktop { param($enable=$true); Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -Value ([int]( -not $enable )); if ($enable) { Enable-NetFirewallRule -DisplayGroup 'Remote Desktop' } else { Disable-NetFirewallRule -DisplayGroup 'Remote Desktop' }; Log-Event ("Set Remote Desktop {0}" -f $enable) }
function Show-RDPStatus { Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' ; Log-Event "Showed RDP status" }
function Backup-ScriptAndLogs { $zip = Join-Path $env:USERPROFILE ('Desktop\SwissArmyBackup_{0}.zip' -f (Get-Date -Format 'yyyyMMdd_HHmmss')); Compress-Archive -Path $PSScriptRoot\* -DestinationPath $zip -Force; Write-Host ("Backup created: {0}" -f $zip); Log-Event ("Created backup {0}" -f $zip) }


# Menu system

function Show-Header {
    Clear-Host
    $date = Get-Date -Format "yyyy-MM-dd  HH:mm:ss"
    $hostName = $env:COMPUTERNAME
    $osInfo = (Get-CimInstance Win32_OperatingSystem)
    $osName = $osInfo.Caption
    $osBuild = $osInfo.BuildNumber
    $ipAddr = (Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias "Ethernet" -ErrorAction SilentlyContinue | Where-Object {$_.IPAddress -ne "127.0.0.1"} | Select-Object -First 1 -ExpandProperty IPAddress)
    if (-not $ipAddr) { $ipAddr = "N/A" }
    $macAddr = (Get-NetAdapter | Where-Object Status -eq "Up" | Select-Object -First 1 -ExpandProperty MacAddress)
    
    # ASCII title (simple block)
    Write-Host " ________  ________  _________   _____   ____  __." -ForegroundColor Yellow
    Write-Host "/   __   \/   __   \/   _____/  /  _  \ |    |/ _|" -ForegroundColor Yellow
    Write-Host "\____    /\____    /\_____  \  /  /_\  \|      <  " -ForegroundColor Yellow
    Write-Host "   /    /    /    / /        \/    |    \    |  \ " -ForegroundColor Yellow
    Write-Host "  /____/    /____/ /_______  /\____|__  /____|__ \" -ForegroundColor Yellow
    Write-Host "                           \/         \/        \/" -ForegroundColor Yellow

    Write-Host ""  
    Write-Host "Powershell Swiss Army Knife" -ForegroundColor Cyan
    
    Write-Host "" 
    Write-Host " Developer" -NoNewline -ForegroundColor White; Write-Host "  Salahuddin" -ForegroundColor Green
    Write-Host " GitHub   " -NoNewline -ForegroundColor White; Write-Host "  https://github.com/salahmed-ctrlz" -ForegroundColor Green
    Write-InfoLine -Label "Date" -Value $date
    Write-InfoLine -Label "Host" -Value $hostName
    Write-InfoLine -Label "OS" -Value ("{0} (Build {1})" -f $osName, $osBuild)
    Write-InfoLine -Label "IP Addr" -Value $ipAddr
    Write-InfoLine -Label "MAC Addr" -Value $macAddr
    Write-Host "" 
    Write-Host "Tip: Press Ctrl+B anytime to instantly close 99SAK (Boss Key)." -ForegroundColor DarkGray
}

function Show-MainMenu {
    while ($true) {
        Show-Header
        Write-Host "Main Menu - Choose a category (type letter, case-insensitive):" -ForegroundColor White
        Write-Option -Key 'A' -Description 'Networking (1-20)' -KeyColor Yellow -DescColor Gray
        Write-Option -Key 'B' -Description 'System Maintenance (21-40)' -KeyColor Yellow -DescColor Gray
        Write-Option -Key 'C' -Description 'Security & Privacy (41-60)' -KeyColor Yellow -DescColor Gray
        Write-Option -Key 'D' -Description 'Utilities (61-80)' -KeyColor Yellow -DescColor Gray
        Write-Option -Key 'E' -Description 'Misc (81-99)' -KeyColor Yellow -DescColor Gray
        Write-Option -Key 'H' -Description 'Command history (last 5)' -KeyColor Yellow -DescColor Gray
        Write-Option -Key 'Q' -Description 'Quit' -KeyColor Red -DescColor Gray
        $choice = (Read-InputWithBossKey "Enter choice").ToUpper()
        if ($choice -match '^(CTRL\+B|BOSS)$') { return }
        switch ($choice) {
            "A" { Show-CategoryMenu -Category "Networking" }
            "B" { Show-CategoryMenu -Category "System" }
            "C" { Show-CategoryMenu -Category "Security" }
            "D" { Show-CategoryMenu -Category "Utilities" }
            "E" { Show-CategoryMenu -Category "Misc" }
            "H" { Show-CommandHistory }
            "Q" { Write-Host "Exiting..."; return }
            default { Handle-InvalidChoice; Start-Sleep -Seconds 1 }
        }
    }
}

function Show-CategoryMenu {
    param([string]$Category)
    do {
        Clear-Host
        Write-Host "Powershell Swiss Army Knife - 99SAK" -ForegroundColor Cyan
        Write-Host ("Category: {0}" -f $Category) -ForegroundColor Green
        switch ($Category) {
            "Networking" {
                Write-Option -Key '1' -Description 'Show active adapters'
                Write-Option -Key '2' -Description 'Enable adapter (name)'
                Write-Option -Key '3' -Description 'Disable adapter (name)'
                Write-Option -Key '4' -Description 'Restart adapter (name)'
                Write-Option -Key '5' -Description 'Show IP config'
                Write-Option -Key '6' -Description 'Release & Renew IP'
                Write-Option -Key '7' -Description 'Flush DNS'
                Write-Option -Key '8' -Description 'Set DNS to Google'
                Write-Option -Key '9' -Description 'Set DNS to Cloudflare'
                Write-Option -Key '10' -Description 'Show active TCP connections'
                Write-Option -Key '11' -Description 'Show listening ports'
                Write-Option -Key '12' -Description 'Test-Connection (ping)'
                Write-Option -Key '13' -Description 'Traceroute (tracert)'
                Write-Option -Key '14' -Description 'Scan common ports'
                Write-Option -Key '15' -Description 'Reset TCP/IP stack'
                Write-Option -Key '16' -Description 'Show ARP table'
                Write-Option -Key '17' -Description 'Show routing table'
                Write-Option -Key '18' -Description 'Add static route'
                Write-Option -Key '19' -Description 'Remove static route'
                Write-Option -Key '20' -Description 'WiFi profiles & passwords'
                Write-Option -Key 'B' -Description 'Back to main menu' -KeyColor Red -DescColor Gray
                $choice = (Read-InputWithBossKey "Enter choice").ToUpper()
                switch ($choice) {
                    "1" { Show-ActiveAdapters }
                    "2" { $n = Read-Host 'Adapter name'; if ($n) { Enable-Adapter -name $n } }
                    "3" { $n = Read-Host 'Adapter name'; if ($n) { Disable-Adapter -name $n } }
                    "4" { $n = Read-Host 'Adapter name'; if ($n) { Restart-NetworkAdapterByName -name $n } }
                    "5" { Show-IPConfig }
                    "6" { if (Confirm-Action 'Release and renew IP?') { Release-Renew } }
                    "7" { if (Confirm-Action 'Flush DNS cache?') { Flush-DNS } }
                    "8" { if (Confirm-Action 'Set DNS to Google?') { Create-RestorePoint -Description 'SetDNS-Google'; Set-DNS-Google } }
                    "9" { if (Confirm-Action 'Set DNS to Cloudflare?') { Create-RestorePoint -Description 'SetDNS-Cloudflare'; Set-DNS-Cloudflare } }
                    "10" { Show-ActiveConnections }
                    "11" { Show-ListeningPorts }
                    "12" { Test-Conn }
                    "13" { Traceroute-Host }
                    "14" { $t=Read-Host 'Target'; Scan-CommonPorts -t $t }
                    "15" { if (Confirm-Action 'Reset TCP/IP stack?') { Create-RestorePoint -Description 'Reset-TCPIP'; Reset-TCPIP } }
                    "16" { Show-ARP }
                    "17" { Show-Routes }
                    "18" { $d=Read-Host 'Dest'; $m=Read-Host 'Mask'; $g=Read-Host 'Gateway'; Add-StaticRoute -dest $d -mask $m -gateway $g }
                    "19" { $d=Read-Host 'Dest to remove'; Remove-StaticRoute -dest $d }
                    "20" { Show-WiFiProfiles; Show-WiFiPasswords }
                    "B" { break }
                    "b" { break }
                    default { Handle-InvalidChoice }
                }
                Handle-PostTask -Category 'Networking' -Choice $choice -ValidChoices @('1','2','3','4','5','6','7','8','9','10','11','12','13','14','15','16','17','18','19','20','B')
            }
            "System" {
                Write-Option -Key '21' -Description 'Show system info'
                Write-Option -Key '22' -Description 'Show disk usage'
                Write-Option -Key '23' -Description 'Clean user temp'
                Write-Option -Key '24' -Description 'Clean system temp'
                Write-Option -Key '25' -Description 'Empty recycle bin'
                Write-Option -Key '26' -Description 'Check disk (chkdsk)'
                Write-Option -Key '27' -Description 'Run SFC scan'
                Write-Option -Key '28' -Description 'Run DISM RestoreHealth'
                Write-Option -Key '29' -Description 'Defrag drive'
                Write-Option -Key '30' -Description 'List running services'
                Write-Option -Key '31' -Description 'Restart a service'
                Write-Option -Key '32' -Description 'Stop a service'
                Write-Option -Key '33' -Description 'Start a service'
                Write-Option -Key '34' -Description 'Disable startup app (search)'
                Write-Option -Key '35' -Description 'List scheduled tasks'
                Write-Option -Key '36' -Description 'Create restore point'
                Write-Option -Key '37' -Description 'Toggle Windows Update (status/stop/start)'
                Write-Option -Key '38' -Description 'Reboot system'
                Write-Option -Key '39' -Description 'Shutdown system'
                Write-Option -Key '40' -Description 'Export system info to file'
                Write-Option -Key 'B' -Description 'Back to main menu' -KeyColor Red -DescColor Gray
                $choice = (Read-InputWithBossKey "Enter choice").ToUpper()
                switch ($choice) {
                    "21" { Show-SystemInfo }
                    "22" { Show-DiskUsage }
                    "23" { if (Confirm-Action 'Clean user temp?') { Create-RestorePoint -Description 'CleanTemp'; Clean-UserTemp } }
                    "24" { if (Confirm-Action 'Clean system temp?') { Create-RestorePoint -Description 'CleanSysTemp'; Clean-SystemTemp } }
                    "25" { if (Confirm-Action 'Empty Recycle Bin?') { Empty-RecycleBin } }
                    "26" { $d = Read-Host 'Drive (C: by default)'; if (-not $d){ $d='C:' }; Chk-Disk -drive $d }
                    "27" { if (Confirm-Action 'Run SFC scan?') { Run-SFC } }
                    "28" { if (Confirm-Action 'Run DISM RestoreHealth?') { Run-DISM } }
                    "29" { $d = Read-Host 'Drive (C: by default)'; if (-not $d){ $d='C:' }; Defrag-Drive -drive $d }
                    "30" { List-Services }
                    "31" { $s=Read-Host 'Service name'; if ($s){ Restart-ServiceByName -name $s } }
                    "32" { $s=Read-Host 'Service name'; if ($s){ Stop-ServiceByName -name $s } }
                    "33" { $s=Read-Host 'Service name'; if ($s){ Start-ServiceByName -name $s } }
                    "34" { $n=Read-Host 'Startup name fragment'; Disable-StartupApp -name $n }
                    "35" { List-ScheduledTasks }
                    "36" { Create-Restore }
                    "37" { $a = Read-Host 'action (status/stop/start)'; Toggle-WindowsUpdate -action $a }
                    "38" { Reboot-System }
                    "39" { Shutdown-System }
                    "40" { $out = Read-Host 'Output path (default Desktop)'; if (-not $out) { $out = Join-Path $env:USERPROFILE 'Desktop\systeminfo.txt' }; Export-SystemInfo -out $out }
                    "B" { break }
                    "b" { break }
                    default { Handle-InvalidChoice }
                }
                Handle-PostTask -Category 'System' -Choice $choice -ValidChoices @('21','22','23','24','25','26','27','28','29','30','31','32','33','34','35','36','37','38','39','40','B')
            }
            "Security" {
                Write-Option -Key '41' -Description 'Enable Firewall'
                Write-Option -Key '42' -Description 'Disable Firewall'
                Write-Option -Key '43' -Description 'Show Firewall rules'
                Write-Option -Key '44' -Description 'Block host (hosts file)'
                Write-Option -Key '45' -Description 'Unblock host (hosts file)'
                Write-Option -Key '46' -Description 'Disable Diagnostics Tracking (DiagTrack)'
                Write-Option -Key '47' -Description 'Show Defender status'
                Write-Option -Key '48' -Description 'Defender quick scan'
                Write-Option -Key '49' -Description 'Defender full scan'
                Write-Option -Key '50' -Description 'Update Defender signatures'
                Write-Option -Key '51' -Description 'Show local users'
                Write-Option -Key '52' -Description 'Lock workstation'
                Write-Option -Key '53' -Description 'Clear recent files'
                Write-Option -Key '54' -Description 'Clear clipboard'
                Write-Option -Key '55' -Description 'List listening ports (security)'
                Write-Option -Key '56' -Description 'Show processes (suspicious)'
                Write-Option -Key '57' -Description 'Show Windows activation status'
                Write-Option -Key '58' -Description 'Check BitLocker status'
                Write-Option -Key '59' -Description 'Toggle Remote Desktop'
                Write-Option -Key '60' -Description 'Show RDP status'
                Write-Option -Key 'B' -Description 'Back to main menu' -KeyColor Red -DescColor Gray
                $choice = (Read-InputWithBossKey "Enter choice").ToUpper()
                switch ($choice) {
                    "41" { Enable-Firewall }
                    "42" { if (Confirm-Action 'Disable firewall?') { Disable-Firewall } }
                    "43" { Show-FirewallRules }
                    "44" { $h=Read-Host 'Host to block'; if ($h){ Block-HostsFile -host $h } }
                    "45" { $h=Read-Host 'Host to unblock'; if ($h){ Unblock-HostsFile -host $h } }
                    "46" { Disable-DiagTrack }
                    "47" { Show-DefenderStatus }
                    "48" { if (Confirm-Action 'Run Defender quick scan?') { Defender-QuickScan } }
                    "49" { if (Confirm-Action 'Run Defender full scan?') { Defender-FullScan } }
                    "50" { Update-DefenderSignatures }
                    "51" { Show-Users }
                    "52" { Lock-Workstation }
                    "53" { Clear-RecentFiles }
                    "54" { Clear-ClipboardHistory }
                    "55" { Get-NetTCPConnection -State Listen | Select-Object LocalAddress,LocalPort,OwningProcess | Format-Table -AutoSize }
                    "56" { Get-Process | Sort-Object CPU -Descending | Select-Object -First 30 | Format-Table -AutoSize }
                    "57" { Show-ActivationStatus }
                    "58" { try { Get-BitLockerVolume | Format-Table -AutoSize } catch { Write-Host 'BitLocker not available' -ForegroundColor Yellow } }
                    "59" { $e = Read-Host 'Enable or Disable? (E/D)'; if ($e -match 'E') { Toggle-RemoteDesktop -enable $true } else { Toggle-RemoteDesktop -enable $false } }
                    "60" { Show-RDPStatus }
                    "B" { break }
                    "b" { break }
                    default { Handle-InvalidChoice }
                }
                Handle-PostTask -Category 'Security' -Choice $choice -ValidChoices @('41','42','43','44','45','46','47','48','49','50','51','52','53','54','55','56','57','58','59','60','B')
            }
            "Utilities" {
                Write-Option -Key '61' -Description 'Take screenshot'
                Write-Option -Key '62' -Description 'List installed programs'
                Write-Option -Key '63' -Description 'Create local admin user'
                Write-Option -Key '64' -Description 'Remove local user'
                Write-Option -Key '65' -Description 'Change user password'
                Write-Option -Key '66' -Description 'List top processes'
                Write-Option -Key '67' -Description 'Kill process'
                Write-Option -Key '68' -Description 'Restart Explorer'
                Write-Option -Key '69' -Description 'Set timezone'
                Write-Option -Key '70' -Description 'Show event logs'
                Write-Option -Key '71' -Description 'Export system info'
                Write-Option -Key '72' -Description 'Disable PnP device'
                Write-Option -Key '73' -Description 'Eject CD/DVD'
                Write-Option -Key '74' -Description 'Mount ISO'
                Write-Option -Key '75' -Description 'Dismount ISO'
                Write-Option -Key '76' -Description 'Create restore point'
                Write-Option -Key '77' -Description 'Generate battery report'
                Write-Option -Key '78' -Description 'Generate energy report'
                Write-Option -Key '79' -Description 'Set power plan to High Performance'
                Write-Option -Key '80' -Description 'List scheduled tasks'
                Write-Option -Key 'B' -Description 'Back to main menu' -KeyColor Red -DescColor Gray
                $choice = (Read-InputWithBossKey "Enter choice").ToUpper()
                switch ($choice) {
                    "61" { Take-Screenshot }
                    "62" { List-InstalledPrograms }
                    "63" { Create-LocalAdmin }
                    "64" { Remove-LocalUser }
                    "65" { Change-UserPassword }
                    "66" { List-TopProcesses }
                    "67" { Kill-Process }
                    "68" { Restart-Explorer }
                    "69" { Set-TimeZone }
                    "70" { Show-EventLogs }
                    "71" { Export-SystemInfo }
                    "72" { Disable-PnPDevice }
                    "73" { Eject-CD }
                    "74" { Mount-ISO }
                    "75" { Dismount-ISO }
                    "76" { Create-Restore }
                    "77" { powercfg /batteryreport; Write-Host 'Battery report generated on desktop' }
                    "78" { powercfg /energy; Write-Host 'Energy report generated' }
                    "79" { powercfg -setactive scheme_min_power; Write-Host 'Set power plan (may vary)' }
                    "80" { List-ScheduledTasks }
                    "B" { break }
                    "b" { break }
                    default { Handle-InvalidChoice }
                }
                Handle-PostTask -Category 'Utilities' -Choice $choice -ValidChoices @('61','62','63','64','65','66','67','68','69','70','71','72','73','74','75','76','77','78','79','80','B')
            }
            "Misc" {
                Write-Option -Key '81' -Description 'Show temp sizes'
                Write-Option -Key '82' -Description 'Clear Windows Update cache'
                Write-Option -Key '83' -Description 'Show SMB shares'
                Write-Option -Key '84' -Description 'Create SMB share'
                Write-Option -Key '85' -Description 'Remove SMB share'
                Write-Option -Key '86' -Description 'Map network drive'
                Write-Option -Key '87' -Description 'Unmap network drive'
                Write-Option -Key '88' -Description 'Sync time (w32tm)'
                Write-Option -Key '89' -Description 'Show activation status'
                Write-Option -Key '90' -Description 'Toggle mute (placeholder)'
                Write-Option -Key '91' -Description 'Open registry editor'
                Write-Option -Key '92' -Description 'Backup registry'
                Write-Option -Key '93' -Description 'Restore registry'
                Write-Option -Key '94' -Description 'Export ARP cache'
                Write-Option -Key '95' -Description 'Toggle hibernate'
                Write-Option -Key '96' -Description 'Set RDP port'
                Write-Option -Key '97' -Description 'Toggle Remote Desktop (enable/disable)'
                Write-Option -Key '98' -Description 'Show RDP status'
                Write-Option -Key '99' -Description 'Backup script and logs to Desktop'
                Write-Option -Key 'B' -Description 'Back to main menu' -KeyColor Red -DescColor Gray
                $choice = (Read-Host "Enter choice").ToUpper()
                switch ($choice) {
                    "81" { Show-TempSizes }
                    "82" { Clear-WindowsUpdateCache }
                    "83" { Show-SmbShares }
                    "84" { New-SmbShare }
                    "85" { Remove-SmbShare }
                    "86" { Map-NetworkDrive }
                    "87" { Unmap-NetworkDrive }
                    "88" { Sync-Time }
                    "89" { Show-ActivationStatus }
                    "90" { Mute-Unmute }
                    "91" { Open-RegistryEditor }
                    "92" { Backup-Registry }
                    "93" { Restore-Registry }
                    "94" { Export-ARP }
                    "95" { Toggle-Hibernate -on (Read-Host 'on/off/status (type on/off/status)') }
                    "96" { $p=Read-Host 'Port number'; if ($p) { Toggle-RDP-Port -port $p } }
                    "97" { $e = Read-Host 'Enable? (Y/N)'; if ($e -match 'Y') { Toggle-RemoteDesktop -enable $true } else { Toggle-RemoteDesktop -enable $false } }
                    "98" { Show-RDPStatus }
                    "99" { Backup-ScriptAndLogs }
                    "B" { break }
                    default { Handle-InvalidChoice }
                }
                Handle-PostTask -Category 'Misc' -Choice $choice -ValidChoices @('81','82','83','84','85','86','87','88','89','90','91','92','93','94','95','96','97','98','99','B')
            }
            default { Write-Host "Unknown category." -ForegroundColor Yellow }
        }
        Write-Host ""
        $cont = (Read-Host "Press Enter to continue in this category, or type B to return to main menu").ToUpper()
    } while ($cont -ne "B")
}

# Ensure admin then run
Ensure-Admin
Show-MainMenu
