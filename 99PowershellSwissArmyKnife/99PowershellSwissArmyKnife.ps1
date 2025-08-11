
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
        if ($sr -ne $null) {
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
    netsh wlan show profiles | Select-String "\:(.*)$" | % { $_.ToString().Split(":")[1].Trim() } | ForEach-Object {
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
function Block-HostsFile { param($host); if (-not $host) { $host=Read-Host 'Host to block' }; Add-Content -Path (Join-Path $env:SystemRoot 'System32\drivers\etc\hosts') -Value ('0.0.0.0 ' + $host); Log-Event ("Blocked host {0}" -f $host) }
function Unblock-HostsFile { param($host); $path = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'; (Get-Content $path) | Where-Object { $_ -notlike "*$host*" } | Set-Content $path; Log-Event ("Unblocked host {0}" -f $host) }
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
function Create-LocalAdmin { param($name); if (-not $name){ $name=Read-Host 'New username' }; $pwd = Read-Host -AsSecureString 'Password'; New-LocalUser -Name $name -Password $pwd -PasswordNeverExpires:$true; Add-LocalGroupMember -Group 'Administrators' -Member $name; Write-Host ("Created local admin {0}" -f $name); Log-Event ("Created local admin {0}" -f $name) }
function Remove-LocalUser { param($name); if (-not $name){ $name=Read-Host 'Username to remove' }; Remove-LocalUser -Name $name -ErrorAction SilentlyContinue; Log-Event ("Removed user {0}" -f $name) }
function Change-UserPassword { param($name); if (-not $name){ $name=Read-Host 'Username' }; $pwd=Read-Host -AsSecureString 'New password'; Set-LocalUser -Name $name -Password $pwd; Log-Event ("Changed password for {0}" -f $name) }
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
function Mute-Unmute { param($action='toggle'); Add-Type -AssemblyName presentationCore; $vol = (Get-Volume -ErrorAction SilentlyContinue); Write-Host 'Use OS volume controls' ; Log-Event "Toggled mute (placeholder)" }
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
    Write-Host "========================================" -ForegroundColor Magenta
    Write-Host "  99Powershell SwissArmyKnife (expanded)  " -ForegroundColor Cyan
    Write-Host " Developer: Medkour Salahuddin - https://github.com/salahmed-ctrlz" -ForegroundColor Yellow
    Write-Host "========================================" -ForegroundColor Magenta
    Write-Host ""
}

function Show-MainMenu {
    while ($true) {
        Show-Header
        Write-Host "Main Menu - Choose a category (type letter, case-insensitive):" -ForegroundColor White
        Write-Host "[A] Networking (1-20)"
        Write-Host "[B] System Maintenance (21-40)"
        Write-Host "[C] Security & Privacy (41-60)"
        Write-Host "[D] Utilities (61-80)"
        Write-Host "[E] Misc (81-99)"
        Write-Host "[Q] Quit"
        $choice = (Read-Host "Enter choice").ToUpper()
        switch ($choice) {
            "A" { Show-CategoryMenu -Category "Networking" }
            "B" { Show-CategoryMenu -Category "System" }
            "C" { Show-CategoryMenu -Category "Security" }
            "D" { Show-CategoryMenu -Category "Utilities" }
            "E" { Show-CategoryMenu -Category "Misc" }
            "Q" { Write-Host "Exiting..."; return }
            default { Write-Host "Invalid choice." -ForegroundColor Yellow; Start-Sleep -Seconds 1 }
        }
    }
}

function Show-CategoryMenu {
    param([string]$Category)
    do {
        Show-Header
        Write-Host ("Category: {0}" -f $Category) -ForegroundColor Green
        switch ($Category) {
            "Networking" {
                Write-Host "[1] Show active adapters"
                Write-Host "[2] Enable adapter (name)"
                Write-Host "[3] Disable adapter (name)"
                Write-Host "[4] Restart adapter (name)"
                Write-Host "[5] Show IP config"
                Write-Host "[6] Release & Renew IP"
                Write-Host "[7] Flush DNS"
                Write-Host "[8] Set DNS to Google"
                Write-Host "[9] Set DNS to Cloudflare"
                Write-Host "[10] Show active TCP connections"
                Write-Host "[11] Show listening ports"
                Write-Host "[12] Test-Connection (ping)"
                Write-Host "[13] Traceroute (tracert)"
                Write-Host "[14] Scan common ports"
                Write-Host "[15] Reset TCP/IP stack"
                Write-Host "[16] Show ARP table"
                Write-Host "[17] Show routing table"
                Write-Host "[18] Add static route"
                Write-Host "[19] Remove static route"
                Write-Host "[20] WiFi profiles & passwords"
                Write-Host "[B] Back to main menu"
                $choice = (Read-Host "Enter choice").ToUpper()
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
                    default { Write-Host 'Invalid choice' -ForegroundColor Yellow }
                }
            }
            "System" {
                Write-Host "[21] Show system info"
                Write-Host "[22] Show disk usage"
                Write-Host "[23] Clean user temp"
                Write-Host "[24] Clean system temp"
                Write-Host "[25] Empty recycle bin"
                Write-Host "[26] Check disk (chkdsk)"
                Write-Host "[27] Run SFC scan"
                Write-Host "[28] Run DISM RestoreHealth"
                Write-Host "[29] Defrag drive"
                Write-Host "[30] List running services"
                Write-Host "[31] Restart a service"
                Write-Host "[32] Stop a service"
                Write-Host "[33] Start a service"
                Write-Host "[34] Disable startup app (search)"
                Write-Host "[35] List scheduled tasks"
                Write-Host "[36] Create restore point"
                Write-Host "[37] Toggle Windows Update (status/stop/start)"
                Write-Host "[38] Reboot system"
                Write-Host "[39] Shutdown system"
                Write-Host "[40] Export system info to file"
                Write-Host "[B] Back to main menu"
                $choice = (Read-Host "Enter choice").ToUpper()
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
                    default { Write-Host 'Invalid choice' -ForegroundColor Yellow }
                }
            }
            "Security" {
                Write-Host "[41] Enable Firewall"
                Write-Host "[42] Disable Firewall"
                Write-Host "[43] Show Firewall rules"
                Write-Host "[44] Block host (hosts file)"
                Write-Host "[45] Unblock host (hosts file)"
                Write-Host "[46] Disable Diagnostics Tracking (DiagTrack)"
                Write-Host "[47] Show Defender status"
                Write-Host "[48] Defender quick scan"
                Write-Host "[49] Defender full scan"
                Write-Host "[50] Update Defender signatures"
                Write-Host "[51] Show local users"
                Write-Host "[52] Lock workstation"
                Write-Host "[53] Clear recent files"
                Write-Host "[54] Clear clipboard"
                Write-Host "[55] List listening ports (security)"
                Write-Host "[56] Show processes (suspicious)"
                Write-Host "[57] Show Windows activation status"
                Write-Host "[58] Check BitLocker status"
                Write-Host "[59] Toggle Remote Desktop"
                Write-Host "[60] Show RDP status"
                Write-Host "[B] Back to main menu"
                $choice = (Read-Host "Enter choice").ToUpper()
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
                    default { Write-Host 'Invalid choice' -ForegroundColor Yellow }
                }
            }
            "Utilities" {
                Write-Host "[61] Take screenshot"
                Write-Host "[62] List installed programs"
                Write-Host "[63] Create local admin user"
                Write-Host "[64] Remove local user"
                Write-Host "[65] Change user password"
                Write-Host "[66] List top processes"
                Write-Host "[67] Kill process"
                Write-Host "[68] Restart Explorer"
                Write-Host "[69] Set timezone"
                Write-Host "[70] Show event logs"
                Write-Host "[71] Export system info"
                Write-Host "[72] Disable PnP device"
                Write-Host "[73] Eject CD/DVD"
                Write-Host "[74] Mount ISO"
                Write-Host "[75] Dismount ISO"
                Write-Host "[76] Create restore point"
                Write-Host "[77] Generate battery report"
                Write-Host "[78] Generate energy report"
                Write-Host "[79] Set power plan to High Performance"
                Write-Host "[80] List scheduled tasks"
                Write-Host "[B] Back to main menu"
                $choice = (Read-Host "Enter choice").ToUpper()
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
                    default { Write-Host 'Invalid choice' -ForegroundColor Yellow }
                }
            }
            "Misc" {
                Write-Host "[81] Show temp sizes"
                Write-Host "[82] Clear Windows Update cache"
                Write-Host "[83] Show SMB shares"
                Write-Host "[84] Create SMB share"
                Write-Host "[85] Remove SMB share"
                Write-Host "[86] Map network drive"
                Write-Host "[87] Unmap network drive"
                Write-Host "[88] Sync time (w32tm)"
                Write-Host "[89] Show activation status"
                Write-Host "[90] Toggle mute (placeholder)"
                Write-Host "[91] Open registry editor"
                Write-Host "[92] Backup registry"
                Write-Host "[93] Restore registry"
                Write-Host "[94] Export ARP cache"
                Write-Host "[95] Toggle hibernate"
                Write-Host "[96] Set RDP port"
                Write-Host "[97] Toggle Remote Desktop (enable/disable)"
                Write-Host "[98] Show RDP status"
                Write-Host "[99] Backup script and logs to Desktop"
                Write-Host "[B] Back to main menu"
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
                    default { Write-Host 'Invalid choice' -ForegroundColor Yellow }
                }
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
