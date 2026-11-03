# Opens one TCP connection to the sandbox bastion on port 22 (an ACCEPT in the flow logs).
# Nothing is sent and no login happens. Schedule it with Task Scheduler (see README).
param(
    [Parameter(Mandatory = $true)][string]$Ip,
    [int]$Port = 22
)

$client = New-Object System.Net.Sockets.TcpClient
try {
    $null = $client.ConnectAsync($Ip, $Port).Wait(3000)
} catch {
    # Connection refused or timed out still leaves a flow-log record; ignore errors.
} finally {
    $client.Dispose()
}
