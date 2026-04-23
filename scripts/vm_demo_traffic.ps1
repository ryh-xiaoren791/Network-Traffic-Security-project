param(
  [string]$TargetHost = "192.168.56.1"
)
$Ports = @(21,22,23,80,135,139,445,3389,8080,8443,9000,10000)
$Rounds = 30

Write-Output "Phase-1 高频连接模拟"
for ($r = 0; $r -lt $Rounds; $r++) {
  foreach ($p in $Ports) {
    Test-NetConnection -ComputerName $TargetHost -Port $p -WarningAction SilentlyContinue | Out-Null
  }
  Start-Sleep -Milliseconds 120
}

Write-Output "Phase-2 高频ICMP模拟"
for ($i = 0; $i -lt 300; $i++) {
  ping -n 1 $TargetHost | Out-Null
}

Write-Output "完成"
