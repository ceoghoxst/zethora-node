Set-Location 'C:\Zethora\zethora-node'
$env:RUSTUP_HOME = "C:\Users\admin\.rustup"
$env:CARGO_HOME = "C:\Users\admin\.cargo_clean"
$env:Path += ";C:\Users\admin\.cargo\bin"

Write-Host "Starting L1 Node..."
$l1 = Start-Process -FilePath ".\target\debug\kaspad.exe" -ArgumentList "--devnet" -NoNewWindow -PassThru -RedirectStandardOutput "l1_devnet.log" -RedirectStandardError "l1_devnet.err"

Write-Host "Starting L2 Node..."
$l2 = Start-Process -FilePath ".\target\debug\zethora-rpc-l2.exe" -NoNewWindow -PassThru -RedirectStandardOutput "l2_devnet.log" -RedirectStandardError "l2_devnet.err"

Write-Host "Waiting 15 seconds for nodes to boot..."
Start-Sleep -Seconds 15

Write-Host "Running Relayer Dry-Run (Port 26610)..."
.\target\debug\relayer.exe --treasury 0x1111111111111111111111111111111111111111 --key 0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef --l1 grpc://127.0.0.1:26610 --l2 http://127.0.0.1:8545 --dry-run --once | Tee-Object -FilePath "relayer_test_output.txt"

Write-Host "Killing devnet processes..."
Stop-Process -Id $l1.Id -Force -ErrorAction SilentlyContinue
Stop-Process -Id $l2.Id -Force -ErrorAction SilentlyContinue
Write-Host "Done."