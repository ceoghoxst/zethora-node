# ============================================================
#  X M I N E R Z - The Zethora CPU Miner
#  A friendly launcher for the Zethora testnet miner.
#  Plain text: open in Notepad to read exactly what it does.
#
#  It only runs zethora-node.exe, zethora-miner.exe and
#  zethora-wallet.exe from this folder. It downloads nothing
#  and changes no settings. Logs: XminerZ-node.log in this
#  folder (only written when XminerZ starts the node itself).
#
#  Testnet only. Testnet coins have no value and no token exists.
# ============================================================
$ErrorActionPreference = 'Continue'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location -LiteralPath $here

$nodeExe   = Join-Path $here 'zethora-node.exe'
$minerExe  = Join-Path $here 'zethora-miner.exe'
$walletExe = Join-Path $here 'zethora-wallet.exe'
$keyFile   = Join-Path $here 'zethora-miner-key-testnet.txt'
$nodeLog   = Join-Path $here 'XminerZ-node.log'
$walletOut = Join-Path $here 'XminerZ-wallet.out'
# The miner dials this address itself (it has no --node flag), so this is the
# port the node has to be serving for mining to work at all.
$grpcPort  = 26210

$script:node      = $null   # the node process, when this script started it
$script:nodeOwned = $false  # $true only when we started the node (we only ever stop our own)
$script:miner     = $null
$script:address   = ''

# ---------- look ----------
function Write-Head($text) { Write-Host ''; Write-Host "  $text" -ForegroundColor Cyan }
function Write-Info($text) { Write-Host "  $text" -ForegroundColor Gray }
function Write-Ok($text)   { Write-Host "  $text" -ForegroundColor Green }
function Write-Warn($text) { Write-Host "  $text" -ForegroundColor Yellow }
function Write-Bad($text)  { Write-Host "  $text" -ForegroundColor Red }

# ---------- banner ----------
function Show-Banner {
  $accent = 'Magenta'
  Write-Host ''
  Write-Host '  ##   ##  #   #  #  #   #  #####  ####  ####     ######' -ForegroundColor $accent
  Write-Host '   #    #  ## ##  #  ##  #  #      #     #   #        #' -ForegroundColor $accent
  Write-Host '    #   #  # # #  #  # # #  ####   ###   ####       #' -ForegroundColor $accent
  Write-Host '     #  #  #   #  #  #  ##  #      #     #  #     #' -ForegroundColor $accent
  Write-Host '  ####  #  #   #  #  #   #  #####  ####  #   #  ######' -ForegroundColor $accent
  Write-Host ''
  Write-Host '       X M I N E R Z - The Zethora CPU Miner' -ForegroundColor White
  Write-Host '       testnet - coins have no value, no token exists' -ForegroundColor DarkGray
  Write-Host ''
}

# ---------- step 1: are the programs here? ----------
function Test-Files {
  $missing = @()
  if (-not (Test-Path -LiteralPath $nodeExe))  { $missing += 'zethora-node.exe' }
  if (-not (Test-Path -LiteralPath $minerExe)) { $missing += 'zethora-miner.exe' }
  if ($missing.Count -eq 0) { return $true }
  Write-Bad "Can't find $($missing -join ' and ') in this folder:"
  Write-Info $here
  Write-Host ''
  Write-Info 'Unzip the WHOLE download into one folder first'
  Write-Info '(right-click the zip, Extract All), then double-click'
  Write-Info 'XminerZ.bat inside that folder.'
  return $false
}

# ---------- step 2: the address ----------
# The address you mine to is the one your mining key file holds. XminerZ never
# asks for a different one: the miner pays the key in this folder, so pointing
# it anywhere else would put the coins somewhere this folder cannot spend them.

function Read-KeyAddress {
  # The wallet works the address out from zethora-miner-key-testnet.txt. That
  # needs no node, and it never changes an existing key file.
  if (-not (Test-Path -LiteralPath $walletExe)) { return '' }
  $r = Invoke-Wallet @('receive', '--testnet')
  if ($r.Code -ne 0) { return '' }
  return (Find-Address $r.Text)
}

function New-KeyAndAddress {
  # No key file yet: the miner creates a random one the first time it runs, and
  # the wallet then prints the address that key mines to.
  Write-Info 'No mining key in this folder yet. Creating one now...'
  $r = Invoke-Wallet @('receive', '--testnet')
  $addr = Find-Address $r.Text
  if ($addr) { return $addr }
  if (Test-Path -LiteralPath $walletExe) {
    Write-Warn 'The wallet could not print an address:'
    if ($r.Text) { Write-Info $r.Text }
  } else {
    Write-Warn 'zethora-wallet.exe is not in this folder, so no address can be shown yet.'
    Write-Info 'The miner still creates the key and prints the address when it starts.'
  }
  return ''
}

function Show-Address([string]$addr) {
  if (-not $addr) {
    Write-Warn 'Your address is not known yet; the miner prints it when it starts.'
    return
  }
  Write-Ok "Your address: $addr"
  Write-Info 'This is where your mined testnet coins go. It comes from'
  Write-Info "$(Split-Path -Leaf $keyFile) in this folder and never changes."
}

function Write-KeyReminder {
  # Losing this file loses the coins, so the reminder is shown on every run.
  if (-not (Test-Path -LiteralPath $keyFile)) { return }
  Write-Warn 'Keep a copy of this file. Anyone who has it can take your coins.'
  Write-Info "  $(Split-Path -Leaf $keyFile)   (in this folder)"
}

# ---------- small helpers ----------
function Get-ProcessByName($name) {
  # Get-Process throws when nothing matches; this always returns an array.
  try { return @(Get-Process -Name $name -ErrorAction SilentlyContinue) } catch { return @() }
}

function Test-PortOpen($port) {
  try {
    $client = New-Object System.Net.Sockets.TcpClient
    $ok = $client.ConnectAsync('127.0.0.1', $port).Wait(1000)
    $client.Close()
    return $ok
  } catch { return $false }
}

function Find-Address([string]$text) {
  # The wallet prints the address on its own line, indented by four spaces, so the
  # pattern is not anchored: indentation must never be able to hide it.
  $m = [regex]::Match([string]$text, 'zethoratest:[a-z0-9]+')
  if ($m.Success) { return $m.Value }
  return ''
}

function Invoke-Wallet([string[]]$walletArgs) {
  # Runs the wallet in this folder and hands back its exit code and output
  # together. Only `receive` is ever called: nothing is sent or spent.
  if (-not (Test-Path -LiteralPath $walletExe)) {
    return @{ Code = -1; Text = 'zethora-wallet.exe is not in this folder.' }
  }
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $walletExe
  $psi.Arguments = (($walletArgs | ForEach-Object { if ($_ -match '\s') { '"' + $_ + '"' } else { $_ } }) -join ' ')
  $psi.WorkingDirectory = $here
  $psi.UseShellExecute = $false
  $psi.CreateNoWindow = $true
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError = $true
  try { $proc = [System.Diagnostics.Process]::Start($psi) } catch {
    return @{ Code = -3; Text = "Couldn't start zethora-wallet.exe. $($_.Exception.Message)" }
  }
  # Both pipes are drained while the wallet runs, so a full pipe can't stall it.
  $outTask = $proc.StandardOutput.ReadToEndAsync()
  $errTask = $proc.StandardError.ReadToEndAsync()
  if (-not $proc.WaitForExit(60000)) {
    try { $proc.Kill() } catch {}
    return @{ Code = -2; Text = 'The wallet did not answer within a minute.' }
  }
  $text = (@("$($outTask.Result)", "$($errTask.Result)") -join "`r`n").Trim()
  return @{ Code = $proc.ExitCode; Text = $text }
}

# ---------- step 3: the node ----------
function Start-Node {
  # A node that is already running is used as it is: a second one cannot have the
  # same ports, and stopping one this script did not start would lose its state.
  $running = Get-ProcessByName 'zethora-node'
  if ($running.Count -gt 0) {
    Write-Ok 'A Zethora node is already running - using it.'
    return $true
  }
  Write-Head 'Starting the node (this is the piece that talks to the network)'
  Write-Info 'It runs in the background and writes XminerZ-node.log in this folder.'
  try { Remove-Item -LiteralPath $nodeLog -Force -ErrorAction SilentlyContinue } catch {}
  try {
    $script:node = Start-Process -FilePath $nodeExe `
        -ArgumentList '--testnet', '--utxoindex', '--enable-unsynced-mining' `
        -WorkingDirectory $here -WindowStyle Hidden `
        -RedirectStandardOutput $nodeLog -RedirectStandardError "$nodeLog.err" -PassThru
  } catch {
    Write-Bad "Couldn't start zethora-node.exe: $($_.Exception.Message)"
    return $false
  }
  $script:nodeOwned = $true
  return (Wait-Node)
}

function Wait-Node {
  # The node is ready when it holds the gRPC port the miner dials. Waiting for the
  # port (up to 3 minutes) beats a blind sleep: on a slow PC the node needs a while.
  Write-Info 'Waiting for the node to be ready...'
  $deadline = (Get-Date).AddSeconds(180)
  while ((Get-Date) -lt $deadline) {
    if ($script:nodeOwned -and $script:node -and $script:node.HasExited) {
      Write-Host ''
      Write-Bad "The node stopped (exit code $($script:node.ExitCode))."
      $err = ''
      if (Test-Path -LiteralPath "$nodeLog.err") {
        $err = ((Get-Content -LiteralPath "$nodeLog.err" -ErrorAction SilentlyContinue) | Select-Object -Last 8) -join "`r`n"
      }
      if ($err.Trim()) { Write-Info $err }
      return $false
    }
    if (Test-PortOpen $grpcPort) {
      Write-Host ''
      Write-Ok "The node is ready (gRPC port $grpcPort)."
      return $true
    }
    Write-Host '.' -NoNewline
    Start-Sleep -Seconds 2
  }
  Write-Host ''
  Write-Warn "The node did not open port $grpcPort within 3 minutes."
  Write-Info 'Mining starts anyway; the miner keeps retrying on its own.'
  return $true
}

# ---------- step 4: the miner ----------
function Start-Miner {
  Write-Head 'Starting the miner'
  Write-Info '  zethora-miner.exe --testnet'
  try { Remove-Item -LiteralPath "$nodeLog.miner" -Force -ErrorAction SilentlyContinue } catch {}
  try {
    $script:miner = Start-Process -FilePath $minerExe -ArgumentList '--testnet' `
        -WorkingDirectory $here -WindowStyle Hidden `
        -RedirectStandardOutput "$nodeLog.miner" -RedirectStandardError "$nodeLog.miner.err" -PassThru
  } catch {
    Write-Bad "Couldn't start zethora-miner.exe: $($_.Exception.Message)"
    return $false
  }
  # Below-normal priority: full speed when the PC is idle, but your other apps first.
  try { $script:miner.PriorityClass = 'BelowNormal' } catch {}
  return $true
}

function Read-New($path, [ref]$pos) {
  # Reads only what was written since the last call, so each line is shown once.
  if (-not (Test-Path -LiteralPath $path)) { return @() }
  try {
    $fs = [IO.File]::Open($path, 'Open', 'Read', 'ReadWrite,Delete')
    if ($fs.Length -lt $pos.Value) { $pos.Value = 0 }
    $fs.Seek($pos.Value, 'Begin') | Out-Null
    $sr = New-Object IO.StreamReader($fs)
    $text = $sr.ReadToEnd()
    $pos.Value = $fs.Position
    $sr.Close()
    return ($text -split "`r?`n" | Where-Object { $_ -ne '' })
  } catch { return @() }
}

function Show-Line([string]$line) {
  # Plain log lines stay readable; a line that needs attention is coloured so it
  # is not lost in a wall of text.
  if ($line -match '(?i)not synced|warning|error|failed|cannot|can''t') {
    Write-Host "  $line" -ForegroundColor Yellow
  } elseif ($line -match '(?i)found|accepted|submitted|BALANCED') {
    Write-Host "  $line" -ForegroundColor Green
  } else {
    Write-Host "  $line" -ForegroundColor Gray
  }
}

# ---------- step 5: run, and keep the window open with the logs ----------
function Wait-Miner {
  $minerPos = [ref]0
  $errPos   = [ref]0
  Write-Head 'Mining'
  Write-Info 'Live log below. Press Ctrl+C to stop mining.'
  Write-Info 'Closing this window also stops the miner and the node XminerZ started.'
  Write-Host ''
  while ($true) {
    foreach ($line in (Read-New "$nodeLog.miner" $minerPos)) { Show-Line $line }
    foreach ($line in (Read-New "$nodeLog.miner.err" $errPos))  { Show-Line $line }
    if ($script:miner.HasExited) {
      $code = $script:miner.ExitCode
      Write-Host ''
      Write-Bad "The miner stopped (exit code $code)."
      switch ($code) {
        5 { Write-Info 'The mining key file is damaged. Restore it from your backup; the miner will not replace it.' }
        3 { Write-Info 'The address did not match the network prefix the miner expected.' }
        2 { Write-Info 'The miner refused an argument.' }
        4 { Write-Info 'The miner could not reach the node.' }
      }
      return
    }
    Start-Sleep -Milliseconds 400
  }
}

function Stop-All {
  # Only what this script started is stopped: a node the user had running, or
  # another miner, is left alone.
  if ($script:miner -and -not $script:miner.HasExited) {
    try { Stop-Process -Id $script:miner.Id -Force } catch {}
  }
  if ($script:nodeOwned -and $script:node -and -not $script:node.HasExited) {
    try { Stop-Process -Id $script:node.Id -Force } catch {}
  }
  try { Remove-Item -LiteralPath $walletOut -Force -ErrorAction SilentlyContinue } catch {}
}

function Main {
  Show-Banner
  if (-not (Test-Files)) { return 1 }

  Write-Head 'Your mining address'
  if (Test-Path -LiteralPath $keyFile) {
    $script:address = Read-KeyAddress
  } else {
    $script:address = New-KeyAndAddress
  }
  Show-Address $script:address
  Write-KeyReminder

  if (-not (Start-Node)) {
    Write-Bad 'The node could not be started, so mining cannot begin.'
    return 1
  }
  if (-not (Start-Miner)) {
    Write-Bad 'The miner could not be started.'
    return 1
  }
  Wait-Miner
  return 0
}

try {
  $code = Main
} catch {
  Write-Bad "Something went wrong: $($_.Exception.Message)"
  $code = 1
} finally {
  Stop-All
}

Write-Host ''
if ($script:miner -or $script:nodeOwned) {
  Write-Info "Logs: $nodeLog.miner   (node: $nodeLog)"
  Write-Ok 'Stopped. Your key file and your coins are kept.'
} else {
  Write-Info 'Nothing was started.'
}
Write-Host ''
exit $code
