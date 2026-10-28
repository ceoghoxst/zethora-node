# ============================================================
#  Zethora (testnet) - one-window miner.
#  Plain text: open in Notepad to read exactly what it does.
#  It only runs zethora-node.exe and zethora-miner.exe from
#  this folder. It downloads nothing and changes no settings.
#  Logs: node.log and miner.log in this folder.
# ============================================================
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
$ErrorActionPreference = 'Continue'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $here

$nodeExe  = Join-Path $here 'zethora-node.exe'
$minerExe = Join-Path $here 'zethora-miner.exe'
$nodeLog  = Join-Path $here 'node.log'
$minerLog = Join-Path $here 'miner.log'
$balLog   = Join-Path $here 'balance.log'

$script:node = $null; $script:miner = $null; $script:bal = $null
$script:minerPos = 0; $script:startedAt = $null; $script:lastBal = [datetime]::MinValue
$script:unbalanced = $false

# ---------- look ----------
$bg = [Drawing.Color]::FromArgb(18,18,24); $panel = [Drawing.Color]::FromArgb(30,30,40)
$fg = [Drawing.Color]::FromArgb(235,235,240); $dim = [Drawing.Color]::FromArgb(150,150,165)
$green = [Drawing.Color]::FromArgb(70,210,120); $red = [Drawing.Color]::FromArgb(235,80,80)
$accent = [Drawing.Color]::FromArgb(140,110,255)

$form = New-Object Windows.Forms.Form
$form.Text = 'Zethora - testnet miner'; $form.Size = New-Object Drawing.Size(720,560)
$form.BackColor = $bg; $form.ForeColor = $fg; $form.StartPosition = 'CenterScreen'
$form.FormBorderStyle = 'FixedSingle'; $form.MaximizeBox = $false
$form.Font = New-Object Drawing.Font('Segoe UI',10)

function New-Label($text,$x,$y,$w,$h,$size,$bold,$color) {
  $l = New-Object Windows.Forms.Label; $l.Text = $text
  $l.Location = New-Object Drawing.Point($x,$y); $l.Size = New-Object Drawing.Size($w,$h)
  $style = if ($bold) { [Drawing.FontStyle]::Bold } else { [Drawing.FontStyle]::Regular }
  $l.Font = New-Object Drawing.Font('Segoe UI',$size,$style); $l.ForeColor = $color
  $form.Controls.Add($l); return $l
}

New-Label 'ZETHORA' 24 16 300 40 22 $true $accent | Out-Null
New-Label 'testnet - coins have no value' 26 54 400 22 9 $false $dim | Out-Null

$btn = New-Object Windows.Forms.Button; $btn.Text = 'START MINING'
$btn.Location = New-Object Drawing.Point(470,22); $btn.Size = New-Object Drawing.Size(210,52)
$btn.FlatStyle = 'Flat'; $btn.BackColor = $accent; $btn.ForeColor = [Drawing.Color]::White
$btn.Font = New-Object Drawing.Font('Segoe UI',12,[Drawing.FontStyle]::Bold)
$form.Controls.Add($btn)

# stat tiles
$tiles = @{}
$defs = @(@('Status','Stopped',24),@('Speed','-',190),@('Blocks found','0',356),@('Balance','-',522))
foreach ($d in $defs) {
  $p = New-Object Windows.Forms.Panel; $p.BackColor = $panel
  $p.Location = New-Object Drawing.Point($d[2],96); $p.Size = New-Object Drawing.Size(158,78)
  $form.Controls.Add($p)
  $t = New-Object Windows.Forms.Label; $t.Text = $d[0]; $t.ForeColor = $dim
  $t.Location = New-Object Drawing.Point(10,8); $t.Size = New-Object Drawing.Size(140,20); $p.Controls.Add($t)
  $v = New-Object Windows.Forms.Label; $v.Text = $d[1]; $v.ForeColor = $fg
  $v.Font = New-Object Drawing.Font('Segoe UI',14,[Drawing.FontStyle]::Bold)
  $v.Location = New-Object Drawing.Point(10,32); $v.Size = New-Object Drawing.Size(145,34); $p.Controls.Add($v)
  $tiles[$d[0]] = $v
}

$supply = New-Label 'Supply check: waiting for first block' 24 188 656 26 11 $true $dim
$addr = New-Label 'Address: (shown after start)' 24 218 656 22 9 $false $dim

$log = New-Object Windows.Forms.TextBox; $log.Multiline = $true; $log.ReadOnly = $true
$log.ScrollBars = 'Vertical'; $log.BackColor = [Drawing.Color]::FromArgb(10,10,14); $log.ForeColor = $dim
$log.Font = New-Object Drawing.Font('Consolas',9); $log.BorderStyle = 'None'
$log.Location = New-Object Drawing.Point(24,248); $log.Size = New-Object Drawing.Size(656,220)
$form.Controls.Add($log)

New-Label 'Keep zethora-miner-key-testnet.txt in this folder: it holds your rewards. Never share it.' 24 478 656 40 9 $false $dim | Out-Null

function Add-Log($s) {
  $log.AppendText("$s`r`n")
  if ($log.Lines.Length -gt 400) { $log.Lines = $log.Lines[-300..-1]; $log.SelectionStart = $log.Text.Length; $log.ScrollToCaret() }
}

function Start-All {
  if (-not (Test-Path $nodeExe) -or -not (Test-Path $minerExe)) {
    [Windows.Forms.MessageBox]::Show("Can't find zethora-node.exe or zethora-miner.exe.`n`nUnzip the whole download into one folder (right-click the zip, Extract All), then open Zethora from inside that folder.",'Zethora') | Out-Null
    return
  }
  $script:unbalanced = $false
  $supply.Text = 'Supply check: waiting for first block'; $supply.ForeColor = $dim
  $tiles['Status'].Text = 'Starting'; $tiles['Status'].ForeColor = $fg
  Add-Log 'Starting node...'
  $script:node = Start-Process -FilePath $nodeExe -ArgumentList '--testnet','--utxoindex','--enable-unsynced-mining' `
      -WorkingDirectory $here -WindowStyle Hidden -RedirectStandardOutput $nodeLog -RedirectStandardError "$nodeLog.err" -PassThru
  $script:startedAt = Get-Date; $script:miner = $null; $script:minerPos = 0
  $btn.Text = 'STOP MINING'; $btn.BackColor = $red
}

function Start-Miner {
  Add-Log 'Starting miner...'
  $script:miner = Start-Process -FilePath $minerExe -ArgumentList '--testnet' `
      -WorkingDirectory $here -WindowStyle Hidden -RedirectStandardOutput $minerLog -RedirectStandardError "$minerLog.err" -PassThru
  $script:minerPos = 0
}

function Stop-All {
  foreach ($p in @($script:miner,$script:node,$script:bal)) {
    if ($p -and -not $p.HasExited) { try { Stop-Process -Id $p.Id -Force } catch {} }
  }
  $script:miner = $null; $script:node = $null; $script:bal = $null; $script:startedAt = $null
  $tiles['Status'].Text = 'Stopped'; $tiles['Status'].ForeColor = $fg; $tiles['Speed'].Text = '-'
  $btn.Text = 'START MINING'; $btn.BackColor = $accent
  Add-Log 'Stopped. Your key file and rewards are kept.'
}

function Read-New($path,[ref]$pos) {
  if (-not (Test-Path $path)) { return @() }
  try {
    $fs = [IO.File]::Open($path,'Open','Read','ReadWrite,Delete')
    if ($fs.Length -lt $pos.Value) { $pos.Value = 0 }
    $fs.Seek($pos.Value,'Begin') | Out-Null
    $sr = New-Object IO.StreamReader($fs); $text = $sr.ReadToEnd(); $pos.Value = $fs.Position; $sr.Close()
    return ($text -split "`r?`n" | Where-Object { $_ -ne '' })
  } catch { return @() }
}

$btn.Add_Click({ if ($script:node) { Stop-All } else { Start-All } })

$timer = New-Object Windows.Forms.Timer; $timer.Interval = 1000
$timer.Add_Tick({
  if (-not $script:node) { return }
  if ($script:node.HasExited) { Add-Log 'The node stopped unexpectedly. See node.log.'; Stop-All; return }
  $age = ((Get-Date) - $script:startedAt).TotalSeconds
  if (-not $script:miner -and $age -ge 20) { Start-Miner }
  if ($script:miner) {
    if ($script:miner.HasExited) { Add-Log 'The miner stopped unexpectedly. See miner.log.'; Stop-All; return }
    $pos = $script:minerPos; $lines = Read-New $minerLog ([ref]$pos); $script:minerPos = $pos
    foreach ($l in $lines) {
      Add-Log $l
      if ($l -match 'Paying rewards to:\s+(\S+)') { $addr.Text = "Address: $($matches[1])" }
      if ($l -match 'Preparing') { $tiles['Status'].Text = 'Preparing' }
      if ($l -match '([\d,\.]+)\s*H/s') { $tiles['Speed'].Text = "$($matches[1]) H/s"; if (-not $script:unbalanced) { $tiles['Status'].Text = 'Mining'; $tiles['Status'].ForeColor = $green } }
      if ($l -match 'Block #(\d+)') { $tiles['Blocks found'].Text = $matches[1] }
      if ($l -match 'Supply check') {
        if ($l -match 'BALANCED') {
          if (-not $script:unbalanced) { $supply.Text = 'Supply check: BALANCED  (no coins created out of thin air)'; $supply.ForeColor = $green }
        } else {
          $script:unbalanced = $true
          $supply.Text = 'Supply check FAILED - stop mining and send a screenshot'; $supply.ForeColor = $red
          $tiles['Status'].Text = 'Problem'; $tiles['Status'].ForeColor = $red
        }
      }
    }
    # balance every 60 seconds, without freezing the window
    if ($script:bal -and $script:bal.HasExited) {
      $out = Get-Content $balLog -Raw -ErrorAction SilentlyContinue
      if ($out -match 'Balance:\s+([\d\.]+)\s+ZTHR') { $tiles['Balance'].Text = ('{0:N4}' -f [double]$matches[1]) }
      $script:bal = $null
    }
    if (-not $script:bal -and $age -ge 60 -and ((Get-Date) - $script:lastBal).TotalSeconds -ge 60) {
      $script:lastBal = Get-Date
      $script:bal = Start-Process -FilePath $minerExe -ArgumentList '--testnet','balance' `
          -WorkingDirectory $here -WindowStyle Hidden -RedirectStandardOutput $balLog -RedirectStandardError "$balLog.err" -PassThru
    }
  }
})
$timer.Start()

$form.Add_FormClosing({ $timer.Stop(); Stop-All })
[void]$form.ShowDialog()
