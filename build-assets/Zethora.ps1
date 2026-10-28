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
$script:balDue = [datetime]::MinValue
$script:restarts = 0

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
$addr = New-Label 'Address: (shown after start)' 24 218 500 22 9 $false $dim

$log = New-Object Windows.Forms.TextBox; $log.Multiline = $true; $log.ReadOnly = $true
$log.ScrollBars = 'Vertical'; $log.BackColor = [Drawing.Color]::FromArgb(10,10,14); $log.ForeColor = $dim
$log.Font = New-Object Drawing.Font('Consolas',9); $log.BorderStyle = 'None'
$log.Location = New-Object Drawing.Point(24,248); $log.Size = New-Object Drawing.Size(656,220)
$form.Controls.Add($log)

New-Label 'Your key file holds your rewards. Back it up (USB or a second drive). Never share it.' 24 482 470 40 9 $false $dim | Out-Null
$keyBtn = New-Object Windows.Forms.Button; $keyBtn.Text = 'BACK UP MY KEY'
$keyBtn.Location = New-Object Drawing.Point(510,476); $keyBtn.Size = New-Object Drawing.Size(170,32)
$keyBtn.FlatStyle = 'Flat'; $keyBtn.ForeColor = $fg; $keyBtn.BackColor = $panel
$form.Controls.Add($keyBtn)
$keyBtn.Add_Click({
  $k = Join-Path $here 'zethora-miner-key-testnet.txt'
  if (Test-Path $k) {
    [Windows.Forms.MessageBox]::Show("File Explorer will open with your key file selected.`n`nCopy it to a USB stick or another safe place. Anyone with this file can take your coins. If you lose it, your coins are gone.",'Back up your key') | Out-Null
    Start-Process explorer.exe "/select,`"$k`""
  } else {
    [Windows.Forms.MessageBox]::Show('No key file yet. It is created the first time you start mining.','Back up your key') | Out-Null
  }
})

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
  # Below-normal priority: full speed when the PC is idle, but your other apps always come first.
  try { $script:miner.PriorityClass = 'BelowNormal' } catch {}
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

$btn.Add_Click({ if ($script:node) { Stop-All } else { $script:restarts = 0; Start-All } })

$timer = New-Object Windows.Forms.Timer; $timer.Interval = 1000
$timer.Add_Tick({
  if (-not $script:node) { return }
  if ($script:node.HasExited) {
    $script:restarts++
    if ($script:restarts -gt 3) { Add-Log 'The node keeps stopping. See node.log and send it to us.'; Stop-All; return }
    Add-Log "The node stopped unexpectedly. Restarting it ($($script:restarts) of 3)..."
    foreach ($p in @($script:miner,$script:bal)) { if ($p -and -not $p.HasExited) { try { Stop-Process -Id $p.Id -Force } catch {} } }
    $script:bal = $null; Copy-Item $nodeLog (Join-Path $here 'node-crash.log') -Force -ErrorAction SilentlyContinue; Start-All; return
  }
  $age = ((Get-Date) - $script:startedAt).TotalSeconds
  if (-not $script:miner -and $age -ge 20) { Start-Miner }
  if ($script:miner) {
    if ($script:miner.HasExited) {
      $script:restarts++
      if ($script:restarts -gt 3) { Add-Log 'The miner keeps stopping. See miner.log and send it to us.'; Stop-All; return }
      Add-Log "The miner stopped unexpectedly. Restarting it ($($script:restarts) of 3)..."
      Copy-Item $minerLog (Join-Path $here 'miner-crash.log') -Force -ErrorAction SilentlyContinue; Start-Miner; return
    }
    $pos = $script:minerPos; $lines = Read-New $minerLog ([ref]$pos); $script:minerPos = $pos
    foreach ($l in $lines) {
      Add-Log $l
      if ($l -match 'Paying rewards to:\s+(\S+)') { $addr.Text = "Address: $($matches[1])" }
      if ($l -match 'Preparing') { $tiles['Status'].Text = 'Preparing' }
      if ($l -match '([\d,\.]+)\s*H/s') { $tiles['Speed'].Text = "$($matches[1]) H/s"; if (-not $script:unbalanced) { $tiles['Status'].Text = 'Mining'; $tiles['Status'].ForeColor = $green } }
      if ($l -match 'Block #(\d+)') { $tiles['Blocks found'].Text = $matches[1]; $script:balDue = (Get-Date).AddSeconds(1); $script:breakT = 10 }
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
    # balance: 1 s after each block found, else every 10 s (one tiny local query to your own node, no mining cost)
    if ($script:bal -and $script:bal.HasExited) {
      $out = Get-Content $balLog -Raw -ErrorAction SilentlyContinue
      if ($out -match 'Balance:\s+([\d\.]+)\s+ZTHR') { $script:balVal = [double]$matches[1]; $tiles['Balance'].Text = ('{0:N4}' -f $script:balVal) }
      $script:bal = $null
    }
    if (-not $script:bal -and $age -ge 25 -and (((Get-Date) -ge $script:balDue -and $script:balDue -gt $script:lastBal) -or ((Get-Date) - $script:lastBal).TotalSeconds -ge 10)) {
      $script:lastBal = Get-Date
      $script:bal = Start-Process -FilePath $minerExe -ArgumentList '--testnet','balance' `
          -WorkingDirectory $here -WindowStyle Hidden -RedirectStandardOutput $balLog -RedirectStandardError "$balLog.err" -PassThru
    }
  }
})
$timer.Start()

$form.Add_FormClosing({ $timer.Stop(); Stop-All })
# ---------- optional idle adventure (OFF by default; cosmetic only) ----------
# The picture only reflects what you mined: it never changes rewards. It is drawn
# about 8 times a second on a small image and pauses when hidden or minimized,
# so the miner keeps the CPU. Pickaxe tier follows your balance.
$chk = New-Object Windows.Forms.CheckBox; $chk.Text = 'Show adventure'; $chk.Checked = $false
$chk.ForeColor = $dim; $chk.Location = New-Object Drawing.Point(540,216); $chk.Size = New-Object Drawing.Size(140,24)
$form.Controls.Add($chk)
$game = New-Object Windows.Forms.PictureBox; $game.Location = $log.Location; $game.Size = $log.Size
$game.BackColor = [Drawing.Color]::FromArgb(10,10,14); $game.Visible = $false
$form.Controls.Add($game)
$script:frame = 0; $script:breakT = 0; $script:balVal = 0.0; $script:rng = New-Object Random
$tiers = @(
  @{ Name='Wood';    Min=0;    Color=[Drawing.Color]::FromArgb(150,100,55) },
  @{ Name='Stone';   Min=10;   Color=[Drawing.Color]::FromArgb(140,140,150) },
  @{ Name='Iron';    Min=100;  Color=[Drawing.Color]::FromArgb(205,205,215) },
  @{ Name='Gold';    Min=500;  Color=[Drawing.Color]::FromArgb(240,195,60) },
  @{ Name='Diamond'; Min=2000; Color=[Drawing.Color]::FromArgb(90,230,240) })
function Get-Tier { $t = 0; for ($i = 0; $i -lt $tiers.Count; $i++) { if ($script:balVal -ge $tiers[$i].Min) { $t = $i } }; return $t }
function Draw-Game {
  $w = $game.Width; $h = $game.Height
  $bmp = New-Object Drawing.Bitmap $w, $h
  $g = [Drawing.Graphics]::FromImage($bmp)
  $g.SmoothingMode = 'AntiAlias'
  $g.Clear([Drawing.Color]::FromArgb(16,14,24))
  $ground = $h - 40
  $g.FillRectangle((New-Object Drawing.SolidBrush ([Drawing.Color]::FromArgb(40,34,50))), 0, $ground, $w, 40)
  $t = Get-Tier; $tier = $tiers[$t]
  # ore wall
  $oreCol = $tiers[[Math]::Min($t + 1, $tiers.Count - 1)].Color
  for ($i = 0; $i -lt 3; $i++) { for ($j = 0; $j -lt 3; $j++) {
    $x = $w - 230 + $i * 62; $y = $ground - 186 + $j * 62
    if ($script:breakT -gt 0 -and $i -eq 0 -and $j -eq 2) { continue }
    $g.FillRectangle((New-Object Drawing.SolidBrush ([Drawing.Color]::FromArgb(70,64,80))), $x, $y, 60, 60)
    $g.FillEllipse((New-Object Drawing.SolidBrush $oreCol), $x + 18, $y + 18, 14, 14)
    $g.FillEllipse((New-Object Drawing.SolidBrush $oreCol), $x + 34, $y + 30, 10, 10) } }
  # miner
  $mx = $w - 330; $my = $ground - 90
  $g.FillEllipse((New-Object Drawing.SolidBrush ([Drawing.Color]::FromArgb(230,190,150))), $mx + 8, $my, 28, 28)
  $g.FillRectangle((New-Object Drawing.SolidBrush $accent), $mx + 6, $my + 28, 32, 40)
  $g.FillRectangle((New-Object Drawing.SolidBrush ([Drawing.Color]::FromArgb(60,60,80))), $mx + 8, $my + 68, 12, 22)
  $g.FillRectangle((New-Object Drawing.SolidBrush ([Drawing.Color]::FromArgb(60,60,80))), $mx + 24, $my + 68, 12, 22)
  # pickaxe swing
  $mining = ($script:miner -ne $null)
  $ang = if ($mining) { -60 + 70 * [Math]::Abs([Math]::Sin($script:frame * 0.45)) } else { -60 }
  $state = $g.Save(); $g.TranslateTransform($mx + 36, $my + 36); $g.RotateTransform($ang)
  $g.FillRectangle((New-Object Drawing.SolidBrush ([Drawing.Color]::FromArgb(120,80,40))), 0, -3, 56, 6)
  $g.FillRectangle((New-Object Drawing.SolidBrush $tier.Color), 50, -16, 10, 32)
  $g.Restore($state)
  # sparks when a block is found
  if ($script:breakT -gt 0) {
    for ($k = 0; $k -lt 14; $k++) {
      $sx = $w - 230 + 30 + $script:rng.Next(-40, 40); $sy = $ground - 64 + 30 + $script:rng.Next(-40, 40)
      $g.FillEllipse((New-Object Drawing.SolidBrush ([Drawing.Color]::FromArgb(255,220,90))), $sx, $sy, 5, 5) }
    $g.DrawString('BLOCK FOUND!', (New-Object Drawing.Font('Segoe UI',14,[Drawing.FontStyle]::Bold)), (New-Object Drawing.SolidBrush $green), $w - 250, 8)
    $script:breakT-- }
  $next = if ($t -lt $tiers.Count - 1) { "next: $($tiers[$t+1].Name) at $($tiers[$t+1].Min) ZTHR" } else { 'max tier' }
  $g.DrawString("Pickaxe: $($tier.Name)  ($next)", (New-Object Drawing.Font('Segoe UI',10)), (New-Object Drawing.SolidBrush $fg), 10, 8)
  $g.DrawString('Just for fun: the picture never changes your rewards.', (New-Object Drawing.Font('Segoe UI',8)), (New-Object Drawing.SolidBrush $dim), 10, $h - 22)
  $g.Dispose()
  $old = $game.Image; $game.Image = $bmp; if ($old) { $old.Dispose() }
  $script:frame++
}
$gameTimer = New-Object Windows.Forms.Timer; $gameTimer.Interval = 125
$gameTimer.Add_Tick({ Draw-Game })
function Update-GameRun {
  $on = $chk.Checked -and $form.WindowState -ne 'Minimized'
  $game.Visible = $chk.Checked; $log.Visible = -not $chk.Checked
  if ($on) { $gameTimer.Start() } else { $gameTimer.Stop() }
}
$chk.Add_CheckedChanged({ Update-GameRun })
$form.Add_Resize({ Update-GameRun })
$form.Add_FormClosing({ $gameTimer.Stop() })

[void]$form.ShowDialog()
