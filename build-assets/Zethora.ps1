# ============================================================
#  Zethora (testnet) - one-window miner.
#  Plain text: open in Notepad to read exactly what it does.
#  It only runs zethora-node.exe, zethora-miner.exe and
#  zethora-wallet.exe from this folder. It downloads nothing
#  and changes no settings.
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
$walletExe = Join-Path $here 'zethora-wallet.exe'

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
$form.Text = 'Zethora - testnet miner'; $form.Size = New-Object Drawing.Size(720,630)
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

# ---------- wallet: receive and send ----------
# Both buttons run zethora-wallet.exe from this folder. The wallet reads the same
# key file the miner uses, so "receive" shows the address you are mining to.
# The process is started directly rather than with Start-Process: Start-Process
# leaves ExitCode empty here, which made every wallet call look like a failure.
# This way the one-minute guard still applies and the exit code is real.
function Invoke-Wallet([string[]]$walletArgs) {
  if (-not (Test-Path $walletExe)) {
    return @{ Code = -1; Text = "Can't find zethora-wallet.exe in this folder.`n`nUnzip the whole download into one folder (right-click the zip, Extract All) and open Zethora from inside that folder." }
  }
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $walletExe
  $psi.Arguments = (($walletArgs | ForEach-Object { if ($_ -match '\s') { '"' + $_ + '"' } else { $_ } }) -join ' ')
  $psi.WorkingDirectory = $here
  $psi.UseShellExecute = $false        # no extra console window in front of the app
  $psi.CreateNoWindow = $true
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError = $true
  $psi.StandardOutputEncoding = [System.Text.Encoding]::UTF8
  $psi.StandardErrorEncoding = [System.Text.Encoding]::UTF8
  try {
    $proc = [System.Diagnostics.Process]::Start($psi)
  } catch {
    return @{ Code = -3; Text = "Couldn't start zethora-wallet.exe.`n`n$($_.Exception.Message)" }
  }
  # Both pipes are drained while the wallet runs, so a full pipe can't stall it.
  $outTask = $proc.StandardOutput.ReadToEndAsync()
  $errTask = $proc.StandardError.ReadToEndAsync()
  if (-not $proc.WaitForExit(60000)) {
    try { $proc.Kill() } catch {}
    return @{ Code = -2; Text = 'The wallet did not answer within a minute. Try again.' }
  }
  $text = (@("$($outTask.Result)","$($errTask.Result)") -join "`r`n").Trim()
  return @{ Code = $proc.ExitCode; Text = $text }
}

# A small dark popup: selectable text plus a copy button, so an address or a
# transaction id can be copied without retyping it.
function Show-Popup([string]$title, [string]$body, [string]$copyText, [string]$copyLabel) {
  $d = New-Object Windows.Forms.Form
  $d.Text = $title; $d.Size = New-Object Drawing.Size(560,300)
  $d.BackColor = $bg; $d.ForeColor = $fg; $d.StartPosition = 'CenterParent'
  $d.FormBorderStyle = 'FixedDialog'; $d.MaximizeBox = $false; $d.MinimizeBox = $false
  $d.Font = New-Object Drawing.Font('Segoe UI',10)
  $box = New-Object Windows.Forms.TextBox
  $box.Multiline = $true; $box.ReadOnly = $true; $box.ScrollBars = 'Vertical'
  $box.BackColor = [Drawing.Color]::FromArgb(10,10,14); $box.ForeColor = $fg; $box.BorderStyle = 'None'
  $box.Font = New-Object Drawing.Font('Consolas',10)
  $box.Location = New-Object Drawing.Point(16,16); $box.Size = New-Object Drawing.Size(512,170)
  $box.Text = $body
  $d.Controls.Add($box)
  $close = New-Object Windows.Forms.Button; $close.Text = 'CLOSE'
  $close.Location = New-Object Drawing.Point(398,204); $close.Size = New-Object Drawing.Size(130,32)
  $close.FlatStyle = 'Flat'; $close.BackColor = $panel; $close.ForeColor = $fg
  $close.Add_Click({ $d.Close() })
  $d.Controls.Add($close); $d.AcceptButton = $close; $d.CancelButton = $close
  if ($copyText) {
    $copy = New-Object Windows.Forms.Button; $copy.Text = $copyLabel
    $copy.Location = New-Object Drawing.Point(16,204); $copy.Size = New-Object Drawing.Size(160,32)
    $copy.FlatStyle = 'Flat'; $copy.BackColor = $accent; $copy.ForeColor = [Drawing.Color]::White
    $copy.Add_Click({ try { Set-Clipboard -Value $copyText; $copy.Text = 'COPIED' } catch { $copy.Text = 'COPY FAILED' } })
    $d.Controls.Add($copy)
  }
  [void]$d.ShowDialog($form)
}

# Asks for a destination address and an amount. Puts the answer in
# $script:sendRequest when the user presses SEND.
function Show-SendDialog {
  $script:sendRequest = $null
  $d = New-Object Windows.Forms.Form
  $d.Text = 'Send ZTHR (testnet)'; $d.Size = New-Object Drawing.Size(580,340)
  $d.BackColor = $bg; $d.ForeColor = $fg; $d.StartPosition = 'CenterParent'
  $d.FormBorderStyle = 'FixedDialog'; $d.MaximizeBox = $false; $d.MinimizeBox = $false
  $d.Font = New-Object Drawing.Font('Segoe UI',10)

  $l1 = New-Object Windows.Forms.Label; $l1.Text = 'Send to this address (it starts with zethoratest:)'
  $l1.Location = New-Object Drawing.Point(16,14); $l1.Size = New-Object Drawing.Size(530,20); $l1.ForeColor = $dim
  $d.Controls.Add($l1)
  $toBox = New-Object Windows.Forms.TextBox
  $toBox.Location = New-Object Drawing.Point(16,38); $toBox.Size = New-Object Drawing.Size(530,26)
  $toBox.BackColor = $panel; $toBox.ForeColor = $fg; $toBox.Font = New-Object Drawing.Font('Consolas',10)
  $d.Controls.Add($toBox)

  $l2 = New-Object Windows.Forms.Label; $l2.Text = 'Amount in ZTHR (for example 1.5)'
  $l2.Location = New-Object Drawing.Point(16,74); $l2.Size = New-Object Drawing.Size(530,20); $l2.ForeColor = $dim
  $d.Controls.Add($l2)
  $amtBox = New-Object Windows.Forms.TextBox
  $amtBox.Location = New-Object Drawing.Point(16,98); $amtBox.Size = New-Object Drawing.Size(160,26)
  $amtBox.BackColor = $panel; $amtBox.ForeColor = $fg; $amtBox.Font = New-Object Drawing.Font('Consolas',10)
  $d.Controls.Add($amtBox)

  $note = New-Object Windows.Forms.Label
  $note.Text = 'Coins come from your key file and a send cannot be undone. Testnet coins have no value.'
  $note.Location = New-Object Drawing.Point(16,134); $note.Size = New-Object Drawing.Size(530,36); $note.ForeColor = $dim
  $note.Font = New-Object Drawing.Font('Segoe UI',9)
  $d.Controls.Add($note)

  $problem = New-Object Windows.Forms.Label
  $problem.Location = New-Object Drawing.Point(16,172); $problem.Size = New-Object Drawing.Size(530,36); $problem.ForeColor = $red
  $problem.Font = New-Object Drawing.Font('Segoe UI',9)
  $d.Controls.Add($problem)

  $go = New-Object Windows.Forms.Button; $go.Text = 'SEND'
  $go.Location = New-Object Drawing.Point(286,222); $go.Size = New-Object Drawing.Size(120,34)
  $go.FlatStyle = 'Flat'; $go.BackColor = $accent; $go.ForeColor = [Drawing.Color]::White
  $d.Controls.Add($go)
  $cancel = New-Object Windows.Forms.Button; $cancel.Text = 'CANCEL'
  $cancel.Location = New-Object Drawing.Point(416,222); $cancel.Size = New-Object Drawing.Size(120,34)
  $cancel.FlatStyle = 'Flat'; $cancel.BackColor = $panel; $cancel.ForeColor = $fg
  $cancel.Add_Click({ $d.Close() })
  $d.Controls.Add($cancel); $d.CancelButton = $cancel

  $go.Add_Click({
    $to = $toBox.Text.Trim(); $amount = $amtBox.Text.Trim()
    if (-not $to) { $problem.Text = 'Type the address you are sending to.'; return }
    if ($to -notmatch '^zethoratest:[a-z0-9]+$') { $problem.Text = 'That is not a Zethora testnet address (it starts with zethoratest:).'; return }
    if ($amount -notmatch '^[0-9]+(\.[0-9]{1,9})?$') { $problem.Text = 'Type an amount like 1.5 - digits and a dot only, no commas, no spaces.'; return }
    if ($amount -notmatch '[1-9]') { $problem.Text = 'The amount has to be more than zero.'; return }
    $script:sendRequest = @{ To = $to; Amount = $amount }
    $d.Close()
  })
  [void]$d.ShowDialog($form)
}

# wallet buttons: the two things a miner needs besides mining
$recvBtn = New-Object Windows.Forms.Button; $recvBtn.Text = 'RECEIVE'
$recvBtn.Location = New-Object Drawing.Point(24,532); $recvBtn.Size = New-Object Drawing.Size(210,44)
$recvBtn.FlatStyle = 'Flat'; $recvBtn.BackColor = $panel; $recvBtn.ForeColor = $fg
$recvBtn.Font = New-Object Drawing.Font('Segoe UI',11,[Drawing.FontStyle]::Bold)
$form.Controls.Add($recvBtn)

$sendBtn = New-Object Windows.Forms.Button; $sendBtn.Text = 'SEND ZTHR'
$sendBtn.Location = New-Object Drawing.Point(246,532); $sendBtn.Size = New-Object Drawing.Size(210,44)
$sendBtn.FlatStyle = 'Flat'; $sendBtn.BackColor = $accent; $sendBtn.ForeColor = [Drawing.Color]::White
$sendBtn.Font = New-Object Drawing.Font('Segoe UI',11,[Drawing.FontStyle]::Bold)
$form.Controls.Add($sendBtn)

New-Label 'Receive shows the address people send coins to. Send spends from the same key file.' 470 532 210 44 9 $false $dim | Out-Null

$recvBtn.Add_Click({
  $r = Invoke-Wallet @('receive','--testnet')
  # The wallet prints the address on its own line, indented by four spaces, so
  # the text is trimmed and the pattern is not anchored to the start of a line:
  # indentation must never be able to hide the address.
  $m = [regex]::Match(([string]$r.Text).Trim(), 'zethoratest:[a-z0-9]+')
  if (-not $m.Success) {
    Add-Log "Receive failed (exit $($r.Code)). $($r.Text)"
    [Windows.Forms.MessageBox]::Show("Couldn't read your address.`n`n$($r.Text)",'Receive') | Out-Null
    return
  }
  $myAddr = $m.Value
  $addr.Text = "Address: $myAddr"
  Add-Log "Your address: $myAddr"
  Show-Popup 'Receive ZTHR' "Your Zethora testnet address:`r`n`r`n$myAddr`r`n`r`nGive this to whoever sends you coins. It comes from your key file and never changes." $myAddr 'COPY ADDRESS'
})

$sendBtn.Add_Click({
  Show-SendDialog
  if (-not $script:sendRequest) { return }
  $to = $script:sendRequest.To; $amount = $script:sendRequest.Amount
  if (-not $script:node) {
    Add-Log 'Send: start mining first, so the node can say which coins you can spend.'
    [Windows.Forms.MessageBox]::Show("Start mining first.`n`nThe wallet asks your own node which coins you can spend, so zethora-node.exe has to be running. Press START MINING, wait a few seconds, then press SEND ZTHR again.",'Send ZTHR') | Out-Null
    return
  }
  $answer = [Windows.Forms.MessageBox]::Show("Send $amount ZTHR to`n`n$to`n`nA send cannot be undone. Continue?",'Send ZTHR',[Windows.Forms.MessageBoxButtons]::YesNo,[Windows.Forms.MessageBoxIcon]::Question)
  if ($answer -ne 'Yes') { return }
  Add-Log "Sending $amount ZTHR to $to..."
  $r = Invoke-Wallet @('send', $to, $amount, '--testnet')
  if ($r.Code -ne 0) {
    Add-Log "Send failed. $($r.Text)"
    [Windows.Forms.MessageBox]::Show("The send did not go through.`n`n$($r.Text)",'Send ZTHR') | Out-Null
    return
  }
  $m = [regex]::Match($r.Text, 'Sent\. Transaction id:\s*(\S+)')
  if (-not $m.Success) { $m = [regex]::Match($r.Text, 'Txid\s*:\s*(\S+)') }
  if (-not $m.Success) {
    Add-Log 'Sent, but the wallet printed no transaction id.'
    Show-Popup 'Send ZTHR' "The wallet says it sent the coins but printed no transaction id.`r`n`r`n$($r.Text)" '' ''
    return
  }
  $txid = $m.Groups[1].Value
  Add-Log "Sent. Transaction id: $txid"
  $script:balDue = (Get-Date)   # ask the node for the new balance on the next tick
  Show-Popup 'Send ZTHR' "Sent $amount ZTHR.`r`n`r`nTransaction id:`r`n$txid`r`n`r`nIt shows in your balance after one confirmation (a few seconds on testnet)." $txid 'COPY ID'
})

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
      if ($l -match 'Block #(\d+)') { $tiles['Blocks found'].Text = $matches[1]; $script:balDue = (Get-Date).AddSeconds(1) }
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
      if ($out -match 'Balance:\s+([\d\.]+)\s+ZTHR') { $tiles['Balance'].Text = ('{0:N4}' -f [double]$matches[1]) }
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
[void]$form.ShowDialog()
