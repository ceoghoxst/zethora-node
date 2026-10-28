Zethora testnet - Windows package
=================================

This zip contains two programs, a one-window app, two launch scripts and supporting files.

  zethora-node.exe          the Zethora node
  zethora-miner.exe         the CPU miner
  README.txt                this file
  SHA256SUMS.txt            checksums for verification
  LICENSE.txt               ISC License (Zethora inherits it from Kaspa)
  THIRD-PARTY-NOTICES.txt   licenses for bundled components
  THIRD-PARTY-CRATES.txt    licenses of every Rust library compiled in
  Zethora.cmd               double-click: one-window miner app
  Zethora.ps1               the app itself (readable text)
  Start-Zethora.cmd         double-click to start node + miner
  Stop-Zethora.cmd          double-click to stop them

SYSTEM REQUIREMENTS

- 64-bit Windows 10 or 11.
- Memory: the miner needs about 2.5 GB free, on top of Windows and the
  node. With less, Windows swaps to disk and mining nearly stops.
  8 GB total is the practical minimum; 16 GB recommended.
- Speed grows with CPU cores and cache. Measured:
    Ryzen 5 2600, 16 GB:            about 1,200 H/s on 12 threads
    Athlon Silver 3050U, 5.9 GB:    1-2 H/s (not enough free memory)

VERIFY THE DOWNLOAD

In PowerShell, run:
  Get-FileHash zethora-node.exe -Algorithm SHA256
  Get-FileHash zethora-miner.exe -Algorithm SHA256

Compare each hash to the corresponding line in SHA256SUMS.txt.
Comparison ignores case. If any hash does not match, do not run the
binary. Delete the zip and report the URL you downloaded from to
https://github.com/ceoghoxst/zethora-node/issues.

WINDOWS SMARTSCREEN

The binaries are unsigned. Windows will show "Windows protected your
PC" the first time you run zethora-node.exe or zethora-miner.exe.
Click "More info" and then "Run anyway". The SHA256 check above is how
you know the binary is the one we published.

EASIEST WAY TO START

Double-click Zethora.cmd. One window opens: click START MINING.
It shows your status, speed, blocks found, balance and the supply
check (it must say BALANCED). Click STOP MINING or close the window
to stop. Zethora.ps1 is the program behind it: plain text, open it
in Notepad to read exactly what it does.

Prefer separate windows? Start-Zethora.cmd and Stop-Zethora.cmd do
the same with the node and miner in their own windows.

GETTING STARTED

A testnet setup guide will be published when testnet opens.

Testnet is not open yet. Do not expect to connect to a live network.

SEE YOUR BALANCE

The miner prints an address starting with zethoratest: when it
starts. That address holds everything you mine. The miner window
also shows a running total of what it has mined this session.

To see the balance of that address, keep the node running (it must
be started with --utxoindex) and, in a second PowerShell window in
this folder, run:

  .\zethora-miner.exe --testnet balance

New rewards show up after the next block and can be spent only after
they mature.

WHAT THIS PACKAGE DOES NOT DO

- Does not mine on mainnet. Mainnet is not launched.
- Does not enable private transactions. This build refuses all private
  payments. A later testnet release turns them on as an experimental,
  unreviewed feature; mainnet keeps them off until an independent review.
- Does not contain a wallet for sending coins. The miner can show your
  balance (see SEE YOUR BALANCE above).
- Does not promise coins, returns, or income. There is no token.

Maintained by DeionRaven (Deion Smith). DeionRaven Labs is a project
name, not a registered company.