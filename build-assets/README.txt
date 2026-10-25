Zethora testnet - Windows package
=================================

This zip contains two programs and supporting files.

  zethora-node.exe          the Zethora node
  zethora-miner.exe         the CPU miner
  README.txt                this file
  SHA256SUMS.txt            checksums for verification
  LICENSE.txt               ISC License (Zethora inherits it from Kaspa)
  THIRD-PARTY-NOTICES.txt   licenses for bundled components

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

GETTING STARTED

A testnet setup guide will be published when testnet opens.

Testnet is not open yet. Do not expect to connect to a live network.

SEE YOUR BALANCE

The miner prints an address starting with zethoratest: when it
starts. That address holds everything you mine. The miner window
also shows a running total of what it has mined this session.
Balance viewing will be documented when testnet opens.

WHAT THIS PACKAGE DOES NOT DO

- Does not mine on mainnet. Mainnet is not launched.
- Does not enable private transactions. All private payments are
  disabled on testnet and mainnet until an external review is complete.
- Does not contain a wallet. Balance viewing will be documented when
  testnet opens.
- Does not promise coins, returns, or income. There is no token.

Maintained by DeionRaven (Deion Smith). DeionRaven Labs is a project
name, not a registered company.