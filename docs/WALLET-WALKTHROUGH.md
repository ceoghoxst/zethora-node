# Wallet and Privacy on Zethora Devnet

Devnet is a private test network for the Zethora team. It is not public, coins have no value, and nothing carries over to testnet or mainnet. No token exists.

All private payments, including shielding, are switched off on testnet and mainnet in today's builds. Testnet will enable them as an experimental, unreviewed feature after the current hardening; mainnet keeps them off until an outside review. This document describes the devnet tool only.

Zethora uses Zcash's Orchard 0.16.0 for privacy. On the devnet, private sending is fully enabled.

The wallet tool is a command-line interface that connects to your running node.

## Prerequisites

- Your node (`kaspad`) must be running with `--utxoindex` and `--enable-unsynced-mining`.

## Check your balance

Open a new PowerShell window and run:

    cd $env:USERPROFILE\zethora-node
    .\target\release\zethora-shield.exe balance

This shows your transparent (visible) balance and your private (shielded) balance.

## Move coins into the private pool (Shielding)

To move coins from your visible balance into the private pool:

    .\target\release\zethora-shield.exe 0.1

This moves 0.1 ZTHR into the shielded pool. Your total balance stays the same, but 0.1 ZTHR is now private.

## Send a private payment

To send 0.05 ZTHR privately (the recipient will not be able to see your balance or the amount, only that a transaction happened):

    .\target\release\zethora-shield.exe send 0.05

## Move coins out of the private pool (Unshielding)

To move coins back from the private pool to the public, visible state:

    .\target\release\zethora-shield.exe unshield 0.05

## Run an attack test (Devnet only)

To verify the double-spend and counterfeiting protections are active:

    .\target\release\zethora-shield.exe attack

This should print that the attack was blocked.

## What to expect

Private transactions use zk-SNARKs. On a slow CPU, generating the proof for a private transaction can take a few seconds.