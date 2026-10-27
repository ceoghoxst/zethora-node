# Zethora Testnet - Getting Started

This guide helps you run a Zethora node and miner on a Windows PC.

**Please read this first:**
* Zethora is on a test network (testnet).
* **Testnet coins have no value.** They are not worth money and cannot be sold.
* Private payments are switched off. You cannot shield, send privately, or unshield on testnet.

You do not need to know how to code. You only download a file and paste a few commands.

## What you need
* A Windows 10 or 11 PC.
* At least 8 GB of memory (16 GB recommended). The miner uses about 2.5 GB.
* An internet connection.

---

## Step 1: Download and unzip

1. In your web browser, go to: https://github.com/ceoghoxst/zethora-node/releases
2. Find the newest testnet release and download the file ending in `.zip`.
3. Right-click the downloaded file and choose **Extract All...**, then click **Extract**.
4. Open the new folder. You should see `zethora-node.exe` and `zethora-miner.exe`.

---

## Step 2: Check the files (recommended)

1. Inside the extracted folder, click the address bar at the very top of the window (where the folder path is).
2. Type `powershell` and press **Enter**. A blue PowerShell window opens in this folder.
3. Paste this command and press **Enter**:

```powershell
Get-FileHash .\zethora-node.exe, .\zethora-miner.exe -Algorithm SHA256
```

4. It prints two long fingerprints. In the folder, open `SHA256SUMS.txt` with Notepad.
5. Each fingerprint must match the line for the same file name (upper/lower case does not matter). If one does not match, stop and do not run the programs.

---

## Step 3: Start the node

Keep using the same PowerShell window from Step 2.

The first time you run it, Windows may show a blue **"Windows protected your PC"** screen: click **More info**, then **Run anyway**. If Windows asks about the firewall, click **Allow access**.

Paste this command and press **Enter**:

```powershell
.\zethora-node.exe --testnet --utxoindex --enable-unsynced-mining
```

The node starts printing text. **Leave this window open.**

*Note: this command is for solo testing. When the public testnet opens, a seed address will be added to it so you can connect to other people.*

---

## Step 4: Start the miner

1. Go back to the extracted folder window.
2. Click the address bar again, type `powershell`, press **Enter**. A second blue window opens.
3. Paste this command and press **Enter**:

```powershell
.\zethora-miner.exe --testnet
```

The first start can take a few minutes. The first block can take longer on slower PCs.

**Important:** on the first run the miner creates a file called `zethora-miner-key-testnet.txt` in this folder. Keep it: it holds your testnet rewards. Never share it.

**How to read the screen:** each time a block is mined, the miner prints a `Supply check` line. It should end with the word **BALANCED**. If a Supply check line does NOT say BALANCED, stop the miner (Ctrl + C) and take a screenshot.

---

## Step 5: Check your balance

The node from Step 3 must still be running.

1. Open a third PowerShell window in the same folder (address bar, type `powershell`, Enter).
2. Paste this command and press **Enter**:

```powershell
.\zethora-miner.exe --testnet balance
```

It prints your testnet balance. New rewards show up after the next block. Testnet coins have no value; this number is only for testing.

---

## Step 6: How to stop

1. Click the miner window and press **Ctrl + C**.
2. Click the node window and press **Ctrl + C**.

To start again later: open PowerShell in the folder (address bar trick) and repeat Step 3, then Step 4.

---

## If something fails

1. Take a screenshot of the window.
2. Copy the last 5 to 10 lines of text.
3. Send them to the person who gave you this guide.

If you are on your own, you can report it publicly at: https://github.com/ceoghoxst/zethora-node/issues
