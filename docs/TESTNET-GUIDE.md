# Zethora testnet: setup guide (Windows)

No experience needed. Every click is written out. Takes about 10 minutes.

**Before you start:** testnet coins are worth zero. This is a practice
network for testing.

**You need:** a Windows 10 or 11 PC with 8 GB of memory or more.

---

## Step 1: Download

1. Open your web browser (Edge, Chrome, or any other).
2. Go to: **github.com/ceoghoxst/zethora-node/releases**
3. Find the newest release at the top of the page.
4. Scroll down to the section called **Assets** in that release.
   (If you only see a few items, click **Assets** to open the list.)
5. Click the file whose name starts with **zethora-windows-x64** and ends
   with **.zip**.
   - Do **not** click "Source code". That is not the program.
6. Wait for the download to finish. Your browser shows it at the top
   right or bottom of the window.

## Step 2: Unzip (important)

A .zip file is a packed folder. Windows can show what is inside without
unpacking it, but the programs **will not work** until you unpack it.

1. Open **File Explorer**: the yellow folder icon on the taskbar, or press
   the **Windows key + E** together.
2. Click **Downloads** on the left side.
3. Find the file **zethora-windows-x64-...zip** (newest at the top).
4. **Right-click** it and choose **Extract All...**
   (On some Windows 11 PCs: right-click, then **Show more options**, then
   **Extract All...**)
5. A window opens. Leave everything as it is and click **Extract**.
6. A new folder opens with the same name as the zip, without ".zip".
   This is your Zethora folder. You should see files like
   **Zethora.cmd**, **zethora-node.exe** and **zethora-miner.exe**.

Tip: you can move this folder anywhere you like, for example to your
Desktop. Keep all the files together.

## Step 3: Start mining

1. In your Zethora folder, double-click **Zethora** (the file named
   Zethora.cmd). If you see file extensions hidden, it shows as just
   "Zethora" with a gear-like icon.
2. Windows may show a blue box **"Windows protected your PC"**. This
   happens with new programs from small projects that are not signed yet.
   Click **More info**, then **Run anyway**.
   - Want to be sure the files are ours? See "Check the download" below.
3. The Zethora window opens. Click the purple **START MINING** button.
4. Wait. The first start takes about 1 to 2 minutes:
   - Status shows **Starting**, then **Preparing**, then **Mining**.
   - Speed shows your hash rate (it climbs over the first few minutes).
5. When you find a block, **Blocks found** goes up and the
   **Supply check** line turns green: **BALANCED**.
6. **Balance** updates a few seconds after each block you find.

If the Supply check ever turns red, click **STOP MINING** and send us a
screenshot.

## Step 4: Back up your key

The first time you mine, a file called **zethora-miner-key-testnet.txt**
is created in your Zethora folder. It controls your coins.

1. Click **BACK UP MY KEY** in the Zethora window.
2. Read the message and click **OK**. File Explorer opens with the key
   file selected.
3. Copy it to a USB stick or another safe place.

Never share this file. Anyone who has it can take your coins.

## Step 5: Stop

Click **STOP MINING**, or close the window with the X. Both stop
everything. Your coins and key are kept.

To mine again later, double-click **Zethora** and click **START MINING**.

---

## Check the download (optional, recommended)

1. In your Zethora folder, click the address bar at the top of File
   Explorer, type **powershell** and press **Enter**.
2. In the window that opens, type:
   `Get-FileHash zethora-node.exe` and press Enter, then
   `Get-FileHash zethora-miner.exe` and press Enter.
3. Open **SHA256SUMS.txt** in the same folder (double-click it).
4. The long code next to each program must match. Upper or lower case
   does not matter. If they don't match, delete everything and tell us.

## Something went wrong?

| What you see | What to do |
|---|---|
| "Can't find zethora-node.exe or zethora-miner.exe" | You opened Zethora from inside the zip. Go back to Step 2 and use **Extract All**. |
| The window opens and closes right away | Right-click **Zethora.cmd**, choose **Show more options** if needed, then check you extracted all files (Step 2). |
| Status stays on **Preparing** for many minutes | Your PC may not have enough free memory. Close other programs. 8 GB or more is needed. |
| Speed is very low | Normal for the first minutes. Other open programs come first; mining uses what is left. |
| "The node keeps stopping" | Send us **node-crash.log** from your Zethora folder. |

Report problems (with a screenshot) at:
**github.com/ceoghoxst/zethora-node/issues**
