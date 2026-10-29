# Zethora testnet: setup guide (Windows)

No experience needed. Every click is written out. Takes about 10 minutes.

(Prefer a zip without installing? The release also has a
**zethora-windows-x64-...zip**: right-click it, **Extract All**, then
double-click **Zethora.cmd** in the extracted folder.)

**Before you start:** testnet coins are worth zero. This is a practice
network for testing.

**You need:** a Windows 10 or 11 PC with 8 GB of memory or more.

---

## Step 1: Download

1. Open your web browser (Edge, Chrome, or any other).
2. Go to: **github.com/ceoghoxst/zethora-node/releases**
3. Find the newest release at the top of the page and open its **Assets**
   list.
4. Click the file that starts with **Zethora-Setup** and ends with **.exe**.
   - Do **not** click "Source code". That is not the program.

### If your browser blocks the download (common, this is expected)

New programs from small projects are not "known" to Windows yet, so the
browser may say the file "isn't commonly downloaded" or "could harm your
device".

**Edge:**
1. Click the **Downloads** icon (arrow pointing down, top right).
2. Next to the Zethora file, click **...** then **Keep**.
3. Click **Show more**, then **Keep anyway**.

**Chrome:** click **Keep** (or **Download anyway**) on the warning.

Want to be sure the file is ours? See "Check the download" below.

## Step 2: Install

1. Open the downloaded **Zethora-Setup** file (click it in the browser's
   download list, or find it in your **Downloads** folder).
2. A blue box may say **"Windows protected your PC"**. Click **More info**,
   then **Run anyway**. (Same reason as above: the program is not signed yet.)
3. Accept the license and click **Next** until you see **Install**. Click it.
4. On the last screen leave **"Open Zethora now"** ticked and click
   **Finish**.

A **Zethora** icon is now on your desktop and in the Start menu. No admin
password is needed; it installs just for your Windows account.

## Step 3: Start mining

1. In the Zethora window, click the purple **START MINING** button.
2. **Windows Firewall will ask to allow Zethora** (a box titled "Windows
   Security"). Zethora needs the network to share blocks with other
   computers. Tick **Private networks**, leave **Public networks** unticked,
   and click **Allow**. It only asks once.
3. Wait. The first start takes about 1 to 2 minutes:
   - Status shows **Starting**, then **Preparing**, then **Mining**.
   - Speed shows your hash rate (it climbs over the first few minutes).
4. When you find a block, **Blocks found** goes up and the
   **Supply check** line turns green: **BALANCED**.
5. **Balance** updates about a second after each block you find.

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

To mine again later, click the **Zethora** icon on your desktop and click
**START MINING**.

To uninstall: Start menu, **Zethora**, **Uninstall Zethora**. Your key file
is never deleted by uninstalling.

---

## Check the download (optional, recommended)

1. Open your **Downloads** folder, click the address bar at the top of File
   Explorer, type **powershell** and press **Enter**.
2. In the window that opens, type `Get-FileHash Zethora-Setup*` and press
   Enter.
3. On the release page, open the **Zethora-Setup-....exe.sha256** file.
4. The long code must match. Upper or lower case
   does not matter. If they don't match, delete everything and tell us.

## Something went wrong?

| What you see | What to do |
|---|---|
| Browser says the download is unsafe or uncommon | Expected for a new, unsigned program. See "If your browser blocks the download" in Step 1. |
| "Windows Security" asks to allow Zethora | Tick **Private networks**, click **Allow**. |
| "Can't find zethora-node.exe or zethora-miner.exe" (zip only) | You opened Zethora from inside the zip. Right-click the zip, **Extract All**, and open it from the extracted folder. |
| The window opens and closes right away | Right-click **Zethora.cmd**, choose **Show more options** if needed, then check you extracted all files (Step 2). |
| Status stays on **Preparing** for many minutes | Your PC may not have enough free memory. Close other programs. 8 GB or more is needed. |
| Speed is very low | Normal for the first minutes. Other open programs come first; mining uses what is left. |
| "The node keeps stopping" | Send us **node-crash.log** from your Zethora folder. |

Report problems (with a screenshot) at:
**github.com/ceoghoxst/zethora-node/issues**
