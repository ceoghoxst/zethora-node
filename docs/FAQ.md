# Zethora FAQ

Short answers for people who are not technical.

**What is Zethora?**
Money you can mine at home with a normal computer. No premine: every coin
comes from mining.

**Can I buy ZTHR? Is there a presale?**
No. Nothing is for sale: no presale, no airdrop, no ICO. Every coin is
created by mining. Testnet coins cannot be sold or traded.

**When does testnet launch?**
When it is ready. We do not publish dates in advance. It opens after
non-technical testers can set it up on their own.

**What is testnet?**
A practice network. Everything works like the real thing, but the coins are
worth zero. It exists so we can find problems before real value is involved.

**How do I start?**
Download **Zethora-Setup** from the releases page, open it, click Next until
it installs, then click START MINING. Every click is written out in
docs/TESTNET-GUIDE.md.

**My browser says the download is unsafe or "not commonly downloaded".**
Expected for a new program that is not code-signed yet. In Edge: Downloads,
"...", Keep, Show more, Keep anyway. Check the file's SHA256 against the
.sha256 file on the release page if you want to be sure it is ours.

**Windows Security asks to allow Zethora on the network.**
Zethora shares blocks with other computers, so it needs the network. Tick
Private networks and click Allow. It only asks once.

**Windows says "Windows protected your PC". Is that a virus?**
The programs are not code-signed yet, so Windows warns about every new
download from a small project. Click "More info", then "Run anyway". To be
sure the file is ours, compare its SHA256 hash with SHA256SUMS.txt (see
README.txt).

**Can I trust the app?**
The app is `Zethora.ps1`, a plain text file. Open it in Notepad and read it:
it only runs the two Zethora programs in the same folder. The full source
code is public at github.com/ceoghoxst/zethora-node.

**What is a node?**
The program that keeps a copy of the blockchain and checks every block.
The miner needs your node to be running.

**What does BALANCED mean?**
After every block, the miner adds up every coin in existence and checks the
total against exactly what mining has issued. BALANCED means they match:
no coins were created out of thin air. If you ever see a supply check that
does not say BALANCED, stop mining and report it.

**Will mining slow down my PC?**
The app runs the miner at below-normal priority. When you use other apps,
Windows gives them the CPU first. The miner uses about 2.5 GB of memory, so
a PC with 8 GB or more works best.

**What is the key file?**
`zethora-miner-key-testnet.txt` is created the first time you mine. It
controls your rewards. Keep it, back it up, and never share it. Anyone with
that file can take your coins. Lose it and your coins are gone.

**Where are my coins stored?**
On the blockchain, tied to your key file. Not in the app. Closing,
updating or reinstalling the app does not touch them.

**Will my testnet balance carry over?**
No. On testnet launch day the chain starts fresh from a new first block,
and everyone starts at zero, including the team. Mainnet will also start
fresh. That is what a fair launch means.

**Can I mine with a mining farm or GPU?**
Zethora uses RandomZ, which is designed for normal CPUs. GPUs and special
mining chips have little advantage. We do not claim to detect or block farms.

**Is it private?**
Private payments are built in, using Zcash's Orchard technology. Today they
are switched off. On testnet they will be turned on as an experimental,
unreviewed feature after the current hardening work. On mainnet they stay
off at launch and turn on only after an independent review. Privacy is
optional: normal payments stay public. See docs/STATUS.md.

**Is this an investment?**
No. Testnet coins are worth zero, and nothing here promises income or a
price. Mine because you want to help test it.

**Something went wrong. What do I do?**
Take a screenshot and open an issue at
github.com/ceoghoxst/zethora-node/issues. If the app says the node or miner
keeps stopping, attach node-crash.log or miner-crash.log from the folder.
