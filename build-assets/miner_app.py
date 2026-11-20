#!/usr/bin/env python3
"""Zethora One-Click Miner - tkinter GUI (local-node fixed)."""
import os, sys, time, socket, threading, subprocess
import tkinter as tk
from tkinter import ttk
from tkinter.scrolledtext import ScrolledText

if getattr(sys, "frozen", False):
    WORKDIR = os.path.dirname(sys.executable)
else:
    WORKDIR = os.path.dirname(os.path.abspath(__file__))
MINER = os.path.join(WORKDIR, "zethora-miner.exe" if os.name == "nt" else "zethora-miner")
KASPAD = os.path.join(WORKDIR, "zethora-node.exe" if os.name == "nt" else "zethora-node")
PORT = 26210
NODE = "grpc://127.0.0.1:%d" % PORT

BG="#1e1e1e"; FG="#f0f0f0"; SUB="#cccccc"; LOGBG="#0f0f0f"; LOGFG="#b8e986"
GREEN="#2e7d32"; RED="#c62828"

def port_open(port, host="127.0.0.1", timeout=0.5):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False

class MinerApp:
    def __init__(self, root):
        self.root = root
        self.proc = None
        self.node_proc = None
        self.stopping = False

        root.title("Zethora One-Click Miner")
        root.geometry("780x620")
        root.minsize(660, 520)
        root.configure(bg=BG)
        try:
            ttk.Style().theme_use("clam")
        except Exception:
            pass

        tk.Label(root, text="Zethora One-Click Miner", bg=BG, fg=FG,
                 font=("Segoe UI", 16, "bold")).pack(pady=(12, 8))

        form = tk.Frame(root, bg=BG)
        form.pack(fill="x", padx=14, pady=4)

        tk.Label(form, text="Network:", bg=BG, fg=SUB,
                 font=("Segoe UI", 10)).grid(row=0, column=0, sticky="w", pady=4)
        self.network_var = tk.StringVar(value="Testnet")
        self.network_menu = ttk.Combobox(form, textvariable=self.network_var,
                                         values=["Testnet", "Devnet"],
                                         state="readonly", width=14)
        self.network_menu.grid(row=0, column=1, sticky="w", padx=(6, 0), pady=4)

        tk.Label(form, text="Node URL:", bg=BG, fg=SUB,
                 font=("Segoe UI", 10)).grid(row=1, column=0, sticky="w", pady=4)
        self.node_var = tk.StringVar(value=NODE)
        self.node_entry = tk.Entry(form, textvariable=self.node_var, width=48,
                                   bg="#2b2b2b", fg=FG, insertbackground=FG, relief="flat")
        self.node_entry.grid(row=1, column=1, sticky="we", padx=(6, 0), pady=4)
        form.columnconfigure(1, weight=1)

        self.autonode_var = tk.BooleanVar(value=True)
        self.autonode_chk = tk.Checkbutton(
            form, text="Start local node automatically (recommended)",
            variable=self.autonode_var, bg=BG, fg=SUB, selectcolor="#2b2b2b",
            activebackground=BG, activeforeground=FG, font=("Segoe UI", 10), anchor="w")
        self.autonode_chk.grid(row=2, column=0, columnspan=2, sticky="w", pady=(2, 0))

        self.light_var = tk.BooleanVar(value=False)
        self.light_chk = tk.Checkbutton(
            form, text="Light Mode (for older PCs)", variable=self.light_var,
            bg="#141a2e", fg="#cdd6f4", selectcolor="#1e2740",
            activebackground="#141a2e", activeforeground="#cdd6f4",
            font=("Segoe UI", 10), anchor="w")
        self.light_chk.grid(row=3, column=0, columnspan=2, sticky="w", padx=10, pady=(0, 6))

        btn_frame = tk.Frame(root, bg=BG)
        btn_frame.pack(fill="x", padx=14, pady=10)
        self.start_btn = tk.Button(btn_frame, text="START MINING", bg=GREEN, fg="white",
                                   activebackground="#1b5e20", activeforeground="white",
                                   relief="flat", font=("Segoe UI", 12, "bold"), height=2,
                                   command=self.start_mining)
        self.start_btn.pack(side="left", expand=True, fill="x", padx=(0, 6))
        self.stop_btn = tk.Button(btn_frame, text="STOP", bg=RED, fg="white",
                                  activebackground="#8e0000", activeforeground="white",
                                  relief="flat", font=("Segoe UI", 12, "bold"), height=2,
                                  state="disabled", command=self.stop_mining)
        self.stop_btn.pack(side="left", expand=True, fill="x", padx=(6, 0))

        log_frame = tk.Frame(root, bg=BG)
        log_frame.pack(fill="both", expand=True, padx=14, pady=(0, 8))
        self.log = ScrolledText(log_frame, bg=LOGBG, fg=LOGFG,
                                insertbackground=LOGFG, relief="flat",
                                font=("Consolas", 9), wrap="word")
        self.log.pack(fill="both", expand=True)

        self.status_var = tk.StringVar(value="Status: Idle")
        tk.Label(root, textvariable=self.status_var, bg=BG, fg=SUB, anchor="w",
                 font=("Segoe UI", 9)).pack(fill="x", padx=14, pady=(0, 10))

        root.protocol("WM_DELETE_WINDOW", self.on_close)

    def append_log(self, text):
        self.log.insert("end", text)
        self.log.see("end")

    def set_status(self, text):
        self.status_var.set("Status: " + text)

    def set_running(self, running):
        st = "disabled" if running else "normal"
        self.start_btn.config(state=st)
        self.stop_btn.config(state="normal" if running else "disabled")
        self.network_menu.config(state="disabled" if running else "readonly")
        self.node_entry.config(state=st)
        self.autonode_chk.config(state=st)
        self.light_chk.config(state=st)

    def build_command(self):
        net = "--testnet" if self.network_var.get() == "Testnet" else "--devnet"
        cmd = [MINER, net]
        if self.light_var.get():
            cmd.append("--light")
        return cmd

    def _start_node_if_needed(self):
        if not self.autonode_var.get():
            return
        if not os.path.exists(KASPAD):
            self.append_log("[warn] No bundled zethora-node.exe here; using node URL as-is.\n")
            return
        if port_open(PORT):
            self.append_log("[info] Node already listening on %d; reusing it.\n" % PORT)
            return
        self.append_log("[info] Starting local node...\n")
        args = ["--testnet", "--rpclisten=127.0.0.1:%d" % PORT,
                "--enable-unsynced-mining", "--utxoindex", "--yes", "--addpeer", "95.216.185.137:26211"]
        try:
            self.node_proc = subprocess.Popen(
                [KASPAD] + args, cwd=os.path.dirname(KASPAD),
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL)
        except Exception as exc:
            self.append_log("[error] Node start failed: %s\n" % exc)
            self.node_proc = None
            return
        self.set_status("Waiting for node...")
        for _ in range(45):
            if self.stopping:
                return
            if port_open(PORT):
                self.append_log("[info] Node up on 127.0.0.1:%d\n" % PORT)
                return
            time.sleep(2)
        self.append_log("[warn] Node slow to open port %d; mining anyway.\n" % PORT)

    def start_mining(self):
        if self.proc is not None:
            return
        self.stopping = False
        self.set_running(True)
        self.set_status("Starting...")
        self._start_node_if_needed()
        if self.stopping:
            self.set_running(False); self.set_status("Stopped"); return
        cmd = self.build_command()
        self.append_log(">>> " + " ".join(cmd) + "\n")
        try:
            self.proc = subprocess.Popen(
                cmd, cwd=WORKDIR, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                bufsize=1, universal_newlines=True)
        except Exception as exc:
            self.proc = None
            self.append_log("[error] Miner start failed: %s\n" % exc)
            self._stop_node(); self.set_status("Stopped"); self.set_running(False)
            return
        self.set_status("Mining")
        threading.Thread(target=self._read_output, daemon=True).start()

    def _read_output(self):
        proc = self.proc
        try:
            for line in iter(proc.stdout.readline, ""):
                self.append_log(line)
        except Exception as exc:
            self.append_log("[error] reader: %s\n" % exc)
        finally:
            try:
                proc.stdout.close()
            except Exception:
                pass
            code = proc.wait()
            self.root.after(0, self._on_exit, code)

    def _on_exit(self, code):
        self.append_log("\n[process exited %s]\n" % code)
        self.proc = None
        self.set_status("Stopped")
        self.set_running(False)

    def _stop_node(self):
        if self.node_proc is not None:
            try:
                self.node_proc.terminate()
                try:
                    self.node_proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.node_proc.kill()
            except Exception:
                pass
            self.node_proc = None

    def stop_mining(self):
        if self.proc is None and self.node_proc is None:
            return
        self.stopping = True
        self.set_status("Stopping...")
        if self.proc is not None:
            try:
                self.proc.terminate()
                try:
                    self.proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    self.proc.kill()
            except Exception:
                pass
        self._stop_node()
        self.proc = None
        self.set_status("Stopped")
        self.set_running(False)

    def on_close(self):
        try:
            self.stop_mining()
        except Exception:
            pass
        self.root.destroy()


def main():
    root = tk.Tk()
    MineApp = MinerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()



