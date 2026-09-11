#!/usr/bin/env python3
"""
DAVILS Encryption Tool (Packaging Pipeline)
Simulates the packaging side of the pipeline:
  1. Encrypts video with AES-256-CTR
  2. Signs with HMAC-SHA256
  3. Automatically builds the hdd_layout/valid directory structure
"""
import sys, os
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

import base64, hashlib, hmac as hmac_mod, json, math, struct
import shutil, subprocess, threading, time
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "cryptography", "-q"])
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# ── Constants ─────────────────────────────────────────────────────────────────
HEADER_SIZE = 128
CHUNK_SIZE  = 1_048_576
SCRIPT_DIR  = os.path.dirname(os.path.abspath(__file__))
KEY_FILE    = os.path.join(SCRIPT_DIR, "output_key.json")
ENC_OUTDIR  = os.path.join(SCRIPT_DIR, "my_encrypted_videos")
os.makedirs(ENC_OUTDIR, exist_ok=True)

# ── Key helpers ───────────────────────────────────────────────────────────────
def load_or_create_master_keys():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE) as f:
            d = json.load(f)
        return bytes.fromhex(d["file_key_hex"]), bytes.fromhex(d["hmac_key_hex"])
    fk, hk = os.urandom(32), os.urandom(32)
    with open(KEY_FILE, "w") as f:
        json.dump({"file_key_hex": fk.hex(), "hmac_key_hex": hk.hex(),
                   "file_key_b64": base64.b64encode(fk).decode(),
                   "hmac_key_b64": base64.b64encode(hk).decode()}, f, indent=2)
    return fk, hk

# ── Encrypt ───────────────────────────────────────────────────────────────────
def encrypt_file(src, dst, file_key, hmac_key, progress_cb=None):
    size  = os.path.getsize(src)
    count = max(1, math.ceil(size / CHUNK_SIZE))
    nonce = os.urandom(16)
    prefix = (b"DAVL" + struct.pack("<B", 1) + b"\x00" * 3
              + struct.pack("<I", count) + struct.pack("<I", CHUNK_SIZE)
              + struct.pack("<Q", size) + nonce)
    cipher = Cipher(algorithms.AES(file_key), modes.CTR(nonce)).encryptor()
    mac    = hmac_mod.new(hmac_key, prefix, hashlib.sha256)
    tmp    = dst + ".tmp"
    with open(src, "rb") as fin, open(tmp, "wb") as fout:
        fout.write(b"\x00" * HEADER_SIZE)
        done = 0
        while True:
            chunk = fin.read(4 * CHUNK_SIZE)
            if not chunk: break
            ct = cipher.update(chunk)
            mac.update(ct); fout.write(ct)
            done += len(chunk)
            if progress_cb: progress_cb(done / size * 100)
        tail = cipher.finalize()
        if tail: mac.update(tail); fout.write(tail)
    header = prefix + mac.digest() + b"\x00" * 56
    with open(tmp, "r+b") as f:
        f.seek(0); f.write(header)
    if os.path.exists(dst): os.remove(dst)
    os.rename(tmp, dst)
    return size, os.path.getsize(dst)

# ── GUI ───────────────────────────────────────────────────────────────────────
BG    = "#1a1a2e"
CARD  = "#16213e"
ACC   = "#0f3460"
HL    = "#e94560"
FG    = "#eaeaea"
DIM   = "#8892a4"
GREEN = "#2ecc71"
PANEL = "#0d1b2a"
F     = ("Segoe UI", 10)
FB    = ("Segoe UI", 10, "bold")
FM    = ("Consolas", 9)

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("DAVILS -- Encryption & Packaging Pipeline")
        self.resizable(False, False)
        self.configure(bg=BG)
        self._enc_path = None
        self._src_path = None
        self._build_ui()

    def _build_ui(self):
        hdr = tk.Frame(self, bg=HL, padx=18, pady=10)
        hdr.pack(fill="x")
        tk.Label(hdr, text="DAVILS  Encryption Pipeline", font=("Segoe UI", 13, "bold"), bg=HL, fg="white").pack(side="left")
        tk.Label(hdr, text="Sprint 1 -- Packaging Tool", font=("Segoe UI", 8), bg=HL, fg="#ffcccc").pack(side="right")

        p = tk.Frame(self, bg=CARD, padx=18, pady=14)
        p.pack(fill="both", expand=True, padx=18, pady=14)

        def section(text):
            tk.Label(p, text=text, font=FB, bg=CARD, fg=HL, anchor="w").pack(fill="x", pady=(14, 4))

        section("Step 1 -- Choose your video file")
        self._src_var = tk.StringVar(value="Click Browse to pick a video...")
        box = tk.Frame(p, bg=ACC, padx=10, pady=9, cursor="hand2")
        box.pack(fill="x")
        src_lbl = tk.Label(box, textvariable=self._src_var, font=F, bg=ACC, fg=FG, anchor="w", wraplength=540)
        src_lbl.pack(fill="x")
        for w in (box, src_lbl):
            w.bind("<Button-1>", lambda e: self._pick_src())
        tk.Button(p, text="Browse...", command=self._pick_src, font=FB, bg=HL, fg="white", relief="flat", padx=12, pady=5, cursor="hand2").pack(anchor="w", pady=(6, 0))

        section("Step 2 -- Encrypted output  (set automatically)")
        self._dst_var = tk.StringVar(value=ENC_OUTDIR)
        tk.Label(p, textvariable=self._dst_var, font=FM, bg=ACC, fg=DIM, anchor="w", padx=10, pady=7, wraplength=540).pack(fill="x")

        section("Step 3 -- Encrypt & Package")
        tk.Label(p, text="This will encrypt the video and automatically generate the hdd_layout/valid/ structure.", font=("Segoe UI", 9), bg=CARD, fg=DIM, anchor="w").pack(fill="x", pady=(0, 10))
        
        row = tk.Frame(p, bg=CARD); row.pack(fill="x")
        self._enc_btn = tk.Button(row, text="Encrypt Video", command=self._start_encrypt, font=("Segoe UI", 11, "bold"), bg="#27ae60", fg="white", relief="flat", padx=18, pady=9, cursor="hand2")
        self._enc_btn.pack(side="left")
        self._enc_pct = tk.StringVar(value="")
        tk.Label(row, textvariable=self._enc_pct, font=F, bg=CARD, fg=DIM).pack(side="left", padx=10)

        self._enc_bar = ttk.Progressbar(p, length=540, mode="determinate")
        self._enc_bar.pack(fill="x", pady=(8, 4))

        self._enc_result = tk.Label(p, text="", font=FM, bg=PANEL, fg=GREEN, anchor="w", padx=10, pady=8, justify="left", wraplength=540)
        self._enc_result.pack(fill="x")

        self._status_var = tk.StringVar(value="Ready.")
        tk.Label(self, textvariable=self._status_var, font=FM, bg=BG, fg=DIM, anchor="w", padx=18, pady=5).pack(fill="x")
        self.geometry("600x520")

    def _pick_src(self):
        path = filedialog.askopenfilename(title="Select video file", filetypes=[("Video", "*.mp4 *.mkv *.avi *.mov *.m4v *.ts *.wmv"), ("All files", "*.*")])
        if not path: return
        self._src_path = path
        stem = os.path.splitext(os.path.basename(path))[0]
        self._enc_path = os.path.join(ENC_OUTDIR, stem + ".enc")
        self._src_var.set(path)
        self._dst_var.set(self._enc_path)
        self._enc_result.config(text="")
        self._enc_bar["value"] = 0
        self._enc_pct.set("")

    def _start_encrypt(self):
        if not getattr(self, "_src_path", None):
            messagebox.showwarning("No file", "Please choose a video file first.")
            return
        self._enc_btn.config(state="disabled", text="Encrypting...")
        self._enc_bar["value"] = 0
        self._enc_pct.set("0%")
        self._enc_result.config(text="")
        src, dst = self._src_path, self._enc_path

        def run():
            try:
                fk, hk = load_or_create_master_keys()
                t0 = time.perf_counter()

                def prog(p):
                    self.after(0, self._enc_bar.configure, {"value": p})
                    self.after(0, self._enc_pct.set, f"{p:.0f}%")

                in_sz, out_sz = encrypt_file(src, dst, fk, hk, prog)
                elapsed = time.perf_counter() - t0
                delta   = out_sz - in_sz

                content_dir = os.path.join(SCRIPT_DIR, "hdd_layout", "valid", "content")
                os.makedirs(content_dir, exist_ok=True)
                shutil.copy2(dst, os.path.join(content_dir, os.path.basename(dst)))

                lic_dir = os.path.join(SCRIPT_DIR, "hdd_layout", "valid", "license")
                os.makedirs(lic_dir, exist_ok=True)
                with open(os.path.join(lic_dir, "license.json"), "w") as lf:
                    json.dump({
                        "file_key_hex":       fk.hex(),
                        "hmac_key_hex":       hk.hex(),
                        "file_key_b64":       base64.b64encode(fk).decode(),
                        "hmac_key_b64":       base64.b64encode(hk).decode(),
                        "deviceFingerprint":  "ANY"
                    }, lf, indent=2)

                txt = (f"Input : {os.path.basename(src)}  ({in_sz:,} bytes)\n"
                       f"Output: {os.path.basename(dst)}  ({out_sz:,} bytes)\n"
                       f"Delta : +{delta} bytes  (header only -- PASS)\n\n"
                       f"Copied to hdd_layout/valid/content/ automatically.\n"
                       f"License saved to hdd_layout/valid/license/.")
                self.after(0, self._on_encrypt_done, txt)
            except Exception as e:
                self.after(0, self._on_encrypt_error, str(e))

        threading.Thread(target=run, daemon=True).start()

    def _on_encrypt_done(self, txt):
        self._enc_bar["value"] = 100
        self._enc_pct.set("Done!")
        self._enc_btn.config(state="normal", text="Encrypt Video")
        self._enc_result.config(text=txt, fg=GREEN)
        self._status_var.set("Encryption complete. You can test it in davils_qa_tester.py")

    def _on_encrypt_error(self, msg):
        self._enc_btn.config(state="normal", text="Encrypt Video")
        self._enc_pct.set("Error!")
        messagebox.showerror("Encrypt failed", msg)
        self._status_var.set("Encryption failed.")

if __name__ == "__main__":
    app = App()
    app.mainloop()
