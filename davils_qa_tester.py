#!/usr/bin/env python3
"""
DAVILS QA Tester
A developer tool to test .enc files.
Features:
  - Export decrypted .mp4 to disk
  - Stream via the exact app protocol (AES-CTR + HTTP Range requests)
"""
import sys, os
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

import base64, hashlib, hmac as hmac_mod, json, struct
import threading, subprocess, time
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import http.server, socketserver, urllib.parse

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "cryptography", "-q"])
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# ── Constants ─────────────────────────────────────────────────────────────────
HEADER_SIZE = 128
CHUNK_SIZE  = 1_048_576
SCRIPT_DIR  = os.path.dirname(os.path.abspath(__file__))
EXPORT_DIR  = os.path.join(SCRIPT_DIR, "qa_exports")
os.makedirs(EXPORT_DIR, exist_ok=True)

# ── Helpers ───────────────────────────────────────────────────────────────────
def load_keys_from_license(lic_path):
    if not os.path.isfile(lic_path):
        raise FileNotFoundError(f"License file not found: {lic_path}")
    with open(lic_path) as f:
        data = json.load(f)
    if "file_key_hex" in data:
        fk = bytes.fromhex(data["file_key_hex"])
        hk = bytes.fromhex(data["hmac_key_hex"])
    else:
        fk = base64.b64decode(data["fileKey"])
        hk = base64.b64decode(data["hmacKey"])
    return fk, hk

def decrypt_file_to_disk(enc_path, dst_path, file_key, hmac_key, progress_cb=None):
    with open(enc_path, "rb") as f:
        hdr = f.read(HEADER_SIZE)
    if hdr[:4] != b"DAVL":
        raise ValueError("Not a DAVL file")
    pt_sz        = struct.unpack_from("<Q", hdr, 16)[0]
    nonce        = hdr[24:40]
    stored_mac   = hdr[40:72]
    
    mac = hmac_mod.new(hmac_key, hdr[:40], hashlib.sha256)
    cipher = Cipher(algorithms.AES(file_key), modes.CTR(nonce)).decryptor()
    
    written = 0
    with open(enc_path, "rb") as fin, open(dst_path, "wb") as fout:
        fin.seek(HEADER_SIZE)
        while True:
            chunk = fin.read(4 * CHUNK_SIZE)
            if not chunk: break
            mac.update(chunk)
            pt = cipher.update(chunk)
            # Trim padding
            if written + len(pt) > pt_sz:
                pt = pt[:pt_sz - written]
            fout.write(pt)
            written += len(pt)
            if progress_cb: progress_cb(written / pt_sz * 100)
            
    if not hmac_mod.compare_digest(mac.digest(), stored_mac):
        os.remove(dst_path)
        raise ValueError("HMAC verification failed. Key is wrong or file is corrupted.")
    return written

def make_seek_cipher(file_key, nonce, byte_offset):
    block = byte_offset // 16
    skip  = byte_offset % 16
    ctr   = ((int.from_bytes(nonce, "big") + block) & ((1 << 128) - 1)).to_bytes(16, "big")
    return Cipher(algorithms.AES(file_key), modes.CTR(ctr)).encryptor(), skip

# ── HTTP Server (App Protocol) ────────────────────────────────────────────────
_srv = {}

class QADataSourceHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, fmt, *args): pass

    def do_GET(self):  self._serve(True)
    def do_HEAD(self): self._serve(False)

    def _serve(self, send_body):
        slug = urllib.parse.unquote(self.path.lstrip("/").split("?")[0])
        enc_path = _srv.get("enc_path")
        if not enc_path or not os.path.isfile(enc_path):
            self.send_response(404)
            self.end_headers()
            return

        file_key = _srv["file_key"]
        if "nonce" not in _srv:
            with open(enc_path, "rb") as f: hdr = f.read(HEADER_SIZE)
            _srv["nonce"] = hdr[24:40]
            _srv["ptsize"] = struct.unpack_from("<Q", hdr, 16)[0]

        nonce = _srv["nonce"]
        pt_size = _srv["ptsize"]

        rng_hdr = self.headers.get("Range", "")
        start, end = 0, pt_size - 1
        partial = False
        if rng_hdr.startswith("bytes="):
            partial = True
            try:
                lo, hi = rng_hdr[6:].split("-", 1)
                if lo: start = int(lo)
                end = int(hi) if hi else pt_size - 1
            except ValueError: pass
            start = max(0, min(start, pt_size - 1))
            end   = max(start, min(end, pt_size - 1))

        length = end - start + 1
        self.send_response(206 if partial else 200)
        if partial: self.send_header("Content-Range", f"bytes {start}-{end}/{pt_size}")
        self.send_header("Content-Type", "video/mp4")
        self.send_header("Content-Length", str(length))
        self.send_header("Accept-Ranges", "bytes")
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        if not send_body: return

        try:
            enc, skip = make_seek_cipher(file_key, nonce, start)
            with open(enc_path, "rb") as f:
                f.seek(HEADER_SIZE + start - skip)
                remaining, first = length, True
                while remaining > 0:
                    want = min(256 * 1024 + (skip if first else 0), remaining + (skip if first else 0))
                    raw  = f.read(want)
                    if not raw: break
                    pt = enc.update(raw)
                    if first and skip:
                        pt = pt[skip:]
                        first = False
                    if len(pt) > remaining: pt = pt[:remaining]
                    self.wfile.write(pt)
                    remaining -= len(pt)
        except (BrokenPipeError, ConnectionResetError):
            pass

class ThreadedServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True

# ── GUI ───────────────────────────────────────────────────────────────────────
BG    = "#2c3e50"
CARD  = "#34495e"
ACC   = "#2980b9"
HL    = "#27ae60"
WARN  = "#e67e22"
FG    = "#ecf0f1"
DIM   = "#bdc3c7"
F     = ("Segoe UI", 10)
FB    = ("Segoe UI", 10, "bold")

class QATesterApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("DAVILS -- QA Tester")
        self.configure(bg=BG)
        self.geometry("650x600")
        self._enc_path = ""
        self._lic_path = os.path.join(SCRIPT_DIR, "hdd_layout", "valid", "license", "license.json")
        self._httpd = None
        self._srv_port = 8080
        self._build_ui()

    def _build_ui(self):
        hdr = tk.Frame(self, bg="#1abc9c", padx=18, pady=10)
        hdr.pack(fill="x")
        tk.Label(hdr, text="QA Decryption Tester", font=("Segoe UI", 13, "bold"), bg="#1abc9c", fg="white").pack(side="left")
        tk.Label(hdr, text="Export MP4 or Test Stream Protocol", font=("Segoe UI", 9), bg="#1abc9c", fg="#e8f8f5").pack(side="right")

        p = tk.Frame(self, bg=BG, padx=20, pady=20)
        p.pack(fill="both", expand=True)

        def section(txt):
            tk.Label(p, text=txt, font=FB, bg=BG, fg="#f1c40f", anchor="w").pack(fill="x", pady=(15, 5))

        # 1. Inputs
        section("Step 1 -- Select .enc File")
        self._enc_var = tk.StringVar(value="Click Browse to select .enc file...")
        row1 = tk.Frame(p, bg=BG); row1.pack(fill="x")
        tk.Button(row1, text="Browse...", command=self._pick_enc, font=FB, bg=ACC, fg="white", relief="flat", padx=10).pack(side="left")
        tk.Label(row1, textvariable=self._enc_var, font=F, bg=CARD, fg=FG, anchor="w", padx=10, wraplength=450).pack(side="left", fill="x", expand=True, padx=(10, 0))

        section("Step 2 -- Select license.json")
        self._lic_var = tk.StringVar(value=self._lic_path)
        row2 = tk.Frame(p, bg=BG); row2.pack(fill="x")
        tk.Button(row2, text="Browse...", command=self._pick_lic, font=FB, bg=ACC, fg="white", relief="flat", padx=10).pack(side="left")
        tk.Label(row2, textvariable=self._lic_var, font=F, bg=CARD, fg=FG, anchor="w", padx=10, wraplength=450).pack(side="left", fill="x", expand=True, padx=(10, 0))

        # 2. Progress
        section("Status / Progress")
        self._status_var = tk.StringVar(value="Ready.")
        tk.Label(p, textvariable=self._status_var, font=("Consolas", 10), bg=CARD, fg=HL, anchor="w", padx=10, pady=10).pack(fill="x")
        self._bar = ttk.Progressbar(p, length=540, mode="determinate")
        self._bar.pack(fill="x", pady=(5, 10))

        # 3. Actions
        section("Step 3 -- Test Actions")
        actions = tk.Frame(p, bg=BG); actions.pack(fill="x")
        
        # Mode A
        mode_a = tk.Frame(actions, bg=CARD, padx=15, pady=15); mode_a.pack(side="left", fill="both", expand=True, padx=(0, 5))
        tk.Label(mode_a, text="Mode A: Export to Disk", font=FB, bg=CARD, fg=FG).pack()
        tk.Label(mode_a, text="Writes plaintext .mp4 to disk for QA validation.", font=("Segoe UI", 8), bg=CARD, fg=DIM, wraplength=200).pack(pady=(0, 10))
        tk.Button(mode_a, text="Export Decrypted MP4", command=self._export_mp4, font=FB, bg="#8e44ad", fg="white", relief="flat", pady=8).pack(fill="x")
        
        self._play_export_btn = tk.Button(mode_a, text="Play Export in VLC", command=self._play_export, font=FB, bg=WARN, fg="white", relief="flat", pady=8, state="disabled")
        self._play_export_btn.pack(fill="x", pady=(10, 0))
        self._exported_path = ""

        # Mode B
        mode_b = tk.Frame(actions, bg=CARD, padx=15, pady=15); mode_b.pack(side="left", fill="both", expand=True, padx=(5, 0))
        tk.Label(mode_b, text="Mode B: Stream Protocol", font=FB, bg=CARD, fg=FG).pack()
        tk.Label(mode_b, text="In-memory AES-CTR HTTP server (App simulation).", font=("Segoe UI", 8), bg=CARD, fg=DIM, wraplength=200).pack(pady=(0, 10))
        self._stream_btn = tk.Button(mode_b, text="Start Stream & Open VLC", command=self._start_stream, font=FB, bg=HL, fg="white", relief="flat", pady=8)
        self._stream_btn.pack(fill="x")
        self._stop_btn = tk.Button(mode_b, text="Stop Server", command=self._stop_stream, font=FB, bg="#c0392b", fg="white", relief="flat", pady=8, state="disabled")
        self._stop_btn.pack(fill="x", pady=(10, 0))

    def _pick_enc(self):
        p = filedialog.askopenfilename(title="Select .enc file", filetypes=[("DAVILS Encrypted", "*.enc")])
        if p:
            self._enc_path = p
            self._enc_var.set(p)

    def _pick_lic(self):
        p = filedialog.askopenfilename(title="Select license.json", filetypes=[("JSON files", "*.json")])
        if p:
            self._lic_path = p
            self._lic_var.set(p)

    def _get_keys(self):
        if not self._enc_path or not os.path.isfile(self._enc_path):
            raise ValueError("Select a valid .enc file.")
        if not self._lic_path or not os.path.isfile(self._lic_path):
            raise ValueError("Select a valid license.json file.")
        return load_keys_from_license(self._lic_path)

    # ── Mode A: Export ────────────────────────────────────────────────────────
    def _export_mp4(self):
        self._stop_stream()
        try:
            fk, hk = self._get_keys()
        except Exception as e:
            messagebox.showerror("Key Error", str(e))
            return
        
        stem = os.path.splitext(os.path.basename(self._enc_path))[0]
        dst = os.path.join(EXPORT_DIR, f"{stem}_decrypted.mp4")
        self._bar["value"] = 0
        self._status_var.set(f"Exporting to {dst} ...")

        def run():
            try:
                def prog(p):
                    self.after(0, lambda: self._bar.configure(value=p))
                    self.after(0, lambda: self._status_var.set(f"Exporting: {p:.1f}%"))
                
                sz = decrypt_file_to_disk(self._enc_path, dst, fk, hk, prog)
                self.after(0, lambda: self._on_export_done(dst, sz))
            except Exception as e:
                self.after(0, lambda: messagebox.showerror("Export Failed", str(e)))
                self.after(0, lambda: self._status_var.set("Export failed."))
                
        threading.Thread(target=run, daemon=True).start()

    def _on_export_done(self, dst, sz):
        self._bar["value"] = 100
        self._status_var.set(f"Export Success! {sz/1e6:.1f} MB saved to:\n{dst}")
        self._exported_path = dst
        self._play_export_btn.config(state="normal")

    def _play_export(self):
        if not self._exported_path or not os.path.isfile(self._exported_path): return
        self._launch_vlc(self._exported_path)

    # ── Mode B: Stream ────────────────────────────────────────────────────────
    def _start_stream(self):
        try:
            fk, hk = self._get_keys()
        except Exception as e:
            messagebox.showerror("Key Error", str(e))
            return
        
        self._stop_stream()
        
        # Start server
        _srv.clear()
        _srv["file_key"] = fk
        _srv["enc_path"] = self._enc_path
        
        port = self._srv_port
        for attempt in range(10):
            try:
                httpd = ThreadedServer(("0.0.0.0", port), QADataSourceHandler)
                break
            except OSError:
                port += 1
        else:
            messagebox.showerror("Port Error", "Could not bind to any port 8080-8089")
            return
            
        self._httpd = httpd
        self._srv_port = port
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        
        url = f"http://localhost:{port}/stream.mp4"
        self._status_var.set(f"Streaming on {url} ... Launching VLC.")
        self._stream_btn.config(state="disabled")
        self._stop_btn.config(state="normal")
        
        self._launch_vlc(url)

    def _stop_stream(self):
        if self._httpd:
            threading.Thread(target=self._httpd.shutdown, daemon=True).start()
            self._httpd = None
        self._stream_btn.config(state="normal")
        self._stop_btn.config(state="disabled")
        self._status_var.set("Server stopped.")

    def _launch_vlc(self, target):
        vlc_paths = [r"C:\Program Files\VideoLAN\VLC\vlc.exe", r"C:\Program Files (x86)\VideoLAN\VLC\vlc.exe"]
        vlc_exe = next((p for p in vlc_paths if os.path.isfile(p)), None)
        if vlc_exe:
            subprocess.Popen([vlc_exe, target])
        else:
            self.clipboard_clear()
            self.clipboard_append(target)
            self.update()
            messagebox.showinfo("VLC Not Found", f"VLC not found. Target copied to clipboard:\n\n{target}")

if __name__ == "__main__":
    app = QATesterApp()
    app.mainloop()
