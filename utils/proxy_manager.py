"""Proxy management utilities for fbsfilter.

Handles loading, validating, and rotating proxies from a file.
Supported formats (one per line):
  protocol://host:port
  protocol://user:pass@host:port
  host:port           (assumed http)
"""

import logging
import random
import threading
from typing import Dict, List, Optional

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger("fbsfilter.proxy")


class ProxyManager:
    """Thread-safe proxy pool with automatic rotation."""

    def __init__(
        self,
        proxy_file: Optional[str] = None,
        rotate_every: int = 1,
        test_proxies: bool = False,
        test_url: str = "https://www.facebook.com",
        timeout: int = 10,
    ):
        self._proxies: List[str] = []
        self._bad_proxies: set = set()
        self._lock = threading.Lock()
        self._request_count = 0
        self._current_index = 0
        self.rotate_every = max(1, rotate_every)
        self.test_url = test_url
        self.timeout = timeout

        if proxy_file:
            self._load(proxy_file)
            if test_proxies:
                self._validate_all()

    def _load(self, filepath: str) -> None:
        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    proxy = line.strip()
                    if not proxy or proxy.startswith("#"):
                        continue
                    if "://" not in proxy:
                        proxy = "http://" + proxy
                    self._proxies.append(proxy)
        except OSError as exc:
            logger.error("Could not load proxy file: %s", exc)

        logger.info("Loaded %d proxies from %s", len(self._proxies), filepath)

    def _validate_all(self) -> None:
        valid: List[str] = []
        for proxy in self._proxies:
            if self._test(proxy):
                valid.append(proxy)
            else:
                logger.debug("Removed bad proxy: %s", proxy)
        self._proxies = valid
        logger.info("%d proxies passed validation", len(valid))

    def _test(self, proxy: str) -> bool:
        proxy_dict = {"http": proxy, "https": proxy}
        try:
            resp = requests.get(
                self.test_url,
                proxies=proxy_dict,
                timeout=self.timeout,
                verify=False,
                allow_redirects=True,
            )
            return resp.status_code < 500
        except Exception:
            return False

    def get(self) -> Optional[Dict[str, str]]:
        """Return the next proxy dict, or None if no proxies are available."""
        with self._lock:
            available = [p for p in self._proxies if p not in self._bad_proxies]
            if not available:
                return None
            self._request_count += 1
            if self._request_count % self.rotate_every == 0:
                self._current_index = (self._current_index + 1) % len(available)
            proxy = available[self._current_index % len(available)]
        return {"http": proxy, "https": proxy}

    def mark_bad(self, proxy_dict: Dict[str, str]) -> None:
        """Permanently remove a proxy that failed."""
        proxy = proxy_dict.get("http") or proxy_dict.get("https")
        if proxy:
            with self._lock:
                self._bad_proxies.add(proxy)
                logger.debug("Marked proxy as bad: %s", proxy)

    @property
    def count(self) -> int:
        with self._lock:
            return len(self._proxies) - len(self._bad_proxies)
