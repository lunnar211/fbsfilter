"""Advanced proxy filtering and validation utilities for fbsfilter.

Features:
  • Parse proxy lists from any pasted text (supports many formats)
  • Filter by protocol type, anonymity level, country code
  • Concurrent proxy testing with timeout
  • Export cleaned list to file
"""

import concurrent.futures
import logging
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Tuple

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger("fbsfilter.proxy_filter")

# Regex that matches the most common proxy formats found on public sites:
#   [protocol://][user:pass@]host:port  (colon-separated)
_PROXY_RE = re.compile(
    r"(?:(?P<proto>https?|socks[45])://)?(?:(?P<auth>[^\s@:]+:[^\s@:]+)@)?"
    r"(?P<host>(?:\d{1,3}\.){3}\d{1,3}|(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,})"
    r":(?P<port>\d{2,5})",
    re.IGNORECASE,
)

# Regex for tab/space-separated table rows (e.g. proxydb.net copy-paste):
#   IP<tab>port<tab>[proto]...
_TABULAR_RE = re.compile(
    r"^(?P<host>(?:\d{1,3}\.){3}\d{1,3})\s+(?P<port>\d{2,5})",
)

# Test URLs used to check proxy connectivity (fast, reliable)
_TEST_URLS = [
    "http://httpbin.org/ip",
    "http://ip-api.com/json",
    "http://checkip.amazonaws.com",
]

ANONYMITY_LEVELS = ("transparent", "anonymous", "elite")
PROXY_TYPES = ("http", "https", "socks4", "socks5")


@dataclass
class ProxyEntry:
    """Represents a single parsed + (optionally) tested proxy."""

    raw: str                          # original string from the dump
    host: str
    port: int
    proto: str = "http"              # http / https / socks4 / socks5
    auth: str = ""                   # "user:pass" or empty
    anonymity: str = "unknown"       # transparent / anonymous / elite / unknown
    country_code: str = ""           # 2-letter ISO code (if detected from dump)
    latency_ms: int = -1             # -1 = not tested
    working: Optional[bool] = None   # None = not tested

    @property
    def url(self) -> str:
        """Return the full proxy URL."""
        if self.auth:
            return f"{self.proto}://{self.auth}@{self.host}:{self.port}"
        return f"{self.proto}://{self.host}:{self.port}"

    @property
    def as_requests_dict(self) -> dict:
        return {"http": self.url, "https": self.url}

    def __str__(self) -> str:
        return self.url


def parse_proxy_text(text: str) -> List[ProxyEntry]:
    """Extract proxy entries from arbitrary pasted text.

    Handles formats like:
      • 1.2.3.4:8080
      • http://1.2.3.4:8080
      • socks5://user:pass@1.2.3.4:1080
      • Tab / space / comma separated columns from proxy sites (proxydb.net etc.)
        e.g.  185.199.228.220  65535  Socks5  Elite  US
      • Lines that include extra metadata (country, anonymity, speed) – these
        are parsed best-effort and the extra fields are stored.
    """
    entries: List[ProxyEntry] = []
    seen: set = set()

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        host_val = ""
        port_val = 0
        proto_val = "http"
        auth_val = ""
        rest = ""

        # Try colon-based format first (URL-style or host:port)
        m = _PROXY_RE.search(line)
        if m:
            host_val = m.group("host")
            try:
                port_val = int(m.group("port"))
            except ValueError:
                continue
            if not (1 <= port_val <= 65535):
                continue
            proto_val = (m.group("proto") or "http").lower()
            auth_val = m.group("auth") or ""
            rest = line[m.end():]
        else:
            # Try tab/space separated table row: IP  PORT  [PROTO]  [ANON]  [CC]  ...
            tm = _TABULAR_RE.match(line)
            if not tm:
                continue
            host_val = tm.group("host")
            try:
                port_val = int(tm.group("port"))
            except ValueError:
                continue
            if not (1 <= port_val <= 65535):
                continue
            rest = line[tm.end():]

        if not host_val:
            continue

        key = f"{host_val}:{port_val}"
        if key in seen:
            continue
        seen.add(key)

        # Best-effort metadata extraction from the rest of the line
        lower_rest = rest.lower()
        anonymity_val = "unknown"
        for level in ANONYMITY_LEVELS:
            if level in lower_rest:
                anonymity_val = level
                break

        # Protocol override from the rest of the line (for tabular rows)
        for pt in PROXY_TYPES:
            if pt in lower_rest:
                proto_val = pt
                break

        # Country code: look for 2-letter uppercase code in the remainder
        country_val = ""
        cc_match = re.search(r'\b([A-Z]{2})\b', rest)
        if cc_match:
            country_val = cc_match.group(1)

        entries.append(ProxyEntry(
            raw=line, host=host_val, port=port_val, proto=proto_val, auth=auth_val,
            anonymity=anonymity_val, country_code=country_val,
        ))

    return entries


def filter_entries(
    entries: List[ProxyEntry],
    types: Optional[List[str]] = None,
    anonymity: Optional[List[str]] = None,
    country_codes: Optional[List[str]] = None,
    working_only: bool = False,
) -> List[ProxyEntry]:
    """Return a filtered subset of proxy entries."""
    result = []
    types_lower = [t.lower() for t in types] if types else []
    anon_lower = [a.lower() for a in anonymity] if anonymity else []
    cc_upper = [c.upper() for c in country_codes] if country_codes else []

    for e in entries:
        if types_lower and e.proto not in types_lower:
            continue
        # Anonymity filter: skip if the entry's anonymity is not in the allowed list.
        # Entries with "unknown" anonymity are kept unless the filter explicitly
        # excludes unknowns (i.e. "unknown" is not in anon_lower).
        if anon_lower and e.anonymity not in anon_lower:
            continue
        if cc_upper and e.country_code.upper() not in cc_upper:
            continue
        if working_only and e.working is not True:
            continue
        result.append(e)
    return result


def test_proxy(
    entry: ProxyEntry,
    timeout: int = 8,
    test_url: str = _TEST_URLS[0],
) -> ProxyEntry:
    """Test a single proxy entry in-place and return it."""
    proxy_dict = entry.as_requests_dict
    start = time.perf_counter()
    try:
        resp = requests.get(
            test_url,
            proxies=proxy_dict,
            timeout=timeout,
            verify=False,
            allow_redirects=True,
        )
        elapsed = int((time.perf_counter() - start) * 1000)
        if resp.status_code < 500:
            entry.working = True
            entry.latency_ms = elapsed
        else:
            entry.working = False
    except Exception:
        entry.working = False
    return entry


def test_proxies_concurrent(
    entries: List[ProxyEntry],
    timeout: int = 8,
    max_workers: int = 50,
    progress_callback: Optional[Callable[[int, int], None]] = None,
) -> List[ProxyEntry]:
    """Test all entries concurrently.  Returns the same list (mutated in-place)."""
    total = len(entries)
    done_count = 0
    lock = threading.Lock()

    def _test(entry: ProxyEntry) -> ProxyEntry:
        nonlocal done_count
        result = test_proxy(entry, timeout=timeout)
        with lock:
            done_count += 1
            if progress_callback:
                progress_callback(done_count, total)
        return result

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(_test, e) for e in entries]
        concurrent.futures.wait(futures)

    return entries


def save_proxy_list(
    entries: List[ProxyEntry],
    filepath: str,
    fmt: str = "url",
) -> int:
    """Write proxy entries to *filepath*.

    fmt options:
      • 'url'     – protocol://[user:pass@]host:port
      • 'hostport' – host:port  (plain, no protocol)
      • 'csv'     – host,port,protocol,anonymity,country,latency_ms
    """
    lines = []
    for e in entries:
        if fmt == "hostport":
            lines.append(f"{e.host}:{e.port}")
        elif fmt == "csv":
            lines.append(
                f"{e.host},{e.port},{e.proto},{e.anonymity},"
                f"{e.country_code},{e.latency_ms}"
            )
        else:
            lines.append(e.url)

    with open(filepath, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
        if lines:
            fh.write("\n")
    return len(lines)
