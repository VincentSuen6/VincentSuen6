from __future__ import annotations

import uuid

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


def build_session(timeout: int = 10) -> requests.Session:
    session = requests.Session()

    retry_strategy = Retry(
        total=3,
        backoff_factor=0.5,
        status_forcelist=[502, 503, 504],
        allowed_methods=["GET", "POST", "PUT", "DELETE"],
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry_strategy, pool_connections=4, pool_maxsize=8)
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    # Identify scanner traffic in WAF logs without impersonating a real browser
    session.headers.update(
        {
            "User-Agent": "AegisLoop-Scanner/1.0 (Authorized-Assessment)",
            "X-Assessment-ID": str(uuid.uuid4()),
            "Accept": "application/json",
        }
    )
    return session
