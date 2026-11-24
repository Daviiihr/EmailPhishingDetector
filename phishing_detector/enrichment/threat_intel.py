"""Pluggable, SSRF-safe URL enrichment and external threat intelligence clients."""

from __future__ import annotations

from abc import ABC, abstractmethod
import base64
from datetime import datetime, timezone
import ipaddress
import json
import os
import socket
from typing import Callable
from urllib.error import URLError
from urllib.parse import urlencode, urljoin, urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener, urlopen


def is_safe_public_hostname(hostname: str) -> bool:
    """Resolve hostname and verify none of its IPs are private/loopback/link-local (SSRF guard)."""
    if not hostname:
        return False
    try:
        ip_obj = ipaddress.ip_address(hostname.strip("[]"))
        return ip_obj.is_global
    except ValueError:
        pass

    try:
        infos = socket.getaddrinfo(hostname, None)
    except OSError:
        return False

    if not infos:
        return False
    for info in infos:
        sockaddr = info[4]
        if not sockaddr:
            continue
        try:
            ip_obj = ipaddress.ip_address(sockaddr[0])
            if not ip_obj.is_global:
                return False
        except ValueError:
            return False
    return True


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class SafeRedirectUnshortener:
    """Follows HTTP 3xx redirects safely with hop limits and SSRF protection."""

    def __init__(
        self,
        *,
        max_redirects: int = 5,
        timeout: float = 4.0,
        host_safety_check: Callable[[str], bool] = is_safe_public_hostname,
        http_head: Callable[[str, float], tuple[int, str | None]] | None = None,
    ) -> None:
        self.max_redirects = max_redirects
        self.timeout = timeout
        self._is_safe_host = host_safety_check
        self._http_head = http_head or self._default_head

    def _default_head(self, url: str, timeout: float) -> tuple[int, str | None]:
        opener = build_opener(_NoRedirectHandler)
        req = Request(url, method="HEAD", headers={"User-Agent": "PhishingDetector/1.0"})
        try:
            with opener.open(req, timeout=timeout) as resp:
                return resp.status, resp.headers.get("Location")
        except URLError as exc:
            # urllib raises HTTPError (subclass of URLError) on 3xx when redirect handler returns None
            code = getattr(exc, "code", 0)
            headers = getattr(exc, "headers", None)
            location = headers.get("Location") if headers else None
            return code, location

    def resolve(self, url: str) -> str | None:
        """Return final destination URL if redirected safely, else None."""
        current = url
        visited = {current}
        for _ in range(self.max_redirects):
            parsed = urlparse(current)
            if parsed.scheme not in ("http", "https") or not parsed.hostname:
                return None
            if not self._is_safe_host(parsed.hostname):
                return None
            try:
                status, location = self._http_head(current, self.timeout)
            except Exception:
                return None
            if status in (301, 302, 303, 307, 308) and location:
                next_url = urljoin(current, location)
                if next_url in visited:
                    break
                visited.add(next_url)
                current = next_url
            else:
                break
        return current if current != url else None


class RdapDomainAgeClient:
    """Queries RDAP (rdap.org) to determine domain registration age in days."""

    def __init__(
        self,
        *,
        timeout: float = 4.0,
        fetcher: Callable[[str, float], dict] | None = None,
    ) -> None:
        self.timeout = timeout
        self._fetcher = fetcher or self._default_fetch

    def _default_fetch(self, url: str, timeout: float) -> dict:
        req = Request(url, headers={"Accept": "application/rdap+json", "User-Agent": "PhishingDetector/1.0"})
        with urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8", errors="replace"))

    def get_domain_age_days(self, domain: str) -> int | None:
        if not domain or "." not in domain:
            return None
        try:
            data = self._fetcher(f"https://rdap.org/domain/{domain}", self.timeout)
        except Exception:
            return None
        events = data.get("events", [])
        for ev in events:
            if str(ev.get("eventAction", "")).lower() == "registration":
                date_str = ev.get("eventDate")
                if not date_str:
                    continue
                try:
                    reg_dt = datetime.fromisoformat(str(date_str).replace("Z", "+00:00"))
                    delta = datetime.now(timezone.utc) - reg_dt.astimezone(timezone.utc)
                    return max(0, delta.days)
                except ValueError:
                    continue
        return None


class ThreatIntelProvider(ABC):
    """Base interface for URL/domain threat intelligence reputation providers."""

    name: str = "generic"

    @abstractmethod
    def check_url(self, url: str, domain: str) -> str | None:
        """Return a descriptive hit string if malicious, else None."""
        raise NotImplementedError


class LocalBlocklistProvider(ThreatIntelProvider):
    """Offline local blocklist check against configured malicious domains."""

    name = "local_blocklist"

    def __init__(self, blocklisted_domains: set[str] | None = None) -> None:
        self.blocklisted_domains = {d.lower() for d in (blocklisted_domains or set())}

    def check_url(self, url: str, domain: str) -> str | None:
        dom = domain.lower()
        if not dom:
            return None
        for blocked in self.blocklisted_domains:
            if dom == blocked or dom.endswith(f".{blocked}"):
                return f"local_blocklist:{blocked}"
        return None


class URLhausProvider(ThreatIntelProvider):
    """Abuse.ch URLhaus API client."""

    name = "urlhaus"

    def __init__(self, timeout: float = 4.0, post_json: Callable[[str, bytes, dict, float], dict] | None = None) -> None:
        self.timeout = timeout
        self._post_json = post_json or _default_post_json

    def check_url(self, url: str, domain: str) -> str | None:
        try:
            body = urlencode({"url": url}).encode("utf-8")
            resp = self._post_json(
                "https://urlhaus-api.abuse.ch/v1/url/",
                body,
                {"Content-Type": "application/x-www-form-urlencoded", "User-Agent": "PhishingDetector/1.0"},
                self.timeout,
            )
            if resp.get("query_status") == "ok" and resp.get("url_status") in ("online", "offline"):
                threat = resp.get("threat", "malware_or_phishing")
                return f"urlhaus:{threat}"
        except Exception:
            return None
        return None


class VirusTotalProvider(ThreatIntelProvider):
    """VirusTotal v3 URL reputation client (requires VIRUSTOTAL_API_KEY)."""

    name = "virustotal"

    def __init__(
        self,
        api_key: str | None = None,
        timeout: float = 4.0,
        get_json: Callable[[str, dict, float], dict] | None = None,
    ) -> None:
        self.api_key = api_key or os.environ.get("VIRUSTOTAL_API_KEY")
        self.timeout = timeout
        self._get_json = get_json or _default_get_json

    def check_url(self, url: str, domain: str) -> str | None:
        if not self.api_key:
            return None
        url_id = base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")
        try:
            resp = self._get_json(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                {"x-apikey": self.api_key, "User-Agent": "PhishingDetector/1.0"},
                self.timeout,
            )
            stats = resp.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = int(stats.get("malicious", 0))
            if malicious > 0:
                return f"virustotal:malicious={malicious}"
        except Exception:
            return None
        return None


class GoogleSafeBrowsingProvider(ThreatIntelProvider):
    """Google Safe Browsing v4 API client (requires GOOGLE_SAFE_BROWSING_API_KEY)."""

    name = "google_safe_browsing"

    def __init__(
        self,
        api_key: str | None = None,
        timeout: float = 4.0,
        post_json: Callable[[str, bytes, dict, float], dict] | None = None,
    ) -> None:
        self.api_key = api_key or os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY")
        self.timeout = timeout
        self._post_json = post_json or _default_post_json

    def check_url(self, url: str, domain: str) -> str | None:
        if not self.api_key:
            return None
        payload = {
            "client": {"clientId": "email-phishing-detector", "clientVersion": "1.0.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }
        try:
            resp = self._post_json(
                f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={self.api_key}",
                json.dumps(payload).encode("utf-8"),
                {"Content-Type": "application/json"},
                self.timeout,
            )
            matches = resp.get("matches", [])
            if matches:
                threat_type = matches[0].get("threatType", "SOCIAL_ENGINEERING")
                return f"google_safe_browsing:{threat_type}"
        except Exception:
            return None
        return None


class ThreatIntelEnricher:
    """Facade combining unshortener, RDAP age lookup, and threat intelligence providers."""

    def __init__(
        self,
        *,
        unshortener: SafeRedirectUnshortener | None = None,
        rdap_client: RdapDomainAgeClient | None = None,
        providers: list[ThreatIntelProvider] | None = None,
        blocklisted_domains: set[str] | None = None,
        timeout: float = 4.0,
        max_redirects: int = 5,
    ) -> None:
        self.unshortener = unshortener or SafeRedirectUnshortener(
            max_redirects=max_redirects, timeout=timeout
        )
        self.rdap_client = rdap_client or RdapDomainAgeClient(timeout=timeout)
        self.local_provider = LocalBlocklistProvider(blocklisted_domains)
        self.external_providers: list[ThreatIntelProvider] = (
            providers
            if providers is not None
            else [
                URLhausProvider(timeout=timeout),
                VirusTotalProvider(timeout=timeout),
                GoogleSafeBrowsingProvider(timeout=timeout),
            ]
        )

    def check_local(self, url: str, domain: str) -> list[str]:
        hit = self.local_provider.check_url(url, domain)
        return [hit] if hit else []

    def check_external(self, url: str, domain: str) -> list[str]:
        hits: list[str] = []
        for provider in self.external_providers:
            hit = provider.check_url(url, domain)
            if hit:
                hits.append(hit)
        return hits


def _default_get_json(url: str, headers: dict, timeout: float) -> dict:
    req = Request(url, headers=headers, method="GET")
    with urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8", errors="replace"))


def _default_post_json(url: str, body: bytes, headers: dict, timeout: float) -> dict:
    req = Request(url, data=body, headers=headers, method="POST")
    with urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8", errors="replace"))
