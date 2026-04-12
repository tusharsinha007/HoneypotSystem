"""
LLMPot — GeoIP Lookup
Free IP geolocation using ip-api.com (45 requests/minute).
"""

import time
import threading
import requests
from typing import Optional
from pathlib import Path
import sys
import json

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from config import GEOIP_API_URL, GEOIP_RATE_LIMIT, GEOIP_CACHE_TTL


class GeoIPLookup:
    """Thread-safe GeoIP lookup with caching and rate limiting."""

    def __init__(self):
        self._cache = {}
        self._cache_times = {}
        self._lock = threading.Lock()
        self._request_times = []
        self._rate_lock = threading.Lock()

    def _rate_limit(self):
        """Enforce rate limiting (max GEOIP_RATE_LIMIT requests per minute)."""
        with self._rate_lock:
            now = time.time()
            # Remove requests older than 60 seconds
            self._request_times = [t for t in self._request_times if now - t < 60]

            if len(self._request_times) >= GEOIP_RATE_LIMIT:
                # Wait until the oldest request expires
                wait_time = 60 - (now - self._request_times[0]) + 0.1
                if wait_time > 0:
                    time.sleep(wait_time)

            self._request_times.append(time.time())

    def lookup(self, ip: str) -> Optional[dict]:
        """
        Look up geographic information for an IP address.

        Returns dict with keys:
            country, countryCode, regionName, city,
            lat, lon, isp, org, as, query
        """
        # Skip private/local IPs
        if self._is_private_ip(ip):
            return self._private_ip_result(ip)

        # Check cache
        with self._lock:
            if ip in self._cache:
                cache_age = time.time() - self._cache_times.get(ip, 0)
                if cache_age < GEOIP_CACHE_TTL:
                    return self._cache[ip]

        # Rate limit
        self._rate_limit()

        try:
            response = requests.get(
                f"{GEOIP_API_URL}{ip}",
                params={
                    "fields": "status,country,countryCode,regionName,city,"
                              "lat,lon,isp,org,as,query"
                },
                timeout=5
            )
            data = response.json()

            if data.get("status") == "success":
                with self._lock:
                    self._cache[ip] = data
                    self._cache_times[ip] = time.time()
                return data
            else:
                return self._unknown_result(ip)

        except (requests.RequestException, json.JSONDecodeError):
            return self._unknown_result(ip)

    def bulk_lookup(self, ips: list) -> dict:
        """Look up multiple IPs. Returns {ip: geo_data}."""
        results = {}
        unique_ips = list(set(ips))
        for ip in unique_ips:
            results[ip] = self.lookup(ip)
        return results

    @staticmethod
    def _is_private_ip(ip: str) -> bool:
        """Check if an IP is private/local."""
        private_prefixes = (
            "10.", "172.16.", "172.17.", "172.18.", "172.19.",
            "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
            "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
            "172.30.", "172.31.", "192.168.", "127.", "0.", "169.254."
        )
        return ip.startswith(private_prefixes) or ip == "::1"

    @staticmethod
    def _private_ip_result(ip: str) -> dict:
        """Return a result for private IPs."""
        return {
            "country": "Local Network",
            "countryCode": "LO",
            "regionName": "Private",
            "city": "Local",
            "lat": 0.0,
            "lon": 0.0,
            "isp": "Private Network",
            "org": "Private",
            "as": "",
            "query": ip,
        }

    @staticmethod
    def _unknown_result(ip: str) -> dict:
        """Return a fallback result for failed lookups."""
        return {
            "country": "Unknown",
            "countryCode": "XX",
            "regionName": "Unknown",
            "city": "Unknown",
            "lat": 0.0,
            "lon": 0.0,
            "isp": "Unknown",
            "org": "Unknown",
            "as": "",
            "query": ip,
        }
