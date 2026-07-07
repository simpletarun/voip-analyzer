import logging
import socket
import threading
import time
from typing import Any, Dict, List, Optional

from src.config import AppConfig
from src.database.repository import CacheRepository
from src.models.ip_info import IPInfo
from src.utils.concurrency import WorkerPool

logger = logging.getLogger(__name__)


class IPIntelligence:
    SERVER_ASN = {
        "AS32934": "Meta/Facebook", "AS63949": "Meta Ireland",
        "AS54115": "Fastly CDN", "AS13335": "Cloudflare",
        "AS16509": "Amazon AWS", "AS14618": "Amazon AWS",
        "AS15169": "Google", "AS8075": "Microsoft Azure",
        "AS20940": "Akamai", "AS3356": "Lumen/Level3",
    }

    def __init__(self, cache_repo: CacheRepository, config: AppConfig,
                 enrichment_manager: Any = None):
        self.cache = cache_repo
        self.config = config
        self.enrichment = enrichment_manager
        self.memory_cache: Dict[str, IPInfo] = {}
        self._lock = threading.Lock()
        self._calls: List[float] = []
        self._pool = WorkerPool(max_workers=getattr(config, "max_api_calls_per_min", 40) or 8)

    def _can_call(self) -> bool:
        try:
            import requests
        except ImportError:
            return False
        now = time.time()
        with self._lock:
            self._calls = [t for t in self._calls if now - t < 60]
            return len(self._calls) < self.config.max_api_calls_per_min

    def _record_call(self) -> None:
        with self._lock:
            self._calls.append(time.time())

    def get_intel(self, ip: str) -> IPInfo:
        if ip in self.memory_cache:
            return self.memory_cache[ip]
        cached = self.cache.get(ip)
        if cached:
            self.memory_cache[ip] = cached
            return cached
        if self._can_call():
            result = self._query_api(ip)
            self._calculate_score(result)
            self.memory_cache[ip] = result
            self.cache.set(ip, result, self.config.cache_ttl_hours)
            self._record_call()
            return result
        return self._minimal(ip)

    def _minimal(self, ip: str) -> IPInfo:
        return IPInfo(ip=ip, is_ipv6=":" in ip, classification="UNKNOWN")

    def _query_api(self, ip: str) -> IPInfo:
        info = IPInfo(ip=ip, is_ipv6=":" in ip)
        try:
            import requests
            url = (f"https://ip-api.com/json/{ip}"
                   "?fields=status,isp,org,city,country,as,lat,lon,mobile,proxy,hosting,reverse")
            r = requests.get(url, timeout=self.config.api_timeout,
                             headers={"User-Agent": "VoIPAnalyzer/3.1.0"})
            d = r.json()
            if d.get("status") == "success":
                info.isp = d.get("isp", "Unknown")
                info.org = d.get("org", "Unknown")
                info.city = d.get("city", "Unknown")
                info.country = d.get("country", "Unknown")
                info.lat = float(d.get("lat", 0) or 0)
                info.lon = float(d.get("lon", 0) or 0)
                info.asn = d.get("as", "N/A") or "N/A"
                info.reverse_dns = d.get("reverse")
                info.is_mobile = bool(d.get("mobile", False))
                info.is_proxy = bool(d.get("proxy", False))
                info.is_hosting = bool(d.get("hosting", False))
            else:
                logger.warning("ip-api.com returned status '%s' for %s",
                               d.get("status"), ip)
        except Exception as e:
            logger.warning("IP lookup failed for %s: %s", ip, e)

        if not info.reverse_dns:
            try:
                old_timeout = socket.getdefaulttimeout()
                socket.setdefaulttimeout(5.0)
                try:
                    info.reverse_dns = socket.gethostbyaddr(ip)[0]
                finally:
                    socket.setdefaulttimeout(old_timeout)
            except Exception:
                pass

        if self.enrichment is not None:
            try:
                extra = self.enrichment.enrich(ip)
                if extra:
                    info.enrichment.update(extra)
                    info.abuse_score = extra.get("abuse_score") or info.abuse_score
                    info.fraud_score = extra.get("ipqs_fraud_score") or info.fraud_score
                    if extra.get("ipqs_vpn"):
                        info.is_vpn = True
                    if extra.get("ipqs_tor"):
                        info.is_tor = True
                    if extra.get("ipqs_proxy"):
                        info.is_proxy = True
                    if extra.get("shodan_ports"):
                        info.open_ports = extra.get("shodan_ports")
            except Exception as exc:  # noqa: BLE001
                logger.warning("Enrichment merge failed for %s: %s", ip, exc)
        return info

    def _calculate_score(self, info: IPInfo) -> None:
        score = 0
        if info.is_hosting:
            score += 50
        if info.is_proxy:
            score += 40
        if info.is_vpn:
            score += 35
        if info.is_tor:
            score += 60
        if info.abuse_score is not None and info.abuse_score >= 50:
            score += 45
        if info.fraud_score is not None and info.fraud_score >= 75:
            score += 40
        asn = (info.asn or "").upper()
        org = (info.org or "").lower()
        for pattern in self.SERVER_ASN:
            if pattern in asn:
                score += 40
                break
        cloud_keywords = ["aws", "azure", "google", "cloudflare", "akamai", "meta", "facebook"]
        if any(kw in org for kw in cloud_keywords):
            score += 30
        if info.is_mobile:
            score -= 40
        if not info.is_hosting and not info.is_proxy and score == 0:
            score -= 20
        info.score = score
        if score > 30:
            info.classification = "RELAY"
            info.confidence = min(0.99, 0.5 + (score - 30) / 100)
        elif score < -10:
            info.classification = "P2P_PEER"
            info.confidence = min(0.99, 0.5 + abs(score + 10) / 100)
        else:
            info.classification = "UNKNOWN"
            info.confidence = 0.3
