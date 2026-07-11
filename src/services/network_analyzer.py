import ipaddress
import logging
import socket

from src.utils.http import build_session

logger = logging.getLogger(__name__)


class NetworkAnalyzer:
    def __init__(self):
        self.my_public_ip: str | None = None
        self.my_public_ip_v6: str | None = None
        self.my_local_ip: str = "127.0.0.1"
        self.my_local_ip_v6: str | None = None
        self.my_isp: str = "Unknown"
        self.my_city: str = "Unknown"
        self.my_region: str = "Unknown"
        self.my_country: str = "Unknown"
        self.my_lat: float = 20.0
        self.my_lon: float = 0.0
        self._session = build_session(5)
        self._detect()

    def _detect(self) -> None:
        self._detect_local_ipv4()
        self._detect_local_ipv6()
        self._detect_public_ips()

    def _detect_local_ipv4(self) -> None:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            self.my_local_ip = s.getsockname()[0]
            s.close()
        except OSError:
            pass

    def _detect_local_ipv6(self) -> None:
        try:
            s6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            s6.connect(("2001:4860:4860::8888", 80))
            self.my_local_ip_v6 = s6.getsockname()[0]
            s6.close()
        except OSError:
            self.my_local_ip_v6 = None

    def _detect_public_ips(self) -> None:
        try:
            r = self._session.get("https://api.ipify.org?format=json", timeout=5)
            self.my_public_ip = r.json().get("ip")
        except Exception:
            self.my_public_ip = self.my_local_ip

        try:
            r6 = self._session.get("https://api64.ipify.org?format=json", timeout=5)
            ip = r6.json().get("ip", "")
            if ":" in ip:
                self.my_public_ip_v6 = ip
        except Exception:
            self.my_public_ip_v6 = None

        self._geolocate()

    def _geolocate(self) -> None:
        for scheme in ("https", "http"):
            try:
                r = self._session.get(
                    f"{scheme}://ip-api.com/json/"
                    "?fields=status,isp,city,regionName,country,lat,lon,query",
                    timeout=5, headers={"User-Agent": "VoIPAnalyzer/3.2.0"})
                d = r.json()
                if d.get("status") == "success":
                    self.my_public_ip = self.my_public_ip or d.get("query")
                    self.my_isp = d.get("isp", "Unknown")
                    self.my_city = d.get("city", "Unknown")
                    self.my_region = d.get("regionName", "Unknown")
                    self.my_country = d.get("country", "Unknown")
                    self.my_lat = float(d.get("lat", 20.0) or 20.0)
                    self.my_lon = float(d.get("lon", 0.0) or 0.0)
                    return
            except Exception:
                continue

    def is_my_ip(self, ip: str | None) -> bool:
        if not ip:
            return False
        if ip in (self.my_public_ip, self.my_local_ip,
                  self.my_public_ip_v6, self.my_local_ip_v6):
            return True
        try:
            addr = ipaddress.ip_address(ip)
            if addr.is_loopback or addr.is_link_local or addr.is_private:
                return True
            if addr.is_reserved:
                return True
        except ValueError:
            pass
        return False
