import ipaddress
import logging
import socket
from typing import Optional

logger = logging.getLogger(__name__)


class NetworkAnalyzer:
    def __init__(self):
        self.my_public_ip: Optional[str] = None
        self.my_public_ip_v6: Optional[str] = None
        self.my_local_ip: str = "127.0.0.1"
        self.my_local_ip_v6: Optional[str] = None
        self.my_isp: str = "Unknown"
        self.my_lat: float = 20.0
        self.my_lon: float = 0.0
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
            import requests
            r = requests.get("https://api.ipify.org?format=json", timeout=5)
            self.my_public_ip = r.json().get("ip")
        except Exception:
            self.my_public_ip = self.my_local_ip

        try:
            import requests
            r6 = requests.get("https://api64.ipify.org?format=json", timeout=5)
            ip = r6.json().get("ip", "")
            if ":" in ip:
                self.my_public_ip_v6 = ip
        except Exception:
            self.my_public_ip_v6 = None

        self._geolocate()

    def _geolocate(self) -> None:
        if not self.my_public_ip:
            return
        try:
            import requests
            r = requests.get(
                f"https://ip-api.com/json/{self.my_public_ip}"
                "?fields=isp,city,country,lat,lon", timeout=5,
                headers={"User-Agent": "VoIPAnalyzer/3.1.0"})
            d = r.json()
            if d.get("status") == "success":
                self.my_isp = d.get("isp", "Unknown")
                self.my_lat = float(d.get("lat", 20.0) or 20.0)
                self.my_lon = float(d.get("lon", 0.0) or 0.0)
        except Exception:
            pass

    def is_my_ip(self, ip: Optional[str]) -> bool:
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
