import logging
import queue
import threading
import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

from src.config import AppConfig
from src.database.repository import PeerRepository, SessionRepository
from src.models.ip_info import IPInfo
from src.models.packet import PacketInfo
from src.models.session import SessionReport
from src.plugins.manager import PluginManager
from src.services.ip_intel import IPIntelligence
from src.services.network_analyzer import NetworkAnalyzer

logger = logging.getLogger(__name__)

HAS_SCAPY = False
try:
    from scapy.all import IP, IPv6, Raw, TCP, UDP, conf, sniff
    conf.verb = 0
    HAS_SCAPY = True
except ImportError:
    pass


class PacketCapturer:
    def __init__(self, config: AppConfig, session_repo: SessionRepository,
                 peer_repo: PeerRepository,
                 intel_service: Optional[IPIntelligence] = None):
        self.config = config
        self.session_repo = session_repo
        self.peer_repo = peer_repo
        self.analyzer = NetworkAnalyzer()
        self.intel = intel_service or IPIntelligence.__new__(IPIntelligence)
        self.plugins = PluginManager()

        self._resolver_queue: "queue.Queue[str]" = queue.Queue()
        self._packet_queue: "queue.Queue[PacketInfo]" = queue.Queue()
        self._stop_event = threading.Event()

        self.running = False
        self.captured = 0
        self.total_bytes = 0
        self.start_time: Optional[float] = None
        self._lock = threading.Lock()
        self._ip_stats: Dict[str, Dict] = defaultdict(
            lambda: {"packets": 0, "bytes": 0, "inbound": 0, "outbound": 0,
                     "stun": 0, "first_seen": "", "last_seen": ""}
        )
        self._all_ips: Dict[str, IPInfo] = {}
        self._p2p_candidates: set = set()
        self._relay_ips: set = set()
        self._mode: str = "UNKNOWN"
        self._signal_callbacks: Dict[str, list] = defaultdict(list)

    def on(self, event: str, callback) -> None:
        self._signal_callbacks[event].append(callback)

    def _emit(self, event: str, *args) -> None:
        for cb in self._signal_callbacks.get(event, []):
            try:
                cb(*args)
            except Exception as e:
                logger.error("Signal handler error: %s", e)

    def get_intel(self, ip: str) -> IPInfo:
        if ip in self.intel.memory_cache:
            return self.intel.memory_cache[ip]
        return self.intel._minimal(ip)

    def set_intel(self, intel_service: IPIntelligence) -> None:
        self.intel = intel_service

    def run(self) -> None:
        if not HAS_SCAPY:
            self._emit("error", "Scapy not installed")
            return

        self.running = True
        self._stop_event.clear()
        self.start_time = time.time()
        with self._lock:
            self.captured = 0
            self.total_bytes = 0
            self._ip_stats.clear()
            self._all_ips.clear()
            self._p2p_candidates.clear()
            self._relay_ips.clear()

        self._resolver_thread = threading.Thread(
            target=self._resolver_loop, daemon=True, name="IPResolver")
        self._dispatcher_thread = threading.Thread(
            target=self._dispatcher_loop, daemon=True, name="PacketDispatcher")
        self._resolver_thread.start()
        self._dispatcher_thread.start()

        clauses = []
        for s, e in self.config.whatsapp_ports:
            clauses.append(f"port {s}" if s == e else f"portrange {s}-{e}")
        bpf = f"(ip or ip6) and (udp or tcp) and ({' or '.join(clauses)})"

        try:
            self._emit("log", f"BPF: {bpf}")
            iface = self.config.interface or None
            if iface:
                self._emit("log", f"Interface: {iface}")
            sniff(
                filter=bpf, prn=self._process_packet, store=False,
                iface=iface,
                stop_filter=lambda _: self._stop_event.is_set()
            )
        except PermissionError:
            self._emit("error", "Permission denied - run as Administrator/root")
        except Exception as e:
            logger.exception("Capture error")
            self._emit("error", f"Capture error: {e}")
        finally:
            self.running = False

    def stop(self) -> None:
        self._stop_event.set()
        self.running = False

    def _resolver_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                ip = self._resolver_queue.get(timeout=0.5)
            except queue.Empty:
                continue
            try:
                intel = self.intel.get_intel(ip)
                with self._lock:
                    self._all_ips[ip] = intel
                    stats = dict(self._ip_stats.get(ip, {}))
                self._emit("peer_update", ip, intel, stats, intel.classification)
            except Exception as e:
                logger.error("Resolver error: %s", e)

    def _dispatcher_loop(self) -> None:
        while not self._stop_event.is_set() or not self._packet_queue.empty():
            try:
                pkt_info = self._packet_queue.get(timeout=0.5)
                self._emit("packet", pkt_info)
            except queue.Empty:
                continue
            except Exception:
                pass

    def _process_packet(self, pkt: Any) -> None:
        if not self.running:
            return
        try:
            if pkt.haslayer(IP):
                src, dst, ver = pkt[IP].src, pkt[IP].dst, 4
            elif pkt.haslayer(IPv6):
                src, dst, ver = pkt[IPv6].src, pkt[IPv6].dst, 6
            else:
                return

            if self.analyzer.is_my_ip(src) and self.analyzer.is_my_ip(dst):
                return

            if self.analyzer.is_my_ip(src) and not self.analyzer.is_my_ip(dst):
                peer, direction = dst, "outbound"
            elif self.analyzer.is_my_ip(dst) and not self.analyzer.is_my_ip(src):
                peer, direction = src, "inbound"
            else:
                return

            if pkt.haslayer(UDP):
                proto, sport, dport = "UDP", pkt[UDP].sport, pkt[UDP].dport
            elif pkt.haslayer(TCP):
                proto, sport, dport = "TCP", pkt[TCP].sport, pkt[TCP].dport
            else:
                proto, sport, dport = "Unknown", 0, 0

            is_stun = False
            if pkt.haslayer(Raw):
                try:
                    payload = bytes(pkt[Raw])
                    if len(payload) >= 8:
                        magic = int.from_bytes(payload[4:8], "big")
                        is_stun = (magic == 0x2112A442)
                except Exception:
                    pass

            now_str = datetime.now(timezone.utc).strftime("%H:%M:%S")
            pkt_len = len(pkt)

            with self._lock:
                self.captured += 1
                self.total_bytes += pkt_len
                stats = self._ip_stats[peer]
                stats["packets"] += 1
                stats["bytes"] += pkt_len
                stats[direction] += 1
                if is_stun:
                    stats["stun"] += 1
                if not stats["first_seen"]:
                    stats["first_seen"] = datetime.now().isoformat()
                stats["last_seen"] = datetime.now().isoformat()

                if peer not in self._all_ips:
                    self._all_ips[peer] = self.intel._minimal(peer)
                    self._resolver_queue.put(peer)
                    self._emit("new_peer", peer, self._all_ips[peer], dict(stats), "UNKNOWN")

                intel = self._all_ips[peer]
                ip_type = self.plugins.classify(pkt, peer, stats, intel)

                if ip_type == "P2P_PEER":
                    self._p2p_candidates.add(peer)
                elif ip_type == "RELAY":
                    self._relay_ips.add(peer)

                self._update_mode()
                protocol_name = self.plugins.detect_protocol(pkt)

            pkt_info = PacketInfo(
                id=self.captured, time=now_str,
                src=src, dst=dst, sport=sport, dport=dport,
                proto=proto, length=pkt_len, peer=peer,
                direction=direction, ip_type=ip_type, ver=ver,
                isp=intel.isp, city=intel.city, country=intel.country,
                lat=intel.lat, lon=intel.lon,
                is_stun=is_stun, protocol_name=protocol_name
            )
            self._packet_queue.put(pkt_info)

        except Exception as e:
            logger.debug("Packet parse error: %s", e)

    def _update_mode(self) -> None:
        p2p = len(self._p2p_candidates)
        relay = len(self._relay_ips)
        if p2p > 0 and relay == 0:
            self._mode = "P2P"
        elif relay > 0 and p2p == 0:
            self._mode = "RELAY"
        elif p2p > 0 and relay > 0:
            self._mode = "MIXED"
        else:
            self._mode = "UNKNOWN"
        self._emit("status", self._mode, p2p, relay)

    def get_report(self) -> SessionReport:
        snapshot_peers: Dict[str, Tuple[IPInfo, Dict, str]] = {}
        with self._lock:
            duration = (time.time() - self.start_time) if self.start_time else 0
            countries = set()
            for ip, intel in self._all_ips.items():
                if intel.country and intel.country not in ("Unknown", "..."):
                    countries.add(intel.country)
            for ip, stats in self._ip_stats.items():
                intel = self._all_ips.get(ip, self.intel._minimal(ip))
                snapshot_peers[ip] = (intel, dict(stats),
                                      "P2P_PEER" if ip in self._p2p_candidates
                                      else "RELAY" if ip in self._relay_ips
                                      else "UNKNOWN")
            unknown = (len(self._all_ips) - len(self._p2p_candidates)
                       - len(self._relay_ips))

        for ip, (intel, stats, ip_type) in snapshot_peers.items():
            self.peer_repo.save(ip, intel, stats,
                                stats.get("first_seen", ""),
                                stats.get("last_seen", ""))

        return SessionReport(
            timestamp=datetime.now(timezone.utc).isoformat(),
            duration_seconds=duration,
            total_packets=self.captured,
            total_bytes=self.total_bytes,
            p2p_count=len(self._p2p_candidates),
            relay_count=len(self._relay_ips),
            unknown_count=max(0, unknown),
            countries=sorted(countries),
            protocol="WhatsApp"
        )

    def get_live_stats(self) -> Tuple[int, float, float, int, int, float]:
        with self._lock:
            elapsed = (time.time() - self.start_time) if self.start_time else 1
            elapsed = max(elapsed, 0.1)
            pps = self.captured / elapsed
            bps = self.total_bytes / elapsed / 1024
            return (self.captured, pps, bps,
                    len(self._p2p_candidates), len(self._relay_ips), elapsed)
