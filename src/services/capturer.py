import logging
import queue
import threading
import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from src.config import AppConfig
from src.database.repository import PeerRepository, SessionRepository
from src.models.ip_info import IPInfo
from src.models.packet import PacketInfo
from src.models.session import SessionReport
from src.plugins.manager import PluginManager
from src.plugins.whatsapp import WhatsAppPlugin
from src.services.ip_intel import IPIntelligence
from src.services.network_analyzer import NetworkAnalyzer
from src.services.stun import describe as describe_stun
from src.services.stun import parse_stun

logger = logging.getLogger(__name__)

HAS_SCAPY = False
try:
    from scapy.all import IP, TCP, UDP, IPv6, Raw, conf, sniff
    conf.verb = 0
    HAS_SCAPY = True
except ImportError:
    pass


class PacketCapturer:
    def __init__(self, config: AppConfig, session_repo: SessionRepository,
                 peer_repo: PeerRepository,
                 intel_service: IPIntelligence,
                 analyzer: NetworkAnalyzer | None = None):
        self.config = config
        self.session_repo = session_repo
        self.peer_repo = peer_repo
        if analyzer is not None:
            self.analyzer = analyzer
        else:
            try:
                self.analyzer = NetworkAnalyzer(lazy=True)
            except Exception:
                logger.exception("Failed to init NetworkAnalyzer")
                self.analyzer = None
        if intel_service is None:
            raise ValueError("intel_service is required")
        self.intel = intel_service
        try:
            self.plugins = PluginManager()
        except Exception:
            logger.exception("Failed to init PluginManager")
            self.plugins = None
        self._resolver_thread = None
        self._dispatcher_thread = None

        self._resolver_queue: queue.Queue[str] = queue.Queue()
        self._packet_queue: queue.Queue[PacketInfo] = queue.Queue()
        self._stop_event = threading.Event()

        self.running = False
        self.captured = 0
        self.total_bytes = 0
        self.start_time: float | None = None
        self._lock = threading.Lock()
        self._ip_stats: dict[str, dict] = defaultdict(
            lambda: {"packets": 0, "bytes": 0, "inbound": 0, "outbound": 0,
                     "stun": 0, "first_seen": "", "last_seen": ""}
        )
        self._all_ips: dict[str, IPInfo] = {}
        self._p2p_candidates: set = set()
        self._relay_ips: set = set()
        self._stun_seen: set = set()
        self._forced_types: dict[str, str] = {}
        self._call_peer_ips: set = set()  # XOR-PEER-ADDRESS from STUN/TURN = actual remote user
        self._media_peer_ips: set = set()  # RTP/RTCP endpoints
        self._mode: str = "UNKNOWN"
        self._signal_callbacks: dict[str, list] = defaultdict(list)

    def on(self, event: str, callback) -> None:
        self._signal_callbacks[event].append(callback)

    def _emit(self, event: str, *args) -> None:
        for cb in self._signal_callbacks.get(event, []):
            try:
                cb(*args)
            except Exception as e:
                logger.error("Signal handler error: %s", e)

    def get_intel(self, ip: str) -> IPInfo:
        return self.intel.get_intel(ip)

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
            self._stun_seen.clear()
            self._forced_types.clear()

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
            self._emit("error", "Permission denied")
        except Exception as e:
            logger.exception("Capture error")
            self._emit("error", f"Capture error: {e}")
        finally:
            self.running = False

    def stop(self) -> None:
        try:
            self._stop_event.set()
        except Exception:
            pass
        self.running = False
        for tname in ("_resolver_thread", "_dispatcher_thread"):
            try:
                t = getattr(self, tname, None)
                if t and hasattr(t, "is_alive") and t.is_alive():
                    try:
                        t.join(timeout=1.0)
                    except Exception:
                        pass
            except Exception:
                pass
        self._resolver_thread = None
        self._dispatcher_thread = None

    def _resolver_loop(self) -> None:
        try:
            while not self._stop_event.is_set():
                try:
                    ip = self._resolver_queue.get(timeout=0.5)
                except queue.Empty:
                    continue
                except Exception:
                    continue
                try:
                    if not hasattr(self, "intel") or self.intel is None:
                        continue
                    intel = self.intel.get_intel(ip)
                    if intel is None:
                        continue
                    with self._lock:
                        self._all_ips[ip] = intel
                        stats = dict(self._ip_stats.get(ip, {}))
                    try:
                        classification = getattr(intel, "classification", None)
                    except Exception:
                        classification = None
                    if ip in self._forced_types:
                        classification = self._forced_types[ip]
                    self._emit("peer_update", ip, intel, stats, classification)
                except Exception as e:
                    logger.error("Resolver error: %s", e)
        except Exception:
            logger.exception("Resolver loop crashed")

    def _dispatcher_loop(self) -> None:
        try:
            while not self._stop_event.is_set() or not self._packet_queue.empty():
                try:
                    pkt_info = self._packet_queue.get(timeout=0.5)
                    try:
                        self._emit("packet", pkt_info)
                    except Exception:
                        pass
                except queue.Empty:
                    continue
                except Exception:
                    continue
        except Exception:
            logger.exception("Dispatcher loop crashed")

    def _process_packet(self, pkt: Any) -> None:
        try:
            if not getattr(self, "running", False):
                return
            if self._stop_event.is_set():
                return
            analyzer = getattr(self, "analyzer", None)
            if analyzer is None:
                return
            if not hasattr(self, "intel") or self.intel is None:
                return
            plugins = getattr(self, "plugins", None)
            try:
                if pkt.haslayer(IP):
                    src, dst, ver = pkt[IP].src, pkt[IP].dst, 4
                elif pkt.haslayer(IPv6):
                    src, dst, ver = pkt[IPv6].src, pkt[IPv6].dst, 6
                else:
                    return
            except Exception:
                return

            try:
                if analyzer.is_my_ip(src) and analyzer.is_my_ip(dst):
                    return

                if analyzer.is_my_ip(src) and not analyzer.is_my_ip(dst):
                    peer, direction = dst, "outbound"
                elif analyzer.is_my_ip(dst) and not analyzer.is_my_ip(src):
                    peer, direction = src, "inbound"
                else:
                    return

                if analyzer.is_my_ip(peer):
                    return
            except Exception:
                return

            try:
                if pkt.haslayer(UDP):
                    proto, sport, dport = "UDP", pkt[UDP].sport, pkt[UDP].dport
                elif pkt.haslayer(TCP):
                    proto, sport, dport = "TCP", pkt[TCP].sport, pkt[TCP].dport
                else:
                    proto, sport, dport = "Unknown", 0, 0
            except Exception:
                proto, sport, dport = "Unknown", 0, 0

            stun = None
            try:
                if pkt.haslayer(Raw):
                    stun = parse_stun(bytes(pkt[Raw]))
            except Exception:
                stun = None
            is_stun = stun is not None

            now_str = datetime.now(timezone.utc).strftime("%H:%M:%S")
            try:
                pkt_len = len(pkt)
            except Exception:
                pkt_len = 0

            try:
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
                        try:
                            try:
                                self._all_ips[peer] = self.intel._minimal(peer)
                            except Exception:
                                try:
                                    self._all_ips[peer] = self.intel.get_intel(peer)
                                except Exception:
                                    self._all_ips[peer] = None
                        except Exception:
                            self._all_ips[peer] = None
                        if self._all_ips.get(peer) is None:
                            pass  # will handle below
                        else:
                            try:
                                self._resolver_queue.put(peer)
                            except Exception:
                                pass
                            try:
                                self._emit("new_peer", peer, self._all_ips[peer], dict(stats), "UNKNOWN")
                            except Exception:
                                pass

                    if peer not in self._all_ips or self._all_ips.get(peer) is None:
                        pass
                    else:
                        intel = self._all_ips[peer]
                    try:
                        if plugins is not None:
                            ip_type = plugins.classify(pkt, peer, stats, intel)
                        else:
                            ip_type = "UNKNOWN"
                    except Exception:
                        ip_type = "UNKNOWN"
                    # Force peer type for media traffic
                    try:
                        if peer in self._media_peer_ips or peer in self._call_peer_ips:
                            ip_type = "P2P_PEER"
                    except Exception:
                        pass

                    try:
                        if ip_type == "P2P_PEER":
                            self._p2p_candidates.add(peer)
                        elif ip_type == "RELAY":
                            self._relay_ips.add(peer)
                    except Exception:
                        pass

                    try:
                        self._update_mode()
                    except Exception:
                        pass
                    try:
                        if plugins is not None:
                            protocol_name = plugins.detect_protocol(pkt)
                        else:
                            protocol_name = proto
                    except Exception:
                        protocol_name = proto
            except Exception:
                return

            try:
                skip = {peer}
                try:
                    if analyzer is not None:
                        my_ip = getattr(analyzer, "my_public_ip", None)
                        if my_ip:
                            skip.add(my_ip)
                except Exception:
                    pass
                pkt_info = PacketInfo(
                    id=self.captured, time=now_str,
                    src=src, dst=dst, sport=sport, dport=dport,
                    proto=proto, length=pkt_len, peer=peer,
                    direction=direction, ip_type=ip_type, ver=ver,
                    isp=getattr(intel, "isp", None), city=getattr(intel, "city", None), country=getattr(intel, "country", None),
                    lat=getattr(intel, "lat", None), lon=getattr(intel, "lon", None),
                    is_stun=is_stun, protocol_name=protocol_name,
                    stun_info=describe_stun(stun, skip) if stun else ""
                )
                try:
                    self._packet_queue.put(pkt_info)
                except Exception:
                    pass
            except Exception:
                pass

            if stun:
                try:
                    self._register_stun(stun)
                except Exception:
                    logger.debug("STUN peer registration failed")

        except Exception as e:
            logger.debug("Packet parse error: %s", e)

    def _register_stun(self, stun: dict) -> None:
        """Turn STUN/TURN addresses into peers, so relayed call users appear."""
        analyzer = getattr(self, "analyzer", None)
        labels = {"peer": "PEER", "relayed": "RELAY"}
        for ip, port, kind in stun.get("addresses", []):
            if kind not in labels:
                continue
            if WhatsAppPlugin.is_noise_ip(ip):
                continue
            if analyzer is not None:
                try:
                    if analyzer.is_my_ip(ip):
                        continue
                except Exception:
                    continue
            # XOR-PEER-ADDRESS is the actual remote user in a call - highest priority
            if kind == "peer":
                ip_type = "P2P_PEER"
                self._call_peer_ips.add(ip)
                self._forced_types[ip] = "P2P_PEER"
            else:
                ip_type = "RELAY"
            with self._lock:
                if ip in self._all_ips:
                    # Update existing
                    self._all_ips[ip]
                    self._forced_types[ip] = ip_type
                    if ip_type == "P2P_PEER":
                        self._p2p_candidates.add(ip)
                        if ip in self._relay_ips:
                            self._relay_ips.discard(ip)
                    else:
                        self._relay_ips.add(ip)
                    stats = self._ip_stats.get(ip)
                    if stats:
                        stats["stun"] += 1
                        snapshot = dict(stats)
                    else:
                        snapshot = {"packets": 1, "bytes": 0, "inbound": 0, "outbound": 0}
                    try:
                        intel = self._all_ips[ip]
                        self._emit("peer_update", ip, intel, snapshot, ip_type)
                    except Exception:
                        pass
                    self._stun_seen.add(ip)
                    try:
                        self._update_mode()
                    except Exception:
                        pass
                    detail = f"{labels[kind]} {ip}:{port}"
                    if stun.get("software"):
                        detail += f" app={stun['software']}"
                    if stun.get("username"):
                        detail += f" user={stun['username']}"
                    try:
                        self._emit("log", f"STUN {detail}")
                    except Exception:
                        pass
                    continue
                self._stun_seen.add(ip)
                try:
                    intel = self.intel._minimal(ip)
                except Exception:
                    intel = None
                if intel is None:
                    continue
                self._all_ips[ip] = intel
                self._forced_types[ip] = ip_type
                if ip_type == "P2P_PEER":
                    self._p2p_candidates.add(ip)
                else:
                    self._relay_ips.add(ip)
                stats = self._ip_stats[ip]
                stats["stun"] += 1
                stats["last_seen"] = datetime.now().isoformat()
                if not stats["first_seen"]:
                    stats["first_seen"] = stats["last_seen"]
                snapshot = dict(stats)
            try:
                self._resolver_queue.put(ip)
            except Exception:
                pass
            try:
                self._emit("new_peer", ip, intel, snapshot, ip_type)
            except Exception:
                pass
            detail = f"{labels[kind]} {ip}:{port}"
            if stun.get("software"):
                detail += f" app={stun['software']}"
            if stun.get("username"):
                detail += f" user={stun['username']}"
            try:
                self._emit("log", f"STUN {detail}")
            except Exception:
                pass
            try:
                self._update_mode()
            except Exception:
                pass

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
        snapshot_peers: dict[str, tuple[IPInfo, dict, str]] = {}
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

    def get_live_stats(self) -> tuple[int, float, float, int, int, float]:
        with self._lock:
            elapsed = (time.time() - self.start_time) if self.start_time else 1
            elapsed = max(elapsed, 0.1)
            pps = self.captured / elapsed
            bps = self.total_bytes / elapsed / 1024
            return (self.captured, pps, bps,
                    len(self._p2p_candidates), len(self._relay_ips), elapsed)
