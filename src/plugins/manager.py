import importlib
import logging
import pkgutil
from typing import Any, Dict, List, Optional

from src.models.ip_info import IPInfo
from src.plugins.base import ProtocolPlugin

logger = logging.getLogger(__name__)


class PluginManager:
    def __init__(self, extra_plugins: Optional[List[str]] = None):
        self.plugins: List[ProtocolPlugin] = self._discover()
        if extra_plugins:
            for mod_name in extra_plugins:
                try:
                    mod = importlib.import_module(mod_name)
                    for attr in dir(mod):
                        obj = getattr(mod, attr)
                        if (isinstance(obj, type) and issubclass(obj, ProtocolPlugin)
                                and obj is not ProtocolPlugin):
                            self.plugins.append(obj())
                            logger.info("Loaded external plugin: %s.%s", mod_name, attr)
                except Exception as e:
                    logger.warning("Failed to load plugin %s: %s", mod_name, e)

    def _discover(self) -> List[ProtocolPlugin]:
        plugins: List[ProtocolPlugin] = []
        try:
            import src.plugins as pkg
            for _, mod_name, _ in pkgutil.iter_modules(pkg.__path__):
                if mod_name in ("base", "__init__", "manager"):
                    continue
                try:
                    mod = importlib.import_module(f"src.plugins.{mod_name}")
                    for attr in dir(mod):
                        obj = getattr(mod, attr)
                        if (isinstance(obj, type) and issubclass(obj, ProtocolPlugin)
                                and obj is not ProtocolPlugin):
                            instance = obj()
                            plugins.append(instance)
                            logger.debug("Discovered plugin: %s", instance.name)
                except Exception as e:
                    logger.debug("Plugin discovery %s failed: %s", mod_name, e)
        except Exception as e:
            logger.error("Plugin discovery error: %s", e)
        if not plugins:
            from src.plugins.generic import GenericPlugin
            plugins.append(GenericPlugin())
        return plugins

    def detect_protocol(self, pkt: Any) -> str:
        for plugin in self.plugins:
            desc = plugin.describe(pkt)
            if desc != "Unknown":
                return desc
        return "Unknown"

    def classify(self, pkt: Any, peer: str, stats: Dict, intel: IPInfo) -> str:
        for plugin in self.plugins:
            result = plugin.identify(pkt, peer, stats, intel)
            if result != "UNKNOWN":
                return result
        return "UNKNOWN"
