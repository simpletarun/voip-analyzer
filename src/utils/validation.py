"""Input validation and sanitization helpers.

All externally supplied values (IPs, search terms) should be validated through
these helpers before they reach the network or database layers. This is the
first line of defence against malformed input and reduces the attack surface
for injection-style bugs.
"""

import re
from typing import Optional

from src.utils.errors import ValidationError

_IPV4_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$"
)


def validate_ip(value: str) -> str:
    """Validate and normalize an IPv4/IPv6 address.

    Raises ValidationError if the value is not a well-formed IP address.
    """
    if not isinstance(value, str):
        raise ValidationError("IP must be a string", field="ip")
    value = value.strip()
    if not value:
        raise ValidationError("IP address is required", field="ip")
    if len(value) > 45:
        raise ValidationError("IP address too long", field="ip")
    try:
        import ipaddress

        addr = ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValidationError(f"Invalid IP address: {value}", field="ip") from exc
    return str(addr)


def is_public_ip(value: str) -> bool:
    """Return True if the address is a routable public IP (not loopback/private/etc.)."""
    try:
        import ipaddress

        addr = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not (
        addr.is_loopback
        or addr.is_link_local
        or addr.is_private
        or addr.is_reserved
        or addr.is_multicast
    )


def sanitize_text(value: Optional[str], max_len: int = 200) -> str:
    """Strip control characters and clamp length for safe display/storage."""
    if not value:
        return ""
    cleaned = "".join(ch for ch in str(value) if ch.isprintable() or ch in "\t\n")
    return cleaned[:max_len]
