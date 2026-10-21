"""Domain Input Validator: turns user input into a safe, normalised DNS name."""
from __future__ import annotations

import ipaddress
import re

_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


class InvalidDomain(ValueError):
    pass


def validate_domain(raw: str) -> str:
    """Return a lower-case ASCII domain name or raise InvalidDomain with a clear message."""
    if raw is None:
        raise InvalidDomain("Please enter a domain name.")
    name = raw.strip().lower()
    if not name:
        raise InvalidDomain("Please enter a domain name.")
    if "://" in name or "/" in name or "?" in name or "@" in name or " " in name:
        raise InvalidDomain("Enter only the domain name (for example example.com), not a URL or e-mail address.")
    if ":" in name and not _looks_like_ip(name):
        raise InvalidDomain("Port numbers are not part of a domain name.")
    if _looks_like_ip(name):
        raise InvalidDomain("That is an IP address. DNScope checks domain names, e.g. example.com.")
    name = name.rstrip(".")
    try:
        name = name.encode("idna").decode("ascii")   # internationalised names -> xn-- form
    except UnicodeError as exc:
        raise InvalidDomain("The domain contains characters that cannot be converted to a valid DNS name.") from exc
    if len(name) > 253:
        raise InvalidDomain("A domain name can be at most 253 characters long.")
    labels = name.split(".")
    if len(labels) < 2:
        raise InvalidDomain("Include the top-level domain, for example example.com.")
    for label in labels:
        if not _LABEL.match(label):
            raise InvalidDomain(
                f"'{label or '(empty)'}' is not a valid label: use 1-63 letters, digits or hyphens, "
                "not starting or ending with a hyphen.")
    return name


def _looks_like_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip("[]"))
        return True
    except ValueError:
        return False
