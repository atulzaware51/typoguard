import ipaddress
import re
from urllib.parse import urlparse


_HOST_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.IGNORECASE)


def _canonical_hostname(hostname: str) -> str:
    """Validate a hostname and return its lowercase ASCII/IDNA form."""
    if hostname.endswith(".."):
        raise ValueError("Invalid URL: hostname has multiple trailing dots")
    hostname = hostname.rstrip(".")
    if not hostname:
        raise ValueError("Invalid URL: hostname is empty")

    if ":" in hostname:  # IPv6 literal (urlparse removes its brackets)
        try:
            return ipaddress.IPv6Address(hostname).compressed.lower()
        except ipaddress.AddressValueError as exc:
            raise ValueError("Invalid URL: malformed IPv6 hostname") from exc

    try:
        ascii_host = hostname.encode("idna").decode("ascii").lower()
        ipaddress.IPv4Address(ascii_host)
        return ascii_host
    except ipaddress.AddressValueError:
        pass
    except UnicodeError as exc:
        raise ValueError("Invalid URL: hostname is not valid IDN") from exc

    if len(ascii_host) > 253 or any(not _HOST_LABEL.fullmatch(label) for label in ascii_host.split(".")):
        raise ValueError("Invalid URL: malformed hostname")
    return ascii_host


def parse_url(url: str) -> dict:
    """Parse a URL string without making any network requests."""
    if not isinstance(url, str) or not url.strip():
        raise ValueError("URL cannot be empty")
    original_url = url
    candidate = url.strip()
    if any(ord(ch) < 32 or ch.isspace() for ch in candidate):
        raise ValueError("URL must not contain whitespace or control characters")
    if "://" not in candidate:
        candidate = "https://" + candidate

    try:
        parsed = urlparse(candidate)
        scheme = parsed.scheme.lower()
        if scheme not in {"http", "https"}:
            raise ValueError("URL scheme must be http or https")
        if "@" in parsed.netloc or parsed.username is not None or parsed.password is not None:
            raise ValueError("Invalid URL: URL credentials are not permitted")
        authority = parsed.netloc
        if authority.endswith(":"):
            raise ValueError("Invalid URL: port number is empty")
        raw_hostname = parsed.hostname
        port = parsed.port  # Raises ValueError for malformed/out-of-range ports.
    except ValueError as exc:
        if str(exc).startswith("URL scheme"):
            raise
        raise ValueError(f"Invalid URL: {exc}") from exc
    if not raw_hostname:
        raise ValueError("Invalid URL: hostname not found")
    hostname = _canonical_hostname(raw_hostname)
    return {
        "original_url": original_url,
        "scheme": scheme,
        "hostname": hostname,
        "port": port,
        "path": parsed.path,
        "query": parsed.query,
        "fragment": parsed.fragment,
    }


def normalize_domain(hostname: str) -> str:
    """
    Convert a hostname into a canonical form for comparison.
    """

    hostname = _canonical_hostname(hostname.strip())

    # Remove trailing dot:
    # google.com. -> google.com
    # Remove www.
    if hostname.startswith("www."):
        hostname = hostname[4:]

    return hostname
