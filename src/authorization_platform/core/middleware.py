from __future__ import annotations

import ipaddress

from django.conf import settings


_FORWARDED_HEADERS = (
    "HTTP_X_FORWARDED_FOR",
    "HTTP_X_FORWARDED_HOST",
    "HTTP_X_FORWARDED_PORT",
    "HTTP_X_FORWARDED_PROTO",
)


def _parse_ip(value: str | None):
    try:
        return ipaddress.ip_address(value or "")
    except ValueError:
        return None


def _is_trusted(address, networks) -> bool:
    return bool(address and any(address in network for network in networks))


def _resolve_forwarded_client(peer, forwarded_for: str, networks):
    candidates = []
    for raw in forwarded_for.split(","):
        address = _parse_ip(raw.strip())
        if address is not None:
            candidates.append(address)
    chain = [*candidates, peer]
    for address in reversed(chain):
        if not _is_trusted(address, networks):
            return address
    # Every hop in the chain (including the direct peer) is inside the trusted
    # proxy range, so nothing in X-Forwarded-For is independently verifiable.
    # Falling back to the first candidate would let the caller choose its own
    # rate-limit identity; use the peer we actually observed instead.
    return peer


class TrustedProxyHeadersMiddleware:
    """Accept forwarded identity only from explicitly configured proxy networks."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        peer = _parse_ip(request.META.get("REMOTE_ADDR"))
        networks = getattr(settings, "TRUSTED_PROXY_NETWORKS", ())
        if not _is_trusted(peer, networks):
            for header in _FORWARDED_HEADERS:
                request.META.pop(header, None)
            return self.get_response(request)

        forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR", "")
        resolved = _resolve_forwarded_client(peer, forwarded_for, networks)
        if resolved is not None:
            request.META["REMOTE_ADDR"] = str(resolved)

        forwarded_proto = request.META.get("HTTP_X_FORWARDED_PROTO", "")
        proto_values = [value.strip().lower() for value in forwarded_proto.split(",") if value.strip()]
        if len(proto_values) != 1 or proto_values[0] not in {"http", "https"}:
            request.META.pop("HTTP_X_FORWARDED_PROTO", None)
        else:
            request.META["HTTP_X_FORWARDED_PROTO"] = proto_values[0]
        return self.get_response(request)
