"""Packet capture for X8 NIDS.

Uses Scapy or pypcap when available for live capture and pcap replay. When
neither is installed, live/replay modes fall back to a clear error message and
the offline simulation engine is used instead. All traffic flows are decoded
into the canonical :class:`Flow` shape consumed by the rules engine.

This module contains NO injection, spoofing, or packet-modification primitives
— this is a detection-only (blue team) tool.
"""

from __future__ import annotations

from typing import Iterator

from .flows import Flow

try:  # pragma: no cover - environment dependent
    from scapy.all import rdpcap, sniff  # type: ignore

    _HAVE_SCAPY = True
except Exception:  # pragma: no cover
    scapy = None
    _HAVE_SCAPY = False

try:  # pragma: no cover - environment dependent
    import pcap  # type: ignore

    _HAVE_PYPCAP = True
except Exception:  # pragma: no cover
    pcap = None
    _HAVE_PYPCAP = False


class CaptureError(Exception):
    """Raised when live capture or replay cannot be performed."""


def capture_available() -> bool:
    """True if any pcap backend (scapy or pypcap) is importable."""
    return _HAVE_SCAPY or _HAVE_PYPCAP


def flow_from_pkt(pkt) -> Flow:
    """Decode a single scapy packet into a :class:`Flow`."""
    ts = float(pkt.time)
    ip = pkt.getlayer(3) if hasattr(pkt, "getlayer") else None
    if ip is None:
        return Flow(ts=ts, src="?", dst="?", sport=0, dport=0, proto="?", flags="")
    src = str(getattr(ip, "src", "?"))
    dst = str(getattr(ip, "dst", "?"))
    proto = "ip"
    sport, dport, flags = 0, 0, ""
    if hasattr(pkt, "getlayer"):
        transport = pkt.getlayer(4)
        if transport is None and hasattr(ip, "payload"):
            transport = ip.payload
        if transport is not None and hasattr(transport, "sport"):
            sport = int(getattr(transport, "sport", 0))
            dport = int(getattr(transport, "dport", 0))
            proto = str(getattr(transport, "name", "tcp")).lower()
            if hasattr(transport, "flags"):
                flags = str(getattr(transport, "flags", ""))
    return Flow(
        ts=ts,
        src=src,
        dst=dst,
        sport=sport,
        dport=dport,
        proto=proto,
        duration=0.0,
        flags=flags,
    )


def iter_pcap(path: str) -> Iterator[Flow]:
    """Replay a pcap file, yielding canonical :class:`Flow` objects.

    Requires scapy. Raises :class:`CaptureError` if unavailable or unreadable.
    """
    if not _HAVE_SCAPY:
        raise CaptureError(
            "pcap replay requires scapy (pip install scapy). "
            "Use 'nids simulate' for an offline demo without capture."
        )
    try:
        from scapy.all import rdpcap  # type: ignore
    except Exception as exc:  # pragma: no cover
        raise CaptureError(f"scapy import failed: {exc}") from exc
    try:
        packets = rdpcap(path)
    except Exception as exc:
        raise CaptureError(f"failed to read pcap {path!r}: {exc}") from exc
    for pkt in packets:
        yield flow_from_pkt(pkt)


def live_capture(iface: str) -> Iterator[Flow]:
    """Continuously sniff ``iface`` ('any' supported), yielding flows.

    Requires scapy with proper privileges. Raises :class:`CaptureError`
    otherwise.
    """
    if not _HAVE_SCAPY:
        raise CaptureError(
            "live capture requires scapy (pip install scapy) and capture "
            "privileges. Use 'nids simulate' for an offline demo."
        )
    from scapy.all import sniff  # type: ignore

    for pkt in sniff(iface=iface, store=False):
        yield flow_from_pkt(pkt)
