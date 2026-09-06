"""Flow model shared across the detection core.

A :class:`Flow` is the normalized unit of traffic that the rules engine
consumes. It is produced by either a live/replay packet decoder or by the
offline simulation engine, providing a single consistent interface for all
detection modules.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, Optional


@dataclass
class Flow:
    """A single network flow between a source and a destination.

    Fields are expressed in the direction ``src -> dst`` where ``src`` is the
    initiator of the connection.

    Attributes:
        ts:       Monotonic or epoch timestamp (float) when the flow began.
        src:      Source IP / hostname (str).
        dst:      Destination IP / hostname (str).
        sport:    Source port.
        dport:    Destination port.
        proto:    Transport protocol (``tcp``, ``udp``, ``icmp``, ...).
        bytes_in: Total payload bytes sent by the source (outbound).
        bytes_out: Total payload bytes received by the source (inbound).
        duration: Flow duration in seconds.
        flags:    Connection state flags / summary string (e.g. ``SA``, ``S0``).
        service:  Optional application service label (e.g. ``ssh``, ``http``).
        is_reply: Whether this record represents the response side of a
                  previously seen request (used for auth-failure correlation).
        meta:     Free-form extra metadata for synthetic flows (label used by
                  the self-test to score precision/recall).
    """

    ts: float
    src: str
    dst: str
    sport: int
    dport: int
    proto: str = "tcp"
    bytes_in: int = 0
    bytes_out: int = 0
    duration: float = 0.0
    flags: str = ""
    service: str = ""
    is_reply: bool = False
    meta: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def now(cls, **kwargs: Any) -> "Flow":
        """Create a flow stamped with the current time, merged with kwargs."""
        kwargs.setdefault("ts", time.time())
        return cls(**kwargs)

    def as_dict(self) -> Dict[str, Any]:
        """Serialize to a plain dict (used for flows JSONL snapshots)."""
        data = asdict(self)
        if "meta" in data and not data["meta"]:
            data.pop("meta", None)
        return data

    def label(self) -> Optional[str]:
        """Return the ground-truth label for synthetic flows, if any."""
        return self.meta.get("label")

    def __hash__(self) -> int:  # type: ignore[override]
        return hash((self.ts, self.src, self.dst, self.sport, self.dport, self.proto))

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, Flow):
            return NotImplemented
        return (
            self.ts == other.ts
            and self.src == other.src
            and self.dst == other.dst
            and self.sport == other.sport
            and self.dport == other.dport
            and self.proto == other.proto
        )
