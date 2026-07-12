"""Live packet capture module — sniffs traffic and feeds flows to the inference engine."""

from .sniffer import PacketSniffer

__all__ = ["PacketSniffer"]
