"""Live network-interface capture source."""

from __future__ import annotations

from scapy.error import Scapy_Exception
from scapy.sendrecv import sniff

from src.capture.common import CaptureStats, PacketHandler, build_packet_callback


def capture_live(
    interface: str,
    packet_handler: PacketHandler | None = None,
) -> CaptureStats:
    """Capture packets from *interface* and send each to one shared callback.

    Stop the capture with Ctrl+C. Packet handler exceptions are isolated so a
    malformed or unsupported packet cannot stop the source.
    """
    stats = CaptureStats()
    callback = build_packet_callback(packet_handler, stats)

    print(f"[INFO] Starting live capture on interface: {interface}")
    try:
        sniff(iface=interface, prn=callback, store=False)
    except KeyboardInterrupt:
        print("\n[INFO] Live capture stopped by user.")
    except (OSError, Scapy_Exception) as exc:
        stats.error = str(exc)
        print(f"[ERROR] Could not capture from interface '{interface}': {exc}")
    finally:
        print(
            "[INFO] Live capture complete: "
            f"{stats.packets_seen} packet(s), "
            f"{stats.handler_errors} handler error(s)."
        )

    return stats
