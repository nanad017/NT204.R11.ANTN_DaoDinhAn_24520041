from __future__ import annotations
from dataclasses import dataclass
from scapy.packet import Packet

def process_packet(packet: Packet) -> None:
    print(packet.summary())
    logger.info(packet.summary())
    try:
        packet_handler(packet)
    except Exception as exc:
        print(f"[WARNING] Packet handler failed: {exc}")
        logger.warning(f"Packet handler failed: {exc}")
    return process_packet
