from scapy.error import Scapy_Exception
from scapy.sendrecv import sniff
import logging
from src.capture.common import Process_Packet

logger = logging.getLogger(__name__)

def capture_live(interface,packet_handler):
    print(f"Starting live capture on {interface}\n")
    logger.info("Starting live capture on interface: %s", interface)
    try:
        sniff(iface=interface,store=False,prn = Process_Packet())
    except KeyboardInterrupt:
        print("Live capture stopped by user.")
        logger.info("Live capture stopped by user.")
    except (OSError, Scapy_Exception) as exc:
        print(f"Could not capture from interface '{interface}': {exc}")
        logger.error(
            "Could not capture from interface '%s': %s",
            interface,
            exc,
        )
    finally:
        print("Live capture complete:")