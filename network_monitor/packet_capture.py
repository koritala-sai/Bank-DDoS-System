"""
Module 2: Network Monitoring and Traffic Analysis - Packet Capture
Provides safe, passive network packet capture using Scapy.

Strict Safety Rules:
- Passive sniffing only.
- No packet crafting, injection, transmission, or attack generation.
- Handles missing Npcap on Windows and permission errors gracefully.
"""

import sys
import threading
import logging
from typing import Optional, Callable, List

logger = logging.getLogger("network_monitor.packet_capture")

# Scapy Import with Availability and Npcap Check
try:
    from scapy.all import sniff, conf, IP, IPv6, TCP, UDP, ICMP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    conf = None
    IP = IPv6 = TCP = UDP = ICMP = None


def check_capture_prerequisites() -> dict:
    """
    Checks if Scapy and packet capture drivers (like Npcap on Windows or root on Linux)
    are available and functioning.

    Returns:
        dict: Status details regarding capture prerequisites.
    """
    if not SCAPY_AVAILABLE:
        return {
            "available": False,
            "reason": "Scapy library is not installed. Run 'pip install scapy'."
        }

    if sys.platform.startswith("win"):
        # On Windows, Scapy requires Npcap or WinPcap for live packet sniffing
        try:
            # Check if any usable interfaces exist
            ifaces = conf.ifaces
            if not ifaces:
                return {
                    "available": False,
                    "reason": (
                        "Npcap is required for live packet capture on Windows. "
                        "Please download and install Npcap from https://npcap.com/ "
                        "with 'WinPcap API-compatible mode' enabled."
                    )
                }
        except Exception as e:
            return {
                "available": False,
                "reason": (
                    f"Packet capture driver initialization failed ({e}). "
                    "On Windows, please install Npcap from https://npcap.com/."
                )
            }

    return {
        "available": True,
        "reason": "Packet capture prerequisites verified."
    }


class PacketCapturer:
    """
    Passive packet capturer supporting count limits, timeouts, and callbacks.
    Does NOT generate or transmit any packets.
    """

    def __init__(self, interface: Optional[str] = None):
        """
        Initialize the packet capturer.

        Args:
            interface (str, optional): Network interface name or Scapy iface object.
        """
        self.interface = interface
        self.is_running = False
        self._stop_event = threading.Event()
        self.captured_packets: List = []

    def stop(self):
        """Signals the packet capture loop to stop."""
        self._stop_event.set()
        self.is_running = False

    def capture(
        self,
        packet_count: int = 100,
        timeout: int = 30,
        callback: Optional[Callable] = None,
        filter_str: Optional[str] = "ip or ip6"
    ) -> List:
        """
        Executes passive packet capture on the designated interface.

        Args:
            packet_count (int): Maximum number of packets to capture.
            timeout (int): Timeout in seconds before stopping capture.
            callback (Callable, optional): Callback invoked per captured packet.
            filter_str (str, optional): BPF filter string (default "ip or ip6").

        Returns:
            List: Captured Scapy Packet objects.
        """
        prereqs = check_capture_prerequisites()
        if not prereqs["available"]:
            logger.error(f"[PacketCapture Error] {prereqs['reason']}")
            raise RuntimeError(prereqs["reason"])

        self._stop_event.clear()
        self.is_running = True
        self.captured_packets = []

        def _packet_handler(pkt):
            if self._stop_event.is_set():
                return
            self.captured_packets.append(pkt)
            if callback is not None:
                try:
                    callback(pkt)
                except Exception as cb_err:
                    logger.warning(f"Error in packet callback: {cb_err}")

        def _stop_filter(pkt):
            return self._stop_event.is_set()

        try:
            sniff_kwargs = {
                "count": packet_count,
                "timeout": timeout,
                "prn": _packet_handler,
                "stop_filter": _stop_filter,
                "store": False
            }
            if self.interface:
                sniff_kwargs["iface"] = self.interface
            if filter_str:
                sniff_kwargs["filter"] = filter_str

            sniff(**sniff_kwargs)

        except PermissionError as pe:
            err_msg = (
                "Permission denied while attempting packet capture. "
                "Administrator privileges (Windows) or root/sudo (Linux/macOS) are required."
            )
            logger.error(f"[PermissionError] {err_msg} - {pe}")
            raise PermissionError(err_msg) from pe
        except OSError as oe:
            err_msg = f"Network interface error during packet capture: {oe}"
            if "winpcap" in str(oe).lower() or "npcap" in str(oe).lower():
                err_msg += " (Ensure Npcap is installed on Windows)."
            logger.error(f"[OSError] {err_msg}")
            raise OSError(err_msg) from oe
        except Exception as ex:
            logger.error(f"[PacketCapture Exception] {ex}")
            raise ex
        finally:
            self.is_running = False

        return self.captured_packets


def start_capture(
    interface: Optional[str] = None,
    packet_count: int = 100,
    timeout: int = 30,
    callback: Optional[Callable] = None
) -> List:
    """
    Convenience function to start passive packet capture.

    Args:
        interface (str, optional): Network interface to sniff on (Scapy default if None).
        packet_count (int): Maximum packets to capture.
        timeout (int): Timeout in seconds.
        callback (Callable, optional): Function called per captured packet.

    Returns:
        List: List of captured packets.
    """
    capturer = PacketCapturer(interface=interface)
    return capturer.capture(packet_count=packet_count, timeout=timeout, callback=callback)
