#!/usr/bin/env python3
"""
CodeAlpha_NetworkSniffer
-------------------------
A basic network packet sniffer built with Scapy for educational purposes.

This tool captures live network traffic and displays key information about
each packet: timestamp, source/destination IP addresses, protocol, ports,
packet length, and a readable snippet of the payload (when present).

IMPORTANT / LEGAL NOTE:
Only run this on networks and devices you own or have explicit permission
to monitor. Capturing traffic on networks without authorization may be
illegal in your jurisdiction. This tool is for learning purposes only.

Usage examples:
    sudo python3 sniffer.py                          # sniff all traffic on default interface
    sudo python3 sniffer.py -i eth0                  # sniff on a specific interface
    sudo python3 sniffer.py -c 50                    # stop after 50 packets
    sudo python3 sniffer.py -f "tcp port 80"         # only HTTP traffic (BPF filter)
    sudo python3 sniffer.py -v                       # verbose mode (show payload)
    sudo python3 sniffer.py -o capture_log.txt        # also save output to a log file
"""

import argparse
import datetime
import sys

try:
    from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, Raw, get_if_list
except ImportError:
    print("[!] Scapy is not installed. Install it with: pip install scapy")
    sys.exit(1)


# Map protocol numbers used by Scapy's IP layer to friendly names
PROTOCOL_NAMES = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
}

log_file_handle = None  # set at runtime if the user passes -o/--output


def log(message: str):
    """Print to console and optionally write to a log file."""
    print(message)
    if log_file_handle:
        log_file_handle.write(message + "\n")
        log_file_handle.flush()


def get_readable_payload(packet, max_bytes: int = 64) -> str:
    """
    Extract a safe, human-readable snippet of the payload.
    Non-printable bytes are shown as dots, similar to a hex-dump ASCII view.
    """
    if not packet.haslayer(Raw):
        return ""

    payload_bytes = bytes(packet[Raw].load)[:max_bytes]
    readable = "".join(
        chr(b) if 32 <= b <= 126 else "." for b in payload_bytes
    )
    suffix = "..." if len(bytes(packet[Raw].load)) > max_bytes else ""
    return readable + suffix


def process_packet(packet, verbose: bool = False):
    """
    Callback executed for every captured packet.
    Parses IP/IPv6 layer + transport layer info and prints a summary line.
    """
    timestamp = datetime.datetime.now().strftime("%H:%M:%S")

    # Determine IP version and extract addresses
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        src_ip, dst_ip = ip_layer.src, ip_layer.dst
        proto_num = ip_layer.proto
    elif packet.haslayer(IPv6):
        ip_layer = packet[IPv6]
        src_ip, dst_ip = ip_layer.src, ip_layer.dst
        proto_num = ip_layer.nh
    else:
        # Not an IP packet (e.g. ARP) — show a minimal summary and skip
        log(f"[{timestamp}] Non-IP packet: {packet.summary()}")
        return

    protocol = PROTOCOL_NAMES.get(proto_num, f"OTHER({proto_num})")
    length = len(packet)

    src_port = dst_port = None
    if packet.haslayer(TCP):
        src_port, dst_port = packet[TCP].sport, packet[TCP].dport
    elif packet.haslayer(UDP):
        src_port, dst_port = packet[UDP].sport, packet[UDP].dport

    # Build the summary line
    endpoint_info = f"{src_ip}"
    endpoint_info += f":{src_port}" if src_port else ""
    endpoint_info += f"  ->  {dst_ip}"
    endpoint_info += f":{dst_port}" if dst_port else ""

    summary = f"[{timestamp}] {protocol:<6} | {endpoint_info:<42} | {length} bytes"
    log(summary)

    if verbose:
        payload_preview = get_readable_payload(packet)
        if payload_preview:
            log(f"           Payload: {payload_preview}")


def main():
    parser = argparse.ArgumentParser(
        description="A basic educational network packet sniffer using Scapy."
    )
    parser.add_argument(
        "-i", "--interface",
        help="Network interface to sniff on (e.g. eth0, wlan0). "
             "Defaults to Scapy's default interface if not specified.",
        default=None,
    )
    parser.add_argument(
        "-c", "--count",
        type=int,
        default=0,
        help="Number of packets to capture (0 = capture indefinitely until Ctrl+C).",
    )
    parser.add_argument(
        "-f", "--filter",
        default="",
        help='BPF filter string, e.g. "tcp", "udp port 53", "host 192.168.1.1".',
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show a readable snippet of each packet's payload.",
    )
    parser.add_argument(
        "-o", "--output",
        help="File path to also save the capture log to.",
        default=None,
    )
    parser.add_argument(
        "--list-interfaces",
        action="store_true",
        help="List available network interfaces and exit.",
    )

    args = parser.parse_args()

    if args.list_interfaces:
        print("Available interfaces:")
        for iface in get_if_list():
            print(f"  - {iface}")
        sys.exit(0)

    global log_file_handle
    if args.output:
        log_file_handle = open(args.output, "a", encoding="utf-8")
        log(f"\n=== Capture started {datetime.datetime.now()} ===")

    print("=" * 70)
    print(" CodeAlpha Network Sniffer — press Ctrl+C to stop")
    print("=" * 70)
    if args.interface:
        print(f"Interface : {args.interface}")
    print(f"Filter    : {args.filter or '(none — capturing all traffic)'}")
    print(f"Count     : {'unlimited' if args.count == 0 else args.count}")
    print(f"Verbose   : {args.verbose}")
    print("-" * 70)

    try:
        sniff(
            iface=args.interface,
            filter=args.filter or None,
            prn=lambda pkt: process_packet(pkt, verbose=args.verbose),
            count=args.count,
            store=False,
        )
    except PermissionError:
        print("\n[!] Permission denied. Try running with sudo/administrator privileges.")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[*] Capture stopped by user.")
    finally:
        if log_file_handle:
            log_file_handle.close()


if __name__ == "__main__":
    main()
