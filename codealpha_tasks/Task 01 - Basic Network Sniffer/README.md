# CodeAlpha_NetworkSniffer

A basic network packet sniffer built in Python using **Scapy**, developed as part of the CodeAlpha Cybersecurity Internship.

## Overview

This tool captures live network traffic on a chosen interface and displays key details about each packet in real time:

- Timestamp
- Source and destination IP address
- Source and destination port (for TCP/UDP)
- Protocol (TCP, UDP, ICMP, etc.)
- Packet length
- A readable snippet of the payload (optional, verbose mode)

Building this helped me understand how data actually moves through a network at the packet level — how IP, TCP, and UDP headers are structured, how the three-way handshake and payloads look on the wire, and why plaintext protocols (like HTTP) expose data to anyone sniffing the network — which is part of why HTTPS/TLS matters.

## How It Works

1. Scapy's `sniff()` function captures raw packets from a network interface.
2. Each packet is passed to a callback function (`process_packet`).
3. The callback inspects the packet's layers (`IP`/`IPv6`, `TCP`/`UDP`/`ICMP`) to extract addressing and protocol info.
4. If a `Raw` layer (payload) is present, it's decoded into a safe, printable preview.
5. A formatted summary line is printed to the console (and optionally saved to a log file).

## Usage

### Install dependencies
```bash
pip install scapy
```

> **Note:** Raw packet capture requires elevated privileges.
> - Linux/macOS: run with `sudo`
> - Windows: install [Npcap](https://npcap.com/) and run terminal as Administrator

### Basic usage
```bash
sudo python3 sniffer.py
```

### List available interfaces
```bash
python3 sniffer.py --list-interfaces
```

### Sniff on a specific interface
```bash
sudo python3 sniffer.py -i eth0
```

### Capture a fixed number of packets
```bash
sudo python3 sniffer.py -c 50
```

### Filter traffic using BPF syntax
```bash
sudo python3 sniffer.py -f "tcp port 80"      # HTTP traffic only
sudo python3 sniffer.py -f "udp port 53"      # DNS traffic only
sudo python3 sniffer.py -f "host 192.168.1.5" # traffic to/from a specific host
```

### Verbose mode (show payload preview)
```bash
sudo python3 sniffer.py -v
```

### Save output to a log file
```bash
sudo python3 sniffer.py -o capture_log.txt
```

## Sample Output

```
======================================================================
 CodeAlpha Network Sniffer — press Ctrl+C to stop
======================================================================
Filter    : tcp port 80
Count     : unlimited
Verbose   : True
----------------------------------------------------------------------
[14:32:10] TCP    | 192.168.1.10:52344  ->  93.184.216.34:80      | 74 bytes
[14:32:10] TCP    | 93.184.216.34:80  ->  192.168.1.10:52344      | 66 bytes
           Payload: GET / HTTP/1.1..Host: example.com..
```

## Key Concepts Demonstrated

- Packet capture and analysis at Layer 3/4 (IP, TCP, UDP, ICMP)
- Use of Berkeley Packet Filter (BPF) syntax to isolate traffic
- Practical understanding of the OSI/TCP-IP model
- Why unencrypted protocols leak visible data over the network

## Legal & Ethical Notice

This tool is intended strictly for **educational purposes** on networks and devices you **own or have explicit permission to monitor**. Unauthorized packet capture on networks you don't control may violate computer misuse laws in your jurisdiction (e.g., the Computer Misuse Act, CFAA, etc.). Always practice responsible and ethical cybersecurity.

## Built With

- Python 3
- [Scapy](https://scapy.net/)

## About This Project

Developed as **Task 01: Basic Network Sniffer** for the CodeAlpha Cybersecurity Internship.
