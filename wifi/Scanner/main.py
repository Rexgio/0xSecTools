#!/usr/bin/env python3
import scapy.all as scapy
from scapy.layers.dot11 import (
    Dot11,
    Dot11Beacon,
    Dot11Elt,
    Dot11EltRSN,
    RadioTap,
)
import sys
import signal
import questionary
import argparse
import pyric
import pyric.pyw as pyw


def ctrl_c(sig, frame):
    print("\n[!] Interruption detected. Exiting...")
    sys.exit(0)


class Scanner:
    def __init__(self, interface):
        self.interface = interface

    def __del__(self):
        self.set_iface("managed")

    def set_iface(self, mode):
        w0 = pyw.getcard(self.interface)
        pyw.down(w0)
        pyw.modeset(w0, mode)
        pyw.up(w0)

    def beacon_frame(self, pkt):
        if pkt.scapy.hashlayer(Dot11):
            if pkt.type==0 and pkt.scapy.subty in (5,8):


    def run(self):
        self.set_iface("monitor")
        scapy.sniff(
            iface=self.interface,
            prn=self.beacon_frame,
            store=0,
            lfilter=lambda x: x.scapy.haslayer(Dot11),
        )


if __name__ == "__main__":
    signal.signal(signal.SIGINT, ctrl_c)
    if len(sys.argv) > 1:
        parser = argparse.ArgumentParser(
            description="ARP Spoofing Tool to sniff network traffic."
        )
        parser.add_argument(
            "-i", "--interface", required=True, help="Network interface (e.g., eth0)."
        )
        args = parser.parse_args()
        inter = args.interface
    else:
        choices_all = [iface.name for iface in scapy.get_working_ifaces()]
        inter = questionary.select("Select the interface:", choices=choices_all).ask()
    scan = Scanner(inter)
