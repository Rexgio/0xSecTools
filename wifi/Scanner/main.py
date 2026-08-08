#!/usr/bin/env python3
import sys
import signal
import argparse
import questionary
import scapy.all as scapy
from Scanner import Scanner


def ctrl_c(sig, frame):
    print("\n[!] Interruption detected. Exiting...")
    sys.exit(0)


if __name__ == "__main__":
    signal.signal(signal.SIGINT, ctrl_c)

    if len(sys.argv) > 1:
        parser = argparse.ArgumentParser(
            description="Wi-Fi Beacon and Probe Response Scanner"
        )
        parser.add_argument(
            "-i", "--interface", required=True, help="Wireless interface (e.g., wlan0)."
        )
        args = parser.parse_args()
        inter = args.interface
    else:
        choices_all = [iface.name for iface in scapy.get_working_ifaces()]
        if not choices_all:
            print("[!] No working wireless interfaces found.")
            sys.exit(1)
        inter = questionary.select("Select the interface:", choices=choices_all).ask()

    scan = Scanner(inter)
    scan.run()
    found_aps = scan.get_aps()

    if not found_aps:
        print("[!] No Access Points were detected.")
        sys.exit(0)

    wifi = questionary.select(
        "Select Wi-Fi Access Point:", choices=list(found_aps)
    ).ask()
    print(f"[*] Selected AP: {wifi}")
