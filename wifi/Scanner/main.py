# /bin/python3
import scapy.all as scapy
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
        w0 = pyw.getcard(self.interface)
        pyw.down(w0)
        pyw.set_mode(w0, "managed")
        pyw.up(w0)

    def set_iface(self):
        w0 = pyw.getcard(self.interface)
        pyw.down(w0)
        pyw.modeset(w0, "monitor")
        pyw.up(w0)

    # def run():


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
