#!/usr/bin/env python3
import subprocess
import threading
import time
from scapy.all import EAPOL
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt
import scapy.all as scapy


class DOS:
    def __init__(self, wifi: str, ifc: str, t: int = 10) -> None:
        self.BSSID = wifi
        self.iface = ifc
        self.channel = 1
        self.tIntercept = t
        self.connectedUsers = set()
        self.running = False
        self.hopper_thread = None
        self.setIface("monitor")
        self.setChannel()
        print("[DEBUG] DOS creado")

    def stop(self):
        self.running = False

        if self.hopper_thread is not None:
            self.hopper_thread.join()
            self.hopper_thread = None

        print("[*] Restaurando la interfaz a modo managed...")

        try:
            self.setIface("managed")
        except Exception as e:
            print(e)

    def channelHopper(self):
        channels = [
            1,
            2,
            3,
            4,
            5,
            6,
            7,
            8,
            9,
            10,
            11,
            12,
            13,
            36,
            40,
            44,
            48,
            52,
            56,
            60,
            64,
            100,
            104,
            108,
            112,
            116,
            120,
            124,
            128,
            132,
            136,
            140,
            144,
        ]

        while self.running:
            for ch in channels:
                if not self.running:
                    break

                self.channel = ch

                subprocess.run(
                    [
                        "iw",
                        "dev",
                        self.iface,
                        "set",
                        "channel",
                        str(ch),
                    ],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )

                time.sleep(0.3)

    def getChannel(self, pkt):
        if not pkt.haslayer(Dot11):
            return

        dot11 = pkt[Dot11]
        bssid = self.BSSID.lower()

        addresses = (
            dot11.addr1,
            dot11.addr2,
            dot11.addr3,
        )

        if not any(addr and addr.lower() == bssid for addr in addresses):
            return

        if pkt.haslayer(Dot11Beacon) or (dot11.type == 0 and dot11.subtype == 5):
            self.running = False

    def setChannel(self):
        self.running = True

        hopper_thread = threading.Thread(target=self.channelHopper, daemon=True)
        hopper_thread.start()

        try:
            scapy.sniff(
                iface=self.iface,
                prn=self.getChannel,
                timeout=1,
                store=0,
            )
        finally:
            self.running = False

    def setIface(self, mode):
        subprocess.run(["ip", "link", "set", self.iface, "down"], check=False)
        subprocess.run(["iw", "dev", self.iface, "set", "type", mode], check=False)
        subprocess.run(["ip", "link", "set", self.iface, "up"], check=False)

    def classifyPkt(self, pkt) -> None:
        if pkt.haslayer(Dot11) and pkt.haslayer(EAPOL):
            wifi = pkt[Dot11]

            addr1 = wifi.addr1
            addr2 = wifi.addr2

            if self.BSSID.lower() in {
                addr1.lower() if addr1 else "",
                addr2.lower() if addr2 else "",
            }:
                print(f"{addr2} -> {addr1}")
                pkt.show()

    def intercept(self) -> None:
        try:
            t = time.time()
            while time.time() - t < self.tIntercept:
                scapy.sniff(
                    iface=self.iface,
                    prn=self.classifyPkt,
                    timeout=1,
                    store=0,
                )
        except Exception as e:
            print(f"[!] sniff error: {type(e).__name__}: {e}")
        finally:
            print("[DEBUG] sniff terminado")
            self.stop()


__all__ = ["DOS"]
