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
        self.setIface("monitor")
        self.setChannel()

    def __del__(self):
        try:
            self.setIface("managed")
        except Exception as e:
            print(e)

    def channelHopper(self):
        while self.running:
            # 5G channels
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
            for ch in channels:
                if not self.running:
                    break
                try:
                    subprocess.run(
                        ["iw", "dev", self.iface, "set", "channel", str(ch)],
                        stderr=subprocess.DEVNULL,
                        stdout=subprocess.DEVNULL,
                    )
                except Exception as e:
                    print(e)
                time.sleep(0.3)

    def getChannel(self, pkt):
        if pkt.haslayer(Dot11):
            bssid = pkt[Dot11].addr2
            if bssid and bssid.lower() == self.BSSID.lower():
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
        self.setIface("monitor")
        scapy.sniff(
            iface=self.iface,
            prn=self.classifyPkt,
            timeout=1,
            store=0,
        )


__all__ = ["DOS"]
