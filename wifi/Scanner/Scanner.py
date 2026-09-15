#!/usr/bin/env python3
import subprocess
import threading
import time
from scapy.all import EAPOL
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt
import scapy.all as scapy


class Scanner:
    def __init__(self, interface, inactivity_timeout=15):
        self.interface = interface
        self.found_aps = set()
        self.handshake = set()
        self.found_aps_ssid = set()
        self.running = True
        self.inactivity_timeout = inactivity_timeout
        self.last_discovery_time = time.time()

    def __del__(self):
        try:
            self.set_iface("managed")
        except Exception:
            pass

    def set_iface(self, mode):
        subprocess.run(["ip", "link", "set", self.interface, "down"], check=False)
        subprocess.run(["iw", "dev", self.interface, "set", "type", mode], check=False)
        subprocess.run(["ip", "link", "set", self.interface, "up"], check=False)

    def channel_hopper(self):
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
                        ["iw", "dev", self.interface, "set", "channel", str(ch)],
                        stderr=subprocess.DEVNULL,
                        stdout=subprocess.DEVNULL,
                    )
                except Exception:
                    pass
                time.sleep(0.3)

    def parse_advanced_beacon(self, pkt):
        if pkt.haslayer(Dot11Beacon):
            bssid = pkt.addr2
            dbm_signal = pkt.dBm_AntSignal if hasattr(pkt, "dBm_AntSignal") else "N/A"

            channel = "N/A"
            crypto = set()

            elt = pkt.getlayer(Dot11Elt)
            while isinstance(elt, Dot11Elt):
                if elt.ID == 3:
                    channel = ord(elt.info) if isinstance(elt.info, bytes) else elt.info
                elif elt.ID == 48:
                    crypto.add("WPA2")
                elif elt.ID == 221 and elt.info.startswith(b"\x00\x50\xf2\x01"):
                    crypto.add("WPA")

                elt = elt.payload.getlayer(Dot11Elt)

            capability = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}")
            if "privacy" not in capability:
                crypto.add("OPEN")

            print(
                f"BSSID: {bssid} | Signal: {dbm_signal} dBm | Ch: {channel} | Security: {', '.join(crypto)}"
            )

    def beacon_frame(self, pkt):
        if pkt.haslayer(Dot11):
            if pkt.type == 0 and pkt.subtype in (5, 8):
                bssid = pkt.addr2
                if bssid and bssid not in self.found_aps:
                    self.found_aps.add(bssid)
                    self.last_discovery_time = time.time()

                    try:
                        ssid = (
                            pkt.info.decode("utf-8", errors="ignore")
                            if hasattr(pkt, "info") and pkt.info
                            else "<Hidden>"
                        )
                        self.found_aps_ssid.add(ssid)
                    except Exception:
                        ssid = "<Unknown>"

                    print(f"[+] AP Detectado: {bssid} | SSID: {ssid}")
                    self.parse_advanced_beacon(pkt)

    def run(self):
        print(f"[*] Configurando {self.interface} en modo monitor...")
        self.set_iface("monitor")

        self.running = True
        self.last_discovery_time = time.time()

        hopper_thread = threading.Thread(target=self.channel_hopper, daemon=True)
        hopper_thread.start()

        print(f"[*] Escaneando en {self.interface}...")

        try:
            while self.running:
                scapy.sniff(
                    iface=self.interface,
                    prn=self.beacon_frame,
                    timeout=1,
                    store=0,
                )
                if time.time() - self.last_discovery_time > self.inactivity_timeout:
                    print(
                        f"\n[*] No se detectaron nuevos APs en {self.inactivity_timeout}s. Deteniendo..."
                    )
                    break
        except Exception as e:
            print(f"[!] Error durante el escaneo: {e}")
        finally:
            self.stop()

    def stop(self):
        self.running = False
        print("[*] Restaurando la interfaz a modo managed...")
        try:
            self.set_iface("managed")
        except Exception:
            pass


__all__ = ["Scanner"]
