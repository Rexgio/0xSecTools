from sqli import SQLIboolean, SQLIerror, SQLItimed
import argparse
import signal
import questionary
import sys


def ctrl_c(sig, frame):
    print("\n[!] Interruption detected. Restoring ARP tables and exiting...")
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
            help="Target URL to test",
        )

        args = parser.parse_args()
        target = args.target
    else:
        target = questionary.text("What's the URL to target: ").ask()
