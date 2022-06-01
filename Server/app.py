import json
import subprocess
from http import HTTPStatus
from typing import Dict, List

from flask import Flask, Response, request

app = Flask(__name__)
app.config.from_object("config")


def CrackHandshake() -> None:
    cmd = [
        "john",                                         # Binary Name
        f"--wordlist={app.config['JOHN_WORDLIST']}",    # Wordlist
        f"--pot={app.config['JOHN_POT_FILE']}",         # Pot file
        app.config["JOHN_HANDSHAKES_FILE"],             # Handshakes file
    ]
    # Run john in background to crack WPA handshakes
    subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return


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
    handshake = out[0]
    if len(handshake) != 0:
        # Append handshakes to the JOHN_HANDSHAKES_FILE
        with open(app.config['JOHN_HANDSHAKES_FILE'], "a+") as file:
            file.write(handshake.decode("utf-8"))
        return True
    return False


def GetCrackedHandshakes() -> Dict[str, str]:
    cmd = [
        "john",                                     # Binary Name
        "--show",                                   # Show cracked hashes
        f"--pot={app.config['JOHN_POT_FILE']}",     # Pot file to use
        app.config["JOHN_HANDSHAKES_FILE"],         # Handshakes file
    ]
    # Run john
    pot = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    # Wait for john to exit
    pot.wait()
    cracked_passwords = {}
    for line in pot.stdout:
        splits = line.strip().decode('utf-8').split(':')
        # Check if found a cracked handshake
        if len(splits) >= 2:
            cracked_passwords[splits[0]] = splits[1]
    return cracked_passwords


def GetUncrackedHandshakes() -> List[str]:
    cmd = [
        "john",                                     # Binary Name
        "--show=left",                              # Show uncracked hashes
        f"--pot={app.config['JOHN_POT_FILE']}",     # Pot file to use
        app.config["JOHN_HANDSHAKES_FILE"],         # Handshakes file
    ]
    # Run john
    pot = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    # Wait for john to exit
    pot.wait()
    uncracked_passwords = []
    for line in pot.stdout:
        splits = line.strip().decode('utf-8').split(':')
        # Check if found a uncracked handshake
        if len(splits) >= 1:
            uncracked_passwords.append(splits[0])
    return uncracked_passwords


@app.route("/passwords", methods=["GET"])
def passwords():
    # Route to get all cracked and uncracked handshakes
    cracked = GetCrackedHandshakes()
    uncracked = GetUncrackedHandshakes()
    return Response(json.dumps({"cracked": cracked, "uncracked": uncracked}), status=HTTPStatus.OK)


@app.route("/upload", methods=["POST"])
def upload():
    # Route to upload john formar handshakes file
    if "file" not in request.files or request.files["file"].filename == "":
        return Response("No file selected", status=HTTPStatus.BAD_REQUEST)
    handshakeFile = request.files["file"]
    # Save the john handshake file in JOHN_HANDSHAKES_FILE
    handshakeFile.save(app.config["JOHN_HANDSHAKES_FILE"])
    # Crack the recieved handshakes
    CrackHandshake()
    return Response("Handshake uploaded for cracking", status=HTTPStatus.CREATED)


def main():
    app.run("0.0.0.0", 1337)


if __name__ == "__main__":
    main()
