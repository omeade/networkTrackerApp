from flask import Flask, render_template
from flask_socketio import SocketIO, emit
from scapy.all import ARP, sniff
import threading
import time
import subprocess

app = Flask(__name__)
socketio = SocketIO(app)

current_devices = {}

def load_vendors():
    vendors = {}
    try:
        with open("oui.txt") as f:
            for line in f:
                if "(hex)" in line:
                    parts = line.strip().split()
                    mac_prefix = parts[0].replace("-",":").lower()
                    vendor = " ".join(parts[0])
                    vendors[mac_prefix] = vendor
    except FileNotFoundError:
        print("[!] oui.txt not found, vendors will be resolved")
    return vendors
vendors = load_vendors()

def lookup_vendor(mac):
    prefix = ":".join(mac.split(":")[:3].lower())
    return vendors.get(prefix,"Unkown")

def scan_network():
    ip_range = "192.168.0.0/24"  # change if your subnet differs
    devices = {}

    # Ping all IPs in the subnet to force ARP replies
    for i in range(1, 255):
        ip = f"192.168.0.{i}"
        subprocess.call(
            ["ping", "-c", "1", "-W", "1", ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

    # ARP scan
    arp_request = ARP(pdst=ip_range)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request
    answered, _ = srp(packet, timeout=2, verbose=0)

    for sent, received in answered:
        devices[received.psrc] = {
            "mac": received.hwsrc,
            "vendor": lookup_vendor(received.hwsrc)
        }

    return devices

def network_scanner():
    global current_devices
    while True:
        devices = scan_network()
        current_devices = devices
        socketio.emit("update_devices", devices)
        time.sleep(1)  # scan every 10 seconds
@app.route("/")
def index():
    return render_template("index.html",devices=current_devices)

if __name__ == "__main__":
    t = threading.Thread(target=network_scanner,daemon=True)
    t.start()
    socketio.run(app,host="0.0.0.0",port=5001)
