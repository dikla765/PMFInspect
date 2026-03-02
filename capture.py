#!/usr/bin/env python3
# capture.py
# Usage: python3 capture.py --channel 6 --duration 120

import time
import subprocess
import os
import argparse
import re
from pathlib import Path
from element import NetworkInfo  # element.py in the same directory

# Base directory of the script
BASE_DIR = Path(__file__).resolve().parent
FILE_DIR = BASE_DIR / "capture"

DEFAULT_CHANNEL = 1
DEFAULT_DURATION = 60
DEFAULT_BSSID = ""

TCPDUMP_PATH = "/usr/sbin/tcpdump"
TCPDUMP_CAPS = "cap_net_raw,cap_net_admin=eip"


def run(cmd, check=False, capture=False, text=True):
    """Helper around subprocess.run()."""
    return subprocess.run(
        cmd,
        check=check,
        capture_output=capture,
        text=text,
    )


def ensure_capture_dir_owned_by_user():
    """
    Ensure the capture/ directory exists and belongs to the current user,
    to avoid the lock icon (root ownership issues).
    """
    FILE_DIR.mkdir(exist_ok=True)
    try:
        st = FILE_DIR.stat()
        uid = os.getuid()
        if st.st_uid != uid:
            print(f"[!] '{FILE_DIR}' is not owned by your user. Fixing (sudo chown)...")
            run(["sudo", "chown", "-R", f"{os.getenv('USER')}:{os.getenv('USER')}", str(FILE_DIR)], check=False)
    except Exception:
        print("[!] Unable to verify/change ownership of capture/ directory.")
        print("    If you still see a lock, run: sudo chown -R $USER:$USER capture")


def tcpdump_has_caps() -> bool:
    """
    Check whether tcpdump has the required Linux capabilities.
    """
    try:
        res = run(["getcap", TCPDUMP_PATH], capture=True)
        out = (res.stdout or "").strip()
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


def enable_monitor_mode(interface):
    print(f"[+] Enabling monitor mode on {interface}")
    subprocess.call(["sudo", "airmon-ng", "start", interface])


def disable_monitor_mode(interface_mon):
    print(f"[+] Disabling monitor mode on {interface_mon}")
    subprocess.call(["sudo", "airmon-ng", "stop", interface_mon])


def set_channel(interface_mon, channel):
    print(f"[+] Setting {interface_mon} to channel {channel}")
    subprocess.call(["sudo", "iwconfig", interface_mon, "channel", str(channel)])


def get_next_pcap_name():
    FILE_DIR.mkdir(exist_ok=True)
    existing = [f for f in os.listdir(FILE_DIR) if re.match(r"capture_\d+\.pcap", f)]
    numbers = [int(re.findall(r"capture_(\d+)\.pcap", f)[0]) for f in existing]
    next_number = max(numbers) + 1 if numbers else 1
    return FILE_DIR / f"capture_{next_number}.pcap"


def start_tcpdump_capture(pcap_file, iface, bssid=""):
    """
    Start tcpdump WITHOUT sudo (thanks to setcap capabilities).
    Optional: apply BSSID filter if provided.
    """
    try:
        print(f"[+] Starting tcpdump capture to {pcap_file}")
        cmd = ["tcpdump", "-i", iface, "-w", str(pcap_file)]

        if bssid:
            cmd += ["ether", "host", bssid]

        return subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception as e:
        print(f"[!] Error starting tcpdump: {e}")
        return None


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


def main():
    parser = argparse.ArgumentParser(description="Capture Wi-Fi in monitor mode using tcpdump (setcap enabled).")
    parser.add_argument("--bssid", default=DEFAULT_BSSID, help="Target BSSID (optional)")
    parser.add_argument("--channel", type=int, default=DEFAULT_CHANNEL, help="Wi-Fi channel")
    parser.add_argument("--duration", type=float, default=DEFAULT_DURATION, help="Capture duration (seconds)")
    args = parser.parse_args()

    # 1) Ensure tcpdump can run without sudo
    ensure_tcpdump_caps()

    # 2) Ensure capture/ belongs to the current user
    ensure_capture_dir_owned_by_user()

    pcap_file = get_next_pcap_name()
    capture_process = None
    mon_interface = None

    try:
        details = NetworkInfo.get_wireless_interface_details()
        interface = details["interface"]

        if not interface:
            print("[ERROR] No Wi-Fi interface detected.")
            return

        print(f"[INFO] Wi-Fi interface : {interface}")
        print(f"[INFO] Local IP        : {details['ip_address']}")
        print(f"[INFO] Local MAC       : {details['mac_address']}")
        print(f"[INFO] Gateway IP      : {details['gateway_ip']}")
        print(f"[INFO] Gateway MAC     : {details['gateway_mac']}")

        enable_monitor_mode(interface)
        mon_interface = interface + "mon"
        set_channel(mon_interface, args.channel)

        print(f"[INFO] Capturing on {mon_interface} for {args.duration} sec...")
        print(f"[INFO] PCAP file : {pcap_file}")
        capture_process = start_tcpdump_capture(pcap_file, mon_interface, args.bssid)

        time.sleep(args.duration)

    except KeyboardInterrupt:
        print("[INFO] Capture manually interrupted.")
    except Exception as e:
        print(f"[ERROR] An exception occurred: {e}")
    finally:
        stop_tcpdump(capture_process)
        if mon_interface:
            disable_monitor_mode(mon_interface)


if __name__ == "__main__":
    main()
