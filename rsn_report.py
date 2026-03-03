#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# rsn_report.py
"""
filtre.py (batch + PMF + negotiated RSN + 4-way handshake)

Features:
1) Split per device:
   - Reads devices.json (MAC -> Device name)
   - For each capture/capture_i.pcap(.pcapng):
       - detects which devices have traffic
       - creates one folder per device in the output directory
       - writes <DeviceName>/<DeviceName>_i.pcap if traffic is found

2) PMF extraction (RSN Capabilities):
   - Association Request (STA -> AP): mfpc/mfpr
   - Association Response (AP -> STA): mfpc/mfpr (=> "negotiated" on AP side)

3) 4-way handshake extraction (EAPOL-Key):
   - Uses Scapy if possible, otherwise falls back to tshark (or forced mode)
   - Decodes key_info + main bits + infers message 1..4
   - Adds a hint about "msg3_key_data_readable" (no decryption, often False)

4) Produces a global JSON "a.json" (in the current working directory):
   - meta + captures[] + devices + assoc_requests/assoc_responses
     + rsn_negotiated + four_way_handshake

Usage:
  python3 filtre.py --devices devices.json --capture-dir capture --out-dir . --min-pkts 1 --json-out a.json

Optional:
  --use-tshark auto     (default) => uses tshark if Scapy cannot
  --use-tshark always   => force tshark
  --use-tshark never    => Scapy only
"""

import argparse
import json
import re
import subprocess
from pathlib import Path
from typing import Dict, List, Set, Optional, Tuple, Any

from scapy.all import rdpcap, wrpcap
from scapy.layers.dot11 import Dot11, Dot11Elt

MAC_RE = re.compile(r"^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$")


# ----------------------------
# Helpers
# ----------------------------

def norm_mac(mac: str) -> str:
    mac = mac.strip().lower()
    if not MAC_RE.match(mac):
        raise ValueError(f"Invalid MAC: {mac}")
    return mac


def safe_dirname(name: str) -> str:
    """Make a filesystem-safe folder/file name."""
    name = name.strip()
    name = re.sub(r"[^\w\s.\-]", "_", name, flags=re.UNICODE)
    name = re.sub(r"\s+", " ", name).strip()
    return name or "UnknownDevice"


def pkt_macs(pkt) -> Set[str]:
    """Return the set of MAC addresses seen in the packet (802.11 addr1..addr4)."""
    macs: Set[str] = set()
    if pkt.haslayer(Dot11):
        d = pkt[Dot11]
        for field in ("addr1", "addr2", "addr3", "addr4"):
            val = getattr(d, field, None)
            if val:
                v = str(val).lower()
                if MAC_RE.match(v):
                    macs.add(v)
    return macs


def load_devices(devices_json: Path) -> Dict[str, List[str]]:
    """
    Load devices.json and group by device name:
      { "Hub H100": ["5c:e9:...", ...], ... }
    """
    data = json.loads(devices_json.read_text(encoding="utf-8"))
    grouped: Dict[str, List[str]] = {}
    for mac_raw, dev_name in data.items():
        mac = norm_mac(mac_raw)
        name = str(dev_name).strip() or "UnknownDevice"
        grouped.setdefault(name, [])
        if mac not in grouped[name]:
            grouped[name].append(mac)
    return grouped


def find_captures(capture_dir: Path) -> List[Path]:
    """Find capture_*.pcap and capture_*.pcapng files."""
    return sorted(list(capture_dir.glob("capture_*.pcap")) + list(capture_dir.glob("capture_*.pcapng")))


def capture_index(capture_path: Path) -> str:
    """Extract i from capture_i.pcap(.pcapng)."""
    m = re.search(r"capture_(\d+)\.(pcap|pcapng)$", capture_path.name)
    return m.group(1) if m else "X"


# ----------------------------
# RSN (MFPC/MFPR) extraction
# ----------------------------

def find_rsn_ie(pkt) -> Optional[bytes]:
    """
    Return RSN IE content (info bytes) if present.
    RSN element: Element ID 48 (0x30).
    """
    elt = pkt.getlayer(Dot11Elt)
    while elt is not None:
        try:
            if getattr(elt, "ID", None) == 48:  # RSN
                return bytes(getattr(elt, "info", b""))
        except Exception:
            pass
        elt = elt.payload.getlayer(Dot11Elt)
    return None


def parse_rsn_mfpc_mfpr(rsn: bytes) -> Optional[Tuple[int, int, int]]:
    """
    Parse RSN IE and return (mfpc, mfpr, rsn_capabilities_int).
    MFPR = bit 6, MFPC = bit 7 in RSN Capabilities (little-endian).
    """
    try:
        if len(rsn) < 2 + 4 + 2:
            return None

        off = 0
        _version = int.from_bytes(rsn[off:off+2], "little")
        off += 2

        if len(rsn) < off + 4:
            return None
        off += 4

        if len(rsn) < off + 2:
            return None
        pw_count = int.from_bytes(rsn[off:off+2], "little")
        off += 2

        pw_len = 4 * pw_count
        if len(rsn) < off + pw_len:
            return None
        off += pw_len

        if len(rsn) < off + 2:
            return None
        akm_count = int.from_bytes(rsn[off:off+2], "little")
        off += 2

        akm_len = 4 * akm_count
        if len(rsn) < off + akm_len:
            return None
        off += akm_len

        # RSN Capabilities (optional)
        if len(rsn) < off + 2:
            return None

        rsn_caps = int.from_bytes(rsn[off:off+2], "little")
        mfpr = (rsn_caps >> 6) & 1
        mfpc = (rsn_caps >> 7) & 1
        return int(mfpc), int(mfpr), int(rsn_caps)
    except Exception:
        return None


def extract_assoc_request_mf_bits(pkts: List, device_macs: Set[str]) -> List[Dict[str, Any]]:
    """
    Association Request: type=0, subtype=0.
    addr2 = STA (device), addr3 = BSSID
    """
    out: List[Dict[str, Any]] = []
    for p in pkts:
        if not p.haslayer(Dot11):
            continue
        d = p[Dot11]
        if getattr(d, "type", None) != 0 or getattr(d, "subtype", None) != 0:
            continue

        sta = (getattr(d, "addr2", None) or "").lower()
        bssid = (getattr(d, "addr3", None) or "").lower()

        if sta and sta in device_macs:
            rsn = find_rsn_ie(p)
            rec: Dict[str, Any] = {
                "frame": "AssociationRequest",
                "sta": sta,
                "bssid": bssid if MAC_RE.match(bssid) else None,
                "has_rsn": bool(rsn),
                "mfpc": None,
                "mfpr": None,
                "rsn_capabilities": None,
            }
            if rsn:
                parsed = parse_rsn_mfpc_mfpr(rsn)
                if parsed:
                    mfpc, mfpr, rsn_caps = parsed
                    rec["mfpc"] = mfpc
                    rec["mfpr"] = mfpr
                    rec["rsn_capabilities"] = rsn_caps
            out.append(rec)
    return out


def extract_assoc_response_mf_bits(pkts: List, device_macs: Set[str]) -> List[Dict[str, Any]]:
    """
    Association Response: type=0, subtype=1.
    addr1 = STA (destination), addr2 = AP (source), addr3 = BSSID
    """
    out: List[Dict[str, Any]] = []
    for p in pkts:
        if not p.haslayer(Dot11):
            continue
        d = p[Dot11]
        if getattr(d, "type", None) != 0 or getattr(d, "subtype", None) != 1:
            continue

        sta = (getattr(d, "addr1", None) or "").lower()
        ap = (getattr(d, "addr2", None) or "").lower()
        bssid = (getattr(d, "addr3", None) or "").lower()

        if sta and sta in device_macs:
            rsn = find_rsn_ie(p)
            rec: Dict[str, Any] = {
                "frame": "AssociationResponse",
                "sta": sta,
                "ap": ap if MAC_RE.match(ap) else None,
                "bssid": bssid if MAC_RE.match(bssid) else None,
                "has_rsn": bool(rsn),
                "mfpc": None,
                "mfpr": None,
                "rsn_capabilities": None,
            }
            if rsn:
                parsed = parse_rsn_mfpc_mfpr(rsn)
                if parsed:
                    mfpc, mfpr, rsn_caps = parsed
                    rec["mfpc"] = mfpc
                    rec["mfpr"] = mfpr
                    rec["rsn_capabilities"] = rsn_caps
            out.append(rec)
    return out


def compute_rsn_negotiated(assoc_req: List[Dict[str, Any]],
                           assoc_resp: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    "Negotiated" RSN PMF view:
    - best: Association Response (AP-selected)
    - fallback: Association Request (STA-advertised)
    """
    def pick_last_valid(lst):
        for x in reversed(lst):
            if x.get("has_rsn") and x.get("mfpc") is not None and x.get("mfpr") is not None:
                return x
        return None

    chosen = pick_last_valid(assoc_resp) or pick_last_valid(assoc_req)

    if not chosen:
        return {"source": None, "mfpc": None, "mfpr": None, "pmf_mode": "unknown", "rsn_capabilities": None}

    mfpc = int(chosen["mfpc"])
    mfpr = int(chosen["mfpr"])

    if mfpc == 0 and mfpr == 0:
        mode = "PMF_not_supported"
    elif mfpc == 1 and mfpr == 0:
        mode = "PMF_capable_optional"
    elif mfpc == 1 and mfpr == 1:
        mode = "PMF_required"
    else:
        mode = "unknown"

    return {
        "source": chosen["frame"],
        "mfpc": mfpc,
        "mfpr": mfpr,
        "pmf_mode": mode,
        "rsn_capabilities": chosen.get("rsn_capabilities"),
    }


# ----------------------------
# 4-way handshake extraction
# ----------------------------

def key_info_bits(key_info: int) -> Dict[str, int]:
    """Decode the main flags of the Key Information field (802.11i / WPA)."""
    return {
        "descriptor_version": key_info & 0b111,          # bits 0..2
        "key_type_pairwise": (key_info >> 3) & 1,       # bit 3
        "install": (key_info >> 6) & 1,                 # bit 6
        "ack": (key_info >> 7) & 1,                     # bit 7
        "mic": (key_info >> 8) & 1,                     # bit 8
        "secure": (key_info >> 9) & 1,                  # bit 9
        "error": (key_info >> 10) & 1,                  # bit 10
        "request": (key_info >> 11) & 1,                # bit 11
        "encrypted_key_data": (key_info >> 12) & 1,     # bit 12
    }


def infer_4way_message(bits: Dict[str, int]) -> Optional[int]:
    """Infer the 4-way handshake message number (1..4) from key_info bits."""
    ack = bits["ack"]
    mic = bits["mic"]
    install = bits["install"]
    secure = bits["secure"]

    if ack == 1 and mic == 0:
        return 1
    if ack == 0 and mic == 1 and secure == 0:
        return 2
    if ack == 1 and mic == 1 and install == 1:
        return 3
    if ack == 0 and mic == 1 and secure == 1:
        return 4
    return None


def try_import_scapy_eapol() -> Tuple[bool, Any]:
    """Try to get a Scapy-decodable EAPOL-Key class."""
    try:
        from scapy.contrib.wpa_eapol import WPA_key
        return True, WPA_key
    except Exception:
        pass
    try:
        from scapy.layers.eap import EAPOL_KEY
        return True, EAPOL_KEY
    except Exception:
        pass
    return False, None


SCAPY_EAPOL_OK, SCAPY_EAPOL_KEY = try_import_scapy_eapol()


def extract_eapol_handshake_scapy(pkts: List, device_macs: Set[str]) -> List[Dict[str, Any]]:
    """Extract EAPOL-Key frames using Scapy (if available)."""
    out: List[Dict[str, Any]] = []
    if not SCAPY_EAPOL_OK or SCAPY_EAPOL_KEY is None:
        return out

    for p in pkts:
        if not p.haslayer(Dot11):
            continue
        if not (pkt_macs(p) & device_macs):
            continue

        if p.haslayer(SCAPY_EAPOL_KEY):
            k = p[SCAPY_EAPOL_KEY]

            ki = None
            for attr in ("key_info", "KeyInfo", "keyinfo"):
                if hasattr(k, attr):
                    try:
                        ki = int(getattr(k, attr))
                        break
                    except Exception:
                        pass
            if ki is None:
                continue

            bits = key_info_bits(ki)
            msg = infer_4way_message(bits)

            replay = None
            for attr in ("replay_counter", "replay", "ReplayCounter"):
                if hasattr(k, attr):
                    try:
                        replay = int(getattr(k, attr))
                        break
                    except Exception:
                        pass

            src = (p[Dot11].addr2 or "").lower()
            dst = (p[Dot11].addr1 or "").lower()

            out.append({
                "frame": "EAPOL-Key",
                "src": src if MAC_RE.match(src) else None,
                "dst": dst if MAC_RE.match(dst) else None,
                "key_info": int(ki),
                "bits": bits,
                "message": msg,
                "key_type": "pairwise" if bits["key_type_pairwise"] == 1 else "group/other",
                "replay_counter": replay,
                "source": "scapy",
            })

    return out


def tshark_available() -> bool:
    try:
        res = subprocess.run(["tshark", "-v"], capture_output=True, text=True)
        return res.returncode == 0
    except Exception:
        return False


def extract_eapol_handshake_tshark(pcap_path: Path, device_macs: Set[str]) -> List[Dict[str, Any]]:
    """
    tshark fallback: extract EAPOL-Key frames using Wireshark fields.
    """
    out: List[Dict[str, Any]] = []
    if not tshark_available():
        return out

    mac_filters = " || ".join([f"wlan.sa=={m} || wlan.da=={m}" for m in sorted(device_macs)])
    display_filter = f"eapol && ({mac_filters})" if mac_filters else "eapol"

    fields = ["wlan.sa", "wlan.da", "eapol.keydes.key_info", "eapol.keydes.replay_counter"]

    cmd = ["tshark", "-r", str(pcap_path), "-Y", display_filter, "-T", "fields", "-E", "separator=\t"]
    for f in fields:
        cmd += ["-e", f]

    try:
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode != 0:
            return out

        for line in (res.stdout or "").splitlines():
            parts = line.split("\t")
            parts += [""] * (len(fields) - len(parts))
            sa, da, key_info_s, replay_s = parts[0], parts[1], parts[2], parts[3]

            sa = (sa or "").strip().lower()
            da = (da or "").strip().lower()
            if sa and not MAC_RE.match(sa):
                sa = ""
            if da and not MAC_RE.match(da):
                da = ""

            ki = None
            if key_info_s.strip():
                s = key_info_s.strip()
                try:
                    ki = int(s, 10)
                except ValueError:
                    try:
                        ki = int(s, 16)
                    except ValueError:
                        ki = None
            if ki is None:
                continue

            replay = None
            if replay_s.strip():
                try:
                    replay = int(replay_s.strip(), 10)
                except ValueError:
                    replay = None

            bits = key_info_bits(int(ki))
            msg = infer_4way_message(bits)

            out.append({
                "frame": "EAPOL-Key",
                "src": sa or None,
                "dst": da or None,
                "key_info": int(ki),
                "bits": bits,
                "message": msg,
                "key_type": "pairwise" if bits["key_type_pairwise"] == 1 else "group/other",
                "replay_counter": replay,
                "source": "tshark",
            })

    except Exception:
        return out

    return out


def annotate_msg3_readability(handshake: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    In message 3, the AP often carries encrypted Key Data (GTK/IGTK/KDE).
    Without the key (PSK/PMK), if encrypted_key_data=1 => not readable.
    """
    for e in handshake:
        if e.get("message") == 3:
            enc = e.get("bits", {}).get("encrypted_key_data")
            return {
                "msg3_present": True,
                "encrypted_key_data": int(enc) if enc is not None else None,
                "msg3_key_data_readable": False if enc == 1 else True,
                "note": "If encrypted_key_data=1, Key Data (GTK/IGTK/KDE) cannot be parsed without decrypting the EAPOL payload."
            }
    return {"msg3_present": False, "encrypted_key_data": None, "msg3_key_data_readable": None}


# ----------------------------
# Split + global JSON
# ----------------------------

def process_capture_split(pcap_path: Path, mac_to_devices: Dict[str, Set[str]]) -> Dict[str, List]:
    """Return { device_name: [pkts...] } only for devices that appear in the capture."""
    pkts = rdpcap(str(pcap_path))
    buckets: Dict[str, List] = {}
    for pkt in pkts:
        macs = pkt_macs(pkt)
        if not macs:
            continue
        touched: Set[str] = set()
        for m in macs:
            ds = mac_to_devices.get(m)
            if ds:
                touched |= ds
        for dev in touched:
            buckets.setdefault(dev, []).append(pkt)
    return buckets


def main():
    ap = argparse.ArgumentParser(
        description="Batch split PCAP per device using devices.json + extract MFPC/MFPR (Assoc Req/Resp) + negotiated RSN + extract 4-way EAPOL-Key."
    )
    ap.add_argument("--devices", default="devices.json", help="Path to devices.json (default: ./devices.json)")
    ap.add_argument("--capture-dir", default="capture", help="Folder containing capture_*.pcap (default: ./capture)")
    ap.add_argument("--out-dir", default=".", help="Output directory (default: current directory)")
    ap.add_argument("--min-pkts", type=int, default=1, help="Write file only if it has >= N packets (default: 1)")
    ap.add_argument("--json-out", default="a.json", help="Global JSON output name (default: a.json in CWD)")
    ap.add_argument(
        "--use-tshark",
        choices=["auto", "always", "never"],
        default="auto",
        help="tshark fallback for EAPOL-Key: auto (default), always, never"
    )
    args = ap.parse_args()

    base = Path(args.out_dir).resolve()
    devices_json = Path(args.devices).resolve()
    capture_dir = Path(args.capture_dir).resolve()

    if not devices_json.exists():
        raise SystemExit(f"[ERROR] devices.json not found: {devices_json}")
    if not capture_dir.exists():
        raise SystemExit(f"[ERROR] capture folder not found: {capture_dir}")

    grouped = load_devices(devices_json)

    mac_to_devices: Dict[str, Set[str]] = {}
    device_to_macs: Dict[str, Set[str]] = {}
    for dev_name, macs in grouped.items():
        s = set(macs)
        device_to_macs[dev_name] = s
        for m in macs:
            mac_to_devices.setdefault(m, set()).add(dev_name)

    caps = find_captures(capture_dir)
    if not caps:
        raise SystemExit(f"[ERROR] No capture_*.pcap/pcapng found in {capture_dir}")

    tshark_ok = tshark_available()
    scapy_ok = bool(SCAPY_EAPOL_OK and SCAPY_EAPOL_KEY is not None)

    report: Dict[str, Any] = {
        "meta": {
            "devices_json": str(devices_json),
            "capture_dir": str(capture_dir),
            "out_dir": str(base),
            "scapy_has_eapol": scapy_ok,
            "tshark_available": tshark_ok,
            "use_tshark_mode": args.use_tshark,
            "note": "MFPC/MFPR are taken from RSN Capabilities in Assoc Req/Resp. 'Negotiated' PMF is best read from the Association Response."
        },
        "captures": []
    }

    print(f"[INFO] devices.json       : {devices_json} ({len(grouped)} device names)")
    print(f"[INFO] capture dir        : {capture_dir} ({len(caps)} captures)")
    print(f"[INFO] out dir            : {base}")
    print(f"[INFO] scapy EAPOL-Key     : {scapy_ok}")
    print(f"[INFO] tshark available    : {tshark_ok}")
    print(f"[INFO] tshark mode         : {args.use_tshark}")

    total_written = 0

    for cap in caps:
        idx = capture_index(cap)
        print(f"\n[CAPTURE] {cap.name} (i={idx})")

        buckets = process_capture_split(cap, mac_to_devices)
        cap_entry: Dict[str, Any] = {"capture_file": cap.name, "index": idx, "devices": {}}

        written_this = 0
        for dev_name, pkts in buckets.items():
            if len(pkts) < args.min_pkts:
                continue

            dev_dir = base / safe_dirname(dev_name)
            dev_dir.mkdir(parents=True, exist_ok=True)

            out_pcap = dev_dir / f"{safe_dirname(dev_name)}_{idx}.pcap"
            wrpcap(str(out_pcap), pkts)

            dev_macs = device_to_macs.get(dev_name, set())

            # RSN: Assoc Req/Resp
            assoc_req = extract_assoc_request_mf_bits(pkts, dev_macs)
            assoc_resp = extract_assoc_response_mf_bits(pkts, dev_macs)
            rsn_neg = compute_rsn_negotiated(assoc_req, assoc_resp)

            # 4-way: scapy/tshark
            hs_list: List[Dict[str, Any]] = []
            if args.use_tshark == "always":
                hs_list = extract_eapol_handshake_tshark(out_pcap, dev_macs)
            elif args.use_tshark == "never":
                hs_list = extract_eapol_handshake_scapy(pkts, dev_macs)
            else:  # auto
                hs_list = extract_eapol_handshake_scapy(pkts, dev_macs)
                if (not hs_list) and tshark_ok:
                    hs_list = extract_eapol_handshake_tshark(out_pcap, dev_macs)

            # counts per message
            msg_counts = {1: 0, 2: 0, 3: 0, 4: 0, "unknown": 0}
            for e in hs_list:
                m = e.get("message", None)
                if m in (1, 2, 3, 4):
                    msg_counts[m] += 1
                else:
                    msg_counts["unknown"] += 1

            msg3_hint = annotate_msg3_readability(hs_list)

            cap_entry["devices"][dev_name] = {
                "pcap_written": str(out_pcap),
                "packet_count": len(pkts),

                "assoc_requests": assoc_req,
                "assoc_responses": assoc_resp,

                "rsn_negotiated": rsn_neg,

                "four_way_handshake": hs_list,
                "four_way_message_counts": msg_counts,

                "msg3_negotiation_hint": msg3_hint,
            }

            print(
                f"  [+] {dev_name}: {len(pkts)} pkts -> {out_pcap} | "
                f"assocReq={len(assoc_req)} assocResp={len(assoc_resp)} eapol={len(hs_list)} | pmf={rsn_neg.get('pmf_mode')}"
            )

            written_this += 1
            total_written += 1

        if written_this == 0:
            print("  [-] No device found in this capture (based on devices.json).")

        report["captures"].append(cap_entry)

    json_path = Path.cwd() / args.json_out
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"\n[OK] Done. Files written: {total_written}")
    print(f"[OK] JSON written: {json_path}")


if __name__ == "__main__":
    main()
