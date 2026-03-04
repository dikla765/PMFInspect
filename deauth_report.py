#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
filtre.py — Deauth robustness analyser
=======================================
Reads all deauth_capture_*.pcap from desauthcapture/ and for each capture:
  - Detects deauth/disassoc frames targeting the device
  - Detects reassociation (→ device came back online)
  - Detects EAPOL 4-way handshake (→ device re-keyed = fully recovered)
  - Detects app traffic (→ device still controllable after attack)
  - Produces a per-capture verdict + global robustness score in a.json

Usage:
  python3 filtre.py --target 50:91:E3:1C:9B:E4 --ap AA:BB:CC:DD:EE:FF
  python3 filtre.py --target 50:91:E3:1C:9B:E4 --ap AA:BB:CC:DD:EE:FF \
          --capture-dir desauthcapture --json-out a.json
"""

import argparse
import json
import re
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from scapy.all import rdpcap
from scapy.layers.dot11 import (Dot11, Dot11Deauth, Dot11Disas,
                                 Dot11AssoReq, Dot11ReassoReq)

MAC_RE = re.compile(r"^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$")


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def norm_mac(mac: str) -> str:
    mac = mac.strip().lower()
    if not MAC_RE.match(mac):
        raise ValueError(f"Invalid MAC: {mac}")
    return mac


def pkt_macs(pkt) -> Set[str]:
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


def find_captures(capture_dir: Path) -> List[Path]:
    files = sorted(
        list(capture_dir.glob("deauth_capture_*.pcap")) +
        list(capture_dir.glob("deauth_capture_*.pcapng"))
    )
    return files


def capture_index(p: Path) -> str:
    m = re.search(r"deauth_capture_(\d+)\.(pcap|pcapng)$", p.name)
    return m.group(1) if m else "?"


def tshark_available() -> bool:
    try:
        return subprocess.run(["tshark", "-v"], capture_output=True).returncode == 0
    except Exception:
        return False


# ─────────────────────────────────────────────
# Deauth / Disassoc counting
# ─────────────────────────────────────────────

def count_deauth_disassoc(pkts, target_mac: str, ap_mac: str) -> Dict[str, int]:
    """Count deauth and disassoc frames that target the device."""
    counts = {"deauth_to_device": 0, "deauth_to_ap": 0,
              "disassoc_to_device": 0, "disassoc_to_ap": 0}
    for p in pkts:
        if not p.haslayer(Dot11):
            continue
        d = p[Dot11]
        a1 = (getattr(d, "addr1", None) or "").lower()
        a2 = (getattr(d, "addr2", None) or "").lower()
        is_deauth   = p.haslayer(Dot11Deauth)
        is_disassoc = p.haslayer(Dot11Disas)
        if not (is_deauth or is_disassoc):
            continue
        key_prefix = "deauth" if is_deauth else "disassoc"
        if a1 == target_mac:
            counts[f"{key_prefix}_to_device"] += 1
        elif a1 == ap_mac and a2 == target_mac:
            counts[f"{key_prefix}_to_ap"] += 1
    return counts


# ─────────────────────────────────────────────
# Reassociation detection
# ─────────────────────────────────────────────

def detect_reassociation(pkts, target_mac: str, ap_mac: str) -> Dict[str, Any]:
    """
    Detect if the device sent an Association or Reassociation Request
    after being deauth'd → it tried to reconnect.
    Returns first & last timestamp if found.
    """
    events = []
    for p in pkts:
        if not p.haslayer(Dot11):
            continue
        d = p[Dot11]
        src = (getattr(d, "addr2", None) or "").lower()
        dst = (getattr(d, "addr1", None) or "").lower()
        if src != target_mac:
            continue
        is_assoc   = p.haslayer(Dot11AssoReq)
        is_reassoc = p.haslayer(Dot11ReassoReq)
        if is_assoc or is_reassoc:
            events.append({
                "type": "ReassocRequest" if is_reassoc else "AssocRequest",
                "dst": dst,
                "time": float(p.time) if hasattr(p, "time") else None,
            })
    return {
        "reassociation_attempts": len(events),
        "reconnected": len(events) > 0,
        "first_reconnect_time": events[0]["time"] if events else None,
        "last_reconnect_time":  events[-1]["time"] if events else None,
        "events": events,
    }


# ─────────────────────────────────────────────
# EAPOL 4-way handshake
# ─────────────────────────────────────────────

def key_info_bits(ki: int) -> Dict[str, int]:
    return {
        "descriptor_version":  ki & 0b111,
        "key_type_pairwise":   (ki >> 3) & 1,
        "install":             (ki >> 6) & 1,
        "ack":                 (ki >> 7) & 1,
        "mic":                 (ki >> 8) & 1,
        "secure":              (ki >> 9) & 1,
        "encrypted_key_data":  (ki >> 12) & 1,
    }


def infer_4way_message(bits: Dict[str, int]) -> Optional[int]:
    ack, mic, install, secure = bits["ack"], bits["mic"], bits["install"], bits["secure"]
    if ack == 1 and mic == 0:                       return 1
    if ack == 0 and mic == 1 and secure == 0:       return 2
    if ack == 1 and mic == 1 and install == 1:      return 3
    if ack == 0 and mic == 1 and secure == 1:       return 4
    return None


def _try_scapy_eapol():
    for mod, cls in [("scapy.contrib.wpa_eapol", "WPA_key"),
                     ("scapy.layers.eap", "EAPOL_KEY")]:
        try:
            import importlib
            m = importlib.import_module(mod)
            return True, getattr(m, cls)
        except Exception:
            pass
    return False, None


SCAPY_EAPOL_OK, SCAPY_EAPOL_CLS = _try_scapy_eapol()


def extract_eapol_scapy(pkts, target_mac: str, ap_mac: str) -> List[Dict[str, Any]]:
    if not SCAPY_EAPOL_OK or SCAPY_EAPOL_CLS is None:
        return []
    out = []
    device_macs = {target_mac, ap_mac}
    for p in pkts:
        if not (pkt_macs(p) & device_macs):
            continue
        if not p.haslayer(SCAPY_EAPOL_CLS):
            continue
        k = p[SCAPY_EAPOL_CLS]
        ki = None
        for attr in ("key_info", "KeyInfo", "keyinfo"):
            if hasattr(k, attr):
                try:
                    ki = int(getattr(k, attr)); break
                except Exception:
                    pass
        if ki is None:
            continue
        bits = key_info_bits(ki)
        msg  = infer_4way_message(bits)
        src  = (getattr(p[Dot11], "addr2", None) or "").lower()
        dst  = (getattr(p[Dot11], "addr1", None) or "").lower()
        out.append({"message": msg, "src": src or None, "dst": dst or None,
                    "key_info": ki, "bits": bits, "source": "scapy"})
    return out


def extract_eapol_tshark(pcap_path: Path, target_mac: str, ap_mac: str) -> List[Dict[str, Any]]:
    out = []
    if not tshark_available():
        return out
    macs = [target_mac, ap_mac]
    mac_filter = " || ".join(f"wlan.sa=={m} || wlan.da=={m}" for m in macs)
    cmd = ["tshark", "-r", str(pcap_path), "-Y", f"eapol && ({mac_filter})",
           "-T", "fields", "-E", "separator=\t",
           "-e", "wlan.sa", "-e", "wlan.da",
           "-e", "eapol.keydes.key_info", "-e", "eapol.keydes.replay_counter"]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True)
        for line in (res.stdout or "").splitlines():
            parts = (line.split("\t") + [""] * 4)[:4]
            sa, da, ki_s, _ = parts
            sa = sa.strip().lower(); da = da.strip().lower()
            if not ki_s.strip():
                continue
            try:
                ki = int(ki_s.strip(), 0)
            except ValueError:
                continue
            bits = key_info_bits(ki)
            msg  = infer_4way_message(bits)
            out.append({"message": msg,
                        "src": sa if MAC_RE.match(sa) else None,
                        "dst": da if MAC_RE.match(da) else None,
                        "key_info": ki, "bits": bits, "source": "tshark"})
    except Exception:
        pass
    return out


def eapol_summary(hs: List[Dict[str, Any]]) -> Dict[str, Any]:
    counts = {1: 0, 2: 0, 3: 0, 4: 0, "unknown": 0}
    for e in hs:
        m = e.get("message")
        counts[m if m in (1, 2, 3, 4) else "unknown"] += 1
    complete = counts[1] >= 1 and counts[2] >= 1 and counts[3] >= 1 and counts[4] >= 1
    return {"message_counts": counts, "complete_handshake_detected": complete}


# ─────────────────────────────────────────────
# App-level traffic detection
# ─────────────────────────────────────────────

def detect_app_traffic(pkts, target_mac: str) -> Dict[str, Any]:
    """
    Look for data frames (type=2) from/to the device → the app
    was still able to exchange data after the attack.
    """
    data_frames = 0
    for p in pkts:
        if not p.haslayer(Dot11):
            continue
        d = p[Dot11]
        if getattr(d, "type", None) != 2:
            continue
        macs = pkt_macs(p)
        if target_mac in macs:
            data_frames += 1
    return {
        "data_frames_after_attack": data_frames,
        "app_traffic_detected": data_frames > 0,
    }


# ─────────────────────────────────────────────
# Per-capture verdict
# ─────────────────────────────────────────────

VERDICT_LEVELS = {
    "robust":           "Device reconnected, completed 4-way handshake and resumed app traffic.",
    "partial":          "Device reconnected but did not complete full 4-way handshake or no app traffic.",
    "reconnected_only": "Device reconnected but no EAPOL or app traffic detected.",
    "not_robust":       "Device did NOT reconnect after the deauth attack.",
}


def compute_verdict(reassoc: Dict, eapol: Dict, app: Dict) -> str:
    reconnected = reassoc["reconnected"]
    complete_hs = eapol["complete_handshake_detected"]
    has_traffic = app["app_traffic_detected"]

    if reconnected and complete_hs and has_traffic:
        return "robust"
    if reconnected and (complete_hs or has_traffic):
        return "partial"
    if reconnected:
        return "reconnected_only"
    return "not_robust"



# ─────────────────────────────────────────────
# Global robustness score
# ─────────────────────────────────────────────

SCORE_MAP = {"robust": 3, "partial": 2, "reconnected_only": 1, "not_robust": 0}


def compute_global_score(captures: List[Dict]) -> Dict[str, Any]:
    verdicts = [c["verdict"] for c in captures]
    scores   = [SCORE_MAP.get(v, 0) for v in verdicts]
    n = len(scores)
    if n == 0:
        return {"score": None, "grade": "N/A", "captures_analysed": 0}
    avg = sum(scores) / (n * 3)          # normalise to [0, 1]
    pct = round(avg * 100, 1)
    grade = ("A" if pct >= 85 else
             "B" if pct >= 65 else
             "C" if pct >= 45 else
             "D" if pct >= 25 else "F")
    verdict_counts = {v: verdicts.count(v) for v in SCORE_MAP}
    return {
        "captures_analysed": n,
        "score_pct": pct,
        "grade": grade,
        "verdict_distribution": verdict_counts,
        "interpretation": (
            "Device is highly robust to deauth attacks." if grade == "A" else
            "Device recovers most of the time." if grade == "B" else
            "Device partially recovers but inconsistently." if grade == "C" else
            "Device rarely recovers from deauth attacks." if grade == "D" else
            "Device does not recover from deauth attacks."
        )
    }


# ─────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Analyse deauth_capture_*.pcap for device robustness"
    )
    parser.add_argument("--target",      required=True,  help="Device MAC address (e.g. 50:91:E3:1C:9B:E4)")
    parser.add_argument("--ap",          required=True,  help="Access Point MAC address")
    parser.add_argument("--capture-dir", default="desauthcapture", help="Folder with deauth_capture_*.pcap")
    parser.add_argument("--json-out",    default="a.json", help="Output JSON file")
    parser.add_argument("--use-tshark",  choices=["auto", "always", "never"], default="auto")
    args = parser.parse_args()

    target_mac = norm_mac(args.target)
    ap_mac     = norm_mac(args.ap)
    cap_dir    = Path(args.capture_dir).resolve()
    tshark_ok  = tshark_available()

    if not cap_dir.exists():
        raise SystemExit(f"[ERROR] Capture folder not found: {cap_dir}")

    caps = find_captures(cap_dir)
    if not caps:
        raise SystemExit(f"[ERROR] No deauth_capture_*.pcap found in {cap_dir}")

    print(f"[INFO] Target MAC   : {target_mac}")
    print(f"[INFO] AP MAC       : {ap_mac}")
    print(f"[INFO] Captures     : {len(caps)}")
    print(f"[INFO] tshark       : {tshark_ok}")

    capture_results = []

    for cap in caps:
        idx = capture_index(cap)
        print(f"\n[CAPTURE] {cap.name}")

        pkts = rdpcap(str(cap))

        # 1. Deauth/disassoc frame counts
        dc = count_deauth_disassoc(pkts, target_mac, ap_mac)

        # 2. Reassociation
        reassoc = detect_reassociation(pkts, target_mac, ap_mac)

        # 3. EAPOL 4-way
        if args.use_tshark == "always":
            hs_raw = extract_eapol_tshark(cap, target_mac, ap_mac)
        elif args.use_tshark == "never":
            hs_raw = extract_eapol_scapy(pkts, target_mac, ap_mac)
        else:
            hs_raw = extract_eapol_scapy(pkts, target_mac, ap_mac)
            if not hs_raw and tshark_ok:
                hs_raw = extract_eapol_tshark(cap, target_mac, ap_mac)

        eapol = eapol_summary(hs_raw)

        # 4. App-level data traffic
        app = detect_app_traffic(pkts, target_mac)

        # 5. Verdict
        verdict = compute_verdict(reassoc, eapol, app)

        entry = {
            "capture_file":        cap.name,
            "index":               idx,
            "total_packets":       len(pkts),
            "deauth_disassoc":     dc,
            "reassociation":       reassoc,
            "eapol_handshake":     {**eapol, "frames": hs_raw},
            "app_traffic":         app,
            "verdict":             verdict,
            "verdict_description": VERDICT_LEVELS[verdict],
        }
        capture_results.append(entry)

        print(f"  deauth→device={dc['deauth_to_device']}  "
              f"reconnected={reassoc['reconnected']}  "
              f"eapol_complete={eapol['complete_handshake_detected']}  "
              f"app_traffic={app['app_traffic_detected']}  "
              f"verdict=[ {verdict} ]")

    # Global score
    global_score = compute_global_score(capture_results)

    report = {
        "meta": {
            "target_mac":    target_mac,
            "ap_mac":        ap_mac,
            "capture_dir":   str(cap_dir),
            "tshark":        tshark_ok,
            "scapy_eapol":   SCAPY_EAPOL_OK,
            "use_tshark":    args.use_tshark,
        },
        "global_robustness": global_score,
        "captures":          capture_results,
        "verdict_legend":    VERDICT_LEVELS,
    }

    out_path = Path(args.json_out).resolve()
    out_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"\n{'='*55}")
    print(f"  ROBUSTNESS SCORE : {global_score['score_pct']}%  (grade {global_score['grade']})")
    print(f"  {global_score['interpretation']}")
    print(f"{'='*55}")
    print(f"[OK] JSON written: {out_path}")


if __name__ == "__main__":
    main()