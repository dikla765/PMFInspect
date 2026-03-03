# PMFInspect

PMFInspect is a **defensive evaluation tool** designed to assess whether an IoT device correctly implements **Protected Management Frames (PMF, IEEE 802.11w)** and to evaluate its robustness against management-frame–based disruptions (e.g., deauthentication and disassociation events).

> ⚠️ **Responsible Use**
> PMFInspect must be used **only** on devices and networks that you own or are explicitly authorized to test.
> This tool is intended exclusively for security auditing and research purposes in controlled laboratory environments.

---

## Experimental Setup

<p align="center">
  <img src="figure.png" alt="Experimental Setup" width="600"/>
</p>

---

## Repository Structure

```
.
├── capture/
│   └── capture_X.pcap
├── desauthcapture/
│   └── deauth_capture_X.pcap
├── example/
├── capture.py
├── deauth_capture.py
├── deauth_report.py
├── device_onoff.py
├── element.py
├── rsn_report.py
├── devices.json
└──requirements.txt

```

* **example/**: Contains example workflows and execution scripts.

* **capture.py**: Captures network traces during the device association phase. It collects traffic during this period and generates a trace file (`capture.pcap`) within the `capture/` directory.

* **deauth_capture.py**: Executes deauthentication and disassociation test scenarios. It captures the resulting traffic and stores the corresponding trace files in the designated directory.

* **element.py**: Network utility module used by both `capture.py` and `deauth_capture.py`.

* **devices.json**: Stores device metadata (e.g., MAC address mappings and device types).

* **requirements.txt**: Lists the required Python dependencies.


* **device_onoff.py**: Python script for automating Android apps via ADB.

* **rsn_report.py**: Processes `.pcap` files from the `capture/` directory and generates a JSON report (`a.json`).

* **deauth_report.py**: Processes `.pcap` files from the `deauth_capture/` directory and generates a JSON report (`b.json`).

---

## Requirements

* A Wi-Fi test environment (Access Point configured with WPA2/WPA3 as appropriate)
* A target IoT device
* An analysis machine (Linux recommended) equipped with:

  * A Wi-Fi interface supporting **monitor mode**
  * Python 3.10 or later
  * ADB installed (`adb devices` must work)

* Mobile phone running Android
  * USB debugging enabled
  * No lock screen password (for auto-unlock)

---

## Usage

```bash
python3 device_onoff.py
```

```bash
python3 device_onoff.py --n 20 --device 300 700 --toggle 900 950 --app com.example.app
```


