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
└── requirements.txt
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

# Capture and Analysis of PMF Implementation

Set up the experimental device, power off the device, and collect traffic in parallel.

```bash
python3 capture.py --channel 6 --duration 120 --bssid 50:91:E3:1C:9B:E4
```

```bash
python3 rsn_report.py \
  --devices devices.json \
  --capture-dir capture \
  --out-dir results \
  --min-pkts 5 \
  --json-out a.json
```

---

# Robustness Test Against Deauthentication / Disassociation

Power on the device and execute the following command.

### Example 1

```bash
sudo python3 desauth.py -t F0:A7:31:5A:34:5F -a 24:5A:4C:12:34:56
```

| Option          | Short | Default             | Description                 |
| --------------- | ----- | ------------------- | --------------------------- |
| `--interface`   | `-i`  | auto                | Wireless interface          |
| `--target`      | `-t`  | `50:91:E3:1C:9B:E4` | Target device MAC           |
| `--ap`          | `-a`  | gateway MAC         | Access point MAC            |
| `--count`       | `-n`  | 1000                | Number of attack iterations |
| `--no-disassoc` | —     | off                 | Send only deauth frames     |
| `--capture-ap`  | —     | off                 | Capture only AP traffic     |

Output: captured packets are saved in

```
desauthcapture/
   deauth_capture_1.pcap
   deauth_capture_2.pcap
```

---

### Example 2

Wi-Fi **deauthentication / disassociation testing tool** with **traffic capture** and **device stress testing**.

Basic execution:

```bash
sudo python3 desauth.py
```

Options

| Option              | Description                                |
| ------------------- | ------------------------------------------ |
| `-i`, `--interface` | Wi-Fi interface (auto-detected by default) |
| `-t`, `--target`    | Target device MAC                          |
| `-a`, `--ap`        | Access point MAC                           |
| `-n`, `--count`     | Number of attack iterations                |
| `--channel`         | Wi-Fi channel                              |
| `--no-disassoc`     | Disable disassociation frames              |
| `--capture-ap`      | Capture only AP traffic                    |
| `--stress`          | Run stress test mode                       |
| `--device-cycles`   | Number of ON/OFF cycles                    |
| `--device-xy`       | Device tap coordinates                     |
| `--toggle-xy`       | Toggle tap coordinates                     |
| `--app`             | Android app package                        |

---

```bash
sudo python3 desauth.py \
 -t F0:A7:31:5A:34:5F \
 --channel 6 \
 --count 500 \
 --stress \
 --device-cycles 10
```

---

### Custom Channel and Packet Count

```bash
sudo python3 desauth.py \
  --channel 6 \
  --count 500
```

---

Captured packets are saved in

```
desauthcapture/
   deauth_capture_1.pcap
   deauth_capture_2.pcap
```

Use **filtre.py** to analyze Wi-Fi deauthentication attack captures and evaluate device robustness.

Basic execution:

```bash
python3 filtre.py --target 50:91:E3:1C:9B:E4 --ap AA:BB:CC:DD:EE:FF
```

Custom directories:

```bash
python3 filtre.py \
  --target 50:91:E3:1C:9B:E4 \
  --ap AA:BB:CC:DD:EE:FF \
  --capture-dir desauthcapture \
  --json-out b.json
```

Options

| Option          | Description                                     |
| --------------- | ----------------------------------------------- |
| `--target`      | Device MAC address                              |
| `--ap`          | Access point MAC                                |
| `--capture-dir` | Folder containing `deauth_capture_*.pcap`       |
| `--json-out`    | Output JSON report                              |
| `--use-tshark`  | `auto`, `always`, or `never` for EAPOL decoding |

---

## Output

The script produces

```
b.json
```
