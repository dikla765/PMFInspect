# PMFInspect

PMFInspect is a **defensive evaluation tool** designed to assess whether an IoT device correctly implements **Protected Management Frames (PMF – IEEE 802.11w)** and to evaluate its robustness against management-frame–based disruptions (e.g., deauthentication and disassociation events).

> ⚠️ Responsible Use  
> Use PMFInspect **only** on devices and networks you own or are explicitly authorized to test.  
> This tool is intended for security auditing and research purposes in controlled lab environments.

---

## Objectives

PMFInspect helps to:

- Determine the advertised PMF configuration via RSN capabilities (**MFPC / MFPR bits**)
- Verify whether PMF support is **effectively enforced**, not just announced

---

## Requirements (General)

- A Wi-Fi test environment (Access Point configured with WPA2/WPA3 as needed)
- A target IoT device
- An analysis machine (Linux recommended) with:
  - A Wi-Fi interface supporting **monitor mode**
  - Python 3.10+

---

## Experimental Setup

<p align="center">
  <img src="figure.png" alt="Experimental Setup" width="600"/>
</p>



##  Repository Structure

```
.
├── example/ Contains example execution workflows and usage demonstrations.
├── capture.py
├── deauth_capture.py
├── element.py
├── devices.json
├── requirements.txt
├── rsn_report.py
└── deauth_report.py
```

* **example**: a folder that contains all example workflows along with execution code.

* **capture.py**: the file responsible for capturing network traces during the device association phase. It assists in collecting trace files during this period. It subsequently creates the trace file *"capture.pcap"* inside the *"capture"* directory.

* **deauth_capture.py**: contains the script used to execute deauthentication and disassociation attack tests. It collects the resulting traces and stores them in the corresponding directory.

* **element.py**: a network utility module used by `capture.py` and `deauth_capture.py`.

* **requirements.txt**: contains the required dependencies.

* **rsn_report.py**: iterates through the `capture/` directory and generates a JSON report named `"report.json"`.

* **deauth_report.py**: iterates through the `deauth_capture/` directory and generates a JSON report named `"report.json"`.

---

