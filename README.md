

```markdown
# 🔒 Bluetooth CVE Detection Tool

This is a Linux-based C project that scans a remote Bluetooth device to infer its **Android version** (or device type) using SDP (Service Discovery Protocol), LMP version, BLE support, and Bluetooth service profile checks. It also searches a local database of CVEs (Common Vulnerabilities and Exposures) relevant to the estimated version using JSON CVE data files.

---

## 📌 Features

- ✅ Detects Bluetooth profiles (A2DP, HFP, MAP, PBAP, OPP)
- ✅ Determines LMP (Link Manager Protocol) version
- ✅ Checks BLE (Bluetooth Low Energy) support
- ✅ Estimates Android OS version or identifies non-Android Bluetooth devices
- ✅ Searches local CVE JSON files for matching vulnerabilities
- ✅ Outputs weighted score and detailed summary

---

## 📂 Project Structure

```

bluetooth-cve-detector/
├── bluetooth\_cve\_tool.c       # Main C program
├── cve\_data/                  # Folder containing .json CVE files
│   ├── cve1.json
│   ├── cve2.json
│   └── ...
├── Makefile                   # For easy compilation (optional)
└── README.md                  # You're here!

````

---

## 🛠️ Requirements

Install the following libraries and headers:

```bash
sudo apt update
sudo apt install libbluetooth-dev libjansson-dev build-essential
````

Make sure you also have `bluez` installed:

```bash
sudo apt install bluez
```

---

## 🧑‍💻 Compilation

Use `gcc` to compile the tool:

```bash
gcc bluetooth_cve_tool.c -o bluetooth_cve_tool -lbluetooth -ljansson
```

Or use a `Makefile` (optional):

```bash
make
```

---

## ▶️ Usage

```bash
./bluetooth_cve_tool <BLUETOOTH_MAC_ADDRESS>
```

Example:

```bash
./bluetooth_cve_tool 00:1A:7D:DA:71:13
```

Make sure your Bluetooth adapter is turned on and in range of the target device.

---

## 📥 CVE Data Format

* Place your CVE JSON files in the `cve_data/` directory.
* Each file should follow the NVD (National Vulnerability Database) format, e.g.:

```json
{
  "CVE_Items": [
    {
      "cve": {
        "CVE_data_meta": {
          "ID": "CVE-2022-12345"
        },
        "description": {
          "description_data": [
            {
              "value": "Bluetooth vulnerability in Android 10 allowing unauthorized access..."
            }
          ]
        }
      }
    }
  ]
}
```

---

## 📊 Output Example

```text
[*] Querying extended SDP services...
[*] LMP version detected: 10
[*] Local adapter supports BLE: Yes
→ Weighted Score: 6.73

===== Bluetooth Device Estimation =====
LMP Version: 10
A2DP: Present
MAP: Absent
PBAP: Absent
HFP: Present
OPP: Absent
BLE Support: Yes
Estimated Device Type/Android Version: Android 11 (Red Velvet Cake)

[*] Looking up CVEs related to Android 11...
CVE ID: CVE-2022-12345
Description: Bluetooth vulnerability in Android 11 allows privilege escalation via SDP...
```

---

## 📚 References

* [Bluetooth SDP (Service Discovery Protocol)](https://www.bluetooth.com/specifications/specs/service-discovery-protocol/)
* [Bluetooth LMP Version Table](https://www.bluetooth.com/specifications/assigned-numbers/link-manager/)
* [National Vulnerability Database (NVD)](https://nvd.nist.gov/)

---

