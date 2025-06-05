🔍 Bluetooth CVE Detection Tool
This tool analyzes a target Bluetooth device (given its MAC address) and estimates its Android version or device type using LMP version, supported Bluetooth services, and BLE capability. It also searches for known CVEs (Common Vulnerabilities and Exposures) related to the estimated version.

🧠 Features
Identifies Bluetooth profiles: A2DP, MAP, PBAP, HFP, OPP.

Retrieves the target's LMP (Link Manager Protocol) version.

Checks if the local adapter supports BLE.

Estimates Android version/device type based on weighted heuristics.

Searches a local CVE dataset (JSON format) for vulnerabilities matching the device type/version.

📁 Project Structure
pgsql
Copy
Edit
bluetooth-cve-detector/
├── bluetooth_cve_detector.c
├── README.md
└── cve_data/             # Folder containing .json CVE files (downloaded from NVD or similar)
🧰 Requirements
Linux system (Tested on Kali Linux)

Bluetooth development libraries

libbluetooth-dev

libjansson-dev

Root privileges (for accessing Bluetooth device info)

📦 Install Dependencies
Use the following command to install all necessary packages:

bash
Copy
Edit
sudo apt update
sudo apt install libbluetooth-dev libjansson-dev build-essential
🛠️ Compile the Tool
bash
Copy
Edit
gcc bluetooth_cve_detector.c -o bluetooth_cve_detector -lbluetooth -ljansson
🚀 How to Use
bash
Copy
Edit
sudo ./bluetooth_cve_detector <BLUETOOTH_MAC_ADDRESS>
Example:

bash
Copy
Edit
sudo ./bluetooth_cve_detector 00:11:22:33:44:55
The tool will:

Query available Bluetooth profiles via SDP.

Retrieve the LMP version.

Check BLE support on your adapter.

Estimate the Android version or type.

Search the cve_data folder for related CVEs.

📂 CVE Data Directory
Make sure to download relevant CVE JSON files into:

swift
Copy
Edit
/home/kali/Desktop/coding/cve/cve_data/
Or modify the path in the source code:

c
Copy
Edit
#define CVE_DIR "/path/to/your/cve_data"
Each file should follow the NVD format and contain a CVE_Items array.

📝 Sample Output
yaml
Copy
Edit
[*] Querying extended SDP services...
[*] LMP version detected: 11
[*] Local adapter supports BLE: Yes

===== Bluetooth Device Estimation =====
LMP Version: 11
A2DP: Present
MAP: Present
PBAP: Present
HFP: Present
OPP: Present
BLE Support: Yes
Estimated Device Type/Android Version: Android 13 (Tiramisu)

[*] Looking up CVEs related to Android 13...
CVE ID: CVE-2023-12345
Description: Vulnerability in the Bluetooth stack of Android 13...
...
