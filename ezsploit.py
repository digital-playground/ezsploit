#!/usr/bin/env python3
"""
exploit_tool.py - Automated exploitation tool based on CVE IDs.
Now with manual port override for any CVE.
"""
import os
import sys
import re
import json
import time
import socket
import ssl
import subprocess
import shutil
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import quote
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
import importlib.util
from typing import Dict, List, Tuple, Optional, Any

# Try to import requests for NVD fallback
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

# ----------------- Configuration -----------------
THREAD_POOL_SIZE = 50
SOCKET_TIMEOUT = 3
CIRCL_DELAY = 0.5
NVD_API_KEY = os.environ.get("NVD_API_KEY", "")  # optional

# Common port mappings (service name -> list of typical ports)
SERVICE_PORT_MAP = {
    'http': [80, 443, 8080, 8443],
    'https': [443, 8443],
    'apache': [80, 443, 8080, 8443],
    'nginx': [80, 443, 8080, 8443],
    'iis': [80, 443],
    'tomcat': [8080, 8443],
    'ssh': [22],
    'ftp': [21],
    'smb': [445, 139],
    'mysql': [3306],
    'mariadb': [3306],
    'postgresql': [5432],
    'redis': [6379],
    'mongodb': [27017],
    'exim': [25],
    'sendmail': [25],
    'smtp': [25],
    'vsftpd': [21],           # default vsftpd port
    'unrealircd': [6667],      # default IRC port
    'distcc': [3632],
}

# Probes for banner grabbing
PROBES = {
    21: b"HELP\r\n",
    22: b"",
    25: b"EHLO example.com\r\n",
    80: b"HEAD / HTTP/1.0\r\n\r\n",
    110: b"CAPA\r\n",
    143: b"a001 CAPABILITY\r\n",
    443: b"HEAD / HTTP/1.0\r\n\r\n",
    8080: b"HEAD / HTTP/1.0\r\n\r\n",
    8443: b"HEAD / HTTP/1.0\r\n\r\n",
    8888: b"HEAD / HTTP/1.0\r\n\r\n",
}

# Simple service fingerprints
SERVICE_FINGERPRINTS = [
    ("openssh", re.compile(r"openssh[_-]?([\d.]+)", re.I)),
    ("apache", re.compile(r"server:\s*apache/?\s*([\d.]+)", re.I)),
    ("nginx", re.compile(r"server:\s*nginx/?\s*([\d.]+)", re.I)),
    ("iis", re.compile(r"server:\s*microsoft-iis/?\s*([\d.]+)", re.I)),
    ("mysql", re.compile(r"mysql.?ver(?:sion)?[:/ ]?([\d.]+)", re.I)),
    ("pure-ftpd", re.compile(r"pure[- ]?ftpd[^\d]*([\d.]+)", re.I)),
    ("vsftpd", re.compile(r"vsftpd[^\d]*([\d.]+)", re.I)),
    ("exim", re.compile(r"exim", re.I)),
    ("unrealircd", re.compile(r"unrealircd", re.I)),
]

# ----------------- Helper Functions -----------------
def resolve_target(target: str) -> str:
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        raise ValueError(f"Could not resolve target: {target}")

def grab_banner(ip: str, port: int) -> Optional[str]:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(SOCKET_TIMEOUT)
        sock.connect((ip, port))
        data = b""
        if port in (443, 8443):
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with ctx.wrap_socket(sock, server_hostname=ip) as ss:
                    ss.send(b"HEAD / HTTP/1.0\r\n\r\n")
                    data = ss.recv(4096)
            except Exception:
                pass
        else:
            if port in PROBES and PROBES[port]:
                try:
                    sock.send(PROBES[port])
                except Exception:
                    pass
            try:
                data = sock.recv(4096)
            except Exception:
                pass
            sock.close()
        return data.decode("utf-8", errors="ignore").strip() if data else None
    except Exception:
        return None

def identify_service(port: int, banner: Optional[str]) -> Tuple[str, str, float]:
    if not banner:
        try:
            name = socket.getservbyport(port)
            return (name.lower(), "", 0.25)
        except Exception:
            return ("unknown", "", 0.15)
    text = banner.lower()
    for name, rx in SERVICE_FINGERPRINTS:
        m = rx.search(text)
        if m:
            ver = m.group(1) if m.lastindex else ""
            return (name, ver, 0.9 if ver else 0.75)
    m_server = re.search(r"server:\s*([^\r\n]+)", banner, re.I)
    if m_server:
        token = m_server.group(1).strip()
        token_name = token.split()[0].lower()
        return (token_name, "", 0.6)
    if "ssh" in text:
        return ("ssh", "", 0.6)
    if "http" in text:
        return ("http", "", 0.5)
    return ("unknown", "", 0.2)

def scan_ports(ip: str, ports: List[int]) -> List[Dict]:
    results = []
    def worker(p):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(SOCKET_TIMEOUT)
            if s.connect_ex((ip, p)) == 0:
                banner = grab_banner(ip, p)
                svc_name, svc_ver, _ = identify_service(p, banner)
                return {'port': p, 'service': svc_name, 'version': svc_ver, 'banner': banner}
        except Exception:
            return None
        finally:
            try:
                s.close()
            except Exception:
                pass
        return None
    with ThreadPoolExecutor(max_workers=min(THREAD_POOL_SIZE, len(ports))) as ex:
        futures = {ex.submit(worker, p): p for p in ports}
        for fut in as_completed(futures):
            r = fut.result()
            if r:
                results.append(r)
    results.sort(key=lambda x: x['port'])
    return results

def get_cve_info_from_circl(cve_id: str) -> Dict[str, Any]:
    url = f"https://cve.circl.lu/api/cve/{quote(cve_id)}"
    try:
        time.sleep(CIRCL_DELAY)
        req = Request(url, headers={"User-Agent": "exploit-tool/1.0"})
        with urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode('utf-8'))
    except Exception:
        return {}

def get_cve_info_from_nvd(cve_id: str) -> Dict[str, Any]:
    if not REQUESTS_AVAILABLE:
        return {}
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"cveId": cve_id}
    headers = {"User-Agent": "exploit-tool/1.0"}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY
    try:
        resp = requests.get(base_url, params=params, headers=headers, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            vuln = data.get('vulnerabilities', [])
            if vuln:
                return vuln[0].get('cve', {})
    except Exception:
        pass
    return {}

def extract_affected_from_nvd(nvd_cve: Dict) -> List[Dict]:
    affected = []
    configurations = nvd_cve.get('configurations', [])
    for config in configurations:
        nodes = config.get('nodes', [])
        for node in nodes:
            cpe_matches = node.get('cpeMatch', [])
            for cpe in cpe_matches:
                criteria = cpe.get('criteria', '')
                # cpe:2.3:a:exim:exim:4.72:*:*:*:*:*:*:*
                m = re.search(r'cpe:2\.3:[ao]:([^:]+):([^:]+):([^:]+)', criteria)
                if m:
                    product = m.group(2)
                    version = m.group(3)
                    if version and version != '*':
                        affected.append({'product': product.lower(), 'version': version})
    return affected

def get_cve_info(cve_id: str) -> Dict[str, Any]:
    # Try CIRCL first
    circl_data = get_cve_info_from_circl(cve_id)
    if circl_data:
        cve = {}
        cve['id'] = circl_data.get('id', cve_id)
        desc = circl_data.get('summary', '')
        cve['summary'] = desc[:200] + '...' if len(desc) > 200 else desc
        cvss = circl_data.get('cvss', 0.0)
        try:
            cve['cvss'] = float(cvss) if cvss else 0.0
        except:
            cve['cvss'] = 0.0
        affected = []
        vuln_products = circl_data.get('vulnerable_product', [])
        cpe_pattern = re.compile(r'cpe:2\.3:[ao]:([^:]+):([^:]+):([^:]+)')
        for cpe in vuln_products:
            m = cpe_pattern.search(cpe)
            if m:
                product = m.group(2)
                version = m.group(3)
                if version and version != '*':
                    affected.append({'product': product.lower(), 'version': version})
        if not affected:
            for conf in circl_data.get('vulnerable_configuration', []):
                m = cpe_pattern.search(conf)
                if m:
                    product = m.group(2)
                    version = m.group(3)
                    if version and version != '*':
                        affected.append({'product': product.lower(), 'version': version})
        cve['affected'] = affected
        if affected:
            return cve

    # Fallback to NVD
    nvd_cve = get_cve_info_from_nvd(cve_id)
    if nvd_cve:
        cve = {}
        cve['id'] = nvd_cve.get('id', cve_id)
        descriptions = nvd_cve.get('descriptions', [])
        desc = next((d['value'] for d in descriptions if d.get('lang') == 'en'), '')
        cve['summary'] = desc[:200] + '...' if len(desc) > 200 else desc
        # CVSS
        metrics = nvd_cve.get('metrics', {})
        cvssv3 = None
        if 'cvssMetricV31' in metrics:
            cvssv3 = metrics['cvssMetricV31'][0]['cvssData'].get('baseScore')
        elif 'cvssMetricV30' in metrics:
            cvssv3 = metrics['cvssMetricV30'][0]['cvssData'].get('baseScore')
        cve['cvss'] = float(cvssv3) if cvssv3 else 0.0
        affected = extract_affected_from_nvd(nvd_cve)
        cve['affected'] = affected
        if affected:
            return cve

    # If all else fails, return minimal info
    return {'id': cve_id, 'summary': 'No details available', 'cvss': 0.0, 'affected': []}

def map_product_to_ports(product: str) -> List[int]:
    product_lower = product.lower()
    for key, ports in SERVICE_PORT_MAP.items():
        if key in product_lower or product_lower in key:
            return ports
    if 'http' in product_lower or 'web' in product_lower or 'apache' in product_lower or 'nginx' in product_lower or 'iis' in product_lower:
        return [80, 443, 8080, 8443]
    if 'ssh' in product_lower:
        return [22]
    if 'ftp' in product_lower:
        return [21]
    if 'smb' in product_lower or 'cifs' in product_lower:
        return [445, 139]
    if 'mysql' in product_lower or 'mariadb' in product_lower:
        return [3306]
    if 'postgresql' in product_lower:
        return [5432]
    if 'redis' in product_lower:
        return [6379]
    if 'mongodb' in product_lower:
        return [27017]
    if 'exim' in product_lower or 'smtp' in product_lower or 'mail' in product_lower:
        return [25]
    return []

def is_version_vulnerable(service_version: str, affected_versions: List[str]) -> bool:
    if not service_version or not affected_versions:
        return False
    for aff in affected_versions:
        if aff in service_version:
            return True
    return False

def get_editor_command() -> List[str]:
    if os.name == 'posix':
        if shutil.which('nano'):
            return ['nano']
        elif shutil.which('vi'):
            return ['vi']
        else:
            return []
    elif os.name == 'nt':
        if shutil.which('notepad'):
            return ['notepad']
        else:
            return []
    return []

def open_editor(filename: str) -> bool:
    editor_cmd = get_editor_command()
    if not editor_cmd:
        print("[-] No suitable text editor found. Please create the file manually.")
        return False
    try:
        subprocess.run(editor_cmd + [filename], check=True)
        return True
    except subprocess.CalledProcessError:
        print("[-] Editor exited with error.")
        return False
    except FileNotFoundError:
        print("[-] Editor not found.")
        return False

def load_exploit(cve_id: str):
    base_name = cve_id.replace('-', '_').upper()
    candidates = [
        f"CVE/{cve_id}.py",
        f"CVE/{cve_id.upper()}.py",
        f"CVE/{base_name}.py",
    ]
    for path in candidates:
        if os.path.isfile(path):
            spec = importlib.util.spec_from_file_location(base_name, path)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            if hasattr(mod, 'exploit'):
                return mod
            else:
                print(f"[-] Exploit module {path} has no 'exploit' function.")
                return None
    return None

# ----------------- Main Exploit Tool Class -----------------
class ExploitTool:
    def __init__(self):
        self.target = None
        self.target_ip = None
        self.cves = []
        self.cve_details = {}
        self.manual_cve_info = {}   # cve_id -> {'product': str, 'port': int}
        self.scan_results = []
        self.matched_cves = []
        self.exploit_results = []

    def set_target_and_cves(self):
        self.target = input("Enter target IP/hostname: ").strip()
        try:
            self.target_ip = resolve_target(self.target)
            print(f"[+] Resolved to IP: {self.target_ip}")
        except ValueError as e:
            print(f"[-] {e}")
            return

        cve_input = input("Enter CVE(s) (comma separated): ").strip()
        self.cves = [c.strip().upper() for c in cve_input.split(',') if c.strip()]
        if not self.cves:
            print("[-] No CVEs provided.")
            return

        print("[*] Fetching CVE details...")
        self.cve_details = {}
        self.manual_cve_info = {}
        for cve in self.cves:
            info = get_cve_info(cve)
            self.cve_details[cve] = info
            print(f"  {cve}: {info['summary']} (CVSS: {info['cvss']})")
            if info['affected']:
                print(f"      Affected: {', '.join([f'{a['product']} {a['version']}' for a in info['affected']])}")
                # Ask for manual override even if affected list exists (to support custom ports)
                ans = input(f"  Do you want to override the port for {cve}? (y/n): ").strip().lower()
                if ans == 'y':
                    product = input("    Enter service name (e.g., 'vsftpd'): ").strip()
                    port_str = input("    Enter port number (e.g., 2121): ").strip()
                    try:
                        port = int(port_str)
                        self.manual_cve_info[cve] = {'product': product, 'port': port}
                        print(f"    Manual port saved: {product} on port {port}")
                    except ValueError:
                        print("    Invalid port. Skipping.")
            else:
                print("      No product/version info found.")
                ans = input(f"  Do you want to manually specify the service/port for {cve}? (y/n): ").strip().lower()
                if ans == 'y':
                    product = input("    Enter service name (e.g., 'exim', 'apache'): ").strip()
                    port_str = input("    Enter port number (e.g., 25): ").strip()
                    try:
                        port = int(port_str)
                        self.manual_cve_info[cve] = {'product': product, 'port': port}
                        print(f"    Manual info saved: {product} on port {port}")
                    except ValueError:
                        print("    Invalid port. Skipping manual entry.")
        self.scan_results = []
        self.matched_cves = []
        self.exploit_results = []

    def scan(self):
        if not self.target_ip:
            print("[-] No target set. Use option 1 first.")
            return
        if not self.cves:
            print("[-] No CVEs set. Use option 1 first.")
            return

        ports_to_scan = set()
        # From automatic CVE details
        for cve in self.cves:
            info = self.cve_details.get(cve, {})
            for aff in info.get('affected', []):
                product = aff.get('product', '')
                if product:
                    ports = map_product_to_ports(product)
                    ports_to_scan.update(ports)
        # From manual entries
        for cve, manual in self.manual_cve_info.items():
            ports_to_scan.add(manual['port'])

        if not ports_to_scan:
            print("[*] Could not determine ports from CVEs. Scanning common ports (21,22,25,80,443,445,8080).")
            ports_to_scan = [21,22,25,80,443,445,8080]
        else:
            print(f"[*] Derived ports from CVEs: {sorted(ports_to_scan)}")

        print("[*] Scanning target...")
        self.scan_results = scan_ports(self.target_ip, list(ports_to_scan))
        if not self.scan_results:
            print("[-] No open ports found on the target.")
            return

        print(f"[+] Found {len(self.scan_results)} open services:")
        for svc in self.scan_results:
            print(f"    Port {svc['port']}: {svc['service']} {svc.get('version', '')}")

        self.matched_cves = []
        # Automatic matching from affected product list
        for cve in self.cves:
            info = self.cve_details.get(cve, {})
            affected_list = info.get('affected', [])
            if affected_list:
                for svc in self.scan_results:
                    svc_name = svc['service'].lower()
                    svc_version = svc.get('version', '')
                    for aff in affected_list:
                        aff_prod = aff.get('product', '').lower()
                        aff_ver = aff.get('version', '')
                        if aff_prod and (aff_prod in svc_name or svc_name in aff_prod):
                            if is_version_vulnerable(svc_version, [aff_ver]):
                                print(f"[+] {cve} matches {svc_name} on port {svc['port']} (version {svc_version})")
                                self.matched_cves.append((cve, svc))
                            else:
                                print(f"[-] {cve}: service version {svc_version} does not match required {aff_ver}")

        # Manual entries matching
        for cve, manual in self.manual_cve_info.items():
            # Check if already matched
            if any(cve == m[0] for m in self.matched_cves):
                continue
            for svc in self.scan_results:
                if svc['port'] == manual['port']:
                    # Rough service name check (optional)
                    if manual['product'].lower() in svc['service'].lower() or svc['service'].lower() in manual['product'].lower():
                        print(f"[+] {cve} manually matched to {svc['service']} on port {svc['port']}")
                        self.matched_cves.append((cve, svc))
                    else:
                        # Still consider it a match if the port is open (user knows best)
                        print(f"[?] {cve} port {svc['port']} open, service {svc['service']} (manual product: {manual['product']})")
                        ans = input("    Is this the correct service? (y/n): ").strip().lower()
                        if ans == 'y':
                            self.matched_cves.append((cve, svc))

        # Heuristic override for known software like Exim when product info missing
        for cve in self.cves:
            if any(cve == m[0] for m in self.matched_cves):
                continue
            info = self.cve_details.get(cve, {})
            summary = info.get('summary', '').lower()
            if 'exim' in summary:
                for svc in self.scan_results:
                    if svc['port'] == 25 and ('smtp' in svc['service'] or 'exim' in svc['service']):
                        print(f"[?] {cve} summary mentions Exim, and port 25 is open with {svc['service']}.")
                        ans = input("    Is this the correct service? (y/n): ").strip().lower()
                        if ans == 'y':
                            print(f"[+] Heuristic match: {cve} on port {svc['port']}")
                            self.matched_cves.append((cve, svc))

        if not self.matched_cves:
            print("[-] No vulnerable services matched.")

    def exploit(self):
        if not self.matched_cves:
            print("[-] No matched CVEs to exploit. Run scan first.")
            return

        for cve, svc in self.matched_cves:
            print(f"\n[*] Attempting exploitation of {cve} on {self.target_ip}:{svc['port']} ({svc['service']})")
            mod = load_exploit(cve)
            if not mod:
                print(f"[-] No exploit script found for {cve} in CVE/ directory.")
                ans = input("Would you like to create it now? (y/n): ").strip().lower()
                if ans == 'y':
                    filename = f"CVE/{cve}.py"
                    os.makedirs("CVE", exist_ok=True)
                    print(f"[*] Opening editor for {filename}. Paste your exploit code, save, and exit.")
                    if open_editor(filename):
                        mod = load_exploit(cve)
                        if mod:
                            print("[+] Exploit module loaded successfully.")
                        else:
                            print("[-] Still could not load the module. Skipping.")
                            self.exploit_results.append((cve, False, "Module creation failed"))
                            continue
                    else:
                        print("[-] Editor could not be launched. Skipping.")
                        self.exploit_results.append((cve, False, "Editor launch failed"))
                        continue
                else:
                    self.exploit_results.append((cve, False, "No exploit script"))
                    continue

            try:
                success = mod.exploit(self.target_ip, svc['port'])
                if success:
                    print(f"[+] {cve} exploitation SUCCEEDED")
                    msg = "Exploit succeeded"
                else:
                    print(f"[-] {cve} exploitation FAILED")
                    msg = "Exploit failed (returned False)"
                self.exploit_results.append((cve, success, msg))
            except Exception as e:
                print(f"[!] Exception during exploit: {e}")
                self.exploit_results.append((cve, False, str(e)))

    def show_results(self):
        print("\n=== Exploitation Results ===")
        if not self.exploit_results:
            print("No exploitation attempts yet.")
        else:
            for cve, success, msg in self.exploit_results:
                status = "SUCCESS" if success else "FAIL"
                print(f"{cve}: {status} - {msg}")

    def menu(self):
        while True:
            print("\n=== Exploitation Tool Menu ===")
            print("1. Set Target & CVEs")
            print("2. Scan Target")
            print("3. Attempt Exploitation")
            print("4. Show Results")
            print("5. Exit")
            choice = input("Choice: ").strip()
            if choice == '1':
                self.set_target_and_cves()
            elif choice == '2':
                self.scan()
            elif choice == '3':
                self.exploit()
            elif choice == '4':
                self.show_results()
            elif choice == '5':
                print("Exiting.")
                break
            else:
                print("Invalid choice.")

if __name__ == "__main__":
    os.makedirs("CVE", exist_ok=True)
    tool = ExploitTool()
    try:
        tool.menu()
    except KeyboardInterrupt:
        print("\nInterrupted.")

create readme.md for this
