import socket
import sys
import time
import ipaddress
import textwrap
from datetime import datetime

# --- METADATA ---
__author__ = "DCR"
__version__ = "8.2 (Flex Range + UI Fixes)"

# --- ETHICAL WARNING ---
# This tool is built for educational and defensive analysis purposes only.
# Port scanning targets without permission is illegal in many jurisdictions.
# The author is not responsible for any misuse of this tool.
# Always obtain written permission before scanning networks you do not own.
# -----------------------

# --- ANSI COLOR CODES ---
YELLOW = "\033[93m"
GREEN  = "\033[32m"
RED    = "\033[91m"
CYAN   = "\033[96m"
RESET  = "\033[0m"

COMMON_PORTS = {
    20: "FTP Data", 21: "FTP Control", 22: "SSH", 23: "Telnet",
    25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
    139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    3389: "RDP", 8080: "HTTP Proxy"
}

def print_help():
    help_text = textwrap.dedent(f"""
    ============================================================
    NETWORK SCANNER MANUAL (v{__version__})
    ============================================================
     
    1. TARGET FORMATS
       You can enter targets in three ways:
       - Single IP:    192.168.1.5
       - CIDR Subnet:  192.168.1.0/24 (Scans .1 to .254)
       - IP Range A:   192.168.1.5 - 10 (Scans .5 to .10)
       - IP Range B:   192.168.1.5 - 192.168.1.10

    2. SCAN MODES
       - Quick Scan:   Checks only the top 14 most common ports
                       (20: "FTP", 
                        21: "FTP", 
                        22: "SSH", 
                        23: "Telnet",
                        25: "SMTP", 
                        53: "DNS", 
                        80: "HTTP", 
                        110: "POP3",
                        139: "NetBIOS", 
                        143: "IMAP", 
                        443: "HTTPS", 
                        445: "SMB",
                        3389: "RDP", 
                        8080: "HTTP Proxy").
       - Custom Scan:  Lets you define a specific numeric range
                       (e.g., Port 1 to 65535).

    3. SCAN SPEED (TIMEOUTS)
       - Fast (0.5s):  Best for local WiFi/LAN. Fast but might miss
                       ports on slow internet connections.
       - Normal (1.0s): Balanced. Good for most uses.
       - Slow (2.0s):  Stealthier and accurate for laggy remote servers.

    4. CONTROLS
       - Back:         Type 'b' at any prompt to return to the menu.
       - Cancel:       Press 'Ctrl+C' during a scan to stop immediately
                       and generate a partial report.
     
    ============================================================
    """)
    print(help_text)
    input("[*] Press Enter to return to menu...")

def get_scan_speed():
    print("\n--- Select Scan Speed ---")
    print("1) Fast   (0.5s timeout)")
    print("2) Normal (1.0s timeout)")
    print("3) Slow   (2.0s timeout)")
    print("b) Back to Main Menu")
    choice = input("Select speed (1-3 or b): ").strip().lower()
    if choice == 'b': return None
    if choice == '1': return 0.5
    if choice == '3': return 2.0
    return 1.0 

def resolve_target_list(target_input):
    target_list = []
    
    # --- TYPE 1: IP RANGE ---
    if "-" in target_input:
        parts = target_input.split("-")
        if len(parts) == 2:
            try:
                start_ip_str = parts[0].strip()
                end_part_str = parts[1].strip()
                
                # Verify start is a valid IP
                start_ip_obj = ipaddress.IPv4Address(start_ip_str)
                
                # --- FLEX RANGE LOGIC START ---
                # Check if the second part contains a dot (indicating a full IP)
                if "." in end_part_str:
                    # User entered: 192.168.1.5 - 192.168.1.10
                    end_ip_obj = ipaddress.IPv4Address(end_part_str)
                    
                    # Security Check: Ensure start and end are on same /24 subnet
                    start_octets = str(start_ip_obj).split('.')
                    end_octets = str(end_ip_obj).split('.')
                    
                    if start_octets[:3] != end_octets[:3]:
                        print(f"{RED}[-] Error: Range scan only supports the same /24 subnet.{RESET}")
                        return []
                        
                    end_val = int(end_octets[3])
                    base_ip = ".".join(start_octets[:3])
                else:
                    # User entered: 192.168.1.5 - 10
                    end_val = int(end_part_str)
                    octets = str(start_ip_obj).split('.')
                    base_ip = ".".join(octets[:3])
                # --- FLEX RANGE LOGIC END ---
                
                start_val = int(str(start_ip_obj).split('.')[3])
                
                if end_val < start_val:
                    print(f"{RED}[-] Error: End of range is smaller than start.{RESET}")
                    return []
                if end_val > 255:
                    print(f"{RED}[-] Error: Octet cannot exceed 255.{RESET}")
                    return []
                
                for i in range(start_val, end_val + 1):
                    target_list.append(f"{base_ip}.{i}")
                    
                print(f"[*] IP Range Detected. Hosts to scan: {len(target_list)}")
                return target_list
            except ValueError:
                pass

    # --- TYPE 2: CIDR ---
    try:
        network = ipaddress.ip_network(target_input, strict=False)
        if network.num_addresses > 1:
            for ip in network.hosts():
                target_list.append(str(ip))
            print(f"[*] CIDR Detected. Hosts to scan: {len(target_list)}")
            return target_list
    except ValueError:
        pass

    # --- TYPE 3: SINGLE HOST ---
    target_list.append(target_input)
    return target_list

def grab_banner(s, port):
    try:
        if port == 80 or port == 8080:
            s.send(b'HEAD / HTTP/1.1\r\n\r\n')
        banner = s.recv(1024).decode().strip()
        return banner
    except:
        return None

def scan_single_host(target_ip, ports_list, timeout):
    findings = []
    open_count = 0
    try:
        for port in ports_list:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            result = s.connect_ex((target_ip, port))
            if result == 0:
                open_count += 1
                service = COMMON_PORTS.get(port, "Unknown")
                s.settimeout(2.0)
                banner = grab_banner(s, port)
                
                # Apply GREEN color to the finding string
                line = f"    {GREEN}[+] Port {port:<5} OPEN  --> {service}{RESET}"
                if banner:
                    line += f"\n        |__ Banner: {banner}"
                findings.append(line)
            s.close()
    except socket.error:
        pass
    return findings, open_count

def print_final_report(scan_results, start_time):
    print("\n" + "="*60)
    # Apply YELLOW to the title, then RESET at the end
    print(f"{YELLOW}FINAL SCAN REPORT - {str(datetime.now())}{RESET}")
    print(f"Scan Duration: {datetime.now() - start_time}")
    print("="*60)
    
    if not scan_results:
        print("[*] No open ports found on any targets.")
    else:
        for ip, lines in scan_results.items():
            print(f"\n{CYAN}[*] Host: {ip}{RESET}")
            for line in lines:
                print(line)
    print("\n" + "="*60)
    print("END OF REPORT")
    print("="*60)

# --- Main Menu ---
if __name__ == "__main__":
    print(f"\n--- Python Network Scanner (v{__version__}) ---")
    print("By: " + __author__)
    print(f"{RED}[!] WARNING: Use only on authorized networks.{RESET}")
    
    while True:
        try:
            print("\n" + "="*40)
            print("MAIN MENU")
            print("="*40)
            print("1) Quick Scan (Host + Top common Ports)")
            print("2) Custom Scan (Specific Port Range)")
            print("3) Help (User Manual)")
            print("4) Exit tool")
            
            choice = input("Select option: ").strip()
            print("") 

            # Setup variables
            targets = []
            ports_to_scan = []
            timeout = 1.0

            if choice == '1':
                t_in = input("Enter Target (IP/CIDR/Range) or 'b' to go BACK: \n").strip()
                print("") 
                
                if t_in.lower() == 'b': continue
                targets = resolve_target_list(t_in)
                if not targets: continue 
                
                timeout = get_scan_speed()
                if timeout is None: continue
                ports_to_scan = list(COMMON_PORTS.keys())

            elif choice == '2':
                t_in = input("Enter Target (IP/CIDR/Range) or 'b' to go BACK: \n").strip()
                print("") 
                
                if t_in.lower() == 'b': continue
                targets = resolve_target_list(t_in)
                if not targets: continue

                try:
                    s_p = input("Start Port (or 'b'): \n").strip()
                    if s_p == 'b': continue
                    start_p = int(s_p)
                    print("")
                    
                    e_p = input("End Port (or 'b'):   \n").strip()
                    if e_p == 'b': continue
                    end_p = int(e_p)
                    print("")

                    ports_to_scan = list(range(start_p, end_p + 1))
                    timeout = get_scan_speed()
                    if timeout is None: continue
                except ValueError:
                    print("Invalid numbers.")
                    continue

            elif choice == '3':
                print_help()
                continue
            
            elif choice == '4':
                print("Exiting tool...")
                sys.exit()
            else:
                print("Invalid selection.")
                continue

            # --- EXECUTION ---
            scan_results = {} 
            hosts_online = 0
            total_ports_open = 0
            total_hosts = len(targets)
            start_time = datetime.now()

            print(f"[*] Starting Scan on {total_hosts} hosts...")
            print("[*] Press Ctrl+C to stop early and see report.\n")
            
            try:
                for index, ip in enumerate(targets):
                    progress = f"[*] Progress: {index+1}/{total_hosts}"
                    stats = f" | Online: {hosts_online} | Open Ports: {total_ports_open}"
                    current = f" | Scanning: {ip:<15}"
                    sys.stdout.write(f"\r{progress}{stats}{current}")
                    sys.stdout.flush()

                    findings, count = scan_single_host(ip, ports_to_scan, timeout)

                    if count > 0:
                        hosts_online += 1
                        total_ports_open += count
                        scan_results[ip] = findings

                sys.stdout.write("\r" + " "*90 + "\r") 
                print_final_report(scan_results, start_time)

            except KeyboardInterrupt:
                sys.stdout.write("\r" + " "*90 + "\r")
                print("\n[!] Scan Aborted by user. Generating partial report...")
                print_final_report(scan_results, start_time)

        except KeyboardInterrupt:
            print("\nExiting...")
            sys.exit()
