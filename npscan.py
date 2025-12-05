import socket
import sys
import time
import ipaddress
import textwrap
import concurrent.futures
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeRemainingColumn

# --- INIT ---
console = Console()
__author__ = "rlgn00s1"
__version__ = "9.6"

# --- CONFIGURATION ---
DEFAULT_THREADS = 100
LOG_FILE = "scan_reports.txt"

# --- TOP 100 COMMON PORTS ---
COMMON_PORTS = {
    7: "Echo", 9: "Discard", 13: "Daytime", 17: "QOTD", 19: "Chargen",
    20: "FTP Data", 21: "FTP Control", 22: "SSH", 23: "Telnet", 25: "SMTP",
    26: "RSFTP", 37: "Time", 42: "WINS", 49: "TACACS", 53: "DNS",
    67: "DHCP", 68: "DHCP", 69: "TFTP", 70: "Gopher", 79: "Finger",
    80: "HTTP", 81: "HTTP Alt", 88: "Kerberos", 102: "Siemens S7", 110: "POP3",
    111: "RPCbind", 113: "Ident", 119: "NNTP", 123: "NTP", 135: "RPC",
    137: "NetBIOS", 138: "NetBIOS", 139: "NetBIOS", 143: "IMAP", 161: "SNMP",
    179: "BGP", 194: "IRC", 201: "AppleTalk", 264: "BGMP", 389: "LDAP",
    443: "HTTPS", 445: "SMB", 465: "SMTPS", 500: "IKE", 513: "Rlogin",
    514: "Syslog", 515: "LPD", 520: "RIP", 548: "AFP", 554: "RTSP",
    587: "SMTP Sub", 631: "IPP", 636: "LDAPS", 873: "Rsync", 902: "VMware",
    989: "FTPS", 990: "FTPS", 993: "IMAPS", 995: "POP3S", 1025: "MS RPC",
    1026: "MS RPC", 1027: "MS RPC", 1080: "SOCKS", 1194: "OpenVPN", 1433: "SQL Server",
    1434: "SQL Monitor", 1521: "Oracle", 1720: "H.323", 1723: "PPTP", 2049: "NFS",
    2082: "cPanel", 2083: "cPanel SSL", 2121: "FTP Alt", 3306: "MySQL", 3389: "RDP",
    3690: "SVN", 4333: "mSQL", 4444: "Metasploit", 4899: "Radmin", 5000: "UPnP",
    5432: "PostgreSQL", 5631: "pcAnywhere", 5800: "VNC HTTP", 5900: "VNC", 5901: "VNC-1",
    6000: "X11", 6001: "X11", 6379: "Redis", 6667: "IRC", 7001: "WebLogic",
    8000: "HTTP Alt", 8008: "HTTP Alt", 8080: "HTTP Proxy", 8081: "HTTP Alt", 8443: "HTTPS Alt",
    8888: "HTTP Alt", 9000: "Sonarqube", 9090: "Websphere", 9200: "Elasticsearch", 27017: "MongoDB"
}

def print_help():
    text = textwrap.dedent(f"""
    [bold cyan]NETWORK SCANNER v{__version__}[/bold cyan]
    
    [bold]1. SCAN MODES[/bold]
    - Option 1 (Top 100): Scans the most critical 100 ports.
    - Option 2 (Custom): Scans a manual range (e.g., 1-65535).
    
    [bold]2. SPACE SAVER UI[/bold]
    - The tool uses a single Global Progress Bar.
    - It will ONLY print detailed tables if OPEN ports are found.
    """)
    console.print(Panel(text, title="Help Manual", border_style="cyan"))
    console.input("[dim]Press Enter to return...[/dim]")

def get_scan_speed():
    console.print("\n[bold]Select Scan Speed:[/bold]")
    console.print("1) [green]Fast[/green]   (0.5s timeout) - Best for LAN/WiFi")
    console.print("2) [yellow]Normal[/yellow] (1.0s timeout) - Balanced")
    console.print("3) [red]Slow[/red]   (2.0s timeout) - For laggy/remote networks")
    
    choice = console.input("[bold cyan]Select (1-3): [/bold cyan]").strip()
    if choice == '1': return 0.5
    if choice == '3': return 2.0
    return 1.0  # Default to Normal

def save_log(content):
    try:
        with open(LOG_FILE, "a") as f:
            f.write(content + "\n")
    except Exception as e:
        console.print(f"[red][!] Error saving log: {e}[/red]")

def resolve_target_list(target_input):
    target_list = []
    
    # TYPE 1: RANGE
    if "-" in target_input:
        parts = target_input.split("-")
        if len(parts) == 2:
            try:
                start_ip_str = parts[0].strip()
                end_part_str = parts[1].strip()
                start_ip_obj = ipaddress.IPv4Address(start_ip_str)
                
                if "." in end_part_str:
                    end_ip_obj = ipaddress.IPv4Address(end_part_str)
                    start_octets = str(start_ip_obj).split('.')
                    end_octets = str(end_ip_obj).split('.')
                    
                    if start_octets[:3] != end_octets[:3]:
                        console.print("[red]Error: Ranges must be in same /24 subnet.[/red]")
                        return []
                    end_val = int(end_octets[3])
                    base_ip = ".".join(start_octets[:3])
                else:
                    end_val = int(end_part_str)
                    octets = str(start_ip_obj).split('.')
                    base_ip = ".".join(octets[:3])
                
                start_val = int(str(start_ip_obj).split('.')[3])
                
                if end_val < start_val or end_val > 255:
                    console.print("[red]Error: Invalid range.[/red]")
                    return []
                
                for i in range(start_val, end_val + 1):
                    target_list.append(f"{base_ip}.{i}")
                return target_list
            except ValueError:
                pass

    # TYPE 2: CIDR
    try:
        network = ipaddress.ip_network(target_input, strict=False)
        for ip in network.hosts():
            target_list.append(str(ip))
        return target_list
    except ValueError:
        pass

    # TYPE 3: SINGLE HOST
    target_list.append(target_input)
    return target_list

def scan_port(ip, port, timeout):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((ip, port))
        
        if result == 0:
            service = COMMON_PORTS.get(port, "Unknown")
            banner = ""
            try:
                s.settimeout(1.0)
                if port in [80, 8080, 443, 8443]:
                    s.send(b'HEAD / HTTP/1.1\r\n\r\n')
                else:
                    s.send(b'Hello\r\n')
                
                banner_bytes = s.recv(1024)
                banner = banner_bytes.decode('utf-8', errors='ignore').strip()
            except:
                banner = None
            
            s.close()
            return (port, service, banner)
        
        s.close()
        return None
    except:
        return None

def run_scan(targets, ports, timeout):
    total_hosts = len(targets)
    console.print(f"\n[bold green][*] Starting Scan on {total_hosts} hosts (Threads: {DEFAULT_THREADS})...[/bold green]")
    console.print("[dim][*] Only displaying hosts with OPEN ports.[/dim]\n")
    
    session_log = f"\n=== SCAN SESSION: {datetime.now()} ===\n"

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]{task.description}"),
        BarColumn(bar_width=40, style="blue", complete_style="green"),
        TextColumn("[bold]{task.completed}/{task.total}"),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeRemainingColumn(),
        console=console,
        transient=False 
    ) as progress:
        
        main_task = progress.add_task("Scanning Network...", total=total_hosts)

        for ip in targets:
            progress.update(main_task, description=f"Scanning {ip}...")
            
            open_ports = []
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=DEFAULT_THREADS) as executor:
                futures = {executor.submit(scan_port, ip, port, timeout): port for port in ports}
                
                for future in concurrent.futures.as_completed(futures):
                    result = future.result()
                    if result:
                        open_ports.append(result)

            if open_ports:
                open_ports.sort(key=lambda x: x[0])
                
                table_output = f"\n[bold cyan]Found on {ip}:[/bold cyan]\n"
                
                table = Table(show_header=True, header_style="bold magenta", box=None)
                table.add_column("Port", style="cyan", width=8)
                table.add_column("Service", style="green")
                table.add_column("Banner", style="dim")
                
                session_log += f"\nHost: {ip}\n"

                for p, s, b in open_ports:
                    b_text = b[:30] + "..." if b and len(b) > 30 else (b or "-")
                    table.add_row(str(p), s, b_text)
                    session_log += f"  [+] {p}/tcp - {s} - {b_text}\n"
                
                progress.console.print(table_output)
                progress.console.print(table)
            
            progress.advance(main_task)

    save_log(session_log)
    console.print(f"\n[bold green][✓] Scan Complete. Saved to {LOG_FILE}[/bold green]")

# --- MAIN ---
if __name__ == "__main__":
    console.clear()
    console.print(Panel.fit(f"[bold green]PYTHON NETWORK SCANNER v{__version__}[/bold green]\nBy: {__author__}", border_style="green"))
    
    while True:
        console.print("\n[bold]1)[/bold] Top 100 Ports (Quick)")
        console.print("[bold]2)[/bold] Custom Range")
        console.print("[bold]3)[/bold] Help")
        console.print("[bold]4)[/bold] Exit")
        
        choice = console.input("\n[bold cyan]Select > [/bold cyan]").strip()
        
        targets = []
        ports = []
        
        if choice == '1':
            t_in = console.input("Target IP/Range: ")
            targets = resolve_target_list(t_in)
            if not targets: continue
            
            ports = list(COMMON_PORTS.keys())
            timeout = get_scan_speed() # ADDED BACK
            run_scan(targets, ports, timeout)
            
        elif choice == '2':
            t_in = console.input("Target IP/Range: ")
            targets = resolve_target_list(t_in)
            if not targets: continue
            
            try:
                s_p = int(console.input("Start Port: "))
                e_p = int(console.input("End Port:   "))
                ports = list(range(s_p, e_p + 1))
                timeout = get_scan_speed() # ADDED BACK
                run_scan(targets, ports, timeout)
            except ValueError:
                console.print("[red]Invalid port numbers.[/red]")
                
        elif choice == '3':
            print_help()
        elif choice == '4':
            sys.exit()
