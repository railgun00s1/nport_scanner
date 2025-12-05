import socket
import sys
import time
import ipaddress
import textwrap
import concurrent.futures
import os
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeRemainingColumn

# --- INIT ---
console = Console()
__author__ = "rlgn00s1"
__version__ = "9.13 (re-scan function)"


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
    
    [bold]WORKFLOW[/bold]
    1. Select Scan Mode.
    2. Run Scan.
    3. [bold green]NEW:[/bold green] After scan, choose "Re-scan" to adjust settings/file without restarting.
    
    [bold]TIPS[/bold]
    - If you get 0 results, choose Re-scan and select a [yellow]Normal[/yellow] speed.
    - Export files always [bold]append[/bold] unless you provide a new name during re-scan.
    """)
    console.print(Panel(text, title="Help Manual", border_style="cyan"))
    console.input("[dim]Press Enter to return...[/dim]")

def get_scan_speed():
    console.print("\n[bold]Select Scan Speed:[/bold]")
    console.print("1) [bold green]Insane[/bold green]   (0.8s timeout, 400 threads) - High Risk/Max Speed")
    console.print("2) [green]Fast[/green]     (1.0s timeout, 200 threads) - Best for LAN")
    console.print("3) [yellow]Normal[/yellow]   (1.5s timeout, 100 threads) - Reliable")
    console.print("4) [orange1]Careful[/orange1]  (2.0s timeout, 5 threads, 0.5s delay) - Stealthier")
    console.print("5) [red]Slow[/red]     (3.0s timeout, 1 thread, 1.0s delay) - Evade IDS")
    
    choice = console.input("[bold cyan]Select (1-5): [/bold cyan]").strip()
    
    if choice == '1': return {'timeout': 0.8, 'delay': 0, 'threads': 400}
    if choice == '2': return {'timeout': 1.0, 'delay': 0, 'threads': 200}
    if choice == '3': return {'timeout': 1.5, 'delay': 0.1, 'threads': 100}
    if choice == '4': return {'timeout': 2.0, 'delay': 0.5, 'threads': 5}
    if choice == '5': return {'timeout': 3.0, 'delay': 1.0, 'threads': 1}
    
    console.print("[dim]Invalid choice, defaulting to Normal (3)[/dim]")
    return {'timeout': 1.5, 'delay': 0.1, 'threads': 100}

def configure_export():
    console.print("\n[bold]Export Configuration:[/bold]")
    choice = console.input("Do you want to save the results? (y/n): ").lower().strip()
    
    if choice not in ['y', 'yes']:
        console.print("[yellow]Results will NOT be saved.[/yellow]")
        return None

    filename = console.input("Enter file name (e.g., scan.txt): ").strip()
    if not filename:
        console.print("[red]No filename provided. Export disabled.[/red]")
        return None
        
    path = console.input("Enter folder path (Press Enter for current folder): ").strip()
    
    full_path = ""
    if not path:
        full_path = os.path.abspath(filename)
        console.print(f"[dim]Saving to current folder: {full_path}[/dim]")
    else:
        if not os.path.exists(path):
            try:
                os.makedirs(path)
                console.print(f"[green]Created directory: {path}[/green]")
            except OSError as e:
                console.print(f"[bold red]Error creating directory: {e}[/bold red]")
                return None
        full_path = os.path.join(path, filename)
        console.print(f"[dim]Saving to: {full_path}[/dim]")
        
    return full_path

def import_targets_from_file(filepath):
    if not os.path.exists(filepath):
        console.print(f"[bold red]Error: File '{filepath}' not found.[/bold red]")
        return []

    all_targets = []
    try:
        with open(filepath, 'r') as f:
            lines = f.readlines()
            
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]Parsing file..."),
            transient=True
        ) as progress:
            progress.add_task("parsing")
            for line in lines:
                line = line.strip()
                if line:
                    targets = resolve_target_list(line)
                    all_targets.extend(targets)
        
        unique_targets = list(dict.fromkeys(all_targets))
        
        if unique_targets:
            console.print(f"[green]Successfully loaded {len(unique_targets)} targets:[/green]")
            for t in unique_targets:
                console.print(f"  [cyan]- {t}[/cyan]")
        else:
            console.print("[yellow]No valid targets found in file.[/yellow]")

        return unique_targets
    except Exception as e:
        console.print(f"[red]Error reading file: {e}[/red]")
        return []

def resolve_target_list(target_input):
    target_list = []
    if "-" in target_input:
        parts = target_input.split("-")
        if len(parts) == 2:
            try:
                start_ip = ipaddress.IPv4Address(parts[0].strip())
                end_val = parts[1].strip()
                if "." in end_val:
                    end_ip = ipaddress.IPv4Address(end_val)
                else:
                    base = str(start_ip).rsplit('.', 1)[0]
                    end_ip = ipaddress.IPv4Address(f"{base}.{end_val}")
                
                start_int = int(start_ip)
                end_int = int(end_ip)
                
                if end_int >= start_int:
                    for ip_int in range(start_int, end_int + 1):
                        target_list.append(str(ipaddress.IPv4Address(ip_int)))
                return target_list
            except ValueError:
                pass

    try:
        network = ipaddress.ip_network(target_input, strict=False)
        for ip in network.hosts():
            target_list.append(str(ip))
        return target_list
    except ValueError:
        pass

    target_list.append(target_input)
    return target_list

def scan_port(ip, port, timeout, delay):
    if delay > 0:
        time.sleep(delay)
        
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((ip, port))
        
        if result == 0:
            service = COMMON_PORTS.get(port, "Unknown")
            banner = ""
            try:
                s.settimeout(1.5) 
                if port in [80, 8080, 443, 8443]:
                    s.send(b'HEAD / HTTP/1.1\r\n\r\n')
                else:
                    s.send(b'Hello\r\n')
                
                banner_bytes = s.recv(1024)
                raw_banner = banner_bytes.decode('utf-8', errors='ignore').strip()
                banner = "".join(ch for ch in raw_banner if ch.isprintable())
                
            except:
                banner = None
            s.close()
            return (port, service, banner)
        
        s.close()
        return None
    except:
        return None

def run_scan(targets, ports, speed_config, export_path=None):
    total_hosts = len(targets)
    timeout = speed_config['timeout']
    delay = speed_config['delay']
    max_threads = speed_config['threads']
    
    console.print(f"\n[bold green][*] Starting Scan on {total_hosts} hosts...[/bold green]")
    console.print(f"[dim]Configuration: Timeout={timeout}s | Threads={max_threads}[/dim]")
    
    session_log = f"=== SCAN SESSION: {datetime.now()} ===\n"
    session_log += f"Config: Timeout={timeout}s, Threads={max_threads}\n"
    
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
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
                futures = {executor.submit(scan_port, ip, port, timeout, delay): port for port in ports}
                
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
                    display_banner = b if b else "-"
                    if len(display_banner) > 50:
                        display_banner = display_banner[:47] + "..."
                    table.add_row(str(p), s, display_banner)
                    clean_log_banner = b if b else "-"
                    session_log += f"  [+] {p}/tcp - {s} - {clean_log_banner}\n"
                
                progress.console.print(table_output)
                progress.console.print(table)
            
            progress.advance(main_task)

    if export_path:
        try:
            with open(export_path, "a", encoding="utf-8") as f:
                f.write(session_log + "\n" + "-"*40 + "\n")
            console.print(f"\n[bold green][✓] Results exported to: {export_path}[/bold green]")
        except Exception as e:
            console.print(f"\n[bold red][!] Error writing to file: {e}[/bold red]")
    
    console.print("\n[bold yellow]--- Scan Complete ---[/bold yellow]")

def start_scan_session(targets, ports):
    # Initial Setup
    export_path = configure_export()
    speed_config = get_scan_speed()

    while True:
        # Run the actual scan
        run_scan(targets, ports, speed_config, export_path)

        # Post-Scan Menu
        console.print("\n[bold]What would you like to do?[/bold]")
        console.print("1) [green]Re-scan same targets[/green] (Adjust Speed/File)")
        console.print("2) [cyan]New Target Selection[/cyan] (Main Menu)")
        console.print("3) [red]Exit Program[/red]")
        
        choice = console.input("[bold cyan]Select > [/bold cyan]").strip()

        if choice == '1':
            console.print(Panel("RE-SCAN CONFIGURATION", border_style="green"))
            
            # 1. Adjust Speed
            console.print(f"Current Speed: [bold]{speed_config['threads']} threads[/bold] (Timeout: {speed_config['timeout']}s)")
            if console.input("Change Speed? (y/N): ").lower() == 'y':
                speed_config = get_scan_speed()
            
            # 2. Adjust File
            if export_path:
                console.print(f"Current Export File: [bold]{export_path}[/bold]")
                console.print("[dim]Note: Default behavior is to APPEND to this file.[/dim]")
                if console.input("Change Filename? (y/N): ").lower() == 'y':
                     export_path = configure_export()
            else:
                 if console.input("Enable Export for this run? (y/N): ").lower() == 'y':
                     export_path = configure_export()
            
            console.print("\n[dim]Re-initializing scan...[/dim]")
            continue # Loops back to run_scan
            
        elif choice == '2':
            break # Breaks session loop, returns to __main__
        elif choice == '3':
            console.print("[bold]Exiting...[/bold]")
            sys.exit()
        else:
            console.print("[red]Invalid selection. Returning to menu.[/red]")
            continue

# --- MAIN ---
if __name__ == "__main__":
    while True:
        console.clear()
        console.print(Panel.fit(f"[bold green]PYTHON NETWORK SCANNER v{__version__}[/bold green]\nBy: {__author__}", border_style="green"))
        
        console.print("\n[bold]1)[/bold] Top 100 Ports")
        console.print("[bold]2)[/bold] Custom Range")
        console.print("[bold]3)[/bold] Help")
        console.print("[bold]4)[/bold] Exit")
        
        choice = console.input("\n[bold cyan]Select > [/bold cyan]").strip()
        
        targets = []
        ports = []
        
        if choice == '1':
            console.print("\n[bold]Target Selection:[/bold]")
            console.print("a) Import File")
            console.print("b) Enter Manually")
            sub_choice = console.input("[bold cyan]Select (a/b): [/bold cyan]").strip().lower()
            
            if sub_choice == 'a':
                f_path = console.input("Enter file path: ").strip()
                targets = import_targets_from_file(f_path)
            elif sub_choice == 'b':
                t_in = console.input("Enter Target IP/Range: ")
                targets = resolve_target_list(t_in)
            else:
                console.print("[red]Invalid selection.[/red]")
                time.sleep(1)
                continue
                
            if not targets:
                console.print("[red]No valid targets found.[/red]")
                time.sleep(1)
                continue
            
            ports = list(COMMON_PORTS.keys())
            
            # Enter Session Loop
            start_scan_session(targets, ports)

        elif choice == '2':
            t_in = console.input("Target IP/Range: ")
            targets = resolve_target_list(t_in)
            
            if not targets: 
                console.print("[red]No targets found.[/red]")
                time.sleep(1)
                continue
            
            try:
                s_p = int(console.input("Start Port: "))
                e_p = int(console.input("End Port:   "))
                ports = list(range(s_p, e_p + 1))
                
                # Enter Session Loop
                start_scan_session(targets, ports)
            except ValueError:
                console.print("[red]Invalid port numbers.[/red]")
                time.sleep(1)

        elif choice == '3':
            print_help()

        elif choice == '4':
            console.print("[bold]Exiting...[/bold]")
            sys.exit()
