#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║          NEXSCAN - Advanced Port Scanner v1.0                ║
║          For authorized lab/network use only                 ║
╚══════════════════════════════════════════════════════════════╝

Author  : NEXSCAN Project
Purpose : Discovers open TCP ports on target machines
Usage   : python3 port_scanner.py [OPTIONS]
"""

# ── Standard library imports — no pip installs needed
import socket        # handles all the actual network connections
import threading     # used for the thread lock in the progress tracker
import argparse      # parses the command-line arguments the user types
import ipaddress     # lets us check if an IP is private or public
import sys           # used to exit the script cleanly on errors
import time          # used to measure scan speed and latency
import json          # for exporting results in JSON format
import csv           # for exporting results in CSV format
import os            # general OS utilities (file paths, etc.)
from datetime import datetime                          # timestamps on reports
from queue import Queue                                # not used directly but available
from concurrent.futures import ThreadPoolExecutor, as_completed  # runs many port scans at the same time


# ─────────────────────────────────────────────────────────────
#  ANSI COLOR PALETTE
#  These are escape codes that color the terminal output.
#  Makes the results much easier to read at a glance.
# ─────────────────────────────────────────────────────────────
class Colors:
    RESET   = "\033[0m"   # resets color back to default
    BOLD    = "\033[1m"   # makes text bold
    RED     = "\033[91m"  # used for errors and danger warnings
    GREEN   = "\033[92m"  # used for open ports
    YELLOW  = "\033[93m"  # used for warnings and filtered ports
    BLUE    = "\033[94m"  # general accent color
    MAGENTA = "\033[95m"  # used for service names
    CYAN    = "\033[96m"  # used for headers and the progress bar
    WHITE   = "\033[97m"  # used for general info text
    GRAY    = "\033[90m"  # used for less important info (closed ports, latency)
    BG_RED  = "\033[41m"  # red background — used on the DANGER tag
    BG_GREEN= "\033[42m"  # green background (available if needed)

# Shortcut so we don't have to type Colors() everywhere
C = Colors()


# ─────────────────────────────────────────────────────────────
#  WELL-KNOWN PORT DATABASE
#  Maps port numbers to (service name, description).
#  When a port is found open, we look it up here to tell the
#  user what's likely running on it.
# ─────────────────────────────────────────────────────────────
SERVICE_DB = {
    20:    ("FTP-Data",       "File Transfer Protocol - Data"),
    21:    ("FTP",            "File Transfer Protocol - Control"),
    22:    ("SSH",            "Secure Shell - encrypted remote login"),
    23:    ("Telnet",         "Unencrypted remote login (INSECURE)"),
    25:    ("SMTP",           "Simple Mail Transfer Protocol"),
    53:    ("DNS",            "Domain Name System"),
    67:    ("DHCP",           "Dynamic Host Configuration (server)"),
    68:    ("DHCP",           "Dynamic Host Configuration (client)"),
    69:    ("TFTP",           "Trivial File Transfer Protocol"),
    80:    ("HTTP",           "HyperText Transfer Protocol"),
    110:   ("POP3",           "Post Office Protocol v3"),
    111:   ("RPC",            "Remote Procedure Call"),
    119:   ("NNTP",           "Network News Transfer Protocol"),
    123:   ("NTP",            "Network Time Protocol"),
    135:   ("MSRPC",          "Microsoft Remote Procedure Call"),
    137:   ("NetBIOS-NS",     "NetBIOS Name Service"),
    138:   ("NetBIOS-DGM",    "NetBIOS Datagram Service"),
    139:   ("NetBIOS-SSN",    "NetBIOS Session Service"),
    143:   ("IMAP",           "Internet Message Access Protocol"),
    161:   ("SNMP",           "Simple Network Management Protocol"),
    162:   ("SNMP-Trap",      "SNMP Trap"),
    179:   ("BGP",            "Border Gateway Protocol"),
    194:   ("IRC",            "Internet Relay Chat"),
    389:   ("LDAP",           "Lightweight Directory Access Protocol"),
    443:   ("HTTPS",          "HTTP Secure (TLS/SSL)"),
    445:   ("SMB",            "Server Message Block / Windows Shares"),
    465:   ("SMTPS",          "SMTP Secure"),
    500:   ("IKE",            "Internet Key Exchange (VPN)"),
    514:   ("Syslog",         "System Logging Protocol"),
    515:   ("LPD",            "Line Printer Daemon"),
    587:   ("SMTP-Sub",       "SMTP Submission Port"),
    631:   ("IPP",            "Internet Printing Protocol"),
    636:   ("LDAPS",          "LDAP over SSL"),
    993:   ("IMAPS",          "IMAP over SSL"),
    995:   ("POP3S",          "POP3 over SSL"),
    1080:  ("SOCKS",          "SOCKS Proxy"),
    1194:  ("OpenVPN",        "OpenVPN"),
    1433:  ("MSSQL",          "Microsoft SQL Server"),
    1434:  ("MSSQL-Mon",      "MS SQL Server Monitor"),
    1521:  ("Oracle",         "Oracle Database"),
    1723:  ("PPTP",           "Point-to-Point Tunneling Protocol"),
    2049:  ("NFS",            "Network File System"),
    2082:  ("cPanel",         "cPanel HTTP"),
    2083:  ("cPanel-SSL",     "cPanel HTTPS"),
    2181:  ("Zookeeper",      "Apache ZooKeeper"),
    2375:  ("Docker",         "Docker (UNENCRYPTED - DANGER)"),
    2376:  ("Docker-TLS",     "Docker over TLS"),
    3000:  ("Dev-Server",     "Common dev server (Node/Rails/etc)"),
    3306:  ("MySQL",          "MySQL / MariaDB Database"),
    3389:  ("RDP",            "Remote Desktop Protocol (Windows)"),
    3690:  ("SVN",            "Apache Subversion"),
    4444:  ("Metasploit",     "Metasploit default listener"),
    5000:  ("UPnP/Dev",       "UPnP or Flask dev server"),
    5432:  ("PostgreSQL",     "PostgreSQL Database"),
    5900:  ("VNC",            "Virtual Network Computing"),
    5985:  ("WinRM",          "Windows Remote Management HTTP"),
    5986:  ("WinRM-SSL",      "Windows Remote Management HTTPS"),
    6379:  ("Redis",          "Redis In-Memory Store (often unauth)"),
    6443:  ("K8s-API",        "Kubernetes API Server"),
    7001:  ("WebLogic",       "Oracle WebLogic Server"),
    8000:  ("HTTP-Alt",       "Alternative HTTP"),
    8008:  ("HTTP-Alt2",      "Alternative HTTP"),
    8080:  ("HTTP-Proxy",     "HTTP Proxy / Dev Server"),
    8443:  ("HTTPS-Alt",      "Alternative HTTPS"),
    8888:  ("Jupyter",        "Jupyter Notebook"),
    9000:  ("SonarQube",      "SonarQube / PHP-FPM"),
    9090:  ("Prometheus",     "Prometheus Metrics"),
    9200:  ("Elasticsearch",  "Elasticsearch REST API"),
    9300:  ("ES-Cluster",     "Elasticsearch Cluster"),
    10250: ("Kubelet",        "Kubernetes Kubelet API"),
    11211: ("Memcached",      "Memcached (often exposed)"),
    27017: ("MongoDB",        "MongoDB Database"),
    27018: ("MongoDB-Shard",  "MongoDB Shard"),
    50000: ("SAP",            "SAP Message Server"),
}

# Ports that are considered risky if found open on a target.
# Things like Telnet (unencrypted), SMB (ransomware favorite),
# Redis (often auth-free), Docker API (can mean full server takeover), etc.
DANGER_PORTS = {23, 135, 137, 138, 139, 445, 2375, 4444, 6379, 11211}

# Predefined port groups — user picks one with --group.
# Saves typing out long port lists manually.
PORT_GROUPS = {
    "top-20":   [21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080],
    "top-100":  list(range(1, 101)),           # ports 1 through 100
    "web":      [80, 443, 8000, 8008, 8080, 8443, 8888, 9000, 9090, 9200],
    "database": [1433, 1521, 3306, 5432, 6379, 9200, 27017],
    "remote":   [22, 23, 3389, 5900, 5985, 5986],
    "mail":     [25, 110, 143, 465, 587, 993, 995],
    "all":      list(range(1, 65536)),         # full scan — all 65535 ports
}


# ─────────────────────────────────────────────────────────────
#  BANNER — printed at startup
#  Just the ASCII art logo and a reminder about authorized use.
# ─────────────────────────────────────────────────────────────
def print_banner():
    banner = f"""
{C.CYAN}{C.BOLD}
 ███╗   ██╗███████╗██╗  ██╗███████╗ ██████╗ █████╗ ███╗   ██╗
 ████╗  ██║██╔════╝╚██╗██╔╝██╔════╝██╔════╝██╔══██╗████╗  ██║
 ██╔██╗ ██║█████╗   ╚███╔╝ ███████╗██║     ███████║██╔██╗ ██║
 ██║╚██╗██║██╔══╝   ██╔██╗ ╚════██║██║     ██╔══██║██║╚██╗██║
 ██║ ╚████║███████╗██╔╝ ██╗███████║╚██████╗██║  ██║██║ ╚████║
 ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
{C.RESET}{C.GRAY}        Advanced Port Scanner | Lab Edition v1.0
        WARNING  Use only on systems you own or have permission to test{C.RESET}
"""
    print(banner)


# ─────────────────────────────────────────────────────────────
#  UTILITY FUNCTIONS
# ─────────────────────────────────────────────────────────────

def resolve_target(target: str) -> tuple[str, str]:
    """
    Takes whatever the user typed as the target (IP or hostname)
    and resolves it to an actual IP address.
    Also tries a reverse DNS lookup to get the hostname.
    If it can't resolve the target at all, it exits the script.
    """
    try:
        ip = socket.gethostbyname(target)   # converts hostname to IP
        try:
            hostname = socket.gethostbyaddr(ip)[0]  # reverse lookup: IP to hostname
        except socket.herror:
            # reverse lookup failed — just use whatever the user typed
            hostname = target if target != ip else "N/A"
        return ip, hostname
    except socket.gaierror:
        # DNS resolution totally failed — nothing to scan
        print(f"{C.RED}[!] Cannot resolve target: {target}{C.RESET}")
        sys.exit(1)


def is_private_ip(ip: str) -> bool:
    """
    Checks if the IP is a private/internal address (192.168.x.x, 10.x.x.x, etc).
    If it's public, we warn the user to make sure they have permission.
    """
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def get_service_info(port: int) -> tuple[str, str]:
    """
    Looks up a port number in our SERVICE_DB first.
    If it's not there, falls back to Python's built-in service list.
    If nothing found, returns 'Unknown'.
    """
    if port in SERVICE_DB:
        return SERVICE_DB[port]   # found in our custom database
    try:
        name = socket.getservbyport(port)   # try the OS service registry
        return name, "Registered service"
    except OSError:
        return "Unknown", "No service information"


def grab_banner(ip: str, port: int, timeout: float) -> str:
    """
    Once a port is confirmed open, this tries to grab whatever text
    the service sends back when you connect to it — called a 'banner'.
    Banners often reveal the service name and version (e.g. 'OpenSSH 7.4').
    We try a few different probes since different services respond differently.
    """
    # Different probe types: HTTP request, blank line, or just connect and listen
    probes = [b"HEAD / HTTP/1.0\r\n\r\n", b"\r\n", b""]
    for probe in probes:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((ip, port))
                if probe:
                    s.send(probe)   # send the probe to trigger a response
                # read up to 1024 bytes of the response
                banner = s.recv(1024).decode("utf-8", errors="replace").strip()
                # only keep the first line — the rest is usually noise
                first_line = banner.split("\n")[0][:80]
                if first_line:
                    return first_line
        except Exception:
            continue   # if this probe fails, try the next one
    return ""   # nothing came back — return empty string


# ─────────────────────────────────────────────────────────────
#  CORE SCANNER
# ─────────────────────────────────────────────────────────────

class ScanResult:
    """
    A simple container to hold everything we learn about a single port.
    Each scanned port gets one ScanResult object.
    """
    def __init__(self, port, state, service, description, banner="", latency=0.0):
        self.port        = port         # the port number (e.g. 80)
        self.state       = state        # "open", "closed", or "filtered"
        self.service     = service      # service name (e.g. "HTTP")
        self.description = description  # human-readable description
        self.banner      = banner       # banner text if grabbed (e.g. "Apache/2.4.7")
        self.latency     = latency      # how long the connection took in milliseconds
        self.is_danger   = port in DANGER_PORTS  # flag if this is a risky port

    def to_dict(self):
        """Converts the result to a plain dictionary — used when exporting to JSON/CSV."""
        return {
            "port": self.port,
            "state": self.state,
            "service": self.service,
            "description": self.description,
            "banner": self.banner,
            "latency_ms": round(self.latency, 2),
            "danger": self.is_danger,
        }


def scan_port(ip: str, port: int, timeout: float, grab_banners: bool) -> ScanResult:
    """
    The main scanning function — this is what runs for every single port.
    It tries to open a TCP connection to ip:port.

    How it works:
      - connect_ex() returns 0 if the connection succeeded (port is OPEN)
      - returns a non-zero error code if it failed (port is CLOSED)
      - if it times out, the port is likely FILTERED by a firewall

    This is called a TCP Connect Scan — it does the full handshake,
    doesn't need root/admin, and works on any OS.
    """
    service, description = get_service_info(port)  # look up what this port likely is
    t0 = time.time()  # record start time so we can calculate latency
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)               # don't wait forever on each port
            result = s.connect_ex((ip, port))   # attempt the connection
            latency = (time.time() - t0) * 1000 # calculate how long it took (ms)

            if result == 0:
                # connection succeeded — port is open
                banner = ""
                if grab_banners:
                    banner = grab_banner(ip, port, timeout)  # try to get version info
                return ScanResult(port, "open", service, description, banner, latency)
            else:
                # connection was refused — port is closed
                return ScanResult(port, "closed", service, description, "", latency)

    except socket.timeout:
        # no response at all — likely a firewall is silently dropping packets
        return ScanResult(port, "filtered", service, description, "", (time.time() - t0) * 1000)
    except Exception:
        # anything else unexpected — treat as filtered
        return ScanResult(port, "filtered", service, description, "", 0.0)


# ─────────────────────────────────────────────────────────────
#  DISPLAY FUNCTIONS
#  These handle printing results to the terminal in a clean,
#  color-coded table format.
# ─────────────────────────────────────────────────────────────

def print_result_header():
    """Prints the column headers above the results table."""
    print(f"\n{C.BOLD}{C.WHITE}{'─'*72}{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}{'PORT':<8}{'STATE':<12}{'SERVICE':<16}{'LATENCY':<12}DETAILS{C.RESET}")
    print(f"{C.BOLD}{C.WHITE}{'─'*72}{C.RESET}")


def print_result(r: ScanResult, verbose: bool = False):
    """
    Prints a single port result as a formatted table row.
    By default, only OPEN ports are printed.
    If verbose=True, closed and filtered ports show up too.
    Dangerous open ports get a red DANGER tag next to them.
    """
    if r.state == "open":
        # add a danger tag if this port is in our DANGER_PORTS set
        danger_tag = f" {C.BG_RED}{C.BOLD} ⚠ DANGER {C.RESET}" if r.is_danger else ""
        color = C.GREEN
        state_str = f"{C.GREEN}OPEN{C.RESET}"
    elif r.state == "filtered":
        if not verbose:
            return   # skip filtered ports unless user asked for verbose
        color = C.YELLOW
        state_str = f"{C.YELLOW}FILTERED{C.RESET}"
        danger_tag = ""
    else:
        if not verbose:
            return   # skip closed ports unless user asked for verbose
        color = C.GRAY
        state_str = f"{C.GRAY}CLOSED{C.RESET}"
        danger_tag = ""

    # format each column with consistent spacing and color
    port_col    = f"{color}{r.port}/tcp{C.RESET}"
    latency_col = f"{C.GRAY}{r.latency:.1f}ms{C.RESET}"
    service_col = f"{C.MAGENTA}{r.service}{C.RESET}"
    desc_col    = f"{C.GRAY}{r.description[:40]}{C.RESET}"

    print(f"  {port_col:<18}{state_str:<20}{service_col:<22}{latency_col:<18}{desc_col}{danger_tag}")

    # if we grabbed a banner, print it on the line below
    if r.banner:
        print(f"  {' '*8}{C.CYAN}Banner: {C.WHITE}{r.banner}{C.RESET}")


def print_summary(target_ip: str, hostname: str, results: list[ScanResult],
                  ports_scanned: int, elapsed: float, args):
    """
    Prints the final summary box at the end of the scan.
    Shows total open/filtered/closed counts, scan speed,
    and a highlighted list of any dangerous ports that were found open.
    """
    # separate results into categories for the summary
    open_ports     = [r for r in results if r.state == "open"]
    filtered_ports = [r for r in results if r.state == "filtered"]
    danger_open    = [r for r in open_ports if r.is_danger]  # dangerous AND open

    print(f"\n{C.BOLD}{C.WHITE}{'='*72}{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}  SCAN SUMMARY{C.RESET}")
    print(f"{C.BOLD}{C.WHITE}{'='*72}{C.RESET}")
    print(f"  Target      : {C.YELLOW}{target_ip}{C.RESET}  ({hostname})")
    print(f"  Scan Time   : {C.WHITE}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{C.RESET}")
    print(f"  Elapsed     : {C.WHITE}{elapsed:.2f}s{C.RESET}  |  "
          f"Threads: {C.WHITE}{args.threads}{C.RESET}  |  "
          f"Timeout: {C.WHITE}{args.timeout}s{C.RESET}")
    print(f"  Ports Scanned: {C.WHITE}{ports_scanned:,}{C.RESET}")
    print(f"  Open        : {C.GREEN}{C.BOLD}{len(open_ports)}{C.RESET}   "
          f"Filtered: {C.YELLOW}{len(filtered_ports)}{C.RESET}   "
          f"Closed: {C.GRAY}{ports_scanned - len(open_ports) - len(filtered_ports)}{C.RESET}")

    # if any dangerous ports are open, call them out clearly
    if danger_open:
        print(f"\n  {C.BG_RED}{C.BOLD} WARNING  DANGEROUS PORTS OPEN: {C.RESET}")
        for r in danger_open:
            print(f"  {C.RED}  -> Port {r.port} ({r.service}): {r.description}{C.RESET}")

    # clean list of all open ports at the bottom for quick reference
    if open_ports:
        print(f"\n  {C.BOLD}Open Ports:{C.RESET}")
        for r in open_ports:
            tag = f" {C.RED}[DANGER]{C.RESET}" if r.is_danger else ""
            print(f"  {C.GREEN}  + {r.port}/tcp{C.RESET} - {C.MAGENTA}{r.service}{C.RESET}{tag}")

    print(f"{C.BOLD}{C.WHITE}{'='*72}{C.RESET}\n")


# ─────────────────────────────────────────────────────────────
#  EXPORT
#  Saves the open port results to a file after the scan.
#  Supports JSON, CSV, and plain text formats.
# ─────────────────────────────────────────────────────────────
def export_results(results: list[ScanResult], target_ip: str, hostname: str,
                   fmt: str, filename: str):
    # only export open ports — no point saving a list of closed ones
    open_results = [r for r in results if r.state == "open"]
    ts = datetime.now().isoformat()  # timestamp for the report header

    if fmt == "json":
        # structured JSON — easy to parse or feed into other tools
        data = {
            "scan_time": ts,
            "target_ip": target_ip,
            "hostname":  hostname,
            "open_ports": [r.to_dict() for r in open_results],
            "total_open": len(open_results),
        }
        with open(filename, "w") as f:
            json.dump(data, f, indent=2)

    elif fmt == "csv":
        # spreadsheet-friendly format — one port per row
        with open(filename, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["port","state","service","description","banner","latency_ms","danger"])
            writer.writeheader()
            for r in open_results:
                writer.writerow(r.to_dict())

    elif fmt == "txt":
        # simple plain text report — easy to read or paste into a write-up
        with open(filename, "w") as f:
            f.write(f"NEXSCAN Report - {ts}\n")
            f.write(f"Target: {target_ip} ({hostname})\n")
            f.write("=" * 60 + "\n")
            for r in open_results:
                f.write(f"Port {r.port}/tcp  {r.service:20} {r.description}\n")
                if r.banner:
                    f.write(f"  Banner: {r.banner}\n")

    print(f"{C.GREEN}[+] Results saved to {C.BOLD}{filename}{C.RESET}")


# ─────────────────────────────────────────────────────────────
#  ARGUMENT PARSER
#  Defines all the flags and options the user can pass in
#  from the command line (e.g. -t, --group, --threads, etc.)
# ─────────────────────────────────────────────────────────────
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="nexscan",
        description="NEXSCAN - Advanced Python Port Scanner (Lab Edition)",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
EXAMPLES:
  Scan a host using top-20 common ports (default):
    python3 port_scanner.py -t 192.168.1.1

  Scan a specific port range:
    python3 port_scanner.py -t 192.168.1.1 -p 1-1024

  Scan only web ports with banner grabbing:
    python3 port_scanner.py -t 192.168.1.1 --group web --banners

  Scan a list of specific ports, 200 threads, save to JSON:
    python3 port_scanner.py -t 192.168.1.1 -p 22,80,443,3306,3389 --threads 200 --output results.json --format json

  Full scan with verbose output (all ports 1-65535):
    python3 port_scanner.py -t 192.168.1.1 --group all --threads 500 -v

WARNING  Only scan systems you own or have explicit written permission to test.
"""
    )

    # required — the IP or hostname to scan
    p.add_argument("-t", "--target",   required=True,   help="Target IP address or hostname")

    # optional port selection — range or comma list; falls back to --group if not set
    p.add_argument("-p", "--ports",    default=None,    help="Port range (e.g. 1-1024) or list (e.g. 22,80,443)")

    # predefined port groups for convenience
    p.add_argument("--group",          default="top-20",
                   choices=list(PORT_GROUPS.keys()),
                   help="Use a predefined port group (default: top-20)")

    # more threads = faster scan, but uses more system resources
    p.add_argument("--threads",        type=int, default=100,  help="Number of concurrent threads (default: 100)")

    # lower timeout = faster scan but may miss slow-responding ports
    p.add_argument("--timeout",        type=float, default=1.0, help="Connection timeout per port in seconds (default: 1.0)")

    # enables banner grabbing on open ports
    p.add_argument("--banners",        action="store_true",     help="Attempt banner grabbing on open ports")

    # show everything, not just open ports
    p.add_argument("-v", "--verbose",  action="store_true",     help="Show closed/filtered ports too")

    # save results to a file
    p.add_argument("--output",         default=None,            help="Save results to file (e.g. report.json)")

    # file format for the export
    p.add_argument("--format",         default="json",
                   choices=["json","csv","txt"],
                   help="Output file format (default: json)")
    return p


# ─────────────────────────────────────────────────────────────
#  PORT LIST BUILDER
#  Turns the user's input (-p or --group) into a plain list
#  of port numbers to scan.
# ─────────────────────────────────────────────────────────────
def build_port_list(args) -> list[int]:
    if args.ports:
        # user gave us a custom range or list, parse it
        ports = []
        for part in args.ports.split(","):
            part = part.strip()
            if "-" in part:
                # it's a range like "1-1024" — expand it
                start, end = part.split("-", 1)
                ports.extend(range(int(start), int(end) + 1))
            else:
                # it's a single port number
                ports.append(int(part))
        return sorted(set(ports))  # remove duplicates and sort
    else:
        # no -p given — use the selected --group
        return PORT_GROUPS[args.group]


# ─────────────────────────────────────────────────────────────
#  PROGRESS TRACKER
#  Shows a live progress bar while the scan is running.
#  Updates every 50 ports with %, ETA, and scan rate.
#  Uses a thread lock so multiple threads don't corrupt the output.
# ─────────────────────────────────────────────────────────────
class Progress:
    def __init__(self, total: int):
        self.total   = total             # total number of ports being scanned
        self.done    = 0                 # how many have been scanned so far
        self.lock    = threading.Lock()  # prevents race conditions between threads
        self.start_t = time.time()       # scan start time — used to calculate rate/ETA

    def tick(self):
        """Called after each port is scanned. Updates and reprints the progress bar."""
        with self.lock:
            self.done += 1
            # only redraw the bar every 50 ports (or on the last port) to avoid flicker
            if self.done % 50 == 0 or self.done == self.total:
                pct     = self.done / self.total * 100
                elapsed = time.time() - self.start_t
                rate    = self.done / elapsed if elapsed else 0        # ports per second
                eta     = (self.total - self.done) / rate if rate else 0  # seconds remaining
                bar_len = 30
                filled  = int(bar_len * self.done / self.total)
                bar     = "#" * filled + "." * (bar_len - filled)     # filled vs empty blocks
                print(
                    f"\r  {C.CYAN}[{bar}]{C.RESET} "
                    f"{C.WHITE}{pct:5.1f}%{C.RESET}  "
                    f"{C.GRAY}{self.done}/{self.total} ports  "
                    f"~{eta:.0f}s remaining  {rate:.0f} ports/s{C.RESET}",
                    end="", flush=True   # \r overwrites the same line each time
                )


# ─────────────────────────────────────────────────────────────
#  MAIN — entry point, ties everything together
# ─────────────────────────────────────────────────────────────
def main():
    print_banner()  # show the ASCII logo first

    # parse what the user typed on the command line
    parser = build_parser()
    args   = parser.parse_args()

    # resolve the target and build the list of ports to scan
    target_ip, hostname = resolve_target(args.target)
    port_list   = build_port_list(args)
    total_ports = len(port_list)

    # print the scan configuration so the user knows what's about to run
    print(f"{C.BOLD}  Target   :{C.RESET} {C.YELLOW}{target_ip}{C.RESET}  ({hostname})")
    if not is_private_ip(target_ip):
        # warn if scanning a public IP — just a safety reminder
        print(f"  {C.YELLOW}WARNING: {target_ip} is a PUBLIC IP. Ensure you have authorization!{C.RESET}")
    print(f"{C.BOLD}  Ports    :{C.RESET} {total_ports:,} ports  "
          f"({port_list[0]}-{port_list[-1]})")
    print(f"{C.BOLD}  Threads  :{C.RESET} {args.threads}   "
          f"Timeout: {args.timeout}s   "
          f"Banners: {'Yes' if args.banners else 'No'}")
    print(f"\n{C.WHITE}  Starting scan at {datetime.now().strftime('%H:%M:%S')} ...{C.RESET}\n")

    print_result_header()  # print the table column headers

    results  = []
    progress = Progress(total_ports)
    t_start  = time.time()

    # ── THE MAIN SCAN LOOP
    # ThreadPoolExecutor runs many scan_port() calls at the same time.
    # max_workers controls how many run in parallel — more = faster (up to a point).
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        # submit all port scans to the thread pool at once
        futures = {
            executor.submit(scan_port, target_ip, port, args.timeout, args.banners): port
            for port in port_list
        }
        # as_completed() yields each future as it finishes (not in order)
        for future in as_completed(futures):
            result = future.result()     # get the ScanResult from the finished thread
            results.append(result)
            if result.state == "open":
                # clear the progress bar line before printing the open port
                print(f"\r{' '*80}\r", end="")
                print_result(result, verbose=args.verbose)
            progress.tick()  # update the progress bar

    elapsed = time.time() - t_start
    print(f"\n")  # move past the progress bar line

    # if verbose mode is on, also print the closed/filtered ports
    if args.verbose:
        non_open = [r for r in results if r.state != "open"]
        for r in sorted(non_open, key=lambda x: x.port):
            print_result(r, verbose=True)

    # print the final summary box
    print_summary(target_ip, hostname, results, total_ports, elapsed, args)

    # if user gave --output, save the results to a file
    if args.output:
        export_results(results, target_ip, hostname, args.format, args.output)


# ── Script entry point
# This makes sure main() only runs when the script is executed directly,
# not when it's imported as a module by something else.
if __name__ == "__main__":
    main()
