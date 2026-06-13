import socket
import sys
import threading
from datetime import datetime

# quick port scanner i built for recon phase of pentests
# works on both single hosts and ranges

open_ports = []
lock = threading.Lock()

common_ports = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 135: "RPC",
    139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    27017: "MongoDB", 1433: "MSSQL"
}

def scan_port(host, port, timeout=1):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((host, port))
        if result == 0:
            service = common_ports.get(port, "unknown")
            with lock:
                open_ports.append((port, service))
        s.close()
    except socket.error:
        pass

def grab_banner(host, port):
    try:
        s = socket.socket()
        s.settimeout(2)
        s.connect((host, port))
        # send generic http request, works for a lot of services
        s.send(b"HEAD / HTTP/1.0\r\n\r\n")
        banner = s.recv(1024).decode(errors="ignore").strip()
        s.close()
        return banner
    except:
        return None

def resolve_host(target):
    try:
        ip = socket.gethostbyname(target)
        return ip
    except socket.gaierror:
        print(f"[-] Couldn't resolve {target}")
        sys.exit(1)

def run_scan(target, port_range=(1, 1024), threads=100):
    ip = resolve_host(target)
    print(f"\n{'='*55}")
    print(f"  Target   : {target} ({ip})")
    print(f"  Port range: {port_range[0]}-{port_range[1]}")
    print(f"  Started  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*55}\n")

    thread_list = []
    for port in range(port_range[0], port_range[1] + 1):
        t = threading.Thread(target=scan_port, args=(ip, port))
        thread_list.append(t)
        t.start()

        # keep thread count under control
        if len(thread_list) >= threads:
            for t in thread_list:
                t.join()
            thread_list = []

    for t in thread_list:
        t.join()

    open_ports.sort()

    if not open_ports:
        print("[-] No open ports found in range")
        return

    print(f"{'PORT':<10}{'SERVICE':<15}{'BANNER'}")
    print("-" * 55)
    for port, service in open_ports:
        banner = grab_banner(ip, port)
        banner_short = banner[:40] if banner else ""
        print(f"{port:<10}{service:<15}{banner_short}")

    print(f"\n[+] Scan complete. {len(open_ports)} open port(s) found.")
    print(f"    Finished: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python port_scanner.py <host> [start_port] [end_port]")
        print("Example: python port_scanner.py scanme.nmap.org 1 1024")
        sys.exit(0)

    host = sys.argv[1]
    start = int(sys.argv[2]) if len(sys.argv) > 2 else 1
    end = int(sys.argv[3]) if len(sys.argv) > 3 else 1024

    run_scan(host, port_range=(start, end))
