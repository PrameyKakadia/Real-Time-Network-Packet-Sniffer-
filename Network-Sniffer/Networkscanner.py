from colorama import init as colorama_init
from colorama import Fore
from colorama import Style
from scapy.all import *
import ipaddress
import re
from prettytable import PrettyTable
import threading
import socket
from queue import Queue
from time import sleep
import subprocess

def is_ipv4(string):
    try:
        ipaddress.IPv4Network(string)
        return "Port"
    except ValueError:
        cider1 = re.compile(r'^([0-9]{1,3}\.){3}[0-9]{1,3}(\/([0-9]|[1-2][0-9]|3[0-2]))?$')
        cider = cider1.search(string)
        if cider:
            return "Scan"
        else:
            return "Not a valid IP address"

def is_host_reachable(ip):
    try:
        # Send 3 ping requests and check for at least 2 successful responses
        successful_pings = 0
        for _ in range(3):
            output = subprocess.check_output(["ping", "-n", "1", ip], universal_newlines=True)
            if "Reply from" in output:
                successful_pings += 1
        return successful_pings >= 2
    except subprocess.CalledProcessError:
        return False

def scanmain():
    print(f"{Fore.BLUE}Welcome to Network Scanner\n{Style.RESET_ALL}")
    try:
        while True:
            ip = input(str("[+] Please Enter IP/CIDR Address: "))
            if is_ipv4(ip) == "Scan":
                if is_host_reachable(ip.split('/')[0]):
                    scan(ip)
                else:
                    print(f"{Fore.RED}[!] Host is not reachable{Style.RESET_ALL}")
                break
            elif is_ipv4(ip) == "Port":
                port_scan_main(ip)
                break
            else:
                print(f"{Fore.RED}[!] Please enter a valid IP address{Style.RESET_ALL}")
    except KeyboardInterrupt:
        print(f"{Fore.RED}\n[!] Redirecting to the main menu...{Style.RESET_ALL}")
        sleep(3)

def scan(ipaddress):
    arp_request = scapy.all.ARP(pdst=ipaddress)
    broadcast = scapy.all.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_boroadcast = broadcast / arp_request
    answered = scapy.all.srp(arp_request_boroadcast, timeout=.5, verbose=0)[0]
    if answered:
        print(f"[+] Number of nodes present on the network: {len(answered)}")
        print_result_node(answered)
    else:
        print(f"{Fore.YELLOW}[!] No nodes found on the network{Style.RESET_ALL}")

def print_result_node(answered):
    t = PrettyTable([f'{Fore.GREEN}IP Address', f'Mac Address{Style.RESET_ALL}'])
    for node in answered:
        t.add_row([node[1].psrc, node[1].hwsrc])
    print(t)

target = ""
queues = Queue()
open_ports = []

def is_host_up(ipaddress):
    # Method 1: Try ping first
    try:
        output = subprocess.check_output(["ping", "-n", "3", ipaddress], universal_newlines=True)
        if "Reply from" in output:
            return True
    except subprocess.CalledProcessError:
        pass

    # Method 2: Try ARP if ping fails (host may block ICMP)
    try:
        arp_request = scapy.all.ARP(pdst=ipaddress)
        broadcast = scapy.all.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered = scapy.all.srp(arp_request_broadcast, timeout=2, verbose=0)[0]
        if answered:
            return True
    except Exception:
        pass

    # Method 3: Try TCP connect on common ports as last resort
    for port in [80, 443, 22, 135, 445]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ipaddress, port))
            sock.close()
            if result == 0:
                return True
        except Exception:
            pass

    return False

def port_scan_main(ipaddress):
    if is_host_up(ipaddress):
        print(f"{Fore.BLUE}[*] Host Is Up!{Style.RESET_ALL}")
        threads = int(input("[+] Enter the number of threads: "))
        t = PrettyTable([f'{Fore.GREEN}TYPE', f'Description{Style.RESET_ALL}'])
        t.add_row(["1", "Select this mode to scan Ports 1 To 1024"])
        t.add_row(["2", "Select This to Scan ports 1 to 49152"])
        t.add_row(["3", "Select thist to scan port 20,21,22,23,25,53,80,110,443"])
        t.add_row(["4", "Select this for Custom port scan"])
        print(t)
        mode = int(input(f"{Fore.WHITE}[+] Enter Mode: {Style.RESET_ALL}"))
        global target
        target = ipaddress
        run_scanner(threads, mode)
    else:
        print(f"{Fore.YELLOW}[*] Host Is Down!{Style.RESET_ALL}")

def run_scanner(threads, mode):
    get_ports(mode)
    thread_list = []
    for _ in range(threads):
        thread = threading.Thread(target=worker)
        thread_list.append(thread)
    for thread in thread_list:
        thread.start()
    for thread in thread_list:
        thread.join()
    if open_ports:
        print("[*] Open ports are:", open_ports)
    else:
        print(f"{Fore.YELLOW}[*] No open ports found{Style.RESET_ALL}")

def get_ports(mode):
    if mode == 1:  # Scan top 1024 ports
        for port in range(1, 1025):
            queues.put(port)
    elif mode == 2:
        for port in range(1, 49153):  # Scan all ports
            queues.put(port)
    elif mode == 3:  # Scan most used ports
        ports = [20, 21, 22, 23, 25, 53, 80, 110, 443]
        for port in ports:
            queues.put(port)
    elif mode == 4:  # Custom ports
        ports = input("[+] Enter your ports (separated by blank):")
        ports = ports.split()
        ports = list(map(int, ports))
        for port in ports:
            queues.put(port)

def worker():
    while not queues.empty():
        port = queues.get()
        if portscan(port):
            print("[*] Port {} is open!".format(port))
            open_ports.append(port)

def portscan(port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((target, port))
        return True
    except:
        return False

scanmain()
