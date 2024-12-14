import os
import socket
import asyncio
from scapy.all import sniff, IP
import subprocess
from datetime import datetime
from ipaddress import ip_address, IPv4Address
import psutil
from colorama import Fore, Style
import threading

# ======== Моніторинг трафіку ========
def detect_port_scan(packet_counts, threshold=100):
    for ip, count in packet_counts.items():
        if count > threshold:
            print(f"{Fore.YELLOW}[УВАГА] Ймовірне сканування портів із {ip}, кількість пакетів: {count}.{Style.RESET_ALL}")
            alert_admin(f"Ймовірне сканування портів із {ip}, кількість пакетів: {count}.")

def detect_anomalous_traffic(packet_counts, threshold=500):
    for ip, count in packet_counts.items():
        if count > threshold:
            print(f"{Fore.RED}[УВАГА] Високий обсяг трафіку із {ip}: {count} пакетів.{Style.RESET_ALL}")
            alert_admin(f"Високий обсяг трафіку із {ip}: {count} пакетів.")

def alert_admin(message):
    """Запис попередження до журналу адміністратора."""
    with open("alerts.log", "a", encoding="utf-8") as log:
        log.write(f"{datetime.now()} - {message}\n")

def monitor_traffic(interface):
    packet_counts = {}
    packet_number = 1

    def process_packet(packet):
        nonlocal packet_number
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = packet[IP].proto
            protocol_name = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(protocol, str(protocol))
            src_port = packet.sport if hasattr(packet, 'sport') else "N/A"
            dst_port = packet.dport if hasattr(packet, 'dport') else "N/A"

            print(f"Пакет №{packet_number} | Джерело: {src_ip} | Порт джерела: {src_port} | Призначення: {dst_ip} | Порт призначення: {dst_port} | Протокол: {protocol_name}")

            packet_counts[src_ip] = packet_counts.get(src_ip, 0) + 1
            detect_port_scan(packet_counts)
            detect_anomalous_traffic(packet_counts)

            packet_number += 1

    print(f"Запуск моніторингу трафіку на інтерфейсі: {interface}")
    sniff(iface=interface, prn=process_packet, store=False, stop_filter=lambda x: False)

# ======== Налаштування брандмауера ========
def configure_firewall():
    print("Інтерактивне налаштування брандмауера...")

    rule_name = input("Введіть назву для правила брандмауера: ")

    # Статус правила
    status_options = {"1": "True", "2": "False"}
    print("Виберіть статус правила:")
    print("1: Увімкнути")
    print("2: Вимкнути")
    status = status_options.get(input("Виберіть (1/2): "), "True")

    # Тип правила
    type_options = {"1": "Allow", "2": "Block"}
    print("Виберіть тип правила:")
    print("1: Дозволити")
    print("2: Заблокувати")
    rule_type = type_options.get(input("Виберіть (1/2): "), "Block")

    # Програма
    program = input("Вкажіть шлях до програми (або залиште порожнім для всіх програм): ") or "Any"

    # IP-адреси
    ip_options = {"1": "Any", "2": "Specific IP", "3": "IP Range"}
    print("Виберіть IP-адреси для застосування правила:")
    print("1: Усі IP-адреси")
    print("2: Конкретна IP-адреса")
    print("3: Діапазон IP-адрес")
    ip_choice = ip_options.get(input("Виберіть (1/2/3): "), "Any")

    if ip_choice == "Specific IP":
        remote_ip = input("Введіть конкретну IP-адресу: ")
    elif ip_choice == "IP Range":
        remote_ip = input("Введіть діапазон IP-адрес (наприклад, 192.168.1.1-192.168.1.255): ")
    else:
        remote_ip = "Any"

    # Протокол
    protocol_options = {"1": "Any", "2": "Specific Protocol"}
    print("Виберіть протокол:")
    print("1: Усі протоколи")
    print("2: Конкретний протокол")
    protocol_choice = input("Виберіть (1/2): ")

    if protocol_choice == "2":
        protocol = input("Введіть протокол (TCP/UDP): ")
    else:
        protocol = "Any"

    # Порти
    ports = "Any"
    if protocol != "Any":  # Порти можна вказати лише для конкретного протоколу
        port_options = {"1": "Any", "2": "Specific Port", "3": "Port Range"}
        print("Виберіть порти:")
        print("1: Усі порти")
        print("2: Конкретний порт")
        print("3: Діапазон портів")
        port_choice = input("Виберіть (1/2/3): ")

        if port_choice == "2":
            ports = input("Введіть конкретний порт: ")
        elif port_choice == "3":
            ports = input("Введіть діапазон портів (наприклад, 20-80): ")

    # Створення команди PowerShell
    command = [
        "powershell", "-Command",
        f"New-NetFirewallRule -DisplayName '{rule_name}' "
        f"-Direction Inbound -Action {rule_type} -Enabled {status} "
        f"-Program '{program}' -RemoteAddress {remote_ip} "
        f"-Protocol {protocol}"
    ]

    if ports != "Any":  # Додаємо параметр портів лише за потреби
        command[2] += f" -LocalPort {ports}"

    # Виконання команди
    try:
        subprocess.run(command, check=True)
        print("Правило брандмауера успішно налаштовано.")
    except subprocess.CalledProcessError as e:
        print(f"Помилка під час налаштування правила брандмауера: {e}")

# ======== Сканування мережі ========
def parse_ip_range(ip_range):
    ips = []
    for part in ip_range.split(','):
        if '-' in part:
            start_ip, end_ip = map(ip_address, part.split('-'))
            ips.extend(range(int(start_ip), int(end_ip) + 1))
        else:
            ips.append(int(ip_address(part)))
    return ips

def parse_port_range(port_range):
    ports = []
    for part in port_range.split(','):
        if '-' in part:
            start_port, end_port = map(int, part.split('-'))
            ports.extend(range(start_port, end_port + 1))
        else:
            ports.append(int(part))
    return ports

def scan_port(host, port, open_ports):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        if result == 0:
            open_ports.append(port)

def scan_ports_multithreaded(host, ports):
    open_ports = []
    threads = []
    for port in ports:
        thread = threading.Thread(target=scan_port, args=(host, port, open_ports))
        threads.append(thread)
        thread.start()
    for thread in threads:
        thread.join()
    return open_ports

def scan_network(ip_range, ports):
    active_hosts = {}

    print(f"Сканування мережі для IP: {', '.join([str(IPv4Address(ip)) for ip in ip_range])} і портів: {', '.join(map(str, ports))}...")
    for ip in ip_range:
        ip_str = str(IPv4Address(ip))  # Конвертуємо числову IP-адресу у строку
        try:
            socket.gethostbyaddr(ip_str)  # Перевірка, чи є хост активним
            active_ports = scan_ports_multithreaded(ip_str, ports)
            if active_ports:
                active_hosts[ip_str] = active_ports
        except socket.herror:
            continue

    return active_hosts

# ======== Основна програма ========
def main():
    print("Оберіть опцію:")
    print("1: Моніторинг мережевого трафіку")
    print("2: Налаштування брандмауера")
    print("3: Сканування мережі")

    choice = int(input("Введіть ваш вибір (1-3): "))
    if choice == 1:
        interfaces = psutil.net_if_addrs()
        iface_names = list(interfaces.keys())
        for i, iface in enumerate(iface_names):
            print(f"{i}: {iface}")
        interface_index = int(input("Оберіть інтерфейс за індексом: "))
        monitor_traffic(iface_names[interface_index])
    elif choice == 2:
        configure_firewall()
    elif choice == 3:
        target_ip_range = parse_ip_range(input("Введіть діапазон IP-адрес (наприклад, 192.168.1.1-192.168.1.10, 192.168.1.20): "))
        target_ports = parse_port_range(input("Введіть діапазон портів (наприклад, 20-80, 443): "))
        results = scan_network(target_ip_range, target_ports)
        if results:
            print("Результати сканування:")
            for ip, ports in results.items():
                print(f"{ip}: Відкриті порти: {', '.join(map(str, ports))}")
        else:
            print("Активних хостів або відкритих портів не знайдено.")

if __name__ == "__main__":
    main()