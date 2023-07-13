import psutil
import socket
import requests
import logging
import time

# Configuration of the logger
logging.basicConfig(filename='log.txt', level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

def get_process_name(pid):
    try:
        process = psutil.Process(pid)
        process_name = process.name()
        return process_name
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return None

def scan_ip(ip_address, api_key):
    url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
    params = {'apikey': api_key, 'ip': ip_address}

    response = requests.get(url, params=params)

    if response.status_code == 200:
        try:
            report = response.json()
            positives = report.get('positives')
            if positives is None:
                positives = 0
            if positives > 0:
                status = 'Not Safe'
            else:
                status = 'Safe'

            # Get the process name associated with the IP
            process_name = None
            dns_name = None
            for conn in psutil.net_connections():
                if conn.status == psutil.CONN_ESTABLISHED and conn.raddr.ip == ip_address:
                    process_name = get_process_name(conn.pid)
                    
                    # Get the DNS name associated with the IP
                    try:
                        dns_name = socket.gethostbyaddr(ip_address)[0]
                    except socket.herror:
                        dns_name = 'Unknown'

                    break

            # If the process name is not available, use 'Unknown'
            if not process_name:
                process_name = 'Unknown'

            # Construct the report message with the DNS name
            if dns_name:
                report_message = f"[{process_name}] {ip_address} | {dns_name} = {status} ({positives})"
            else:
                report_message = f"[{process_name}] {ip_address} = {status} ({positives})"

            logging.info(report_message)
            with open('report.txt', 'a') as file:
                file.write(report_message + '\n')

            print(report_message)
        except ValueError:
            logging.error(f"An error occurred while decoding the report for the IP: {ip_address}")
    else:
        error_message = response.json().get('verbose_msg')
        logging.error(f"An error occurred while retrieving the report for the IP: {ip_address}. Error: {error_message}")

# Read API key from file
def read_api_key():
    with open('API-key.txt', 'r') as file:
        api_key = file.read().strip()
    return api_key

# Scan variable to check if the scan has already been done
scan_done = False

# Scan only if it has not already been done
if not scan_done:
    api_key = read_api_key()

    connections = psutil.net_connections()
    connected_ips = set()

    for conn in connections:
        if conn.status == psutil.CONN_ESTABLISHED and conn.raddr:
            ip_address = conn.raddr.ip
            # Add IPv4 IP addresses only
            if ':' not in ip_address:
                connected_ips.add(ip_address)

    for ip_address in connected_ips:
        scan_ip(ip_address, api_key)
        time.sleep(15)  # 15 second interval between requests

    scan_done = True
