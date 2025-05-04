import csv
import ipaddress
import re
import socket

import dns.exception
from dns.resolver import Resolver

cf_iprange: list[str] = [
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22",
]


def input_files(file_list):
    ips = []
    for filename in file_list:
        try:
            with open(filename) as file:
                for line in file:
                    if not line.strip():
                        continue
                    ips.append(line.strip())
        except FileNotFoundError:
            print(f"Error: File not found: {filename}")
    return ips


def append_dict_to_csv(file_path, field_names, data_dict):
    # writing to csv file
    with open(file_path, "a", newline="") as csvfile:
        # creating a csv dict writer object
        writer = csv.DictWriter(csvfile, fieldnames=field_names)
        # writing headers (field names)
        if csvfile.tell() == 0:
            writer.writeheader()
        # writing data rows
        writer.writerows(data_dict)
    return True


def get_ip_from_domain(domain):
    try:
        ip_address = socket.gethostbyname(domain)
        return ip_address
    except socket.gaierror as e:
        return f"Error resolving domain: {e}"


def validate_domain_name(domain_name):
    if len(domain_name) > 253:
        return False

    pattern = r"^((?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,}$"

    # Check if the domain name matches the pattern
    return bool(re.match(pattern, domain_name))


def validate_ip(ip_address):
    try:
        ipaddress.ip_address(ip_address)
        return True
    except ValueError:
        return False


def dns_lookup(input, timeout=3, server=None):
    """
    Perform a simple DNS lookup, return results in a dictionary
    """
    resolver = Resolver()
    resolver.timeout = float(timeout)
    resolver.lifetime = float(timeout)

    result = {}

    if server:
        resolver.nameservers = server
    try:
        records = resolver.resolve(input)
        result = {
            "addrs": [ii.address for ii in records],
            "error": "",
            "name": input,
        }
    except dns.resolver.NXDOMAIN as e:
        result = {
            "addrs": [],
            "error": f"No such domain {input}",
            "name": input,
        }
    except dns.resolver.Timeout:
        result = {
            "addrs": [],
            "error": f"Timed out while resolving {input}",
            "name": input,
        }
    except dns.exception.DNSException as e:
        result = {
            "addrs": [],
            "error": f"Unhandled exception ({repr(e)})",
            "name": input,
        }

    return result


def ip_to_cidr(ip_address_string):
    """Converts an IP address string to its /32 CIDR representation.

    Args:
        ip_address_string: The IP address string to convert.

    Returns:
        A string representing the IP address in CIDR notation (e.g., "192.168.1.1/32").
    """
    try:
        ip_network = ipaddress.ip_network(f"{ip_address_string}/24", strict=False)
        return str(ip_network)
    except ValueError:
        return None


def check_ip_range_port_80(ip_range_cidr):
    """
    Checks which IP addresses within a given CIDR range have port 80 open.

    Args:
    ip_range_cidr: A string representing the CIDR range (e.g., "192.168.1.0/24").

    Returns:
    A list of IP addresses with port 80 open.
    """

    open_ports = []
    try:
        network = ipaddress.ip_network(ip_range_cidr, strict=False)
    except ValueError:
        print(f"Invalid CIDR range: {ip_range_cidr}")
        return open_ports

    for ip in network.hosts():
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2)  # Set a timeout to avoid indefinite blocking
                result = s.connect_ex((str(ip), 80))  # Use connect_ex for non-blocking check
                if result == 0:  # 0 indicates a successful connection
                    open_ports.append(str(ip))
        except socket.gaierror:
            print(f"Could not resolve address for {ip}")
            continue
        except OSError:
            # Handle other potential connection errors (e.g., firewall)
            continue

    return open_ports
