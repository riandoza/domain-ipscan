import csv
import ipaddress
import os
import re
import socket
import sys
from io import StringIO
from pathlib import Path

import dns.exception
import pandas as pd
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


def process_file(file_path):
    filename = Path(file_path)
    if filename.suffix in [".csv", ".txt"]:
        return file_path
    else:
        return sys.exit("filename not allowed\nOnly txt or csv file are allowed")


def input_files(file_list):
    data = []
    for filename in file_list:
        try:
            with open(filename) as file:
                for line in file:
                    if not line.strip():
                        continue
                    data.append(line.strip())
        except FileNotFoundError:
            print(f"Error: File not found: {filename}")
    return data


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
    except dns.resolver.NXDOMAIN:
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


def validate_port(port):
    try:
        port = int(port)
    except ValueError:
        print(f"{port} is not a valid port number")
    if 1 <= port <= 65535:
        return port
    else:
        print(f"{port} is not a valid port number")


def check_ip_range_port(ip_range_cidr, port_number=80, output_file=None):
    """
    Checks which IP addresses within a given CIDR range have port_number open.

    Args:
    ip_range_cidr: A string representing the CIDR range (e.g., "192.168.1.0/24").

    Returns:
    A list of IP addresses with port_number open.
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
                result = s.connect_ex((str(ip), port_number))  # Use connect_ex for non-blocking check
                if result == 0:  # 0 indicates a successful connection
                    print(str(ip))
                    append_string_to_csv(output_file, str(ip))
                    open_ports.append(str(ip))
        except socket.gaierror:
            print(f"Could not resolve address for {ip}")
            continue
        except OSError:
            # Handle other potential connection errors (e.g., firewall)
            continue

    return open_ports


def append_string_to_csv(csv_filepath, string_to_append):
    try:
        df = pd.read_csv(csv_filepath)
    except FileNotFoundError:
        df = pd.DataFrame()

    string_io = StringIO(string_to_append)
    df_to_append = pd.read_csv(string_io, header=None)

    df = pd.concat([df_to_append], ignore_index=True)
    df.to_csv(csv_filepath, mode="a", index=False, header=False)


def is_csv_by_sniffing(filename):
    try:
        with open(filename) as file:
            start = file.read(4096)
            csv.Sniffer().sniff(start)
        return True
    except csv.Error:
        return False


def get_column_pandas(file_path, column_name):
    """
    Extracts a column from a CSV file using pandas.

    Args:
        file_path (str): The path to the CSV file.
        column_name (str): The name of the column to extract.

    Returns:
        list: A list containing the values from the specified column, or None if an error occurs.
    """
    try:
        df = pd.read_csv(file_path)
        if column_name in df.columns:
            return df[column_name].tolist()
        else:
            print(f"Error: Column '{column_name}' not found.")
            return None
    except FileNotFoundError:
        print(f"Error: File not found at '{file_path}'")
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None
