# import argparse
import argparse
import gc
import ipaddress
import sys

import pandas as pd
from func import (
    append_dict_to_csv,
    cf_iprange,
    check_ip_range_port_80,
    dns_lookup,
    input_files,
    ip_to_cidr,
    validate_domain_name,
    validate_ip,
)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--cidr", type=str, help="Check Open Port 80 on CIDR range. Ex: 192.168.1.0/24")
    parser.add_argument("-d", "--duplicate", type=str, help="Remove duplicate lines of CSV file.")
    parser.add_argument("-i", "--input", nargs="+", dest="files", help="Check domains or IP address under Cloudflare")

    parser.add_argument(
        "-f",
        "--file",
        type=str,
        help="Filtering CSV File by specific column. Eg: python main.py -f ./data/output.csv filter dns==normal",
    )
    file_filter = parser.add_subparsers(dest="filter", help="Filtering CSV File by specific column.")
    _filter_by = file_filter.add_parser("filter")
    _filter_by.add_argument(
        "filter_by", nargs="+", help="Filter CSV File. Eg: python main.py -f ./data/output.csv filter dns==normal"
    )

    args = parser.parse_args()

    arguments = sys.argv[1:]
    if len(arguments) == 0:
        try:
            parser.print_help()
        except ValueError:
            print("No arguments provided.")
        except Exception as err:
            print(f"Unexpected {err=}, {type(err)=}")
            raise

    if args.file and args.filter:
        for item in args.filter_by:
            with open("./data/output_filtered.csv", "w") as f:
                pass
            if "==" not in item:
                sys.exit("Invalid filter format. Use '==' to separate column name from value.")
            row = item.strip().split("==")
            df = pd.read_csv(args.file)
            filtered_df = df[df[row[0]].str.contains(row[1])]
            if filtered_df is not None and len(filtered_df) > 0:
                filtered_df.to_csv("./data/output_filtered.csv", mode="a", header=False, index=False)

    if args.cidr:
        open_ports = check_ip_range_port_80(args.cidr)

        if open_ports:
            print("IP addresses with port 80 open:")
            for ip in open_ports:
                print(ip)
        else:
            print("No IPs with port 80 open found in the specified range.")

    if args.duplicate:
        if not args.duplicate.lower().endswith(".csv"):
            sys.exit("Error: The filename must end with '.csv'")
        file_path = args.duplicate
        try:
            data = pd.read_csv(file_path)
            data = data.drop_duplicates()
            data.to_csv(file_path, index=False)
        except pd.errors.EmptyDataError:
            print(f"Skipping empty file: {file_path}")
        except FileNotFoundError:
            print(f"File not found: {file_path}")

    if args.files:
        list_of_addr = input_files(args.files)
        output = []
        for addr in list_of_addr:
            if not validate_ip(addr) and not validate_domain_name(addr):
                continue

            ip = addr
            if validate_domain_name(ip):
                lookup = dns_lookup(ip)
                if len(lookup["addrs"]) > 0:
                    ip = lookup["addrs"][0]
            output.append(dict(cidr=ip_to_cidr(ip), ipv4=ip, domain=addr, dns="normal"))
            for s in cf_iprange:
                net = ipaddress.ip_network(s)
                ip = ipaddress.ip_address(ip)
                if ip in net:
                    output.pop()
                    output.append(dict(cidr=ip_to_cidr(ip), ipv4=ip, domain=addr, dns="cloudflare"))
                    break
            gc.collect()
        filename = "./data/output.csv"
        fields = ["cidr", "ipv4", "domain", "dns"]

        append_dict_to_csv(filename, fields, output)


if __name__ == "__main__":
    main()
