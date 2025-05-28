# import argparse
import argparse
import gc
import ipaddress
import sys
from pathlib import Path

import pandas as pd
from app.func import (
    append_dict_to_csv,
    cf_iprange,
    dns_lookup,
    ip_to_cidr,
    process_file,
    validate_domain_name,
    validate_ip,
)


def cf(command_line=None):
    parser = argparse.ArgumentParser()

    subparsers = parser.add_subparsers(dest="command", help="Commands to run", required=True)
    cf = subparsers.add_parser("cf", help="Check domains or IP address under Cloudflare")
    cf.add_argument("-i", "--input", type=process_file, required=True, help="Input file path")
    cf.add_argument("-o", "--output", type=process_file, required=True, help="Output file path")
    args = parser.parse_args(command_line)

    arguments = sys.argv[1:]
    if len(arguments) == 0:
        try:
            parser.print_help()
        except ValueError:
            print("No arguments provided.")
        except Exception as err:
            print(f"Unexpected {err=}, {type(err)=}")
            raise

    if args.command == "cf":
        file_input = args.input
        file_output = args.output
        fields = ["cidr", "ipv4", "domain", "dns"]
        data = []
        with open(file_input) as file:
            for line in file:
                if not line.strip():
                    continue
                data.append(line.strip())
        output = []
        for addr in data:
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
                    output.append(
                        dict(
                            cidr=ip_to_cidr(ip),
                            ipv4=ip,
                            domain=addr,
                            dns="cloudflare",
                        )
                    )
                    break
            gc.collect()

        append_dict_to_csv(file_output, fields, output)
        gc.collect()


if __name__ == "__main__":
    cf()
