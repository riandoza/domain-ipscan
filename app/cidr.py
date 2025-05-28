import argparse
import gc
import sys
from pathlib import Path

# pip install git+https://github.com/jamesdolan/ip_to_country.git@main
import ip_to_country
from app.func import append_dict_to_csv, check_ip_range_port, process_file, validate_ip, validate_port


def cidr(command_line=None):
    parser = argparse.ArgumentParser(description="Get Country Code from IP")

    subparsers = parser.add_subparsers(dest="command", help="Commands to run", required=True)
    cidr = subparsers.add_parser("cidr", help="cidr")
    cidr.add_argument(
        "-c",
        "--cidr",
        type=str,
        help="Check Open Port on CIDR range. Ex: 192.168.1.0/24",
    )
    cidr.add_argument("-i", "--ips", type=str, required=True, help="IP address")
    cidr.add_argument("-p", "--port", type=int, required=True, help="Port number")
    cidr.add_argument("-o", "--output", type=process_file, required=True, help="Output file path")

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

    if args.command == "cidr":
        open_ports = check_ip_range_port(args.ips, args.port, args.output)

        if open_ports:
            print(f"IP addresses with port {args.port} open:")
            for ip in open_ports:
                print(ip)
        else:
            print(f"No IPs with port {args.port} open found in the specified range.")
        gc.collect()


if __name__ == "__main__":
    cidr()
