import argparse
import gc
import sys
from pathlib import Path

# pip install git+https://github.com/jamesdolan/ip_to_country.git@main
import ip_to_country
from app.func import append_dict_to_csv, process_file


def ip2cc(command_line=None):
    parser = argparse.ArgumentParser(description="Get Country Code from IP")

    subparsers = parser.add_subparsers(dest="command", help="Commands to run", required=True)
    ip2cc = subparsers.add_parser("ip2cc", help="ip2cc")
    ip2cc.add_argument("-i", "--input", type=process_file, required=True, help="Input file path")
    ip2cc.add_argument("-o", "--output", type=process_file, required=True, help="Output file path")
    ip2cc.add_argument("-f", "--filter", help="Filter by Country Code. Separate multiple CC by Comma. Ex: US,SG")
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

    if args.command == "ip2cc":
        file_input = args.input
        file_output = args.output
        fields = ["ipv4", "cc"]

        ctx = ip_to_country.Context()
        output = []
        with open(file_input) as file:
            for line in file:
                cc = ctx.country_code(line.strip())
                if args.filter:
                    if cc in list(map(str, args.filter.split(","))):
                        output.append(dict(ipv4=line.strip(), cc=cc))
                else:
                    output.append(dict(ipv4=line.strip(), cc=cc))
        append_dict_to_csv(file_output, fields, output)
        gc.collect()


if __name__ == "__main__":
    ip2cc()
