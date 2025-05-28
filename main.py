import sys

from app.cf import cf
from app.cidr import cidr
from app.duplicate import duplicate
from app.filter import filterby
from app.ip2cc import ip2cc


def main():
    print_help_message = "Operation type (cf, cidr, duplicate, filter, ip2cc)\nEx: python main.py cf --help"

    arguments = sys.argv[1:]
    if len(arguments) == 0:
        try:
            print("Domain IP Scan Tools with I/O Files\n")
            print(print_help_message)
        except ValueError:
            print("No arguments provided.")
        except Exception as err:
            print(f"Unexpected {err=}, {type(err)=}")
            raise

    allowed_operation = ["cf", "cidr", "filter", "duplicate", "ip2cc"]

    if sys.argv[1] not in allowed_operation:
        sys.exit(f"Invalid operation type {sys.argv[1]}\n{print_help_message}")

    match sys.argv[1]:
        case "cf":
            cf()
        case "cidr":
            cidr()
        case "ip2cc":
            ip2cc()
        case "filter":
            filterby()
        case "duplicate":
            duplicate()
        case _:
            print("Something else")


if __name__ == "__main__":
    main()
