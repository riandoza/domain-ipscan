# import argparse
import argparse
import gc
import sys
from pathlib import Path

import pandas as pd
from app.func import process_file


def filterby(command_line=None):
    parser = argparse.ArgumentParser(description="Filtering CSV File by specific column")

    subparsers = parser.add_subparsers(dest="command", help="Commands to run", required=True)
    filter = subparsers.add_parser(
        "filter",
        help="Filtering CSV File by specific column. Eg: python main.py filter -i ./output.csv -o ./filtered.csv --column dns==normal",
    )
    filter.add_argument("-i", "--input", type=process_file, required=True, help="Input file path")
    filter.add_argument("-o", "--output", type=process_file, required=True, help="Output file path")
    filter.add_argument(
        "-c", "--column", nargs="+", required=True, help="Filtering CSV File by specific column. Ex: dns==normal"
    )

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

    if args.command == "filter":
        file_input = args.input
        file_output = args.output
        for item in args.column:
            with open(file_output, "w"):
                pass
            if "==" not in item:
                print("Invalid filter format. Use '==' to separate column name from value.")
                break
            row = item.strip().split("==")
            df = pd.read_csv(file_input)
            filtered_df = df[df[row[0]].str.contains(row[1])]
            if filtered_df is not None and len(filtered_df) > 0:
                filtered_df.to_csv(
                    file_output,
                    mode="a",
                    header=True,
                    index=False,
                )
        gc.collect()


if __name__ == "__main__":
    filterby()
