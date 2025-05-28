import argparse
import gc
import sys
from pathlib import Path

import pandas as pd
from app.func import is_csv_by_sniffing, process_file


def duplicate(command_line=None):
    parser = argparse.ArgumentParser(description="Remove duplicate lines")

    subparsers = parser.add_subparsers(dest="command", help="Commands to run", required=True)
    duplicate = subparsers.add_parser("duplicate", help="duplicate")
    duplicate.add_argument("-i", "--input", type=process_file, required=True, help="Input file path")
    duplicate.add_argument("-o", "--output", type=process_file, help="Output file path")

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

    if args.command == "duplicate":
        file_input = args.input
        file_output = args.output
        try:
            if is_csv_by_sniffing(file_input):
                pass
        except OSError as e:
            print("Error opening file:", e)
        try:
            df = pd.read_csv(file_input)
            df = df.drop_duplicates()
            if file_output:
                df.to_csv(file_output, index=False)
            else:
                df.to_csv(file_input, index=False)
            total_rows = df.shape[0]
            print(f"Duplicates removed from file. Total rows: {total_rows + 1}")
        except pd.errors.EmptyDataError:
            print(f"Skipping empty file: {file_input}")
        except FileNotFoundError:
            print(f"File not found: {file_input}")
        gc.collect()


if __name__ == "__main__":
    duplicate()
