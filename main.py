"""
OpenScanPy Main Entry Point (CLI)
"""

import sys
from scripts import api

def main():
    if len(sys.argv) < 2:
        print("OpenScanPy: No action specified. Try:")
        print("  python main.py parse-bsdl")
        return

    command = sys.argv[1]

    if command == "parse-bsdl":
        print("Running BSDL parser...")
        api.run_bsdl_parser()
    else:
        print(f"Unknown command: {command}")

if __name__ == "__main__":
    main()
