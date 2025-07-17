"""
OpenScanPy Public API for C# integration (via pythonnet)
"""

from scripts.bsdl_parser import parse_bsdl_directory

def run_bsdl_parser():
    """Run BSDL parser on resources/bsdl and output to bsdl_json"""
    parse_bsdl_directory("resources/bsdl")

def get_supported_commands():
    return ["run_bsdl_parser", "get_supported_commands"]
