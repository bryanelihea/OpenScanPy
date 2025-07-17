# OpenScan

**OpenScan** is an open-source boundary scan framework for automating test and interconnect validation using FTDI based hardware.
It supports scan chain discovery, BSDL parsing, device modeling, and scripted test execution.

This project is a derivative of earlier hardware automation tools and is designed to be modular, extensible, and hardware-agnostic where possible.

## Features

- FT2232D-based JTAG controller support (e.g., JT3705, Olimex ARM-USB-TINY)
- BSDL parser and auto-generated scan model JSONs
- Composite device support (e.g., JT2111 with multiple DIOS blocks)
- Cluster test execution using scripts
- Netlist-to-model mapping and interactive test building
- Python API (exposed to C# via pybridge.dll)
- Project-based structure for repeatable testing
- Optional GUI via C# OpenScanGUI

## License

This project is licensed under the **Apache License 2.0 with an additional Patent Non-Assertion Clause**.  
See the [LICENSE](./LICENSE) and [NOTICE](./NOTICE) files for details.

## Attribution

If used in a commercial or derivative project, attribution should be given as:

    "Powered by OpenScan"

## Repository Structure


## Status

Currently under active development. Contributions are welcome under the terms of the license.
