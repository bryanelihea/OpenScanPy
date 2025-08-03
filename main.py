import ftd2xx
import time
from enum import IntEnum
import re
import json
import os
from collections import defaultdict
import csv
import scripts.resolve_bsr as resolve_bsr

class TestState(IntEnum):
    UNINIT = -1
    TLR = 0
    IDLE = 1
    SELECT_DR = 2
    CAPTURE_DR = 3
    SHIFT_DR = 4
    EXIT1_DR = 5
    PAUSE_DR = 6
    EXIT2_DR = 7
    UPDATE_DR = 8
    SELECT_IR = 9
    CAPTURE_IR = 10
    SHIFT_IR = 11
    EXIT1_IR = 12
    PAUSE_IR = 13
    EXIT2_IR = 14
    UPDATE_IR = 15

# Track current state of each TAP globally
tap1_current_state = TestState.UNINIT
tap2_current_state = TestState.UNINIT

selected_tap = 0

# Global FTDI handles
ftdi_a = None  # MPSSE mode
ftdi_b = None  # Non-MPSSE mode

# Global state tracker
pin_state = {
    "value": 0x00,      # Output values
    "direction": 0x1B   # Assuming bits 0–4 are outputs (adjust if needed)
}

# Constants
BIT_TMS = 3
BIT_TRST = 4

assigned_devices = {}   # this is where we allocate the bsdl files
fullBsrLength = 0
project_name = ''

assigned_devices = {}

outgoing_bsr_bits = ""  # MSB→LSB bitstring
incoming_bsr_bits = ""  # MSB→LSB bitstring

BASE_BSDL_PATH = os.path.join(os.path.dirname(__file__), "resources", "bsdl_json")

import os

def updateBsrLength():
    global fullBsrLength, outgoing_bsr_bits, incoming_bsr_bits
    fullBsrLength = 0
    for device in assigned_devices:
        fullBsrLength += assigned_devices[device]["bsr_length"]

    outgoing_bsr_bits = b''
    incoming_bsr_bits = b''

    return fullBsrLength

def get_bsdl_names():
    """
    Returns a list of BSDL names (folder names) in resources/bsdl_json/
    """
    if not os.path.isdir(BASE_BSDL_PATH):
        return ""
    b = ','.join(sorted([
        name for name in os.listdir(BASE_BSDL_PATH)
        if os.path.isdir(os.path.join(BASE_BSDL_PATH, name))
    ]))
    ##print(f"Available Devices: {b}")
    return b


def assign_device(index, bsdl_name) -> int:
    if not isinstance(int(index), int) or int(index) < 1:
        raise ValueError("Index must be a positive integer starting from 1")

    json_path = os.path.join(BASE_BSDL_PATH, bsdl_name, "bsdl.json")
    if not os.path.isfile(json_path):
        raise FileNotFoundError(f"BSDL JSON file not found: {json_path}")

    with open(json_path, "r") as f:
        bsdl_data = json.load(f)

    ir_len = bsdl_data["ir_length"]
    bsr_len = bsdl_data["bsr_length"]

    raw_idcode = bsdl_data.get("idcode")
    idcode = int(re.sub(r"\s+", "", raw_idcode), 2) if raw_idcode else None

    # Normalize opcode keys
    raw_opcodes = bsdl_data.get("opcodes", {})
    commands = {k.upper(): v for k, v in raw_opcodes.items()}  

    assigned_devices[int(index)] = {
        "bsdl_file": bsdl_name,
        "ir_length": ir_len,
        "bsr_length": bsr_len,
        "idcode": idcode,
        "commands": commands,
        "bsdl_data": bsdl_data
    }

    # Print confirmation
    print(f"Assigned Device {int(index)}:")
    print(f"  BSDL File : {bsdl_name}")
    print(f"  IR Length : {ir_len}")
    print(f"  BSR Bits  : {bsr_len}")
    if idcode is not None:
        print(f"  IDCODE    : 0x{idcode:08X}")
    else:
        print(f"  IDCODE    : (not specified)")
    print(f"  Commands  : {', '.join(f'{k}={v}' for k, v in commands.items() if v)}")

    return f"0x{idcode:08X}"

def set_tms(level: int):
    if level:
        pin_state["value"] |= (1 << BIT_TMS)
    else:
        pin_state["value"] &= ~(1 << BIT_TMS)
    
    ftdi_a.write(bytes([0x80, pin_state["value"], pin_state["direction"]]))
    flush()

def set_trst(level: int):
    if level:
        pin_state["value"] |= (1 << BIT_TRST)
    else:
        pin_state["value"] &= ~(1 << BIT_TRST)

    ftdi_a.write(bytes([0x80, pin_state["value"], pin_state["direction"]]))
    flush()


def jtag_clock(tms_level):
    """
    Set TMS to the desired level, then pulse TCK once.
    Leaves TMS in that state after the pulse.
    """
    TCK = 0x01  # ADBUS0

    # Set TMS to desired level (updates global pin_state)
    set_tms(tms_level)

    # 1. TCK high (rising edge)
    ftdi_a.write(bytes([0x80, pin_state["value"] | TCK, pin_state["direction"]]))
    flush()

    # 2. TCK low again
    ftdi_a.write(bytes([0x80, pin_state["value"], pin_state["direction"]]))
    flush()

def set_test_state(new_state: TestState):
    global tap1_current_state, tap2_current_state

    if isinstance(new_state, str):
        try:
            new_state = TestState[new_state]
        except KeyError:
            raise ValueError(f"Invalid state name: {new_state}")
    elif isinstance(new_state, int):
        try:
            new_state = TestState(new_state)
        except ValueError:
            raise ValueError(f"Invalid state value: {new_state}")
    elif not isinstance(new_state, TestState):
        raise TypeError("Expected a TestState, string, or int")

    if selected_tap == 1:
        current_state = tap1_current_state
    elif selected_tap == 2:
        current_state = tap2_current_state
    else:
        raise ValueError("Invalid TAP number. Must be 1 or 2.")

    if new_state == TestState.TLR:
        for _ in range(5):
            jtag_clock(1)
        current_state = TestState.TLR
    elif current_state == TestState.UNINIT:
        return
    else:
        while current_state != new_state:
            if current_state == TestState.TLR:
                jtag_clock(0)
                current_state = TestState.IDLE
            elif current_state == TestState.IDLE:
                jtag_clock(1)
                current_state = TestState.SELECT_DR
            elif current_state == TestState.SELECT_DR:
                if new_state in (TestState.CAPTURE_DR, TestState.SHIFT_DR,
                                 TestState.EXIT1_DR, TestState.PAUSE_DR,
                                 TestState.EXIT2_DR, TestState.UPDATE_DR):
                    jtag_clock(0)
                    current_state = TestState.CAPTURE_DR
                else:
                    jtag_clock(1)
                    current_state = TestState.SELECT_IR
            elif current_state == TestState.CAPTURE_DR:
                if new_state == TestState.SHIFT_DR:
                    jtag_clock(0)
                    current_state = TestState.SHIFT_DR
                else:
                    jtag_clock(1)
                    current_state = TestState.EXIT1_DR
            elif current_state == TestState.SHIFT_DR:
                jtag_clock(1)
                current_state = TestState.EXIT1_DR
            elif current_state == TestState.EXIT1_DR:
                if new_state in (TestState.PAUSE_DR, TestState.EXIT2_DR, TestState.SHIFT_DR):
                    jtag_clock(0)
                    current_state = TestState.PAUSE_DR
                else:
                    jtag_clock(1)
                    current_state = TestState.UPDATE_DR
            elif current_state == TestState.PAUSE_DR:
                jtag_clock(1)
                current_state = TestState.EXIT2_DR
            elif current_state == TestState.EXIT2_DR:
                if new_state in (TestState.SHIFT_DR, TestState.EXIT1_DR, TestState.PAUSE_DR):
                    jtag_clock(0)
                    current_state = TestState.SHIFT_DR
                else:
                    jtag_clock(1)
                    current_state = TestState.UPDATE_DR
            elif current_state == TestState.UPDATE_DR:
                if new_state == TestState.IDLE:
                    jtag_clock(0)
                    current_state = TestState.IDLE
                else:
                    jtag_clock(1)
                    current_state = TestState.SELECT_DR
            elif current_state == TestState.SELECT_IR:
                jtag_clock(0)
                current_state = TestState.CAPTURE_IR
            elif current_state == TestState.CAPTURE_IR:
                if new_state == TestState.SHIFT_IR:
                    jtag_clock(0)
                    current_state = TestState.SHIFT_IR
                else:
                    jtag_clock(1)
                    current_state = TestState.EXIT1_IR
            elif current_state == TestState.SHIFT_IR:
                jtag_clock(1)
                current_state = TestState.EXIT1_IR
            elif current_state == TestState.EXIT1_IR:
                if new_state in (TestState.PAUSE_IR, TestState.EXIT2_IR, TestState.SHIFT_IR):
                    jtag_clock(0)
                    current_state = TestState.PAUSE_IR
                else:
                    jtag_clock(1)
                    current_state = TestState.UPDATE_IR
            elif current_state == TestState.PAUSE_IR:
                jtag_clock(1)
                current_state = TestState.EXIT2_IR
            elif current_state == TestState.EXIT2_IR:
                if new_state in (TestState.SHIFT_IR, TestState.EXIT1_IR, TestState.PAUSE_IR):
                    jtag_clock(0)
                    current_state = TestState.SHIFT_IR
                else:
                    jtag_clock(1)
                    current_state = TestState.UPDATE_IR
            elif current_state == TestState.UPDATE_IR:
                if new_state == TestState.IDLE:
                    jtag_clock(0)
                    current_state = TestState.IDLE
                else:
                    jtag_clock(1)
                    current_state = TestState.SELECT_DR

    # Final assignment back to the correct TAP tracker
    if selected_tap == 1:
        tap1_current_state = current_state
    else:
        tap2_current_state = current_state

    return str(current_state)

def wait_for_bytes(num_bytes, timeout=100):
    count = 0
    while ftdi_a.getQueueStatus() < num_bytes and count < timeout:
        time.sleep(0.01)
        count += 1

def open_ftdi(index: int, mpsse: bool) -> ftd2xx.FTD2XX:
    ftdi = ftd2xx.open(index)
    ftdi.resetDevice()
    ftdi.setBitMode(0x00, 0x00)
    mode = 0x02 if mpsse else 0x01
    mask = 0x00 if mpsse else 0xCE
    ftdi.setBitMode(mask, mode)
    ftdi.setLatencyTimer(2)
    ftdi.setTimeouts(5000, 5000)
    return ftdi

def sync_mpsse():
    # Clear buffers and sync
    ftdi_a.purge(3)  # PURGE RX and TX

    # --- Sync check ---
    ftdi_a.write(b'\xAA')       # Send bad command (0xAA)
    flush()
    wait_for_bytes(2)
    assert ftdi_a.read(2) == b'\xFA\xAA', "MPSSE sync failed (0xAA)"

    ftdi_a.write(b'\xAB')       # Second sync check
    flush()
    wait_for_bytes(2)
    assert ftdi_a.read(2) == b'\xFA\xAB', "MPSSE sync failed (0xAB)"

    # --- Init MPSSE ---
    ftdi_a.write(b'\x84')       # Disable 3-phase clocking (required for JTAG)
    ftdi_a.write(b'\x85')       # Disable loopback

def set_clock(freq_hz):
    divisor = int((12e6 / (2 * freq_hz)) - 1)
    ftdi_a.write(bytes([0x86, divisor & 0xFF, (divisor >> 8) & 0xFF]))
    flush()

def set_idle():
    set_tms(0)
    set_trst(1)

def select_tap(tap: int):
    global selected_tap
    set_tap_enable(1 if int(tap) == 1 else 0, 1 if int(tap) == 2 else 0)
    selected_tap = int(tap)
    print(f"TAP {selected_tap} selected")
    return selected_tap

def set_tap_enable(tap1_enable: int, tap2_enable: int):
    # this enables the TMS signal to be gated to the individual TAPs. TAP1_EN also controls the TDO routing
    # it is possible to have both TMS pins routed but only TDO on TAP1 will be routed in that instance
    # Combine bits into data byte
    data = (tap2_enable << 1) | tap1_enable  # bit 1 = ACBUS1, bit 0 = ACBUS0
    ftdi_a.write(bytes([0x82, data, 0x03]))  # 0x03 = both ACBUS0/1 as outputs

def send_bytes_same(value, byte_count = 64):
    ftdi_a.write(bytes([0x19, byte_count - 1, 0x00]) + bytes([value] * (byte_count)))

def send_bytes_while_read(data):
    if not data:
        return b''
    if isinstance(data, (bytes, bytearray)):
        data = list(data)
    elif not isinstance(data, list):
        raise TypeError("Data must be a list, bytes, or bytearray.")

    n = len(data)
    length = n - 1
    cmd = bytearray()
    cmd.append(0x39)                    # 0x39 = clock in/out, LSB-first
    cmd.append(length & 0xFF)          # Length LSB
    cmd.append((length >> 8) & 0xFF)   # Length MSB
    cmd.extend(data)
    ftdi_a.write(bytes(cmd))
    wait_for_bytes(n)
    return ftdi_a.read(n)

def send_bytes_while_read_hexstring(hex_string):
    """
    Accepts a string like '00 00 00 00' and sends it as bytes.
    """
    try:
        byte_values = bytes(int(b, 16) for b in hex_string.split())
        return send_bytes_while_read(byte_values)
    except Exception as e:
        return f"Error: {e}"

def send_bits(value, bit_count):
    ftdi_a.write(bytes([0x1B, bit_count - 1, value]))

def clear_read_buffer():
    ftdi_a.purge(1)  # Clear read buffer

def flush():
    ftdi_a.write(bytes([0x87]))  # Flush the output buffer

def detect_chain_length():
    global tap1_current_state, tap2_current_state

    flush()
    set_test_state(TestState.TLR)    # we are now in known state
    set_test_state(TestState.SHIFT_IR)
    send_bytes_same(0xFF,256)   # put entire chain into bypass mode by clocking all 1's
    flush()
    set_tms(1)
    send_bits(0x01, 1)  # now in EXIT1_IR
    if selected_tap == 1:
        tap1_current_state = TestState.EXIT1_IR # manually set state we ended up in
    else:
        tap2_current_state = TestState.EXIT1_IR # manually set state we ended up in
    set_test_state(TestState.SHIFT_DR)   # passes through UPDATE_IR en-route
    send_bytes_same(0x00,256)   # send zeroes to clear register
    flush()
    clear_read_buffer()
    rx_byte = send_bytes_while_read(bytes([0x01]))  # now send single byte of 0x01 while reading
    detected = detect_device_count_from_byte(rx_byte[0])
    print(f"Detected {detected} devices on TAP {selected_tap}")
    return detected

def detect_device_count_from_byte(tdo_byte: int) -> int:
    for i in range(8):  # LSB-first
        if (tdo_byte >> i) & 1:
            return i
    return 0  # No 1 found (possible error)

def get_controllers():
    try:
        count = ftd2xx.createDeviceInfoList()
        if count <= 0:
            return "None"

        devices = []

        for i in range(count):
            info = ftd2xx.getDeviceInfoDetail(i)
            desc = info["description"]
            serial = info["serial"]

            # Decode bytes if needed
            if isinstance(desc, bytes):
                desc = desc.decode("utf-8")
            if isinstance(serial, bytes):
                serial = serial.decode("utf-8")

            # Only include Channel A
            if desc.endswith(" A"):
                cleaned_desc = desc[:-2]

                # Strip trailing A/B/C/D from serial (e.g. FT123ABC → FT123AB)
                cleaned_serial = re.sub(r"[A-D]$", "", serial)

                devices.append(f"{i}:{cleaned_desc}:{cleaned_serial}")

        return ",".join(devices) if devices else "None"
    except Exception as e:
        return f"ERR:{e}"

def set_jt3705_3v3():
    global ftdi_b
    # this sets the DAC for output voltage to 3v3 on both TAPs and the input voltage threshold to 1.5V
    # only required on a real JT3705 but TwinTAP will just leave the pins unused and be locked for 3V3 operation
    sequences = [
        [
            0xce, 0xc6, 0xc4, 0xc0, 0xc4, 0xc0, 0xc4, 0xc0, 0xc4, 0xc0, 0xc4, 0xc0, 0xc4, 0xc0, 0xc4, 0xc0, 0xc6, 0xc2, 0xc6, 0xc2, 0xc6, 0xc2, 0xc4, 0xc0, 0xc6, 0xc2, 0xc4, 0xc0, 0xc4, 0xc0, 0xc4, 0xc0, 0xc4, 0xc0, 0xce, 

        ],
        [
            0xce, 0xc6, 0xc4, 0xc0, 0xc6, 0xc2, 0xc4, 0xc0, 0xc4, 0xc0, 0xc4, 0xc0, 0xc6, 0xc2, 0xc4, 0xc0, 0xc6, 0xc2, 0xc6, 0xc2, 0xc6, 0xc2, 0xc4, 0xc0, 0xc6, 0xc2, 0xc4, 0xc0, 0xc4, 0xc0, 0xc4, 0xc0, 0xc4, 0xc0, 0xce, 

        ],
        [
            0xce, 0xc6, 0xc6, 0xc2, 0xc4, 0xc0, 0xc4, 0xc0, 0xc4, 0xc0, 0xc4, 0xc0, 0xc4, 0xc0, 0xc4, 0xc0, 0xc6, 0xc2, 0xc6, 0xc2, 0xc6, 0xc2, 0xc4, 0xc0, 0xc6, 0xc2, 0xc4, 0xc0, 0xc4, 0xc0, 0xc4, 0xc0, 0xc4, 0xc0, 0xce, 

        ],
        [
            0xce, 0xc6, 0xc6, 0xc2, 0xc6, 0xc2, 0xc4, 0xc0, 0xc4, 0xc0, 0xc4, 0xc0, 0xc6, 0xc2, 0xc4, 0xc0, 0xc6, 0xc2, 0xc6, 0xc2, 0xc6, 0xc2, 0xc4, 0xc0, 0xc6, 0xc2, 0xc4, 0xc0, 0xc4, 0xc0, 0xc4, 0xc0, 0xc4, 0xc0, 0xce, 
        ],
    ]

    for seq in sequences:
        ftdi_b.write(bytes(seq))

def set_buffers(enable: int):
    # we enable both sets of buffers all of the time as the tap is controlled via the TMS_EN
    if enable == 1:
          ftdi_b.write(bytes([0b00001110]))
    else:
        ftdi_b.write(bytes([0b11001110]))

def open_controller(ftdi_index: int):
    global ftdi_a, ftdi_b

    ftdi_a = open_ftdi(int(ftdi_index), mpsse=True)
    ftdi_b = open_ftdi(int(ftdi_index) + 1, mpsse=False)
    time.sleep(0.1)

    # setup the channels
    sync_mpsse()
    set_clock(1000000)
    ftdi_a.write(b'\x83\x87')  # Slew/Schmitt config or edge-quality aid
    flush()
    set_jt3705_3v3()
    flush()
    set_idle()  # get into idle state
    set_buffers(1)  # enable the output buffers
    flush()
    print("Opened Controller Successfully")
    return "success"

def close_controller():
    ftdi_a.close()
    ftdi_b.close()
    print("Closed Controller")

def tlr():
    ret = set_test_state(TestState.TLR)
    flush()
    return str(ret)

def send_ir_chain(*args) -> str:
    """
    Supports:
    - send_ir_chain({1: "IDCODE", 2: "BYPASS"})     # original dict form
    - send_ir_chain("IDCODE", "BYPASS", "EXTEST")   # positional args: index 1 gets first, etc.

    Returns: Comma-separated string of DR lengths per device based on the instruction,
             e.g., "32,1,55"
    """

    if len(args) == 1 and isinstance(args[0], dict):
        device_cmd_map = args[0]
    else:
        device_cmd_map = {i + 1: arg for i, arg in enumerate(args)}

    _send_ir_chain_internal(device_cmd_map)

    dr_lengths = []
    for i in sorted(assigned_devices.keys()):
        cmd = device_cmd_map.get(i, "BYPASS").upper()
        dev = assigned_devices[i]
        if cmd == "BYPASS":
            dr_lengths.append("1")
        elif cmd == "IDCODE":
            dr_lengths.append(str(dev["commands"]["IDCODE"].__len__()))
        elif cmd in ("EXTEST", "SAMPLE", "SAMPLE/PRELOAD"):
            dr_lengths.append(str(dev["bsr_length"]))
        else:
            # Default fallback to BSR length for unknowns
            dr_lengths.append(str(dev["bsr_length"]))

    return ",".join(dr_lengths)

def _send_ir_chain_internal(device_cmd_map) -> str:
    """
    Internal IR shift logic that expects a {device_index: command} dict.
    Builds IR chain from TDI to TDO (Device 1 → N), MSB-to-LSB.
    """
    chain_ir_bits = []

    # Build IR chain from TDI to TDO (lowest to highest index)
    for index in sorted(assigned_devices.keys()):
        device = assigned_devices[index]
        cmd = device_cmd_map.get(index, "BYPASS")
        opcode_bin = device["commands"].get(cmd.upper())

        if opcode_bin is None:
            raise ValueError(f"Command '{cmd}' not defined for device {index}.")

        ir_len = device["ir_length"]
        padded = opcode_bin.zfill(ir_len)  # e.g., "000010"
        print(f"OpCode: {padded}")
        chain_ir_bits.append(padded)  # MSB-to-LSB, do NOT reverse

    # Create full IR bitstream (MSB to LSB)
    full_ir = ''.join(chain_ir_bits)
    total_len = len(full_ir)

    print(f"Full IR:          {full_ir}")

    # Pad to next full byte boundary
    pad_len = (8 - total_len % 8) % 8
    full_ir_padded =  full_ir + ("0" * pad_len)
    total_padded_len = len(full_ir_padded)

    print(f"Full IR Padded: {full_ir_padded}")

    # Convert to bytes, starting from LSB (FTDI will reverse bits)
    bytes_list = []
    for i in range(0, total_padded_len, 8):
        byte_str = full_ir_padded[i:i+8]
        byte_val = int(byte_str, 2)
        bytes_list.append(byte_val)

    bytes_list = list(reversed(bytes_list))
    print(f"Byte List: {bytes_list}")

    # FTDI expects full bytes via 0x19, remaining bits via 0x1B, final bit with TMS
    cmd = bytearray()
    set_test_state(TestState.SHIFT_IR)

    if len(bytes_list) > 1:
        cmd.append(0x19)
        cmd.append(len(bytes_list) - 2)  # minus 1 for FTDI, then minus 1 for final bit
        cmd.append(0x00)
        for b in bytes_list[:-1]:
            cmd.append(b)

    if total_padded_len > 1:
        # Bits before the last one (handled with TMS)
        bits_to_send = (total_padded_len - 1) % 8 or 8
        last_byte = bytes_list[-1]
        partial = last_byte & ((1 << bits_to_send) - 1)
        cmd.append(0x1B)
        cmd.append(bits_to_send - 1)
        cmd.append(partial)

    if cmd:
        print(f"cmd: {cmd}")
        ftdi_a.write(bytes(cmd))
    flush()
    # Final bit (MSB) goes with TMS=1
    final_bit_index = total_padded_len - 1
    final_bit = int(full_ir_padded[final_bit_index])
    set_tms(1)
    final_cmd = bytearray()
    final_cmd.append(0x1B)
    final_cmd.append(0x00)
    final_cmd.append(0x01 if final_bit else 0x00)
    print(f"Final cmd: {final_cmd}")
    ftdi_a.write(bytes(final_cmd))
    flush()

    # Update TAP state
    if selected_tap == 1:
        global tap1_current_state
        tap1_current_state = TestState.EXIT1_IR
    elif selected_tap == 2:
        global tap2_current_state
        tap2_current_state = TestState.EXIT1_IR

    set_test_state(TestState.UPDATE_IR)

    return str(bytes_list)

def generate_safe_bsr():
    """
    Constructs the full-chain safe BSR as a bitstring.
    Stored in memory MSB → LSB (Device 1 to Device N).
    """
    global outgoing_bsr_bits

    bitstream = ''

    # Build MSB→LSB bitstring (Device 1 to N)
    for index in sorted(assigned_devices.keys()):  # TDI → TDO
        cells = assigned_devices[index]["bsdl_data"]["bsr"]
        for cell in cells:
            safe = str(cell.get("safe", "X")).strip().upper()
            bitstream += '1' if safe == '1' else '0'

    outgoing_bsr_bits = bitstream

    print(f"Generated safe BSR (stored MSB→LSB): {bitstream}")
    return outgoing_bsr_bits


def format_bsr_bits_for_debug(bitstr: str) -> str:
    return bitstr  # no padding added anymore

def exchange_bsr(update=True):
    global incoming_bsr_bits, tap1_current_state, tap2_current_state

    set_test_state(TestState.SHIFT_DR)
    flush()
    
    bitstr = outgoing_bsr_bits
    total_bits = len(bitstr)

    cmd = bytearray()
    tx_bytes = []

    # Work from LSB end to group into bytes
    i = total_bits
    while i > 8:
        byte_bits = bitstr[i - 8:i]
        tx_bytes.append(int(byte_bits, 2))
        i -= 8

    # remaining bits (less than or equal to 8)
    remainder_bits = bitstr[0:i]

    remainder_rx_bytes = 0

    # Shift full bytes first
    if len(tx_bytes) > 1:
        remainder_rx_bytes = 2
        cmd += bytes([0x39, len(tx_bytes) - 1, 0x00])   #39
        #cmd += bytes(tx_bytes[:-1])
        cmd += bytes(tx_bytes)
    else:
        remainder_rx_bytes = 1

    # Partial bits before final bit (all but last)
    if len(remainder_bits) > 1:
        partial_bits_value = int(remainder_bits[:-1], 2)
        partial_bits_len = len(remainder_bits) - 1
        cmd += bytes([0x3B, partial_bits_len - 1, partial_bits_value])  #3B

    ftdi_a.write(bytes(cmd))
    flush()

    # Final bit with TMS = 1
    if update:
        set_tms(1)

    final_bit = int(remainder_bits[-1])
    ftdi_a.write(bytes([0x3B, 0x00, final_bit]))

    flush()

    # Wait for and read back incoming bytes
    num_bytes = (len(tx_bytes) + remainder_rx_bytes)
    wait_for_bytes(num_bytes)

    rx = ftdi_a.read(len(tx_bytes)) # this is the whole bytes only

    # Reconstruct MSB→LSB bitstream from reversed byte order
    incoming_bsr_bits = ''.join(f'{b:08b}' for b in rx)

    if remainder_rx_bytes > 1:
        rx_remainder_except_last = ftdi_a.read(1)
        incoming_bsr_bits = f'{rx_remainder_except_last[0]:08b}'[-(len(remainder_bits) - 1):] + incoming_bsr_bits

    rx_final = ftdi_a.read(1)
    incoming_bsr_bits = f'{rx_final[0]:08b}'[-1] + incoming_bsr_bits

    # Debug
    print("\n========== BSR Exchange ==========")
    #print(f"Total BSR Bits Intended  : {total_bits}")
    print(f"Outgoing Bitstream       : {format_bsr_bits_for_debug(bitstr)}")
    #print(f"FTDI 0x39 Bytes Clocked  : {len(tx_bytes)}")
    #print(f"FTDI 0x3B Bits Clocked   : {(len(remainder_bits) - 1) if len(remainder_bits) > 1 else 0}")
    #print(f"FTDI Final Bit (TMS Bit) : {final_bit}")
    print(f"Incoming Bitstream       : {format_bsr_bits_for_debug(incoming_bsr_bits)}")
    print("==================================\n")

    if update:
        if selected_tap == 1:
            tap1_current_state = TestState.EXIT1_DR
        else:
            tap2_current_state = TestState.EXIT1_DR

        set_test_state(TestState.UPDATE_DR)

    return incoming_bsr_bits

def get_device_ref_for_bsdl(model: dict, bsdl_name: str) -> str:
    """
    Given a model dict and bsdl_name, returns the device reference (e.g., 'U1') that
    is of type 'bsdl' and has matching 'bsdl_name'.
    """
    for ref, details in model.get("devices", {}).items():
        if details.get("type") == "bsdl" and details.get("bsdl_name") == bsdl_name:
            return ref
    raise ValueError(f"No device with type 'bsdl' and bsdl_name '{bsdl_name}' found in model.")

def set_project(name):
    global project_name
    project_name = name

def set_bsr_bit(bit_index_from_right, value) -> str:
    global outgoing_bsr_bits
    """
    Sets the bit at the given index (counting from right, LSB = 0) to 0 or 1.
    Returns the updated bitstring.
    """
    if int(value) not in (0, 1):
        raise ValueError("Bit value must be 0 or 1.")
    if int(bit_index_from_right) < 0 or int(bit_index_from_right) >= len(outgoing_bsr_bits):
        raise IndexError("Bit index out of range.")

    bsr_list = list(outgoing_bsr_bits)
    bsr_list[-(int(bit_index_from_right) + 1)] = str(value)
    outgoing_bsr_bits = ''.join(bsr_list)
    return outgoing_bsr_bits

def parse_netlist_to_model(netlist_csv, bom_csv, output_path, model_name):
    model = {
        "model": model_name,
        "devices": {
            "@": {
                "type": "@"
            }
        },
        "netlist": {}
    }

    nets = defaultdict(list)
    devices = {}
    pin_counts = defaultdict(set)
    part_info = {}

    # Parse BoM file with normalized headers
    with open(bom_csv, newline='') as bomfile:
        raw_reader = csv.reader(bomfile)
        headers = [h.strip().strip('"') for h in next(raw_reader)]
        reader = csv.DictReader(bomfile, fieldnames=headers)
        for row in reader:
            ref = row['Designator'].strip()
            part_info[ref] = {
                "part_number": row.get("Part_Number", "").strip().replace("'",""),
                "package": row.get("Package", "").strip().replace("'",""),
                "stock_number": row.get("Stock_Number", "").strip().replace("'",""),
                "value": row.get("Value", "").strip().replace("'",""),
                "function": row.get("Function", "").strip().replace("'","")
            }

    # Parse netlist CSV
    with open(netlist_csv, newline='') as csvfile:
        raw_reader = csv.reader(csvfile, delimiter=';')
        headers = [h.strip().strip('"') for h in next(raw_reader)]
        reader = csv.DictReader(csvfile, delimiter=';', fieldnames=headers)
        for row in reader:
            ref = row['Component Ref ID'].strip()
            pin = row['Pin Ref ID'].strip().replace("\"","")
            net = row['Net Name'].strip().replace("\"","").strip()

            if not ref or not pin or not net:
                continue

            pin_counts[ref].add(pin)

            if ref not in devices:
                part = part_info.get(ref, {})
                part_number = part.get("part_number", "")
                model_type = "unknown"

                # Check if part-specific model exists
                model_path = os.path.join("resources", "models", f"{str.lower(part_number)}_model.json")
                if part_number and os.path.isfile(model_path):
                    model_type = str.lower(part_number)

                function = part.get("function", "").lower()

                if function == "fuse":
                    model_type = "link"
                elif ref.upper().startswith("J"):
                    model_type = "IGNORE"
                elif ref.upper().startswith("R"):
                    model_type = "resistor"
                elif ref.upper().startswith("LK"):
                    model_type = "link"
                elif ref.upper().startswith("C"):
                    model_type = "IGNORE"

                part = part_info.get(ref, {})

                devices[ref] = {
                    "type": "model",
                    "model_name": model_type,
                    "part_number": part.get("part_number", ""),
                    "package": part.get("package", ""),
                    "stock_number": part.get("stock_number", ""),
                    "value": part.get("value", ""),
                    "function": part.get("function", "")
                }

            nets[net].append({
                "device": ref,
                "pin": pin
            })

    # Promote single-pin devices to '@'
    single_pin_refs = {ref for ref, pins in pin_counts.items() if len(pins) == 1}

    for net, conns in nets.items():
        for conn in conns:
            ref = conn["device"]
            if ref in single_pin_refs:
                conn["device"] = "@"
                conn["pin"] = ref
                devices.pop(ref, None)

    model["devices"].update(devices)
    model["netlist"] = dict(nets)

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(model, f, indent=2)

    print(f"Model '{model_name}' written to {output_path}")

        # Print devices with unknown model_name
    print("\nDevices with unknown model type:")
    for ref, props in devices.items():
        if props.get("model_name") == "unknown":
            print(f"  {ref}: part_number='{props.get('part_number', '')}', package='{props.get('package', '')}', function='{props.get('function', '')}'")


def odb_component_parser(input_path1, output_csv_path, input_path2=None):
    """
    Parses one or two ODB-style component files and outputs a CSV with Designator, Part_Number, and Package.

    :param input_path1: Path to first component file (e.g., top side)
    :param output_csv_path: Path to output CSV
    :param input_path2: Optional path to second component file (e.g., bottom side)
    """
    def parse_file(path):
        components = {}
        current_ref = None

        with open(path, 'r') as file:
            for line in file:
                line = line.strip()
                if line.startswith("#") or not line:
                    continue

                if line.startswith("CMP"):
                    parts = line.split()
                    current_ref = parts[6]
                    stk_ref = parts[7]
                    components[current_ref] = {"Stock Number": "", "Part_Number": "", "Package": "", "Value": "", "Function": ""}
                    components[current_ref]["Stock_Number"] = stk_ref
                elif line.startswith("PRP") and current_ref:
                    parts = line.split(maxsplit=2)
                    if len(parts) == 3:
                        key, value = parts[1], parts[2].strip('"')
                        if key == "Part_Number":
                            components[current_ref]["Part_Number"] = value
                        elif key == "Package":
                            components[current_ref]["Package"] = value
                        elif key == "R_Ohms":
                            components[current_ref]["Value"] = value
                        elif key == "Function":
                            components[current_ref]["Function"] = value
        return components

    all_components = parse_file(input_path1)
    if input_path2 and os.path.exists(input_path2):
        all_components.update(parse_file(input_path2))

    # Write to CSV
    with open(output_csv_path, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["Designator", "Stock_Number", "Part_Number", "Package", "Value", "Function"])
        for ref, props in sorted(all_components.items()):
            writer.writerow([ref, props["Stock_Number"], props["Part_Number"], props["Package"], props["Value"], props["Function"]])













# --- Usage example ---
if __name__ == "__main__":
    resolve_bsr.set_project("71065")
    # this creates the BoM from the ODB++ component files
    #odb_component_parser("projects/71065/bom/components_top", "projects/71065/bom/71065_bom.csv", "projects/71065/bom/components_bot")

    # this takes the netlist exported from ZofZ and the BoM extracted from the ODB++ file and generates the PCB model
    # any single pin COMPONENTS are treated as "pins" for the model - i.e. test points
    '''
    parse_netlist_to_model(
        bom_csv="projects/71065/bom/71065_bom.csv",
        netlist_csv="projects/71065/netlists/71065_netlist.csv",
        model_name="71065",
        output_path="projects/71065/models/71065_model.json"
    )
    '''
    

    #print(get_bsr_cells_from_package_pin("71065", "am335x", "TP54"))
    print(resolve_bsr.get_bsr_cells_from_package_pin("71065", "am335x", "TP136"))

    # below is for testing the actual boundary scan chain
    
    '''
    print(get_controllers())
    open_controller(0)

    select_tap(1)
    print(f"Detected {detect_chain_length()} devices in chain")

    print(f"Available devices: {get_bsdl_names()}")

    #id1 = assign_device(1, "mpv_diosa")
    #id2 = assign_device(2, "mpv_diosa")
    #id3 = assign_device(3, "mpv_diosa")
    #id4 = assign_device(4, "mpv_diosa")

    #print(f"Total BSR Length: {updateBsrLength()}")
    assign_device(1, "am335x")
    
    tlr()

    print(send_ir_chain("IDCODE"))  #, "IDCODE", "IDCODE", "IDCODE"))
    set_test_state(TestState.SHIFT_DR)
    print(send_bytes_while_read(bytes([0x00] * 4 )))#* 4)))

    tlr()
    
    generate_safe_bsr() # this is needed to initialise the outgoing variable

    print(send_ir_chain("EXTEST"))

    print(exchange_bsr(True))   # write the safe values
    
    print(exchange_bsr(True))   # write again while reading to get local copy in sync

    outgoing_bsr_bits = incoming_bsr_bits   # so we match what the current state is exactly though doesn't matter really
    pins = get_bsr_cells_from_package_pin("osd3358", "am335x", "P13")
    print(pins)

    set_bsr_bit(pins[1], 1) #set USR0 output high
    set_bsr_bit(pins[2], 0) #enable the output cell

    print(exchange_bsr(True))

    # now we can read back
    #print(exchange_bsr(True))

    '''