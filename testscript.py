import ftd2xx
import time
from enum import IntEnum
import re

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

import json
import os
import re

assigned_devices = {}

BASE_BSDL_PATH = os.path.join(os.path.dirname(__file__), "resources", "bsdl_json")

import os

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
    opcodes = {k.upper(): v for k, v in raw_opcodes.items()}

    # Extract commonly used commands
    commands = {
        "BYPASS": opcodes.get("BYPASS"),
        "EXTEST": opcodes.get("EXTEST"),
        "SAMPLE": opcodes.get("SAMPLE") or opcodes.get("SAMPLE/PRELOAD"),
        "IDCODE": opcodes.get("IDCODE"),
        "CLAMP": opcodes.get("CLAMP"),
        "HIGHZ": opcodes.get("HIGHZ"),
    }

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
    ftdi_a.purge(3)  # Clear read buffer

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
    set_clock(12000000)
    ftdi_a.write(b'\x83\x87')  # Slew/Schmitt config or edge-quality aid
    flush()
    set_jt3705_3v3()
    flush()
    set_idle()  # get into idle state
    set_buffers(1)  # enable the output buffers
    flush()
    print("Opened Controller Successfully")

def close_controller():
    ftdi_a.close()
    ftdi_b.close()
    print("Closed Controller")

def tlr():
    set_test_state(TestState.TLR)
    flush()

def send_ir_chain(*args) -> str:
    """
    Supports:
    - send_ir_chain({1: "IDCODE", 2: "BYPASS"})     # original dict form
    - send_ir_chain("IDCODE", "BYPASS", "BYPASS")   # positional args: index 1 gets first, etc.
    """

    if len(args) == 1 and isinstance(args[0], dict):
        device_cmd_map = args[0]
    else:
        # Build device_cmd_map from positional args: 1-based index
        device_cmd_map = {i + 1: arg for i, arg in enumerate(args)}

    
    return _send_ir_chain_internal(device_cmd_map)

def _send_ir_chain_internal(device_cmd_map) -> str:
    """
    Internal IR shift logic that expects a {device_index: command} dict.
    """

    chain_ir_bits = []

    # Build IR chain from TDO to TDI (highest to lowest index)
    for index in sorted(assigned_devices.keys(), reverse=True):
        device = assigned_devices[index]
        cmd = device_cmd_map.get(index, "BYPASS")  # Default to BYPASS if not specified
        opcode_bin = device["commands"].get(cmd.upper())
        if opcode_bin is None:
            raise ValueError(f"Command '{cmd}' not defined for device {index}.")

        ir_len = device["ir_length"]
        padded = opcode_bin.zfill(ir_len)
        chain_ir_bits.append(padded[::-1])  # Reverse each instruction for LSB-first

    # Full IR stream, LSB-first
    full_ir = ''.join(chain_ir_bits)
    total_len = len(full_ir)

    if total_len % 8 == 0:
        full_bytes = (total_len // 8) - 1
        leftover_bits = 8
    else:
        full_bytes = total_len // 8
        leftover_bits = total_len % 8

    cmd = bytearray()
    pos = 0
    
    set_test_state(TestState.SHIFT_IR)

    if full_bytes > 0:
        cmd.append(0x19)
        cmd.append(full_bytes - 1)
        cmd.append(0x00)
        for i in range(full_bytes):
            byte = int(full_ir[pos:pos+8][::-1], 2)
            cmd.append(byte)
            pos += 8
    
    remaining = total_len - pos
    if remaining > 1:
        bits_to_send = remaining - 1
        cmd.append(0x1B)
        cmd.append(bits_to_send - 1)
        bits = int(full_ir[pos:pos+bits_to_send][::-1], 2)
        cmd.append(bits)
        pos += bits_to_send

    if cmd:
        ftdi_a.write(bytes(cmd))

    if pos < total_len:
        final_bit = int(full_ir[pos])
        set_tms(1)
        final_cmd = bytearray()
        final_cmd.append(0x1B)
        final_cmd.append(0x00)
        final_cmd.append(0x01 if final_bit else 0x00)
        ftdi_a.write(bytes(final_cmd))

    if selected_tap == 1:
        global tap1_current_state
        tap1_current_state = TestState.EXIT1_IR
    elif selected_tap == 2:
        global tap2_current_state
        tap2_current_state = TestState.EXIT1_IR

    return "success"

# --- Usage example ---
if __name__ == "__main__":
    tap = 1
    print(get_controllers())
    open_controller(0)

    select_tap(tap)

    print(f"Detected {detect_chain_length()} devices in chain")

    print(f"Available devices: {get_bsdl_names()}")

    assign_device(1, "mpv_diosa")
    assign_device(2, "mpv_diosa")
    assign_device(3, "mpv_diosa")
    assign_device(4, "mpv_diosa")

    send_ir_chain("IDCODE", "IDCODE", "IDCODE", "IDCODE")

    set_test_state(TestState.SHIFT_DR)
    print(send_bytes_while_read(bytes([0x00] * 4 * 4)))
    close_controller()