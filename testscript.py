import ftd2xx
import time
from enum import Enum
import re

class TestState(Enum):
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

def send_byte_while_read(value):
    ftdi_a.write(bytes([0x39, 0x00, 0x00, value]))

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
    send_byte_while_read(0x01)  # now send single byte of 0x01 while reading
    wait_for_bytes(1)
    rx_byte = ftdi_a.read(1)
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

# --- Usage example ---
if __name__ == "__main__":
    tap = 1
    print(get_controllers())
    open_controller(0)

    select_tap(tap)

    print(f"Detected {detect_chain_length()} devices in chain")

    close_controller()