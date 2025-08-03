import os
import json
import csv
project_name = ''

def set_project(name):
    global project_name
    project_name = name

def get_bsr_cells_from_package_pin(model_name: str, bsdl_name: str, package_pin: str) -> tuple[str, str, str]:
    """
    Given model + BSDL + package pin, return (input_cell, output_cell, control_cell)
    by recursively resolving netlist mappings to find the actual BSDL pin.
    Now supports behavioural traversal.
    """

    def load_model(model_name: str):
        path = os.path.join("resources", "models", f"{model_name}_model.json")
        if not os.path.exists(path):
            path = os.path.join("projects", project_name, "models", f"{model_name}_model.json")
        print(f"[INFO] Loading model: {path}")
        with open(path, "r") as f:
            return json.load(f)

    def is_power_net(netname: str) -> bool:
        return any(x in netname.upper() for x in ["VCC", "VDD", "3P3", "PWR", "GND"])

    def resolve_to_bsdl_pin(model_name, device, pin, visited=None) -> tuple[str, str]:
        if visited is None:
            visited = set()
        key = (model_name, device, pin)
        if key in visited:
            return ("null", "null")
        visited.add(key)

        print(f"[TRACE] Resolving {device}.{pin} in model {model_name}")
        model = load_model(model_name)
        netlist = model.get("netlist", {})
        devices = model.get("devices", {})

        for net_id, pins in netlist.items():
            for p in pins:
                if p["device"] == device and p["pin"].upper() == pin.upper():
                    pin_list = [f"{pp['device']}.{pp['pin']}" for pp in pins]
                    print(f"[MATCH] Net '{net_id}' for {device}.{pin} → {pin_list}")

                    for other in pins:
                        if other == p:
                            continue
                        other_device = other["device"]
                        other_pin = other["pin"]

                        if other_device == "@":
                            continue

                        dev_type = devices.get(other_device, {}).get("type", "UNKNOWN")
                        print(f"[CHECK] {other_device}.{other_pin} (type={dev_type})")

                        if dev_type == "IGNORE":
                            continue
                        elif dev_type == "bsdl":
                            bsdl_ref = devices[other_device]["bsdl_name"]
                            print(f"[FOUND] BSDL: {bsdl_ref} pin {other_pin}")
                            return bsdl_ref, other_pin
                        elif dev_type == "model":
                            submodel_name = devices[other_device]["model_name"]
                            print(f"[ENTER] Submodel {submodel_name} via {other_device}.{other_pin}")
                            submodel = load_model(submodel_name)

                            if submodel.get("behavioural") or submodel.get("behavioral"):
                                print(f"[DEBUG] Behavioural model detected for {submodel_name}")
                                path = submodel.get("behavior", {}).get("path", {})
                                from_net = path.get("from_net") or path.get("from")
                                to_net = path.get("to_net") or path.get("to")
                                bidir = path.get("bidirectional", False)

                                matched_net = None
                                for sub_net_id, sub_pins in submodel.get("netlist", {}).items():
                                    for sub_pin in sub_pins:
                                        if sub_pin["device"] == "@" and sub_pin["pin"].upper() == other_pin.upper():
                                            matched_net = sub_net_id
                                            break
                                    if matched_net:
                                        break

                                if matched_net is None:
                                    print(f"[ERROR] No matching net for @.{other_pin} in submodel {submodel_name}")
                                    continue

                                if matched_net == to_net or (bidir and matched_net == from_net):
                                    target_net = from_net if matched_net == to_net else to_net
                                    print(f"[BEHAVIOR MODEL] {other_device}.{other_pin} (net={matched_net}) → submodel @{target_net}")

                                    next_pin = None
                                    for sub_pin in submodel.get("netlist", {}).get(target_net, []):
                                        if sub_pin["device"] == "@":
                                            next_pin = sub_pin["pin"]
                                            break

                                    if not next_pin:
                                        print(f"[ERROR] No @ pin on target_net {target_net} in submodel {submodel_name}")
                                        continue

                                    print(f"[RETURN] Jumping back to parent model {model_name} via @{next_pin}")
                                    return resolve_to_bsdl_pin(model_name, other_device, next_pin, visited)

                            for sub_net_id, sub_pins in submodel.get("netlist", {}).items():
                                for sub_pin in sub_pins:
                                    if sub_pin["device"] == "@" and sub_pin["pin"].upper() == other_pin.upper():
                                        for paired in sub_pins:
                                            if paired["device"] != "@":
                                                sub_type = submodel["devices"][paired["device"]]["type"]
                                                if sub_type == "bsdl":
                                                    bsdl_ref = submodel["devices"][paired["device"]]["bsdl_name"]
                                                    print(f"[FOUND] BSDL: {bsdl_ref} pin {paired['pin']}")
                                                    return bsdl_ref, paired["pin"]
                                                elif sub_type == "model":
                                                    print(f"[ENTER] {paired['device']} → {paired['pin']}")
                                                    return resolve_to_bsdl_pin(submodel["devices"][paired["device"]]["model_name"], "@", paired["pin"], visited)

        raise ValueError(f"[FAIL] Could not resolve {device}.{pin} in model {model_name}")

    print(f"[START] Resolving pin '{package_pin}' in model '{model_name}' → BSDL '{bsdl_name}'")
    try:
        resolved_bsdl, core_pin = resolve_to_bsdl_pin(model_name, "@", package_pin)
    except Exception as e:
        print(str(e))
        return ("null", "null", "null")

    if resolved_bsdl != bsdl_name:
        print(f"[MISMATCH] Expected '{bsdl_name}', got '{resolved_bsdl}'")
        return ("null", "null", "null")

    bsdl_path = os.path.join("resources", "bsdl_json", resolved_bsdl, "bsdl.json")
    if not os.path.exists(bsdl_path):
        bsdl_path = os.path.join("projects", project_name, "bsdl_json", resolved_bsdl, "bsdl.json")
    if not os.path.exists(bsdl_path):
        print(f"[ERROR] BSDL file not found: {resolved_bsdl}")
        return ("null", "null", "null")

    print(f"[INFO] Loading BSDL from {bsdl_path}")
    with open(bsdl_path, "r") as f:
        bsdl = json.load(f)

    ports = bsdl.get("ports", [])
    bsr = bsdl.get("bsr", [])

    signal_name = None
    for port in ports:
        if port.get("pin", "").upper() == core_pin.upper():
            signal_name = port.get("name")
            print(f"[MATCH] Signal '{signal_name}' for pin '{core_pin}'")
            break

    if not signal_name:
        print(f"[ERROR] No signal name for pin '{core_pin}' in BSDL '{resolved_bsdl}'")
        return ("null", "null", "null")

    input_cell = "null"
    output_cell = "null"
    control_port_name = None

    for cell in bsr:
        if cell.get("port") == signal_name:
            func = cell.get("function", "").lower()
            cell_num = str(cell.get("cell_num"))
            print(f"[BSR] Cell {cell_num} → {func}")
            if func == "input":
                input_cell = cell_num
            elif func.startswith("output"):
                output_cell = cell_num
                control_port_name = cell.get("c_cell")

    if control_port_name:
        print(f"[BSR] Cell '{control_port_name}' → control")

    return (input_cell, output_cell, control_port_name)








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
    set_project("71065")
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
    print(get_bsr_cells_from_package_pin("71065", "am335x", "TP136"))