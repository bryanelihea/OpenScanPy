import os
import json

project_name = ""

def set_project(name):
    global project_name
    project_name = name

import os
import json

def get_device_pins_from_model_pin(model_name: str, model_pin: str) -> list[tuple[str, str, str]]:
    """
    Given a model name and an @ pin (model_pin), return a list of (device, pin, source)
    for each connected pin. Source is either 'model:<model_name>' or 'bsdl:<bsdl_name>'.
    """
    def load_model(name):
        path = os.path.join("resources", "models", f"{name}_model.json")
        if not os.path.exists(path):
            path = os.path.join("projects", project_name, "models", f"{name}_model.json")
        if not os.path.exists(path):
            raise FileNotFoundError(f"Model file not found: {name}")
        with open(path, "r") as f:
            return json.load(f)

    model = load_model(model_name)
    results = []

    for net_id, pins in model.get("netlist", {}).items():
        if any(p["device"] == "@" and p["pin"].upper() == model_pin.upper() for p in pins):
            for p in pins:
                if p["device"] != "@":
                    dev = p["device"]
                    pin = p["pin"]
                    dev_info = model.get("devices", {}).get(dev, {})
                    dev_type = dev_info.get("type", "").lower()

                    if dev_type == "model":
                        source = f"model:{dev_info.get('model_name', 'unknown')}"
                    elif dev_type == "bsdl":
                        source = f"bsdl:{dev_info.get('bsdl_name', 'unknown')}"
                    else:
                        source = "unknown"

                    results.append((dev, pin, source))

    print(f"[INFO] {model_name} @.{model_pin} → {results}")
    return results

def get_bsr_cells_from_pin(bsdl_name: str, pin: str) -> tuple[str, str, str]:
    """
    Given a BSDL name and a package pin, return (input_cell, output_cell, control_cell)
    from the corresponding BSR table.
    """
    bsdl_path = os.path.join("resources", "bsdl_json", bsdl_name, "bsdl.json")
    if not os.path.exists(bsdl_path):
        bsdl_path = os.path.join("projects", project_name, "bsdl_json", bsdl_name, "bsdl.json")
    if not os.path.exists(bsdl_path):
        print(f"[ERROR] BSDL file not found for: {bsdl_name}")
        return ("null", "null", "null")

    print(f"[INFO] Loading BSDL from: {bsdl_path}")
    with open(bsdl_path, "r") as f:
        bsdl = json.load(f)

    ports = bsdl.get("ports", [])
    bsr = bsdl.get("bsr", [])

    signal_name = None
    for port in ports:
        if port and port.get("pin", "").upper() == pin.upper():
            signal_name = port.get("name")
            print(f"[MATCH] Pin '{pin}' → Signal '{signal_name}'")
            break

    if not signal_name:
        print(f"[ERROR] No signal found for pin '{pin}' in BSDL '{bsdl_name}'")
        return ("null", "null", "null")

    input_cell = "null"
    output_cell = "null"
    control_cell = "null"

    for cell in bsr:
        if cell.get("port") == signal_name:
            func = cell.get("function", "").lower()
            cell_num = str(cell.get("cell_num"))
            print(f"[BSR] {signal_name} → Cell {cell_num} ({func})")

            if func == "input":
                input_cell = cell_num
            elif func.startswith("output"):
                output_cell = cell_num
                control_cell = cell.get("c_cell", "null")
                if control_cell:
                    print(f"[BSR] {signal_name} → Cell {control_cell} (control)")

    return (input_cell, output_cell, control_cell)

def resolve_bsr(model, pin, bsdl):
    def find_bsdl_targets(results, bsdl_name):
        bsdl_name = bsdl_name.strip().lower()
        return [
            (device, device_pin, typ)
            for device, device_pin, typ in results
            if typ.strip().lower() == f"bsdl:{bsdl_name}"
        ]

    results = get_device_pins_from_model_pin(model, pin)
    return find_bsdl_targets(results, bsdl)

# Example test run
if __name__ == "__main__":
    set_project("71065")  # Replace with your project folder
    print(f"RESOLVE: {resolve_bsr('71065', 'TP54', 'am335x')}")
    print(f"RESOLVE: {resolve_bsr('osd3358-512m-bsm', 'B10', 'am335x')}")
    print(get_device_pins_from_model_pin('71065', 'TP54'))
    print(get_device_pins_from_model_pin('osd3358-512m-bsm', 'B10'))
    print(get_bsr_cells_from_pin('am335x', 'D18'))

    #print(get_bsr_cells_from_package_pin("71065", "am335x", "TP136"))
