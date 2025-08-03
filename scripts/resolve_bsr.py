import os
import json

project_name = ""

def set_project(name):
    global project_name
    project_name = name

def get_bsr_cells_from_package_pin(model_name: str, bsdl_name: str, package_pin: str) -> tuple[str, str, str]:
    """
    Given model + BSDL + package pin, return (input_cell, output_cell, control_cell)
    Assumes the model '@' netlist pin maps directly to a BSDL pin.
    """

    def load_model(name: str):
        path = os.path.join("resources", "models", f"{name}_model.json")
        if not os.path.exists(path):
            path = os.path.join("projects", project_name, "models", f"{name}_model.json")
        print(f"[INFO] Loading model: {path}")
        with open(path, "r") as f:
            return json.load(f)

    print(f"[START] Resolving pin '{package_pin}' in model '{model_name}' → BSDL '{bsdl_name}'")

    model = load_model(model_name)
    netlist = model.get("netlist", {})
    resolved_pin = None

    for net, pins in netlist.items():
        for pin in pins:
            if pin["device"] == "@" and pin["pin"].upper() == package_pin.upper():
                for connected in pins:
                    if connected["device"] != "@":
                        device_info = model["devices"].get(connected["device"], {})
                        if device_info.get("type") == "bsdl" and device_info.get("bsdl_name") == bsdl_name:
                            resolved_pin = connected["pin"]
                            print(f"[RESOLVED] Package pin {package_pin} → BSDL pin {resolved_pin}")
                            break
                if resolved_pin:
                    break
        if resolved_pin:
            break

    if not resolved_pin:
        print(f"[ERROR] Could not resolve pin '{package_pin}' to BSDL")
        return ("null", "null", "null")

    bsdl_path = os.path.join("resources", "bsdl_json", bsdl_name, "bsdl.json")
    if not os.path.exists(bsdl_path):
        bsdl_path = os.path.join("projects", project_name, "bsdl_json", bsdl_name, "bsdl.json")
    if not os.path.exists(bsdl_path):
        print(f"[ERROR] BSDL file not found: {bsdl_name}")
        return ("null", "null", "null")

    with open(bsdl_path, "r") as f:
        bsdl = json.load(f)

    ports = bsdl.get("ports", [])
    bsr = bsdl.get("bsr", [])

    signal_name = None
    for port in ports:
        if not port:
            continue
        if port.get("pin", "").upper() == resolved_pin.upper():
            signal_name = port.get("name")
            print(f"[MATCH] Signal '{signal_name}' for pin '{resolved_pin}'")
            break

    if not signal_name:
        print(f"[ERROR] No signal name found for pin '{resolved_pin}' in BSDL '{bsdl_name}'")
        return ("null", "null", "null")

    input_cell = "null"
    output_cell = "null"
    control_cell = "null"

    for cell in bsr:
        if cell.get("port") == signal_name:
            func = cell.get("function", "").lower()
            cell_num = str(cell.get("cell_num"))
            if func == "input":
                input_cell = cell_num
            elif func.startswith("output"):
                output_cell = cell_num
                control_cell = str(cell.get("c_cell", "null"))

    return (input_cell, output_cell, control_cell)

# Example test run
if __name__ == "__main__":
    set_project("example_project")  # Replace with your project folder
    print(get_bsr_cells_from_package_pin("osd3358-512m-bsm", "am335x", "TP54"))



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
    

    print(get_bsr_cells_from_package_pin("osd3358-512m-bsm", "am335x", "B10"))
    #print(get_bsr_cells_from_package_pin("71065", "am335x", "TP136"))