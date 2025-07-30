"""
BSDL Parser module for OpenScanPy
"""

import os
import json
import re

# --- Original Functions ---
'''
TODO:
    Need to allow for multiple pins with same signal "VSS:(10,26,49,74,99)" -> "VSS:10, VSS:26, VSS:49...."
    Also need to allow for this when creating the ports list in JSON
'''
def read_bsdl_file(file_path):
    try:
        with open(file_path, 'r') as file:
            content = file.read()
        return content
    except FileNotFoundError:
        print(f"Error: File not found at path {file_path}")
        return None
    except Exception as e:
        print(f"An error occurred while reading the file: {e}")
        return None

def normalize_line_endings(content):
    if content:
        # Replace any LF or CR-only line endings with CRLF
        content = content.replace('\r\n', '\n').replace('\r', '\n')
        return content.replace('\n', '\r\n')
    return content

def strip_blank_lines(content):
    if content:
        lines = content.splitlines()
        non_blank_lines = [line for line in lines if line.strip()]
        return "\r\n".join(non_blank_lines).replace("\r\n","\r\n")
    return content

def normalize_whitespace(content):
    if content:
        # Replace tabs with spaces
        content = content.replace('\t', ' ')
        # Remove leading whitespace for the entire content
        content = content.lstrip()
        lines = content.splitlines()
        # Normalize whitespace for each line
        normalized_lines = [re.sub(r'\s+', ' ', line).strip() for line in lines]
        return "\r\n".join(normalized_lines)
    return content


def remove_comments(content):
    if content:
        # Remove everything after '--' on each line
        lines = content.splitlines()
        uncommented_lines = [re.sub(r'--.*', '', line).strip() for line in lines]
        return "\r\n".join(uncommented_lines)
    return content

def remove_whitespace_around_delimiters(content):
    if content:
        # Process each line individually to preserve line endings
        lines = content.splitlines()
        processed_lines = [
            re.sub(r'\s*,\s*', ',', 
                   re.sub(r'\s*;\s*', ';', 
                          re.sub(r'\s*:\s*', ':', 
                                 re.sub(r'\s*=\s*', '=', line))))
            for line in lines
        ]
        return "\r\n".join(processed_lines)
    return content

def concat_ampersand_lines(content):
    if content:
        lines = content.splitlines()
        processed_lines = []
        buffer = ""

        for line in lines:
            if line.strip().endswith("&"):
                buffer += line.strip()[:-1]  # Remove the trailing '&' and keep the line content
            else:
                buffer += line.strip()
                processed_lines.append(buffer)
                buffer = ""  # Reset the buffer for the next group of lines

        # Join the processed lines back into a single string with CRLF line endings
        return "\r\n".join(processed_lines).replace('""', '')
    return content

def concat_lines_without_semicolon(content):
    if content:
        lines = content.splitlines()
        processed_lines = []
        buffer = ""

        for line in lines:
            if not line.strip().endswith(";"):
                buffer += line.strip() + " "  # Add a space for concatenation
            else:
                buffer += line.strip()
                processed_lines.append(buffer)
                buffer = ""  # Reset the buffer for the next group of lines

        # Append any remaining buffer content
        if buffer.strip():
            processed_lines.append(buffer.strip())

        # Join the processed lines back into a single string with CRLF line endings
        return "\r\n".join(processed_lines)
    return content

def expand_vectors(content):
    """
    Expands bit_vector declarations and multiple signals declared together
    into individual signal declarations, ensuring no redundant semicolons (;).
    """
    import re

    def expand_vector_declaration(match):
        vector_name = match.group(1).strip()
        direction = match.group(2).strip()
        range_start, range_end = map(int, match.group(3).split('to'))
        expanded_signals = [
            f"{vector_name}{i}:{direction} bit" for i in range(range_start, range_end + 1)
        ]
        return ";\n".join(expanded_signals) + ";"

    def expand_multiple_signals(match):
        # Handle multiple signals like TMS,TDI,TCK,TRST:in bit
        signal_names = match.group(1).split(",")
        direction = match.group(2).strip()
        return ";\n".join([f"{signal.strip()}:{direction} bit" for signal in signal_names]) + ";"

    # Expand bit_vector declarations
    vector_pattern = r"(\w+)\s*:\s*(in|out|inout)\s*bit_vector\((\d+\s+to\s+\d+)\)"
    content = re.sub(vector_pattern, expand_vector_declaration, content)

    # Expand multiple signals declared together
    multiple_signals_pattern = r"([\w,]+)\s*:\s*(in|out|inout|linkage)\s*bit"
    content = re.sub(multiple_signals_pattern, expand_multiple_signals, content)

    # Remove redundant semicolons
    content = re.sub(r";{2,}", ";", content)

    return content

def expand_pin_map_vectors(content):
    def expand_shorthand(match):
        pin_map_string = match.group(1)
        expanded_entries = []
        start_idx = 0

        while start_idx < len(pin_map_string):
            colon_pos = pin_map_string.find(":", start_idx)
            if colon_pos == -1:
                break

            prefix = pin_map_string[start_idx:colon_pos].strip()
            if pin_map_string[colon_pos + 1] == "(":
                # Locate the closing bracket for this shorthand entry
                open_brackets = 1
                closing_pos = colon_pos + 2
                while closing_pos < len(pin_map_string) and open_brackets > 0:
                    if pin_map_string[closing_pos] == "(":
                        open_brackets += 1
                    elif pin_map_string[closing_pos] == ")":
                        open_brackets -= 1
                    closing_pos += 1

                # Extract and expand the shorthand values
                values = pin_map_string[colon_pos + 2:closing_pos - 1]
                values_list = values.split(",")
                expanded_entries.extend([f"{prefix}{idx + 1}:{value.strip()}" for idx, value in enumerate(values_list)])
                start_idx = closing_pos + 1  # Move past the shorthand entry
            else:
                # Handle standard entries like S1:126
                comma_pos = pin_map_string.find(",", colon_pos)
                if comma_pos == -1:
                    expanded_entries.append(pin_map_string[start_idx:].strip())
                    break
                else:
                    expanded_entries.append(pin_map_string[start_idx:comma_pos].strip())
                    start_idx = comma_pos + 1

        return f'constant DIOS:PIN_MAP_STRING:="{",".join(expanded_entries)}";'

    # Apply regex to find and expand the PIN_MAP_STRING
    content = re.sub(
        r'constant\s+\w+\s*:\s*PIN_MAP_STRING\s*:=\s*"([^"]*)";',
        expand_shorthand,
        content,
    )
    return content

def normalise_content(content):
    normalised_content = content.replace('\r\n', '\n').replace('\r', '\n').replace("\n\n","\n").replace("     ","").replace('" "', ' ').replace('is generic(', 'is generic (').replace('port(', 'port (').replace(':= ', ':=')
    return normalised_content

def create_json_from_bsdl(content, output_file):
    import json
    import re

    try:
        # Extract the entity name
        entity_match = re.search(r'entity\s+(\w+)\s+is', content, re.IGNORECASE)
        entity_name = entity_match.group(1) if entity_match else "UNKNOWN_ENTITY"
        print(entity_match)
        # Extract generics
        generics_match = re.search(
            r'generic\s*\(\s*(\w+)\s*:\s*\w+\s*:=\s*([\w"]+)', content, re.IGNORECASE
        )
        print(generics_match)
        generics = {}
        if generics_match:
            generic_name = generics_match.group(1).strip()
            generic_value = generics_match.group(2).strip().strip('"')
            generics[generic_name] = generic_value

        # Extract constants and parse PIN_MAP_STRING
        constants = {}
        pin_map = {}
        constants_match = re.search(
            
            r'constant\s+([\w-]+)\s*:\s*(\w+)\s*:?\s*=\s*"(.*?)"', content, re.IGNORECASE
        )
        print(constants_match)
        print("\r\n")
        if constants_match:
            constant_name = constants_match.group(1).strip()
            constant_type = constants_match.group(2).strip()
            constant_value = constants_match.group(3).strip()
            constants[constant_name] = {
                "type": constant_type,
                "value": constant_value
            }

            # Parse PIN_MAP_STRING if present
            if constant_type == "PIN_MAP_STRING":
                pin_map_entries = constant_value.split(",")
                for entry in pin_map_entries:
                    if ":" in entry:
                        pin_name, pin_values = entry.split(":", 1)
                        pin_name = pin_name.strip()
                        pin_values = pin_values.strip()
                        if pin_values.startswith("(") and pin_values.endswith(")"):
                            values = pin_values.strip("()").split(",")
                            for idx, value in enumerate(values, start=1):
                                pin_map[f"{pin_name}{idx}"] = int(value.strip())
                        else:
                            pin_map[pin_name] = pin_values

        # Extract attributes
        attributes = []
        attribute_matches = re.findall(
            r'attribute\s+(\w+)\s+of\s+\w+\s*:\s*entity\s+is\s+(?:"([^"]*)"|([^;]*));',
            content,
            re.IGNORECASE
        )
        for name, quoted_value, unquoted_value in attribute_matches:
            value = quoted_value if quoted_value else unquoted_value.strip()
            attributes.append({"name": name, "value": value})

        # Extract and expand ports, integrating pin map data
        ports = []
        port_match = re.search(r'port\s*\(([^)]+)\);', content, re.IGNORECASE | re.DOTALL)
        if port_match:
            port_content = port_match.group(1)
            port_lines = port_content.split(";")
            for line in port_lines:
                if ":" in line:
                    port_name, details = line.split(":", 1)
                    details = details.strip()
                    direction, port_type = re.search(r"(\w+)\s+(\w+)", details).groups()
                    if "," in port_name:
                        for name in port_name.split(","):
                            pin_number = pin_map.get(name.strip(), None)
                            ports.append({"name": name.strip(), "direction": direction, "type": port_type, "pin": pin_number})
                    else:
                        pin_number = pin_map.get(port_name.strip(), None)
                        ports.append({"name": port_name.strip(), "direction": direction, "type": port_type, "pin": pin_number})

        # Extract standard, ir_length, and bsr_length
        standard_match = re.search(
            r'attribute\s+COMPONENT_CONFORMANCE\s+of\s+\w+\s*:\s*entity\s+is\s+"([^"]*)";',
            content,
            re.IGNORECASE
        )
        standard = standard_match.group(1) if standard_match else None

        ir_length_match = re.search(
            r'attribute\s+INSTRUCTION_LENGTH\s+of\s+\w+\s*:\s*entity\s+is\s+(\d+);',
            content,
            re.IGNORECASE
        )
        ir_length = int(ir_length_match.group(1)) if ir_length_match else None

        bsr_length_match = re.search(
            r'attribute\s+BOUNDARY_LENGTH\s+of\s+\w+\s*:\s*entity\s+is\s+(\d+);',
            content,
            re.IGNORECASE
        )
        bsr_length = int(bsr_length_match.group(1)) if bsr_length_match else None

        # Extract opcodes
        opcode_match = re.search(
            r'attribute\s+INSTRUCTION_OPCODE\s+of\s+\w+\s*:\s*entity\s+is\s+("[^;]*");',
            content,
            re.IGNORECASE
        )
        opcodes = {}
        if opcode_match:
            opcode_content = opcode_match.group(1).replace('"', '').replace("\n", "").strip()
            opcode_pairs = re.findall(r'(\w+)\s*\(([^)]+)\)', opcode_content)
            for name, value in opcode_pairs:
                opcodes[name.strip()] = value.strip()

        # Extract IDCODE_REGISTER
        idcode_register = None
        for line in content.splitlines():
            if "attribute IDCODE_REGISTER" in line:
                idcode_register = ''.join(re.findall(r'"([^"]*)"', line))
                break

        # Extract INSTRUCTION_CAPTURE
        instruction_capture_match = re.search(
            r'attribute\s+INSTRUCTION_CAPTURE\s+of\s+\w+\s*:\s*entity\s+is\s+"([^"]*)";',
            content,
            re.IGNORECASE
        )
        instruction_capture = instruction_capture_match.group(1) if instruction_capture_match else None

        # Extract Boundary Scan Register (BSR)
        bsr = []
        for line in content.splitlines():
            if "attribute BOUNDARY_REGISTER" in line:
                # Extract all quoted parts and concatenate them
                bsr_raw = ''.join(re.findall(r'"([^"]*)"', line))
                current_cell = ""
                bracket_level = 0

                for char in bsr_raw:
                    current_cell += char
                    if char == "(":
                        bracket_level += 1
                    elif char == ")":
                        bracket_level -= 1

                    if bracket_level == 0 and current_cell.strip().endswith(")") and "(" in current_cell:
                        # Normalize and process the cell
                        cleaned_cell = current_cell.strip().lstrip(" ,")  # Remove leading commas and spaces
                        match = re.match(r'(\d+)\s*\((.*)\)', cleaned_cell)
                        if match:
                            cell_num = int(match.group(1))
                            cell_value = match.group(2)
                            # Remove outer brackets and split by comma
                            components = cell_value.strip("()").split(",")
                            # Populate components, with missing ones set to null
                            bsr.append({
                                "cell_num": cell_num,
                                "cell_type": components[0].strip(),
                                "port": components[1].strip() if len(components) > 1 else None,
                                "function": components[2].strip() if len(components) > 2 else None,
                                "safe": components[3].strip() if len(components) > 3 else None,
                                "c_cell": components[4].strip() if len(components) > 4 else None,
                                "disval": components[5].strip() if len(components) > 5 else None,
                                "rslt": components[6].strip() if len(components) > 6 else None
                            })
                        current_cell = ""  # Reset for the next cell



        # Create the JSON structure
        json_data = {
            "entity": entity_name,
            #"generics": generics,
            #"constants": constants,
            #"attributes": attributes,
            "standard": standard,
            "ir_length": ir_length,
            "bsr_length": bsr_length,
            "idcode": idcode_register,
            "instruction_capture": instruction_capture,
            "opcodes": opcodes,
            "ports": ports,
            "bsr": bsr
        }

        # Write JSON to the output file
        with open(output_file, 'w') as json_file:
            json.dump(json_data, json_file, indent=4)
        #print(f"JSON file successfully created: {output_file}")

    except Exception as e:
        print(f"An error occurred: {e}")

def write_to_file(content, file_path):
    try:
        with open(file_path, 'w') as file:
            file.write(content)
        #print(f"Content successfully written to {file_path}")
    except Exception as e:
        print(f"An error occurred while writing to the file: {e}")

if __name__ == "__main__":
    # Get the directory of the script
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Loop through all .bsd and .bsdl files in the directory
    for filename in os.listdir(script_dir):
        if filename.endswith(".bsd") or filename.endswith(".bsdl"):
            bsdl_file_path = os.path.join(script_dir, filename)
            normalised_path = os.path.join(script_dir, f"{os.path.splitext(filename)[0]}.txt")
            outfile_path = os.path.join(script_dir, f"{os.path.splitext(filename)[0]}.json")
            
            print(f"Processing file: {bsdl_file_path}")

            # Read and process the BSDL file
            bsdl_content = read_bsdl_file(bsdl_file_path)
            bsdl_content = normalize_line_endings(bsdl_content)
            bsdl_content = strip_blank_lines(bsdl_content)
            bsdl_content = normalize_whitespace(bsdl_content)
            bsdl_content = remove_comments(bsdl_content)
            bsdl_content = remove_whitespace_around_delimiters(bsdl_content)
            bsdl_content = concat_ampersand_lines(bsdl_content)
            bsdl_content = concat_lines_without_semicolon(bsdl_content)
            bsdl_content = expand_vectors(bsdl_content)
            bsdl_content = expand_pin_map_vectors(bsdl_content)
            bsdl_content = strip_blank_lines(bsdl_content)
            bsdl_content = normalise_content(bsdl_content)

            write_to_file(bsdl_content, normalised_path)

            create_json_from_bsdl(bsdl_content, outfile_path)

            #print(f"JSON file created: {outfile_path}")



# --- Entry Point ---
def parse_bsdl_directory(directory_path):
    for filename in os.listdir(directory_path):
        if filename.endswith(".bsd") or filename.endswith(".bsdl"):
            device_name = os.path.splitext(filename)[0]

            # Determine output directory and file path
            json_output_dir = os.path.join(os.path.dirname(directory_path), "bsdl_json", device_name)
            json_output_file = os.path.join(json_output_dir, "bsdl.json")

            # Skip if already parsed
            if os.path.exists(json_output_file):
                print(f"Skipping {filename} (already parsed)")
                continue

            os.makedirs(json_output_dir, exist_ok=True)

            bsdl_file_path = os.path.join(directory_path, filename)
            normalised_path = os.path.join(json_output_dir, "normalized.txt")
            outfile_path = json_output_file

            print(f"Processing file: {bsdl_file_path}")

            bsdl_content = read_bsdl_file(bsdl_file_path)
            bsdl_content = normalize_line_endings(bsdl_content)
            bsdl_content = strip_blank_lines(bsdl_content)
            bsdl_content = normalize_whitespace(bsdl_content)
            bsdl_content = remove_comments(bsdl_content)
            bsdl_content = remove_whitespace_around_delimiters(bsdl_content)
            bsdl_content = concat_ampersand_lines(bsdl_content)
            bsdl_content = concat_lines_without_semicolon(bsdl_content)
            bsdl_content = expand_vectors(bsdl_content)
            bsdl_content = expand_pin_map_vectors(bsdl_content)
            bsdl_content = strip_blank_lines(bsdl_content)
            bsdl_content = normalise_content(bsdl_content)

            write_to_file(bsdl_content, normalised_path)
            create_json_from_bsdl(bsdl_content, outfile_path)

if __name__ == "__main__":
    parse_bsdl_directory("resources/bsdl")
