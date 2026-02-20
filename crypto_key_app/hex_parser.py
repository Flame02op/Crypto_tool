def parse_hex(file_path):
    """
    Parses an Intel HEX file and returns the data as a dictionary.
    :param file_path: Path to the Intel HEX file.
    :return: Dictionary with addresses as keys and data as values.
    """
    data = {}
    base_address = 0

    try:
        with open(file_path, 'r') as file:
            for line in file:
                line = line.strip()
                if not line or not line.startswith(':'):
                    continue

                byte_count = int(line[1:3], 16)
                address = int(line[3:7], 16)
                record_type = int(line[7:9], 16)
                data_bytes = line[9:9 + (byte_count * 2)]
                checksum = int(line[9 + (byte_count * 2):], 16)

                # Handle record types
                if record_type == 0x00:  # Data record
                    full_address = base_address + address
                    for i in range(0, len(data_bytes), 2):
                        byte_value = int(data_bytes[i:i + 2], 16)
                        data[full_address] = byte_value
                        # print(f"Address: {hex(full_address)}, Data: {hex(byte_value)}")  # Debug
                        full_address += 1
                elif record_type == 0x04:  # Extended linear address record
                    base_address = int(data_bytes, 16) << 16
                    # print(f"Base Address Updated: {hex(base_address)}")  # Debug
                elif record_type == 0x01:  # End of file record
                    break

        return data

    except Exception as e:
        print(f"Error parsing Intel HEX file: {e}")
        return None


def parse_intel_hex(file_path):
    """
    Parses an Intel HEX file and returns the data as a dictionary.
    :param file_path: Path to the Intel HEX file.
    :return: Dictionary with addresses as keys and data as values.
    """
    data = {}
    base_address = 0
    memory_map ={}

    try:
        with open(file_path, 'r') as file:
            for line in file:
                line = line.strip()
                if not line or not line.startswith(':'):
                    continue

                byte_count = int(line[1:3], 16)
                address = int(line[3:7], 16)
                record_type = int(line[7:9], 16)
                data_bytes = line[9:9 + (byte_count * 2)]
                checksum = int(line[9 + (byte_count * 2):], 16)

                # Handle record types
                if record_type == 0x00:  # Data record
                    full_address = base_address + address
                    for i in range(0, len(data_bytes), 2):
                        byte_value = int(data_bytes[i:i + 2], 16)
                        data[full_address] = byte_value
                        full_address += 1
                elif record_type == 0x04:  # Extended linear address record
                    base_address = int(data_bytes, 16) << 16
                elif record_type == 0x01:  # End of file record
                    break

        return data

    except Exception as e:
        print(f"Error parsing Intel HEX file: {e}")
        return None
    
def extract_data(parsed_data, start_addr=None, end_addr=None):
    """
    Extracts data between the specified start and end addresses from the parsed data.
    :param parsed_data: Dictionary with addresses as keys and data as values.
    :param start_addr: Start address (inclusive).
    :param end_addr: End address (inclusive).
    :return: Formatted output as a hex viewer-like string.
    """
    if start_addr is None:
        start_addr = min(parsed_data.keys())
    if end_addr is None:
        end_addr = max(parsed_data.keys())

    sorted_keys = sorted(addr for addr in parsed_data.keys() if start_addr <= addr <= end_addr)

    result = []
    line = []
    prev_addr = None

    for addr in sorted_keys:
        if prev_addr is None or addr == prev_addr + 1:
            line.append(parsed_data[addr])
        else:
            result.append(f"{prev_addr - len(line) + 1:08X}: " + " ".join(f"{b:02X}" for b in line))
            line = [parsed_data[addr]]
        prev_addr = addr

    if line:
        result.append(f"{prev_addr - len(line) + 1:08X}: " + " ".join(f"{b:02X}" for b in line))

    return "\n".join(result)

def extract_payload_only(hex_viewer_str):
    """
    Extracts only the payload data (hex bytes) from a hex viewer string.
    Removes addresses and spaces.
    """
    lines = hex_viewer_str.splitlines()
    payload = ""
    for line in lines:
        if ':' in line:
            _, data = line.split(':', 1)
            payload += data.replace(" ", "")
    return payload

def parse_data(filepath, start_add=None, end_add=None):
    """
    Parses the data from a file (SREC or Intel HEX) and fetches data
    between the specified start and end addresses. If no addresses are
    provided, fetches the entire file's data.
    """

    parsed_data = parse_intel_hex(filepath)
    if not parsed_data:
        return None

    # Extract data between the specified addresses
    formatted_output = extract_data(parsed_data, start_add, end_add)
    # Extract only the payload data
    hex_string = extract_payload_only(formatted_output)
    return bytes.fromhex(hex_string)

if __name__ == "__main__":
    # # Case 1: Parse an Intel HEX file
    # hex_file = "./KDS_C0_CM2E_Filled_AB.hex"
    # full_data = parse_data(hex_file)
    # full_data = extract_payload_only(full_data)
    # print(full_data)
    pass
