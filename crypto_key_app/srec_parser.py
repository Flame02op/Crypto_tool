import re
import base64

memory_map = {}

def parse_srec(file_path):
    """
    Parses any SREC record (S0-S9) and extracts payload data for S1, S2, S3.
    :param file_path: Path to the SREC file.
    :return: Sorted list of addresses (for data records) and a list of all parsed records.
    """
    global memory_map
    memory_map = {}
    all_records = []

    with open(file_path, 'r') as file:
        for line in file:
            line = line.strip()
            match = re.match(r'^S([0-9])([0-9A-Fa-f]{2})([0-9A-Fa-f]+)([0-9A-Fa-f]{2})$', line)
            if not match:
                continue

            record_num = int(match.group(1))
            byte_count = int(match.group(2), 16)
            payload = match.group(3)
            checksum = match.group(4)

            # Address length by record type
            if record_num == 0:      # S0: header, 2-byte address
                address_length = 4
            elif record_num == 1:    # S1: data, 2-byte address
                address_length = 4
            elif record_num == 2:    # S2: data, 3-byte address
                address_length = 6
            elif record_num == 3:    # S3: data, 4-byte address
                address_length = 8
            elif record_num in [5,6]: # S5/S6: count, 2/3-byte address
                address_length = 4 if record_num == 5 else 6
            elif record_num in [7,8,9]: # S7/S8/S9: start address, 4/3/2-byte address
                address_length = {7:8, 8:6, 9:4}[record_num]
            else:
                continue

            address = int(payload[:address_length], 16)
            data = payload[address_length:len(payload)]

            # Store all record info
            all_records.append({
                "type": f"S{record_num}",
                "address": address,
                "data": data,
                "checksum": checksum
            })

            # For S1, S2, S3: store data in memory_map
            if record_num in [1,2,3]:
                # Data field length in bytes: byte_count - (address bytes + 1 for checksum)
                for i in range(0, len(data), 2):
                    memory_map[address + (i // 2)] = int(data[i:i + 2], 16)

    sorted_keys = sorted(memory_map.keys())
    return sorted_keys, all_records

def extract_data(sorted_keys, start_addr=None, end_addr=None):

    if start_addr is not None:
        sorted_keys = [addr for addr in sorted_keys if addr >= start_addr]
    if end_addr is not None:
        sorted_keys = [addr for addr in sorted_keys if addr <= end_addr]

    # Format output like a hex viewer
    result = []
    line = []
    prev_addr = None

    for addr in sorted_keys:
        if prev_addr is None or addr == prev_addr + 1:
            line.append(memory_map[addr])
        else:
            result.append(f"{prev_addr - len(line) + 1:08X}: " + " ".join(f"{b:02X}" for b in line))
            line = [memory_map[addr]]
        prev_addr = addr

    if line:
        result.append(f"{prev_addr - len(line) + 1:08X}: " + " ".join(f"{b:02X}" for b in line))

    return "\n".join(result)

def parse_data(filepath, start_add, end_add):   
    sorted_keys, all_records = parse_srec(filepath)
    if start_add is None:
        start_add = sorted_keys[0]  # First address in the sorted keys
    if end_add is None:
        end_add = sorted_keys[-1]  # Last address in the sorted keys
    formatted_output = extract_data(sorted_keys, start_add, end_add)

    # output_data = formatted_output.split(":")[1].replace(" ", "")[:-2]
    # Extract only the hex data (remove addresses and spaces)
    hex_lines = formatted_output.splitlines()
    hex_str = ""
    for line in hex_lines:
        if ':' in line:
            _, data = line.split(':', 1)
            hex_str += data.replace(" ", "")
    if hex_str:
        return bytes.fromhex(hex_str)
    return None


if __name__ == "__main__":
    pass
