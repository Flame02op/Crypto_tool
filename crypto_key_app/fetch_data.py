import re

memory_map = {}

def parse_srec(file_path):
    """Parses an SREC file and extracts payload data, formatting it like a hex viewer."""
    
    with open(file_path, 'r') as file:
        for line in file:
            match = re.match(r'^S3(\d{2})([A-Fa-f0-9]{8})([A-Fa-f0-9]+)([A-Fa-f0-9]{2})$', line.strip())
            if match:
                byte_count = int(match.group(1), 16) - 5  # Total bytes - (address + checksum)
                address = int(match.group(2), 16)
                payload = match.group(3)[: byte_count * 2]  # Extract only data, ignore checksum
                
                for i in range(0, len(payload), 2):
                    memory_map[address + (i // 2)] = int(payload[i:i+2], 16)

    sorted_keys = sorted(memory_map.keys())
    return sorted_keys

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

# srec_file = "./Zeekr_IHU_CX1E_BM.srec"
# sorted_keys = parse_srec(srec_file)

# start_address = 0xA0080000
# end_address = 0xA0080000

# for i in range(0,20):
#     start_address = end_address
#     end_address += 0x10
#     formatted_output = extract_data(sorted_keys, start_address, end_address)
#     formatted_output = formatted_output[:-2]
#     print(formatted_output)
