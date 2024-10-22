import crcmod
import crcmod.predefined

def calculate_crc(data, algorithm='crc-32'):
    if check_for_algorithm(algorithm):
        if isinstance(data, str):
            data = data.encode('utf-8')
        try:
            crc_func = crcmod.predefined.mkPredefinedCrcFun(algorithm)
            return crc_func(data)
        except Exception as e:
            print(f"Error calculating CRC: {e}") 
            return None
    else:
        raise ValueError(f"Invalid algorithm name '{algorithm}'. Use a valid CRC algorithm name like 'crc-32', 'crc-16', etc.")

def verify_crc(data, algorithm, calculated_crc):
    actual_crc = calculate_crc(data,algorithm)
    return actual_crc == calculated_crc

def check_for_algorithm(algorithm=''):
    for algo in crcmod.predefined._crc_definitions_by_name.values():
        if algorithm == algo['name']:
            return True
    return False