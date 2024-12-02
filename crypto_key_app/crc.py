import crcmod
import crcmod.predefined

def calculate_crc(data, algorithm='crc-32'):
    if check_for_algorithm(algorithm):
        if isinstance(data, str):
            data = data.encode('utf-8')
        try:
            crc_func = crcmod.predefined.mkPredefinedCrcFun(algorithm)
            return ("Success", crc_func(data))
        except Exception as e:
            print(f"Error calculating CRC: {e}") 
            return ("Error", str(e))
    else:
        return ("Failure", f"Invalid algorithm name '{algorithm}'. Use a valid CRC algorithm name like 'crc-32', 'crc-16', etc.")

def verify_crc(data, algorithm, calculated_crc):
    try:
        actual_crc = calculate_crc(data,algorithm)
        if actual_crc == calculated_crc:
            return("Success", "CRC verified")
        else:
            return("Failure", "Verification failed")
    except Exception as e:
        return("Error", str(e))

def check_for_algorithm(algorithm=''):
    for algo in crcmod.predefined._crc_definitions_by_name.values():
        if algorithm == algo['name']:
            return True
    return False