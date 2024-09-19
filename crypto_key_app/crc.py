import crcmod

def calculate_crc(data, algorithm='crc32'):
    crc32_func = crcmod.predefined.mkPredefinedCrcFun(algorithm)
    return crc32_func(data)