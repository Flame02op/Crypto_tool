import os
import bincopy

SREC_EXTENSIONS = {'.srec', '.s19', '.s28', '.s37', '.mot'}
HEX_EXTENSIONS = {'.hex', '.ihx', '.ihex'}


def is_srec_or_hex_file(file_path):
    """Return True if the file is a SREC or Intel HEX file based on its extension."""
    ext = os.path.splitext(file_path)[1].lower()
    return ext in SREC_EXTENSIONS or ext in HEX_EXTENSIONS


def parse_file(file_path, start_addr=None, end_addr=None):
    """Parse a SREC or Intel HEX file and return binary data for the given address range.

    Args:
        file_path (str): Path to the .srec or .hex file.
        start_addr (str or None): Optional start address as a hex string (e.g. '0x08000000')
            or decimal string. If None the lowest address in the file is used.
        end_addr (str or None): Optional end address (inclusive) as a hex string or decimal
            string. If None the highest address in the file is used.

    Returns:
        tuple: ('Success', bytearray) or ('Error', error_message_str)
    """
    try:
        b = bincopy.BinFile()
        ext = os.path.splitext(file_path)[1].lower()

        if ext in SREC_EXTENSIONS:
            b.add_srec_file(file_path)
        elif ext in HEX_EXTENSIONS:
            b.add_ihex_file(file_path)
        else:
            return ('Error', f"Unsupported file format: '{ext}'. Expected SREC or Intel HEX.")

        if len(b) == 0:
            return ('Error', 'No data found in the file.')

        def _parse_addr(val):
            if val is None:
                return None
            val = str(val).strip()
            # Accept hex ('0x…'/'0X…') or plain decimal strings
            if val.startswith('0x') or val.startswith('0X'):
                return int(val, 16)
            return int(val, 10)

        lo = _parse_addr(start_addr) if start_addr else b.minimum_address
        hi = _parse_addr(end_addr) if end_addr else b.maximum_address

        if lo > hi:
            return ('Error',
                    f'Start address (0x{lo:X}) must be less than or equal to end address (0x{hi:X}).')

        # as_binary maximum_address is exclusive, so pass hi + 1
        data = b.as_binary(minimum_address=lo, maximum_address=hi + 1)
        return ('Success', data)

    except Exception as e:
        return ('Error', str(e))
