from . import PyMym as __PyMym

import ctypes
import struct
import inspect

# TODO: Make lots of things optional in the pyi file, mask, offset, result_instance
# TODO: Make it so that strings, ints, floats, and byte arrays can be passed in as the pattern, then make mask using it
# TODO: Add in specification of the value, if a string is passed and "Hex" is given, treat it as a hex pattern

# TODO: Add in toggle for endian-ness as an optional arg, default is little endian
# TODO: Reduce the code for the memory scan, make a helper function that performs the search so all 3 scans can use it
# TODO: Use struct and ctypes, check constraint, then use struct to pack into byte array, then iterate over array to form pattern
# TODO: Switch up how the __flip_endian function works
# TODO: REMOVE READ_DATATYPE FUNCTIONS FROM C++ AND INTERPRET IN PYTHON INSTEAD

def __get_caller_function():
    s = inspect.stack()
    return s[2].function if len(s) > 2 else s[1].function

def __hexstring(pattern: str):
    if pattern[2] != " ":
        raise ValueError("Invalid format given for hex string, expected the following format: 'XX XX XX'")

    broken_str = pattern.split(" ")
    return [int(x, 16) for x in broken_str]

def __create_byte_pattern(pattern, hex_string=False, flip_endian=False):
    ret = []

    if isinstance(pattern, str):
        if not hex_string:
            ret = [int(hex(ord(x)), 16) for x in pattern]
        else:
            ret = __hexstring(pattern)
    elif isinstance(pattern, bytes):
        ret = list(pattern)
    elif isinstance(pattern, list):
        for x in pattern:
            if x > 255 or x < 0:
                raise ValueError("Byte iterable contains bytes that do not fall within the range 0 - 255")
        ret = pattern
    else:
        raise TypeError("Invalid type given for {}, expected type is: str | bytes | list[int]".format(__get_caller_function()))

    return ret if not flip_endian else ret[::-1]

def __check_constraint(data_type, signed=True):
    return (2 ** ((ctypes.sizeof(data_type) * 8) - 1) - 1) if signed else (2 ** (ctypes.sizeof(data_type) * 8) - 1)

def __final_target(target=None, **kwargs):
    pid = kwargs.get('pid', target)
    application_name = kwargs.get('application_name')

    if pid == None and application_name == None:
        raise TypeError("{} requires one of the following arguments: 'pid' or 'application_name'".format(__get_caller_function()))

    return pid if pid is not None else application_name

def moduleAOBScan(target=None, module_name=None, pattern=None, mask=None, offset=0, result_instance=0, flip_endian=False, hex_string=False, **kwargs):
    if None in [module_name, pattern]:
        raise TypeError("moduleAOBScan is missing the following required arguments: 'module_name' and 'pattern'")

    byte_pattern = __create_byte_pattern(pattern=pattern, hex_string=hex_string, flip_endian=flip_endian)
    fin_mask = mask
    if fin_mask == None:
        fin_mask = "x" * len(byte_pattern)
    return __PyMym.moduleAOBScan(__final_target(**kwargs), module_name, byte_pattern, fin_mask, offset, result_instance)

def getModules(target, **kwargs):
    pid = kwargs.get('pid', target)
    application_name = kwargs.get('application_name')

    function_target = pid if pid is not None else application_name
    return __PyMym.getModules(function_target)

def getPID(application_name):
    return __PyMym.getPID(application_name)

def getPIDs():
    return __PyMym.getPIDs()

def getProcessName(pid):
    return __PyMym.getProcessName(pid)

def getProcessNames():
    return __PyMym.getProcessNames()

def heapAOBScan(target=None, pattern=None, mask=None, offset=0, result_instance=0, flip_endian=False, hex_string=False, **kwargs):
    if pattern == None:
        raise TypeError("heapAOBScan is missing the following required argument: 'pattern'")

    byte_pattern = __create_byte_pattern(pattern=pattern, hex_string=hex_string, flip_endian=flip_endian)
    fin_mask = mask
    if fin_mask == None:
        fin_mask = "x" * len(byte_pattern)
    return __PyMym.heapAOBScan(__final_target(**kwargs), byte_pattern, fin_mask, offset, result_instance)


def stackAOBScan(target=None, pattern=None, mask=None, offset=0, result_instance=0, flip_endian=False, hex_string=False, **kwargs):
    if pattern == None:
        raise TypeError("stackAOBScan is missing the following required argument: 'pattern'")

    byte_pattern = __create_byte_pattern(pattern=pattern, hex_string=hex_string, flip_endian=flip_endian)
    fin_mask = mask
    if fin_mask == None:
        fin_mask = "x" * len(byte_pattern)
    return __PyMym.stackAOBScan(__final_target(**kwargs), byte_pattern, fin_mask, offset, result_instance)


def readBytes(target=None, memory_address=None, num_bytes=0, big_endian=False, **kwargs):
    val = __PyMym.readBytes(__final_target(**kwargs), memory_address, num_bytes)
    return val[::-1] if not big_endian else val

def readDouble(target=None, memory_address=None, big_endian=False, **kwargs):
    if memory_address == None:
        raise TypeError

    val = __PyMym.readBytes(__final_target(**kwargs), memory_address, ctypes.sizeof(ctypes.c_double))
    ret = 0

    if big_endian:
        ret = struct.unpack(">d", bytes(val))[0]
    else:
        ret = struct.unpack("<d", bytes(val))[0]

    return ret

def readFloat(target=None, memory_address=None, big_endian=False, **kwargs):
    if memory_address == None:
        raise TypeError

    val = __PyMym.readBytes(__final_target(**kwargs), memory_address, ctypes.sizeof(ctypes.c_float))
    ret = 0

    if big_endian:
        ret = struct.unpack(">f", bytes(val))[0]
    else:
        ret = struct.unpack("<f", bytes(val))[0]

    return ret

def readInteger(target=None, memory_address=None, big_endian=False, **kwargs):
    if memory_address == None:
        raise TypeError

    val = __PyMym.readBytes(__final_target(**kwargs), memory_address, ctypes.sizeof(ctypes.c_int))
    ret = 0

    if big_endian:
        ret = struct.unpack(">i", bytes(val))[0]
    else:
        ret = struct.unpack("<i", bytes(val))[0]

    return ret

def readLong(target=None, memory_address=None, big_endian=False, **kwargs):
    if memory_address == None:
        raise TypeError

    val = __PyMym.readBytes(__final_target(**kwargs), memory_address, ctypes.sizeof(ctypes.c_long))
    ret = 0

    if big_endian:
        ret = struct.unpack(">l", bytes(val))[0]
    else:
        ret = struct.unpack("<l", bytes(val))[0]

    return ret

def readLongLong(target=None, memory_address=None, big_endian=False, **kwargs):
    if memory_address == None:
        raise TypeError

    val = __PyMym.readBytes(__final_target(**kwargs), memory_address, ctypes.sizeof(ctypes.c_longlong))
    ret = 0

    if big_endian:
        ret = struct.unpack(">q", bytes(val))[0]
    else:
        ret = struct.unpack("<q", bytes(val))[0]

    return ret

def readShort(target=None, memory_address=None, big_endian=False, **kwargs):
    if memory_address == None:
        raise TypeError

    val = __PyMym.readBytes(__final_target(**kwargs), memory_address, ctypes.sizeof(ctypes.c_short))
    ret = 0

    if big_endian:
        ret = struct.unpack(">h", bytes(val))[0]
    else:
        ret = struct.unpack("<h", bytes(val))[0]

    return ret

def writeBytes(target=None, memory_address=None, bytes=None, hex_string=False, big_endian=False, **kwargs):
    if bytes == None:
        raise TypeError

    if memory_address == None:
        raise TypeError

    bytes_to_write = __create_byte_pattern(bytes, hex_string, big_endian)
    num_bytes = len(bytes_to_write)
    return __PyMym.writeBytes(__final_target(**kwargs), memory_address, num_bytes, bytes_to_write)

def writeDouble(target=None, memory_address=None, val=None, big_endian=False, **kwargs):
    if memory_address == None:
        raise TypeError
    if val == None:
        raise TypeError
    if val > __check_constraint(ctypes.c_double):
        raise ValueError

    bytes_to_write = bytes()
    if big_endian:
        bytes_to_write = struct.pack(">d", val)
    else:
        bytes_to_write = struct.pack("<d", val)

    fin_val = __create_byte_pattern(pattern=bytes_to_write)

    return __PyMym.writeBytes(__final_target(**kwargs), memory_address, ctypes.sizeof(ctypes.c_double), fin_val)

def writeFloat(target=None, memory_address=None, val=None, big_endian=False, **kwargs):
    if memory_address == None:
        raise TypeError
    if val == None:
        raise TypeError
    if val > __check_constraint(ctypes.c_float):
        raise ValueError

    bytes_to_write = bytes()
    if big_endian:
        bytes_to_write = struct.pack(">f", val)
    else:
        bytes_to_write = struct.pack("<f", val)

    fin_val = __create_byte_pattern(pattern=bytes_to_write)

    return __PyMym.writeBytes(__final_target(**kwargs), memory_address, ctypes.sizeof(ctypes.c_float), fin_val)

def writeInteger(target=None, memory_address=None, val=None, big_endian=False, **kwargs):
    if memory_address == None:
        raise TypeError
    if val == None:
        raise TypeError
    if val > __check_constraint(ctypes.c_int):
        raise ValueError

    bytes_to_write = bytes()
    if big_endian:
        bytes_to_write = struct.pack(">i", val)
    else:
        bytes_to_write = struct.pack("<i", val)

    fin_val = __create_byte_pattern(pattern=bytes_to_write)

    return __PyMym.writeBytes(__final_target(**kwargs), memory_address, ctypes.sizeof(ctypes.c_int), fin_val)

def writeLong(target=None, memory_address=None, val=None, big_endian=False, **kwargs):
    if memory_address == None:
        raise TypeError
    if val == None:
        raise TypeError
    if val > __check_constraint(ctypes.c_long):
        raise ValueError

    bytes_to_write = bytes()
    if big_endian:
        bytes_to_write = struct.pack(">l", val)
    else:
        bytes_to_write = struct.pack("<l", val)

    fin_val = __create_byte_pattern(pattern=bytes_to_write)

    return __PyMym.writeBytes(__final_target(**kwargs), memory_address, ctypes.sizeof(ctypes.c_long), fin_val)

def writeLongLong(target=None, memory_address=None, val=None, big_endian=False, **kwargs):
    if memory_address == None:
        raise TypeError
    if val == None:
        raise TypeError
    if val > __check_constraint(ctypes.c_longlong):
        raise ValueError

    bytes_to_write = bytes()
    if big_endian:
        bytes_to_write = struct.pack(">q", val)
    else:
        bytes_to_write = struct.pack("<q", val)

    fin_val = __create_byte_pattern(pattern=bytes_to_write)

    return __PyMym.writeBytes(__final_target(**kwargs), memory_address, ctypes.sizeof(ctypes.c_longlong), fin_val)

def writeShort(target=None, memory_address=None, val=None, big_endian=False, **kwargs):
    if memory_address == None:
        raise TypeError
    if val == None:
        raise TypeError
    if val > __check_constraint(ctypes.c_short):
        raise ValueError

    bytes_to_write = bytes()
    if big_endian:
        bytes_to_write = struct.pack(">h", val)
    else:
        bytes_to_write = struct.pack("<h", val)

    fin_val = __create_byte_pattern(pattern=bytes_to_write)

    return __PyMym.writeBytes(__final_target(**kwargs), memory_address, ctypes.sizeof(ctypes.c_short), fin_val)

def readUnsignedShort(target=None, memory_address=None, big_endian=False, **kwargs):
    if memory_address == None:
        raise TypeError

    val = __PyMym.readBytes(__final_target(**kwargs), memory_address, ctypes.sizeof(ctypes.c_ushort))
    ret = 0

    if big_endian:
        ret = struct.unpack(">H", bytes(val))[0]
    else:
        ret = struct.unpack("<H", bytes(val))[0]

    return ret

def readUnsignedInteger(target=None, memory_address=None, big_endian=False, **kwargs):
    if memory_address == None:
        raise TypeError

    val = __PyMym.readBytes(__final_target(**kwargs), memory_address, ctypes.sizeof(ctypes.c_uint))
    ret = 0

    if big_endian:
        ret = struct.unpack(">I", bytes(val))[0]
    else:
        ret = struct.unpack("<I", bytes(val))[0]

    return ret

def readUnsignedLong(target=None, memory_address=None, big_endian=False, **kwargs):
    if memory_address == None:
        raise TypeError

    val = __PyMym.readBytes(__final_target(**kwargs), memory_address, ctypes.sizeof(ctypes.c_ulong))
    ret = 0

    if big_endian:
        ret = struct.unpack(">L", bytes(val))[0]
    else:
        ret = struct.unpack("<L", bytes(val))[0]

    return ret

def readUnsignedLongLong(target=None, memory_address=None, big_endian=False, **kwargs):
    if memory_address == None:
        raise TypeError

    val = __PyMym.readBytes(__final_target(**kwargs), memory_address, ctypes.sizeof(ctypes.c_ulonglong))
    ret = 0

    if big_endian:
        ret = struct.unpack(">Q", bytes(val))[0]
    else:
        ret = struct.unpack("<Q", bytes(val))[0]

    return ret

def writeUnsignedShort(target=None, memory_address=None, val=None, big_endian=False, **kwargs):
    if memory_address == None:
        raise TypeError
    if val == None:
        raise TypeError
    if val > __check_constraint(ctypes.c_ushort):
        raise ValueError

    bytes_to_write = bytes()
    if big_endian:
        bytes_to_write = struct.pack(">H", val)[0]
    else:
        bytes_to_write = struct.pack("<H", val)[0]

    fin_val = __create_byte_pattern(pattern=bytes_to_write)

    return __PyMym.writeBytes(__final_target(**kwargs), memory_address, ctypes.sizeof(ctypes.c_ushort), fin_val)

def writeUnsignedInteger(target=None, memory_address=None, val=None, big_endian=False, **kwargs):
    if memory_address == None:
        raise TypeError
    if val == None:
        raise TypeError
    if val > __check_constraint(ctypes.c_uint):
        raise ValueError

    bytes_to_write = bytes()
    if big_endian:
        bytes_to_write = struct.pack(">I", val)[0]
    else:
        bytes_to_write = struct.pack("<I", val)[0]

    fin_val = __create_byte_pattern(pattern=bytes_to_write)

    return __PyMym.writeBytes(__final_target(**kwargs), memory_address, ctypes.sizeof(ctypes.c_uint), fin_val)

def writeUnsignedLong(target=None, memory_address=None, val=None, big_endian=False, **kwargs):
    if memory_address == None:
        raise TypeError
    if val == None:
        raise TypeError
    if val > __check_constraint(ctypes.c_ulong):
        raise ValueError

    bytes_to_write = bytes()
    if big_endian:
        bytes_to_write = struct.pack(">L", val)[0]
    else:
        bytes_to_write = struct.pack("<L", val)[0]

    fin_val = __create_byte_pattern(pattern=bytes_to_write)

    return __PyMym.writeBytes(__final_target(**kwargs), memory_address, ctypes.sizeof(ctypes.c_ulong), fin_val)

def writeUnsignedLongLong(target=None, memory_address=None, val=None, big_endian=False, **kwargs):
    if memory_address == None:
        raise TypeError
    if val == None:
        raise TypeError
    if val > __check_constraint(ctypes.c_ulonglong):
        raise ValueError

    bytes_to_write = bytes()
    if big_endian:
        bytes_to_write = struct.pack(">Q", val)[0]
    else:
        bytes_to_write = struct.pack("<Q", val)[0]

    fin_val = __create_byte_pattern(pattern=bytes_to_write)

    return __PyMym.writeBytes(__final_target(**kwargs), memory_address, ctypes.sizeof(ctypes.c_ulonglong), fin_val)