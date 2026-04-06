from __future__ import annotations
import ctypes
import struct
import inspect

from .src_PyMym import *

# TODO: Reduce the code for the memory scan, make a helper function that performs the search so all 3 scans can use it
# TODO: Add in tests for the new class
# TODO: Add in support for wide characters/ UTF-16

# TODO: Update all descriptions in PyMym.pyi and make sure they match the functions

__all__ = [
    "ProcessWrapper",
    "pack_float",
    "pack_double",
    "pack_short",
    "pack_int",
    "pack_long",
    "pack_longlong",
    "pack_ushort",
    "pack_uint",
    "pack_ulong",
    "pack_ulonglong",
    "unpack_float",
    "unpack_double",
    "unpack_short",
    "unpack_int",
    "unpack_long",
    "unpack_longlong",
    "unpack_ushort",
    "unpack_uint",
    "unpack_ulong",
    "unpack_ulonglong",
    "read_bytes",
    "read_float",
    "read_double",
    "read_short",
    "read_int",
    "read_long",
    "read_longlong",
    "read_ushort",
    "read_uint",
    "read_ulong",
    "read_ulonglong",
    "write_bytes",
    "write_float",
    "write_double",
    "write_short",
    "write_int",
    "write_long",
    "write_longlong",
    "write_ushort",
    "write_uint",
    "write_ulong",
    "write_ulonglong",
    "get_modules",
    "get_pid",
    "get_pids",
    "get_process_name",
    "get_process_names",
    "module_aob_scan",
    "heap_aob_scan",
    "stack_aob_scan",
    "_create_byte_pattern",
]

def __check_constraint(data_type, signed=True):
    return (2 ** ((ctypes.sizeof(data_type) * 8) - 1) - 1) if signed else (2 ** (ctypes.sizeof(data_type) * 8) - 1)

_constraint_map = {
    ctypes.c_byte: __check_constraint(ctypes.c_byte),
    ctypes.c_float: __check_constraint(ctypes.c_float),
    ctypes.c_double: __check_constraint(ctypes.c_double),
    ctypes.c_short: __check_constraint(ctypes.c_short),
    ctypes.c_int: __check_constraint(ctypes.c_int),
    ctypes.c_long: __check_constraint(ctypes.c_long),
    ctypes.c_longlong: __check_constraint(ctypes.c_longlong),
    ctypes.c_ushort: __check_constraint(ctypes.c_ushort, False),
    ctypes.c_uint: __check_constraint(ctypes.c_uint, False),
    ctypes.c_ulong: __check_constraint(ctypes.c_ulong, False),
    ctypes.c_ulonglong: __check_constraint(ctypes.c_ulonglong, False)
}

def __get_caller_function():
    s = inspect.stack()
    return s[2].function if len(s) > 2 else s[1].function

def __hexstring(pattern: str):
    broken_str = pattern.split(" ")

    for x in broken_str:
        if len(x) > 2 or len(x) % 2 == 1:
            raise ValueError("Invalid format given for hex string, expected the following format: 'XX XX XX'")

    return [int(x, 16) for x in broken_str]

def _create_byte_pattern(pattern, hex_string=False, flip_endian=False):
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
                raise OverflowError("Byte iterable contains bytes that do not fall within the range 0 - 255")
        ret = pattern
    else:
        raise TypeError(f"Invalid type given for {__get_caller_function()}, expected type is: str | bytes | list[int]")

    return ret if not flip_endian else ret[::-1]

def pack_float(val, big_endian=False):
    bytes_to_write = bytes()
    if big_endian:
        bytes_to_write = struct.pack(">f", val)
    else:
        bytes_to_write = struct.pack("<f", val)

    return _create_byte_pattern(pattern=bytes_to_write)

def pack_double(val, big_endian=False):
    bytes_to_write = bytes()
    if big_endian:
        bytes_to_write = struct.pack(">d", val)
    else:
        bytes_to_write = struct.pack("<d", val)

    return _create_byte_pattern(pattern=bytes_to_write)

def pack_short(val, big_endian=False):
    bytes_to_write = bytes()
    if big_endian:
        bytes_to_write = struct.pack(">h", val)
    else:
        bytes_to_write = struct.pack("<h", val)

    return _create_byte_pattern(pattern=bytes_to_write)

def pack_int(val, big_endian=False):
    bytes_to_write = bytes()
    if big_endian:
        bytes_to_write = struct.pack(">i", val)
    else:
        bytes_to_write = struct.pack("<i", val)

    return _create_byte_pattern(pattern=bytes_to_write)

def pack_long(val, big_endian=False):
    bytes_to_write = bytes()
    if big_endian:
        bytes_to_write = struct.pack(">l", val)
    else:
        bytes_to_write = struct.pack("<l", val)

    return _create_byte_pattern(pattern=bytes_to_write)

def pack_longlong(val, big_endian=False):
    bytes_to_write = bytes()
    if big_endian:
        bytes_to_write = struct.pack(">q", val)
    else:
        bytes_to_write = struct.pack("<q", val)

    return _create_byte_pattern(pattern=bytes_to_write)

def pack_ushort(val, big_endian=False):
    bytes_to_write = bytes()
    if big_endian:
        bytes_to_write = struct.pack(">H", val)
    else:
        bytes_to_write = struct.pack("<H", val)

    return _create_byte_pattern(pattern=bytes_to_write)

def pack_uint(val, big_endian=False):
    bytes_to_write = bytes()
    if big_endian:
        bytes_to_write = struct.pack(">I", val)
    else:
        bytes_to_write = struct.pack("<I", val)

    return _create_byte_pattern(pattern=bytes_to_write)

def pack_ulong(val, big_endian=False):
    bytes_to_write = bytes()
    if big_endian:
        bytes_to_write = struct.pack(">L", val)
    else:
        bytes_to_write = struct.pack("<L", val)

    return _create_byte_pattern(pattern=bytes_to_write)

def pack_ulonglong(val, big_endian=False):
    bytes_to_write = bytes()
    if big_endian:
        bytes_to_write = struct.pack(">Q", val)
    else:
        bytes_to_write = struct.pack("<Q", val)

    return _create_byte_pattern(pattern=bytes_to_write)

def unpack_float(val, big_endian=False):
    if big_endian:
        return struct.unpack(">f", bytes(val))[0]

    return struct.unpack("<f", bytes(val))[0]

def unpack_double(val, big_endian=False):
    if big_endian:
        return struct.unpack(">d", bytes(val))[0]

    return struct.unpack("<d", bytes(val))[0]

def unpack_short(val, big_endian=False):
    if big_endian:
        return struct.unpack(">h", bytes(val))[0]

    return struct.unpack("<h", bytes(val))[0]

def unpack_int(val, big_endian=False):
    if big_endian:
        return struct.unpack(">i", bytes(val))[0]

    return struct.unpack("<i", bytes(val))[0]

def unpack_long(val, big_endian=False):
    if big_endian:
        return struct.unpack(">l", bytes(val))[0]

    return struct.unpack("<l", bytes(val))[0]

def unpack_longlong(val, big_endian=False):
    if big_endian:
        return struct.unpack(">q", bytes(val))[0]

    return struct.unpack("<q", bytes(val))[0]

def unpack_ushort(val, big_endian=False):
    if big_endian:
        return struct.unpack(">H", bytes(val))[0]

    return struct.unpack("<H", bytes(val))[0]

def unpack_uint(val, big_endian=False):
    if big_endian:
        return struct.unpack(">I", bytes(val))[0]

    return struct.unpack("<I", bytes(val))[0]

def unpack_ulong(val, big_endian=False):
    if big_endian:
        return struct.unpack(">L", bytes(val))[0]

    return struct.unpack("<L", bytes(val))[0]

def unpack_ulonglong(val, big_endian=False):
    if big_endian:
        return struct.unpack(">Q", bytes(val))[0]

    return struct.unpack("<Q", bytes(val))[0]

def __final_target(target=None, **kwargs):
    pid = kwargs.get('pid', target)
    application_name = kwargs.get('application_name')

    if pid == None and application_name == None:
        raise TypeError("{} requires one of the following arguments: 'pid' or 'application_name'".format(__get_caller_function()))

    return pid if pid is not None else application_name

def _validate_input(val, data_type, memory_address):
    if memory_address == None:
        raise TypeError("Missing required argument: 'memory_address'")
    if val == None:
        raise TypeError("Missing required argument: 'val'")
    if isinstance(val, (list)):
        for i in val:
            if abs(i) > _constraint_map[data_type]:
                raise OverflowError(f"Given value {i} cannot fit within {data_type}")
    else:
        if abs(val) > _constraint_map[data_type]:
            raise OverflowError(f"Given value {val} cannot fit within {data_type}")

def module_aob_scan(target=None, module_name=None, pattern=None, mask=None, offset=0, result_instance=0, flip_endian=False, hex_string=False, **kwargs):
    if None in [module_name, pattern]:
        raise TypeError("moduleAOBScan is missing the following required arguments: 'module_name' and 'pattern'")

    byte_pattern = _create_byte_pattern(pattern=pattern, hex_string=hex_string, flip_endian=flip_endian)
    fin_mask = mask
    if fin_mask == None:
        fin_mask = "x" * len(byte_pattern)
    return moduleAOBScan(__final_target(**kwargs), module_name, byte_pattern, fin_mask, offset, result_instance)

def get_modules(target=None, **kwargs):
    return getModules(__final_target(**kwargs))

def get_pid(application_name):
    return getPID(application_name)

def get_pids():
    return getPIDs()

def get_process_name(pid):
    return getProcessName(pid)

def get_process_names():
    return getProcessNames()

def heap_aob_scan(target=None, pattern=None, mask=None, offset=0, result_instance=0, flip_endian=False, hex_string=False, **kwargs):
    if pattern == None:
        raise TypeError("heapAOBScan is missing the following required argument: 'pattern'")

    byte_pattern = _create_byte_pattern(pattern=pattern, hex_string=hex_string, flip_endian=flip_endian)
    fin_mask = mask
    if fin_mask == None:
        fin_mask = "x" * len(byte_pattern)
    return heapAOBScan(__final_target(**kwargs), byte_pattern, fin_mask, offset, result_instance)

def stack_aob_scan(target=None, pattern=None, mask=None, offset=0, result_instance=0, flip_endian=False, hex_string=False, **kwargs):
    if pattern == None:
        raise TypeError("stackAOBScan is missing the following required argument: 'pattern'")

    byte_pattern = _create_byte_pattern(pattern=pattern, hex_string=hex_string, flip_endian=flip_endian)
    fin_mask = mask
    if fin_mask == None:
        fin_mask = "x" * len(byte_pattern)
    return stackAOBScan(__final_target(**kwargs), byte_pattern, fin_mask, offset, result_instance)

def read_bytes(target=None, memory_address=None, n=1, flip_endian=False, **kwargs):
    val = readBytes(__final_target(**kwargs), memory_address, n)
    fval = val if not flip_endian else val[::-1]
    return fval if len(fval) > 1 else fval[0]

def read_double(target=None, memory_address=None, big_endian=False, n=1, **kwargs):
    if memory_address == None:
        raise TypeError

    val = readBytes(__final_target(**kwargs), memory_address, n * ctypes.sizeof(ctypes.c_double))

    ret = []
    for i in range(n):
        ret.append(unpack_double(val[i * ctypes.sizeof(ctypes.c_double) : (i + 1) * ctypes.sizeof(ctypes.c_double)], big_endian=big_endian))
    return ret if len(ret) > 1 else ret[0]

def read_float(target=None, memory_address=None, big_endian=False, n=1, **kwargs):
    if memory_address == None:
        raise TypeError

    val = readBytes(__final_target(**kwargs), memory_address, n * ctypes.sizeof(ctypes.c_float))

    ret = []
    for i in range(n):
        ret.append(unpack_float(val[i * ctypes.sizeof(ctypes.c_float) : (i + 1) * ctypes.sizeof(ctypes.c_float)], big_endian=big_endian))
    return ret if len(ret) > 1 else ret[0]

def read_int(target=None, memory_address=None, big_endian=False, n=1, **kwargs):
    if memory_address == None:
        raise TypeError

    val = readBytes(__final_target(**kwargs), memory_address, n * ctypes.sizeof(ctypes.c_int))

    ret = []
    for i in range(n):
        ret.append(unpack_int(val[i * ctypes.sizeof(ctypes.c_int) : (i + 1) * ctypes.sizeof(ctypes.c_int)], big_endian=big_endian))
    return ret if len(ret) > 1 else ret[0]

def read_long(target=None, memory_address=None, big_endian=False, n=1, **kwargs):
    if memory_address == None:
        raise TypeError

    val = readBytes(__final_target(**kwargs), memory_address, n * ctypes.sizeof(ctypes.c_long))

    ret = []
    for i in range(n):
        ret.append(unpack_long(val[i * ctypes.sizeof(ctypes.c_long) : (i + 1) * ctypes.sizeof(ctypes.c_long)], big_endian=big_endian))
    return ret if len(ret) > 1 else ret[0]

def read_longlong(target=None, memory_address=None, big_endian=False, n=1, **kwargs):
    if memory_address == None:
        raise TypeError

    val = readBytes(__final_target(**kwargs), memory_address, n * ctypes.sizeof(ctypes.c_longlong))

    ret = []
    for i in range(n):
        ret.append(unpack_longlong(val[i * ctypes.sizeof(ctypes.c_longlong) : (i + 1) * ctypes.sizeof(ctypes.c_longlong)], big_endian=big_endian))
    return ret if len(ret) > 1 else ret[0]

def read_short(target=None, memory_address=None, big_endian=False, n=1, **kwargs):
    if memory_address == None:
        raise TypeError

    val = readBytes(__final_target(**kwargs), memory_address, n * ctypes.sizeof(ctypes.c_short))

    ret = []
    for i in range(n):
        ret.append(unpack_short(val[i * ctypes.sizeof(ctypes.c_short) : (i + 1) * ctypes.sizeof(ctypes.c_short)], big_endian=big_endian))
    return ret if len(ret) > 1 else ret[0]

def write_bytes(target=None, memory_address=None, val=None, hex_string=False, flip_endian=False, n=1, **kwargs):
    if val == None:
        raise TypeError

    if memory_address == None:
        raise TypeError

    bytes_to_write = _create_byte_pattern(val, hex_string=hex_string, flip_endian=flip_endian)

    if len(bytes_to_write) < n:
        bytes_to_write = bytes_to_write + [0] * (n - len(bytes_to_write))

    return writeBytes(__final_target(**kwargs), memory_address, len(bytes_to_write), bytes_to_write)

def write_double(target=None, memory_address=None, val=None, big_endian=False, n=1, **kwargs):
    _validate_input(val, ctypes.c_double, memory_address)
    fval = []

    if isinstance(val, list):
        for i in val:
            fval += pack_double(i, big_endian=big_endian)
    else:
        fval += pack_double(val, big_endian=big_endian)

    if n > len(fval):
        fval += pack_double(0, big_endian=big_endian) * (n - len(fval))

    return writeBytes(__final_target(**kwargs), memory_address, len(fval), fval)

def write_float(target=None, memory_address=None, val=None, big_endian=False, n=1, **kwargs):
    _validate_input(val, ctypes.c_float, memory_address)
    fval = []

    if isinstance(val, list):
        for i in val:
            fval += pack_float(i, big_endian=big_endian)
    else:
        fval += pack_float(val, big_endian=big_endian)

    if n > len(fval):
        fval += pack_float(0, big_endian=big_endian) * (n - len(fval))

    return writeBytes(__final_target(**kwargs), memory_address, len(fval), fval)

def write_int(target=None, memory_address=None, val=None, big_endian=False, n=1, **kwargs):
    _validate_input(val, ctypes.c_int, memory_address)
    fval = []

    if isinstance(val, list):
        for i in val:
            fval += pack_int(i, big_endian=big_endian)
    else:
        fval += pack_int(val, big_endian=big_endian)

    if n > len(fval):
        fval += pack_int(0, big_endian=big_endian) * (n - len(fval))

    return writeBytes(__final_target(**kwargs), memory_address, len(fval), fval)

def write_long(target=None, memory_address=None, val=None, big_endian=False, n=1, **kwargs):
    _validate_input(val, ctypes.c_long, memory_address)
    fval = []

    if isinstance(val, list):
        for i in val:
            fval += pack_long(i, big_endian=big_endian)
    else:
        fval += pack_long(val, big_endian=big_endian)

    if n > len(fval):
        fval += pack_long(0, big_endian=big_endian) * (n - len(fval))

    return writeBytes(__final_target(**kwargs), memory_address, len(fval), fval)

def write_longlong(target=None, memory_address=None, val=None, big_endian=False, n=1, **kwargs):
    _validate_input(val, ctypes.c_longlong, memory_address)
    fval = []

    if isinstance(val, list):
        for i in val:
            fval += pack_longlong(i, big_endian=big_endian)
    else:
        fval += pack_longlong(val, big_endian=big_endian)

    if n > len(fval):
        fval += pack_longlong(0, big_endian=big_endian) * (n - len(fval))

    return writeBytes(__final_target(**kwargs), memory_address, len(fval), fval)

def write_short(target=None, memory_address=None, val=None, big_endian=False, n=1, **kwargs):
    _validate_input(val, ctypes.c_short, memory_address)
    fval = []

    if isinstance(val, list):
        for i in val:
            fval += pack_short(i, big_endian=big_endian)
    else:
        fval += pack_short(val, big_endian=big_endian)

    if n > len(fval):
        fval += pack_short(0, big_endian=big_endian) * (n - len(fval))

    return writeBytes(__final_target(**kwargs), memory_address, len(fval), fval)

def read_ushort(target=None, memory_address=None, big_endian=False, n=1, **kwargs):
    if memory_address == None:
        raise TypeError

    val = readBytes(__final_target(**kwargs), memory_address, n * ctypes.sizeof(ctypes.c_ushort))

    ret = []
    for i in range(n):
        ret.append(unpack_ushort(val[i * ctypes.sizeof(ctypes.c_ushort) : (i + 1) * ctypes.sizeof(ctypes.c_ushort)], big_endian=big_endian))
    return ret if len(ret) > 1 else ret[0]


def read_uint(target=None, memory_address=None, big_endian=False, n=1, **kwargs):
    if memory_address == None:
        raise TypeError

    val = readBytes(__final_target(**kwargs), memory_address, n * ctypes.sizeof(ctypes.c_uint))

    ret = []
    for i in range(n):
        ret.append(unpack_uint(val[i * ctypes.sizeof(ctypes.c_uint) : (i + 1) * ctypes.sizeof(ctypes.c_uint)], big_endian=big_endian))
    return ret if len(ret) > 1 else ret[0]

def read_ulong(target=None, memory_address=None, big_endian=False, n=1, **kwargs):
    if memory_address == None:
        raise TypeError

    val = readBytes(__final_target(**kwargs), memory_address, n * ctypes.sizeof(ctypes.c_ulong))

    ret = []
    for i in range(n):
        ret.append(unpack_ulong(val[i * ctypes.sizeof(ctypes.c_ulong) : (i + 1) * ctypes.sizeof(ctypes.c_ulong)], big_endian=big_endian))
    return ret if len(ret) > 1 else ret[0]

def read_ulonglong(target=None, memory_address=None, big_endian=False, n=1, **kwargs):
    if memory_address == None:
        raise TypeError

    val = readBytes(__final_target(**kwargs), memory_address, n * ctypes.sizeof(ctypes.c_ulonglong))

    ret = []
    for i in range(n):
        ret.append(unpack_ulonglong(val[i * ctypes.sizeof(ctypes.c_ulonglong) : (i + 1) * ctypes.sizeof(ctypes.c_ulonglong)], big_endian=big_endian))
    return ret if len(ret) > 1 else ret[0]

def write_ushort(target=None, memory_address=None, val=None, big_endian=False, n=1, **kwargs):
    _validate_input(val, ctypes.c_ushort, memory_address)
    fval = []

    if isinstance(val, list):
        for i in val:
            fval += pack_ushort(i, big_endian=big_endian)
    else:
        fval += pack_ushort(val, big_endian=big_endian)

    if n > len(fval):
        fval += pack_ushort(0, big_endian=big_endian) * (n - len(fval))

    return writeBytes(__final_target(**kwargs), memory_address, len(fval), fval)

def write_uint(target=None, memory_address=None, val=None, big_endian=False, n=1, **kwargs):
    _validate_input(val, ctypes.c_uint, memory_address)
    fval = []

    if isinstance(val, list):
        for i in val:
            fval += pack_uint(i, big_endian=big_endian)
    else:
        fval += pack_uint(val, big_endian=big_endian)

    if n > len(fval):
        fval += pack_uint(0, big_endian=big_endian) * (n - len(fval))

    return writeBytes(__final_target(**kwargs), memory_address, len(fval), fval)

def write_ulong(target=None, memory_address=None, val=None, big_endian=False, n=1, **kwargs):
    _validate_input(val, ctypes.c_ulong, memory_address)
    fval = []

    if isinstance(val, list):
        for i in val:
            fval += pack_ulong(i, big_endian=big_endian)
    else:
        fval += pack_ulong(val, big_endian=big_endian)

    if n > len(fval):
        fval += pack_ulong(0, big_endian=big_endian) * (n - len(fval))

    return writeBytes(__final_target(**kwargs), memory_address, len(fval), fval)

def write_ulonglong(target=None, memory_address=None, val=None, big_endian=False, n=1, **kwargs):
    _validate_input(val, ctypes.c_ulonglong, memory_address)
    fval = []

    if isinstance(val, list):
        for i in val:
            fval += pack_ulonglong(i, big_endian=big_endian)
    else:
        fval += pack_ulonglong(val, big_endian=big_endian)

    if n > len(fval):
        fval += pack_ulonglong(0, big_endian=big_endian) * (n - len(fval))

    return writeBytes(__final_target(**kwargs), memory_address, len(fval), fval)

class MemoryProxy:
    def __init__(self, wrapper, data_type):
        self.wrapper: ProcessWrapper = wrapper
        self.data_type = data_type

    def __getitem__(self, key):
        if isinstance(key, slice):
            start = key.start if key.start != None else 0
            stop = key.stop if key.stop != None else 1

            if key.step != None and key.step != 1:
                raise NotImplementedError("Stepped reads are not supported")

            return self.wrapper.read_datatype(start, self.data_type, n=(stop - start))
        else:
            return self.wrapper.read_datatype(key, self.data_type)

    def __setitem__(self, key, val):
        if isinstance(key, slice):
            start = key.start if key.start != None else 0
            stop = key.stop if key.stop != None else 1

            if key.step != None and key.step != 1:
                raise NotImplementedError("Stepped writes are not supported")

            for i in val:
                if abs(i) > _constraint_map[self.data_type]:
                    raise OverflowError(f"{i} cannot be represented within {self.data_type}")

            return self.wrapper.write_datatype(memory_address=start, data_type=self.data_type, val=val, n=(stop - start))
        else:
            fval = val
            if not isinstance(val, list):
                fval = [val]
            for i in fval:
                if abs(i) > _constraint_map[self.data_type]:
                    raise OverflowError(f"{i} cannot be represented within {self.data_type}")
            return self.wrapper.write_datatype(memory_address=key, data_type=self.data_type, val=fval)

class ProcessWrapper():
    def __init__(self, target=None, big_endian=False, **kwargs):
        self.__application_name = kwargs.get('application_name')
        self.__pid = kwargs.get('pid')
        self.__big_endian = big_endian

        if self.__application_name == None and self.__pid == None:
            raise TypeError("ProcessWrapper requires one of the following: application_name or pid")

        if self.__pid == None:
            self.__pid = getPID(self.__application_name)
        if self.__application_name == None:
            self.__application_name = getProcessName(self.__pid)

        self.__handle = openProcess(self.__pid)

        if self.__handle == None:
            raise ValueError()

        self.float = MemoryProxy(self, ctypes.c_float)
        self.double = MemoryProxy(self, ctypes.c_double)
        self.int = MemoryProxy(self, ctypes.c_int)
        self.short = MemoryProxy(self, ctypes.c_short)
        self.long = MemoryProxy(self, ctypes.c_long)
        self.longlong = MemoryProxy(self, ctypes.c_longlong)
        self.uint = MemoryProxy(self, ctypes.c_uint)
        self.ushort = MemoryProxy(self, ctypes.c_ushort)
        self.ulong = MemoryProxy(self, ctypes.c_ulong)
        self.ulonglong = MemoryProxy(self, ctypes.c_ulonglong)

    def __enter__(self):
        return self

    def __exit__(self, exception_type, exception_val, exception_trace):
        if exception_type:
            print(f"An exception occurred: {exception_val}")
            print(f"Traceback: {exception_trace}")
        self.close()

    def __delete__(self):
        self.close()

    def __repr__(self):
        return f"{self.__class__.__name__}(application_name={self.__application_name!r}, pid={self.__pid})"

    def __str__(self):
        return f"<{self.__application_name} (PID: {self.__pid}) [{"Open" if self.__handle != None else "Closed"}]>"

    def __bool__(self):
        return self.__handle != None

    def __getitem__(self, key):
        if isinstance(key, slice):
            start = key.start if key.start != None else 0
            stop = key.stop if key.stop != None else 1

            if key.step != None and key.step != 1:
                raise NotImplementedError("Stepped reads are not supported")

            return self.read_bytes(start, stop - start)
        else:
            return self.read_bytes(key)

    def __setitem__(self, key, val):
        if isinstance(key, slice):
            start = key.start if key.start != None else 0
            stop = key.stop if key.stop != None else 1

            if key.step != None and key.step != 1:
                raise NotImplementedError("Stepped writes are not supported")

            return self.write_bytes(memory_address=start, val=val, n=(stop-start))
        else:
            return self.write_bytes(key, [val])

    def __eq__(self, other):
        if not isinstance(other, ProcessWrapper):
            return False
        return self.__pid == other.get_pid()

    def close(self):
        if self.__handle:
            closeProcess(self.__handle)
            self.__handle = None
            self.__pid = None
            self.__application_name = None

    def set_endian(self, new_endian="little"):
        if new_endian.lower() == "big":
            self.__big_endian = True
        else:
            self.__big_endian = False

    def get_endian(self):
        return "big" if self.__big_endian else "little"

    def read_datatype(self, memory_address, data_type, n=1):
        r = None
        match data_type:
            case ctypes.c_byte:
                r = self.read_bytes(memory_address)
            case ctypes.c_float:
                r = self.read_float(memory_address, n)
            case ctypes.c_double:
                r = self.read_double(memory_address, n)
            case ctypes.c_short:
                r = self.read_short(memory_address, n)
            case ctypes.c_int:
                r = self.read_int(memory_address, n)
            case ctypes.c_long:
                r = self.read_long(memory_address, n)
            case ctypes.c_longlong:
                r = self.read_longlong(memory_address, n)
            case ctypes.c_ushort:
                r = self.read_ushort(memory_address, n)
            case ctypes.c_uint:
                r = self.read_uint(memory_address, n)
            case ctypes.c_ulong:
                r = self.read_ulong(memory_address, n)
            case ctypes.c_ulonglong:
                r = self.read_ulonglong(memory_address, n)
            case _:
                raise TypeError(f"{data_type} is not a valid type")
        return r

    def write_datatype(self, memory_address, data_type, val, n=1):
        r = None
        match data_type:
            case ctypes.c_byte:
                r = self.write_bytes(memory_address, val)
            case ctypes.c_float:
                r = self.write_float(memory_address, val, n)
            case ctypes.c_double:
                r = self.write_double(memory_address, val, n)
            case ctypes.c_short:
                r = self.write_short(memory_address, val, n)
            case ctypes.c_int:
                r = self.write_int(memory_address, val, n)
            case ctypes.c_long:
                r = self.write_long(memory_address, val, n)
            case ctypes.c_longlong:
                r = self.write_longlong(memory_address, val, n)
            case ctypes.c_ushort:
                r = self.write_ushort(memory_address, val, n)
            case ctypes.c_uint:
                r = self.write_uint(memory_address, val, n)
            case ctypes.c_ulong:
                r = self.write_ulong(memory_address, val, n)
            case ctypes.c_ulonglong:
                r = self.write_ulonglong(memory_address, val, n)
            case _:
                raise TypeError(f"{data_type} is not a valid type")
        return r

    def read_bytes(self, memory_address=None, n=1):
        if memory_address == None:
            raise TypeError

        fval = handledReadBytes(self.__handle, memory_address, n)

        return fval if n > 1 else fval[0]

    def read_float(self, memory_address=None, n=1):
        if memory_address == None:
            raise TypeError

        val = handledReadBytes(self.__handle, memory_address, n * ctypes.sizeof(ctypes.c_float))

        ret = []
        for i in range(n):
            ret.append(unpack_float(val[i * ctypes.sizeof(ctypes.c_float) : (i + 1) * ctypes.sizeof(ctypes.c_float)], big_endian=self.__big_endian))
        return ret if len(ret) > 1 else ret[0]

    def read_double(self, memory_address=None, n=1):
        if memory_address == None:
            raise TypeError

        val = handledReadBytes(self.__handle, memory_address, n * ctypes.sizeof(ctypes.c_double))

        ret = []
        for i in range(n):
            ret.append(unpack_double(val[i * ctypes.sizeof(ctypes.c_double) : (i + 1) * ctypes.sizeof(ctypes.c_double)], big_endian=self.__big_endian))
        return ret if len(ret) > 1 else ret[0]

    def read_short(self, memory_address=None, n=1):
        if memory_address == None:
            raise TypeError

        val = handledReadBytes(self.__handle, memory_address, n * ctypes.sizeof(ctypes.c_short))

        ret = []
        for i in range(n):
            ret.append(unpack_short(val[i * ctypes.sizeof(ctypes.c_short) : (i + 1) * ctypes.sizeof(ctypes.c_short)], big_endian=self.__big_endian))
        return ret if len(ret) > 1 else ret[0]

    def read_int(self, memory_address=None, n=1):
        if memory_address == None:
            raise TypeError

        val = handledReadBytes(self.__handle, memory_address, n * ctypes.sizeof(ctypes.c_int))

        ret = []
        for i in range(n):
            ret.append(unpack_int(val[i * ctypes.sizeof(ctypes.c_int) : (i + 1) * ctypes.sizeof(ctypes.c_int)], big_endian=self.__big_endian))
        return ret if len(ret) > 1 else ret[0]

    def read_long(self, memory_address=None, n=1):
        if memory_address == None:
            raise TypeError

        val = handledReadBytes(self.__handle, memory_address, n * ctypes.sizeof(ctypes.c_long))

        ret = []
        for i in range(n):
            ret.append(unpack_long(val[i * ctypes.sizeof(ctypes.c_long) : (i + 1) * ctypes.sizeof(ctypes.c_long)], big_endian=self.__big_endian))
        return ret if len(ret) > 1 else ret[0]

    def read_longlong(self, memory_address=None, n=1):
        if memory_address == None:
            raise TypeError

        val = handledReadBytes(self.__handle, memory_address, n * ctypes.sizeof(ctypes.c_longlong))

        ret = []
        for i in range(n):
            ret.append(unpack_longlong(val[i * ctypes.sizeof(ctypes.c_longlong) : (i + 1) * ctypes.sizeof(ctypes.c_longlong)], big_endian=self.__big_endian))
        return ret if len(ret) > 1 else ret[0]

    def read_uint(self, memory_address=None, n=1):
        if memory_address == None:
            raise TypeError

        val = handledReadBytes(self.__handle, memory_address, n * ctypes.sizeof(ctypes.c_uint))

        ret = []
        for i in range(n):
            ret.append(unpack_uint(val[i * ctypes.sizeof(ctypes.c_uint) : (i + 1) * ctypes.sizeof(ctypes.c_uint)], big_endian=self.__big_endian))
        return ret if len(ret) > 1 else ret[0]

    def read_ushort(self, memory_address=None, n=1):
        if memory_address == None:
            raise TypeError

        val = handledReadBytes(self.__handle, memory_address, n * ctypes.sizeof(ctypes.c_ushort))

        ret = []
        for i in range(n):
            ret.append(unpack_ushort(val[i * ctypes.sizeof(ctypes.c_ushort) : (i + 1) * ctypes.sizeof(ctypes.c_ushort)], big_endian=self.__big_endian))
        return ret if len(ret) > 1 else ret[0]

    def read_ulong(self, memory_address=None, n=1):
        if memory_address == None:
            raise TypeError

        val = handledReadBytes(self.__handle, memory_address, n * ctypes.sizeof(ctypes.c_ulong))

        ret = []
        for i in range(n):
            ret.append(unpack_ulong(val[i * ctypes.sizeof(ctypes.c_ulong) : (i + 1) * ctypes.sizeof(ctypes.c_ulong)], big_endian=self.__big_endian))
        return ret if len(ret) > 1 else ret[0]

    def read_ulonglong(self, memory_address=None, n=1):
        if memory_address == None:
            raise TypeError

        val = handledReadBytes(self.__handle, memory_address, n * ctypes.sizeof(ctypes.c_ulonglong))

        ret = []
        for i in range(n):
            ret.append(unpack_ulonglong(val[i * ctypes.sizeof(ctypes.c_ulonglong) : (i + 1) * ctypes.sizeof(ctypes.c_ulonglong)], big_endian=self.__big_endian))
        return ret if len(ret) > 1 else ret[0]

    def write_bytes(self, memory_address=None, val=None, n=1, overwrite_endian=False, hex_string=False):
        if val == None:
            raise TypeError

        if memory_address == None:
            raise TypeError

        endian = self.__big_endian if not overwrite_endian else not self.__big_endian

        bytes_to_write = _create_byte_pattern(val, hex_string=hex_string, flip_endian=endian)

        if len(bytes_to_write) < n:
            bytes_to_write = bytes_to_write + [0] * (n - len(bytes_to_write))

        return handledWriteBytes(self.__handle, memory_address, len(bytes_to_write), bytes_to_write)

    def write_float(self, memory_address=None, val=None, n=1):
        _validate_input(val, ctypes.c_float, memory_address)
        fval = []

        if isinstance(val, list):
            for i in val:
                fval += pack_float(i, big_endian=self.__big_endian)
        else:
            fval += pack_float(val, big_endian=self.__big_endian)

        if n > len(fval):
            fval += pack_float(0, big_endian=self.__big_endian) * (n - len(fval))

        return handledWriteBytes(self.__handle, memory_address, len(fval), fval)

    def write_double(self, memory_address=None, val=None, n=1):
        _validate_input(val, ctypes.c_double, memory_address)
        fval = []

        if isinstance(val, list):
            for i in val:
                fval += pack_double(i, big_endian=self.__big_endian)
        else:
            fval += pack_double(val, big_endian=self.__big_endian)

        if n > len(fval):
            fval += pack_double(0, big_endian=self.__big_endian) * (n - len(fval))

        return handledWriteBytes(self.__handle, memory_address, len(fval), fval)

    def write_short(self, memory_address=None, val=None, n=1):
        _validate_input(val, ctypes.c_short, memory_address)
        fval = []

        if isinstance(val, list):
            for i in val:
                fval += pack_short(i, big_endian=self.__big_endian)
        else:
            fval += pack_short(val, big_endian=self.__big_endian)

        if n > len(fval):
            fval += pack_short(0, big_endian=self.__big_endian) * (n - len(fval))

        return handledWriteBytes(self.__handle, memory_address, len(fval), fval)

    def write_int(self, memory_address=None, val=None, n=1):
        _validate_input(val, ctypes.c_int, memory_address)
        fval = []

        if isinstance(val, list):
            for i in val:
                fval += pack_int(i, big_endian=self.__big_endian)
        else:
            fval += pack_int(val, big_endian=self.__big_endian)

        if n > len(fval):
            fval += pack_int(0, big_endian=self.__big_endian) * (n - len(fval))

        return handledWriteBytes(self.__handle, memory_address, len(fval), fval)

    def write_long(self, memory_address=None, val=None, n=1):
        _validate_input(val, ctypes.c_long, memory_address)
        fval = []

        if isinstance(val, list):
            for i in val:
                fval += pack_long(i, big_endian=self.__big_endian)
        else:
            fval += pack_long(val, big_endian=self.__big_endian)

        if n > len(fval):
            fval += pack_long(0, big_endian=self.__big_endian) * (n - len(fval))

        return handledWriteBytes(self.__handle, memory_address, len(fval), fval)

    def write_longlong(self, memory_address=None, val=None, n=1):
        _validate_input(val, ctypes.c_longlong, memory_address)
        fval = []

        if isinstance(val, list):
            for i in val:
                fval += pack_longlong(i, big_endian=self.__big_endian)
        else:
            fval += pack_longlong(val, big_endian=self.__big_endian)

        if n > len(fval):
            fval += pack_longlong(0, big_endian=self.__big_endian) * (n - len(fval))

        return handledWriteBytes(self.__handle, memory_address, len(fval), fval)

    def write_uint(self, memory_address=None, val=None, n=1):
        _validate_input(val, ctypes.c_uint, memory_address)
        fval = []

        if isinstance(val, list):
            for i in val:
                fval += pack_uint(i, big_endian=self.__big_endian)
        else:
            fval += pack_uint(val, big_endian=self.__big_endian)

        if n > len(fval):
            fval += pack_uint(0, big_endian=self.__big_endian) * (n - len(fval))

        return handledWriteBytes(self.__handle, memory_address, len(fval), fval)

    def write_ushort(self, memory_address=None, val=None, n=1):
        _validate_input(val, ctypes.c_ushort, memory_address)
        fval = []

        if isinstance(val, list):
            for i in val:
                fval += pack_ushort(i, big_endian=self.__big_endian)
        else:
            fval += pack_ushort(val, big_endian=self.__big_endian)

        if n > len(fval):
            fval += pack_ushort(0, big_endian=self.__big_endian) * (n - len(fval))

        return handledWriteBytes(self.__handle, memory_address, len(fval), fval)

    def write_ulong(self, memory_address=None, val=None, n=1):
        _validate_input(val, ctypes.c_ulong, memory_address)
        fval = []

        if isinstance(val, list):
            for i in val:
                fval += pack_ulong(i, big_endian=self.__big_endian)
        else:
            fval += pack_ulong(val, big_endian=self.__big_endian)

        if n > len(fval):
            fval += pack_ulong(0, big_endian=self.__big_endian) * (n - len(fval))

        return handledWriteBytes(self.__handle, memory_address, len(fval), fval)

    def write_ulonglong(self, memory_address=None, val=None, n=1):
        _validate_input(val, ctypes.c_ulonglong, memory_address)
        fval = []

        if isinstance(val, list):
            for i in val:
                fval += pack_ulonglong(i, big_endian=self.__big_endian)
        else:
            fval += pack_ulonglong(val, big_endian=self.__big_endian)

        if n > len(fval):
            fval += pack_ulonglong(0, big_endian=self.__big_endian) * (n - len(fval))

        return handledWriteBytes(self.__handle, memory_address, len(fval), fval)

    def module_aob_scan(self, module_name=None, pattern=None, mask=None, offset=0, result_instance=0, hex_string=False, flip_endian=False):
        if None in [module_name, pattern]:
            raise TypeError("module_aob_scan is missing the following required arguments: 'module_name' and 'pattern'")

        endian = self.__big_endian if not flip_endian else not self.__big_endian

        byte_pattern = _create_byte_pattern(pattern=pattern, hex_string=hex_string, flip_endian=endian)
        fin_mask = mask
        if fin_mask == None:
            fin_mask = "x" * len(byte_pattern)
        return handledModuleAOBScan(self.__handle, module_name, byte_pattern, fin_mask, offset, result_instance)

    def stack_aob_scan(self, pattern=None, mask=None, offset=0, result_instance=0, hex_string=False, flip_endian=False):
        if pattern == None:
            raise TypeError("stack_aob_scan is missing the following required argument: 'pattern'")

        endian = self.__big_endian if not flip_endian else not self.__big_endian

        byte_pattern = _create_byte_pattern(pattern=pattern, hex_string=hex_string, flip_endian=endian)
        fin_mask = mask
        if fin_mask == None:
            fin_mask = "x" * len(byte_pattern)
        return handledStackAOBScan(self.__handle, self.__pid, byte_pattern, fin_mask, offset, result_instance)

    def heap_aob_scan(self, pattern=None, mask=None, offset=0, result_instance=0, hex_string=False, flip_endian=False):
        if pattern == None:
            raise TypeError("heap_aob_scan is missing the following required argument: 'pattern'")

        endian = self.__big_endian if not flip_endian else not self.__big_endian

        byte_pattern = _create_byte_pattern(pattern=pattern, hex_string=hex_string, flip_endian=endian)
        fin_mask = mask
        if fin_mask == None:
            fin_mask = "x" * len(byte_pattern)
        return handledHeapAOBScan(self.__handle, byte_pattern, fin_mask, offset, result_instance)

    def get_pid(self):
        return self.__pid

    def get_application_name(self):
        return self.__application_name

    def get_modules(self):
        return handledGetModules(self.__handle)