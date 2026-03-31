from . import PyMym as __PyMym

import ctypes
import struct
import inspect

# TODO: Make it so that strings, ints, floats, and byte arrays can be passed in as the pattern, then make mask using it
# TODO: Reduce the code for the memory scan, make a helper function that performs the search so all 3 scans can use it
# TODO: Make a wrapper class, make methods, make Python methods, overload C++ functions to create a handled version of each function
# TODO: EXAMPLE: read_bytes(HANDLE hProcess, ...), read_bytes(int pid, ....) {HANDLE hProcess = OpenProcess(pid) -> return read_bytes(hProcess, ...)}
# TODO: Have the Python class keep a handle open to reduce function calls to OpenProcess, add in a close() and __exit__() method, check out "with PyMemProcess() as p:"
# TODO: Add in a proxy class so that .float[mem_addr] and other datatypes can be used
# TODO: add in open process and close process function within C++ file
# TODO: Add in byte padding for odd bytes (ie. pad 5 -> 6, 3 -> 4, etc.), take ints and other data types for scanners, can pack them to bytes then create pattern
# TODO: Make all function names Pythonic and PEP8
# TODO: Make sure to add new functionality to the pyi file, update names in pyi and the test files
# TODO: Add in tests for the new class
# TODO: When slicing, add in a bunch of 0's if the user does not specify a fill value
# TODO: For the AOBsearches, try and fit user given value into smallest signed data type, so try short, then int, long, longlong, or float, double in that order
# TODO: Use the constraint checker function
# TODO: Add in support for wide characters/ UTF-16

def __check_constraint(data_type, signed=True):
    return (2 ** ((ctypes.sizeof(data_type) * 8) - 1) - 1) if signed else (2 ** (ctypes.sizeof(data_type) * 8) - 1)

__constraint_map = {
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
                raise OverflowError("Byte iterable contains bytes that do not fall within the range 0 - 255")
        ret = pattern
    else:
        raise TypeError("Invalid type given for {}, expected type is: str | bytes | list[int]".format(__get_caller_function()))

    return ret if not flip_endian else ret[::-1]

def __final_target(target=None, **kwargs):
    pid = kwargs.get('pid', target)
    application_name = kwargs.get('application_name')

    if pid == None and application_name == None:
        raise TypeError("{} requires one of the following arguments: 'pid' or 'application_name'".format(__get_caller_function()))

    return pid if pid is not None else application_name

def module_aob_scan(target=None, module_name=None, pattern=None, mask=None, offset=0, result_instance=0, flip_endian=False, hex_string=False, **kwargs):
    if None in [module_name, pattern]:
        raise TypeError("moduleAOBScan is missing the following required arguments: 'module_name' and 'pattern'")

    byte_pattern = __create_byte_pattern(pattern=pattern, hex_string=hex_string, flip_endian=flip_endian)
    fin_mask = mask
    if fin_mask == None:
        fin_mask = "x" * len(byte_pattern)
    return __PyMym.moduleAOBScan(__final_target(**kwargs), module_name, byte_pattern, fin_mask, offset, result_instance)

def get_modules(target, **kwargs):
    pid = kwargs.get('pid', target)
    application_name = kwargs.get('application_name')

    function_target = pid if pid is not None else application_name
    return __PyMym.getModules(function_target)

def get_pid(application_name):
    return __PyMym.getPID(application_name)

def get_pids():
    return __PyMym.getPIDs()

def get_process_name(pid):
    return __PyMym.getProcessName(pid)

def get_process_names():
    return __PyMym.getProcessNames()

def heap_aob_scan(target=None, pattern=None, mask=None, offset=0, result_instance=0, flip_endian=False, hex_string=False, **kwargs):
    if pattern == None:
        raise TypeError("heapAOBScan is missing the following required argument: 'pattern'")

    byte_pattern = __create_byte_pattern(pattern=pattern, hex_string=hex_string, flip_endian=flip_endian)
    fin_mask = mask
    if fin_mask == None:
        fin_mask = "x" * len(byte_pattern)
    return __PyMym.heapAOBScan(__final_target(**kwargs), byte_pattern, fin_mask, offset, result_instance)


def stack_aob_scan(target=None, pattern=None, mask=None, offset=0, result_instance=0, flip_endian=False, hex_string=False, **kwargs):
    if pattern == None:
        raise TypeError("stackAOBScan is missing the following required argument: 'pattern'")

    byte_pattern = __create_byte_pattern(pattern=pattern, hex_string=hex_string, flip_endian=flip_endian)
    fin_mask = mask
    if fin_mask == None:
        fin_mask = "x" * len(byte_pattern)
    return __PyMym.stackAOBScan(__final_target(**kwargs), byte_pattern, fin_mask, offset, result_instance)


def read_bytes(target=None, memory_address=None, num_bytes=0, flip_endian=False, **kwargs):
    val = __PyMym.readBytes(__final_target(**kwargs), memory_address, num_bytes)
    return val if not flip_endian else val[::-1]

def read_double(target=None, memory_address=None, big_endian=False, **kwargs):
    if memory_address == None:
        raise TypeError

    val = __PyMym.readBytes(__final_target(**kwargs), memory_address, ctypes.sizeof(ctypes.c_double))
    ret = 0

    if big_endian:
        ret = struct.unpack(">d", bytes(val))[0]
    else:
        ret = struct.unpack("<d", bytes(val))[0]

    return ret

def read_float(target=None, memory_address=None, big_endian=False, **kwargs):
    if memory_address == None:
        raise TypeError

    val = __PyMym.readBytes(__final_target(**kwargs), memory_address, ctypes.sizeof(ctypes.c_float))
    ret = 0

    if big_endian:
        ret = struct.unpack(">f", bytes(val))[0]
    else:
        ret = struct.unpack("<f", bytes(val))[0]

    return ret

def read_int(target=None, memory_address=None, big_endian=False, **kwargs):
    if memory_address == None:
        raise TypeError

    val = __PyMym.readBytes(__final_target(**kwargs), memory_address, ctypes.sizeof(ctypes.c_int))
    ret = 0

    if big_endian:
        ret = struct.unpack(">i", bytes(val))[0]
    else:
        ret = struct.unpack("<i", bytes(val))[0]

    return ret

def read_long(target=None, memory_address=None, big_endian=False, **kwargs):
    if memory_address == None:
        raise TypeError

    val = __PyMym.readBytes(__final_target(**kwargs), memory_address, ctypes.sizeof(ctypes.c_long))
    ret = 0

    if big_endian:
        ret = struct.unpack(">l", bytes(val))[0]
    else:
        ret = struct.unpack("<l", bytes(val))[0]

    return ret

def read_longlong(target=None, memory_address=None, big_endian=False, **kwargs):
    if memory_address == None:
        raise TypeError

    val = __PyMym.readBytes(__final_target(**kwargs), memory_address, ctypes.sizeof(ctypes.c_longlong))
    ret = 0

    if big_endian:
        ret = struct.unpack(">q", bytes(val))[0]
    else:
        ret = struct.unpack("<q", bytes(val))[0]

    return ret

def read_short(target=None, memory_address=None, big_endian=False, **kwargs):
    if memory_address == None:
        raise TypeError

    val = __PyMym.readBytes(__final_target(**kwargs), memory_address, ctypes.sizeof(ctypes.c_short))
    ret = 0

    if big_endian:
        ret = struct.unpack(">h", bytes(val))[0]
    else:
        ret = struct.unpack("<h", bytes(val))[0]

    return ret

def write_bytes(target=None, memory_address=None, bytes=None, hex_string=False, flip_endian=False, **kwargs):
    if bytes == None:
        raise TypeError

    if memory_address == None:
        raise TypeError

    bytes_to_write = __create_byte_pattern(bytes, hex_string, flip_endian)
    num_bytes = len(bytes_to_write)
    return __PyMym.writeBytes(__final_target(**kwargs), memory_address, num_bytes, bytes_to_write)

def write_double(target=None, memory_address=None, val=None, big_endian=False, **kwargs):
    if memory_address == None:
        raise TypeError
    if val == None:
        raise TypeError
    if abs(val) > __constraint_map[ctypes.c_double]:
        raise OverflowError()

    bytes_to_write = bytes()
    if big_endian:
        bytes_to_write = struct.pack(">d", val)
    else:
        bytes_to_write = struct.pack("<d", val)

    fin_val = __create_byte_pattern(pattern=bytes_to_write)

    return __PyMym.writeBytes(__final_target(**kwargs), memory_address, ctypes.sizeof(ctypes.c_double), fin_val)

def write_float(target=None, memory_address=None, val=None, big_endian=False, **kwargs):
    if memory_address == None:
        raise TypeError
    if val == None:
        raise TypeError
    if abs(val) > __constraint_map[ctypes.c_float]:
        raise OverflowError()

    bytes_to_write = bytes()
    if big_endian:
        bytes_to_write = struct.pack(">f", val)
    else:
        bytes_to_write = struct.pack("<f", val)

    fin_val = __create_byte_pattern(pattern=bytes_to_write)

    return __PyMym.writeBytes(__final_target(**kwargs), memory_address, ctypes.sizeof(ctypes.c_float), fin_val)

def write_int(target=None, memory_address=None, val=None, big_endian=False, **kwargs):
    if memory_address == None:
        raise TypeError
    if val == None:
        raise TypeError
    if abs(val) > __constraint_map[ctypes.c_int]:
        raise OverflowError()

    bytes_to_write = bytes()
    if big_endian:
        bytes_to_write = struct.pack(">i", val)
    else:
        bytes_to_write = struct.pack("<i", val)

    fin_val = __create_byte_pattern(pattern=bytes_to_write)

    return __PyMym.writeBytes(__final_target(**kwargs), memory_address, ctypes.sizeof(ctypes.c_int), fin_val)

def write_long(target=None, memory_address=None, val=None, big_endian=False, **kwargs):
    if memory_address == None:
        raise TypeError
    if val == None:
        raise TypeError
    if abs(val) > __constraint_map[ctypes.c_long]:
        raise ValueError

    bytes_to_write = bytes()
    if big_endian:
        bytes_to_write = struct.pack(">l", val)
    else:
        bytes_to_write = struct.pack("<l", val)

    fin_val = __create_byte_pattern(pattern=bytes_to_write)

    return __PyMym.writeBytes(__final_target(**kwargs), memory_address, ctypes.sizeof(ctypes.c_long), fin_val)

def write_longlong(target=None, memory_address=None, val=None, big_endian=False, **kwargs):
    if memory_address == None:
        raise TypeError
    if val == None:
        raise TypeError
    if abs(val) > __constraint_map[ctypes.c_longlong]:
        raise ValueError

    bytes_to_write = bytes()
    if big_endian:
        bytes_to_write = struct.pack(">q", val)
    else:
        bytes_to_write = struct.pack("<q", val)

    fin_val = __create_byte_pattern(pattern=bytes_to_write)

    return __PyMym.writeBytes(__final_target(**kwargs), memory_address, ctypes.sizeof(ctypes.c_longlong), fin_val)

def write_short(target=None, memory_address=None, val=None, big_endian=False, **kwargs):
    if memory_address == None:
        raise TypeError
    if val == None:
        raise TypeError
    if abs(val) > __constraint_map[ctypes.c_short]:
        raise ValueError

    bytes_to_write = bytes()
    if big_endian:
        bytes_to_write = struct.pack(">h", val)
    else:
        bytes_to_write = struct.pack("<h", val)

    fin_val = __create_byte_pattern(pattern=bytes_to_write)

    return __PyMym.writeBytes(__final_target(**kwargs), memory_address, ctypes.sizeof(ctypes.c_short), fin_val)

def read_ushort(target=None, memory_address=None, big_endian=False, **kwargs):
    if memory_address == None:
        raise TypeError

    val = __PyMym.readBytes(__final_target(**kwargs), memory_address, ctypes.sizeof(ctypes.c_ushort))
    ret = 0

    if big_endian:
        ret = struct.unpack(">H", bytes(val))[0]
    else:
        ret = struct.unpack("<H", bytes(val))[0]

    return ret

def read_uint(target=None, memory_address=None, big_endian=False, **kwargs):
    if memory_address == None:
        raise TypeError

    val = __PyMym.readBytes(__final_target(**kwargs), memory_address, ctypes.sizeof(ctypes.c_uint))
    ret = 0

    if big_endian:
        ret = struct.unpack(">I", bytes(val))[0]
    else:
        ret = struct.unpack("<I", bytes(val))[0]

    return ret

def read_ulong(target=None, memory_address=None, big_endian=False, **kwargs):
    if memory_address == None:
        raise TypeError

    val = __PyMym.readBytes(__final_target(**kwargs), memory_address, ctypes.sizeof(ctypes.c_ulong))
    ret = 0

    if big_endian:
        ret = struct.unpack(">L", bytes(val))[0]
    else:
        ret = struct.unpack("<L", bytes(val))[0]

    return ret

def read_ulonglong(target=None, memory_address=None, big_endian=False, **kwargs):
    if memory_address == None:
        raise TypeError

    val = __PyMym.readBytes(__final_target(**kwargs), memory_address, ctypes.sizeof(ctypes.c_ulonglong))
    ret = 0

    if big_endian:
        ret = struct.unpack(">Q", bytes(val))[0]
    else:
        ret = struct.unpack("<Q", bytes(val))[0]

    return ret

def write_ushort(target=None, memory_address=None, val=None, big_endian=False, **kwargs):
    if memory_address == None:
        raise TypeError
    if val == None:
        raise TypeError
    if abs(val) > __constraint_map[ctypes.c_ushort]:
        raise ValueError

    bytes_to_write = bytes()
    if big_endian:
        bytes_to_write = struct.pack(">H", val)
    else:
        bytes_to_write = struct.pack("<H", val)

    fin_val = __create_byte_pattern(pattern=bytes_to_write)

    return __PyMym.writeBytes(__final_target(**kwargs), memory_address, ctypes.sizeof(ctypes.c_ushort), fin_val)

def write_uint(target=None, memory_address=None, val=None, big_endian=False, **kwargs):
    if memory_address == None:
        raise TypeError
    if val == None:
        raise TypeError
    if abs(val) > __constraint_map[ctypes.c_uint]:
        raise ValueError

    bytes_to_write = bytes()
    if big_endian:
        bytes_to_write = struct.pack(">I", val)
    else:
        bytes_to_write = struct.pack("<I", val)

    fin_val = __create_byte_pattern(pattern=bytes_to_write)

    return __PyMym.writeBytes(__final_target(**kwargs), memory_address, ctypes.sizeof(ctypes.c_uint), fin_val)

def write_ulong(target=None, memory_address=None, val=None, big_endian=False, **kwargs):
    if memory_address == None:
        raise TypeError
    if val == None:
        raise TypeError
    if abs(val) > __constraint_map[ctypes.c_ulong]:
        raise ValueError

    bytes_to_write = bytes()
    if big_endian:
        bytes_to_write = struct.pack(">L", val)
    else:
        bytes_to_write = struct.pack("<L", val)

    fin_val = __create_byte_pattern(pattern=bytes_to_write)

    return __PyMym.writeBytes(__final_target(**kwargs), memory_address, ctypes.sizeof(ctypes.c_ulong), fin_val)

def write_ulonglong(target=None, memory_address=None, val=None, big_endian=False, **kwargs):
    if memory_address == None:
        raise TypeError
    if val == None:
        raise TypeError
    if abs(val) > __constraint_map[ctypes.c_ulonglong]:
        raise ValueError

    bytes_to_write = bytes()
    if big_endian:
        bytes_to_write = struct.pack(">Q", val)
    else:
        bytes_to_write = struct.pack("<Q", val)

    fin_val = __create_byte_pattern(pattern=bytes_to_write)

    return __PyMym.writeBytes(__final_target(**kwargs), memory_address, ctypes.sizeof(ctypes.c_ulonglong), fin_val)

class MemoryProxy:
    def __init__(self, wrapper, data_type):
        self.wrapper = wrapper
        self.data_type = data_type

    # TODO: Check out how to do slicing and edit all functions to slice properly
    # TODO: Within the Process Wrapper read_datatype function
    def __getitem__(self, addr):
        return self.wrapper.read_datatype(addr, self.data_type)

    def __setitem__(self, addr, val):
        if abs(val) > __constraint_map[self.data_type]:
            raise OverflowError(f"{val} cannot be represented within {ctypes.sizeof(self.data_type)} bytes")
        return self.wrapper.write_datatype(addr, self.data_type, val)

class ProcessWrapper():
    def __init__(self, target=None, big_endian=False, **kwargs):
        self.__application_name = kwargs["application_name"]
        self.__pid = kwargs["pid"]
        self.__big_endian = big_endian

        if self.__application_name == None and self.__pid == None:
            raise TypeError("ProcessWrapper requires one of the following: application_name or pid")

        if self.__pid == None:
            self.__pid = __PyMym.getPID(self.__application_name)
        if self.__application_name == None:
            self.__application_name = __PyMym.getProcessName(self.__pid)

        self.__handle = __PyMym.openProcess(self.__pid)

        if self.__handle == None:
            raise ValueError()

        self.byte = MemoryProxy(self, ctypes.c_byte)
        self.float = MemoryProxy(self, ctypes.c_float)
        self.double = MemoryProxy(self, ctypes.c_double)
        self.integer = MemoryProxy(self, ctypes.c_int)
        self.short = MemoryProxy(self, ctypes.c_short)
        self.long = MemoryProxy(self, ctypes.c_long)
        self.longlong = MemoryProxy(self, ctypes.c_longlong)
        self.u_integer = MemoryProxy(self, ctypes.c_uint)
        self.u_short = MemoryProxy(self, ctypes.c_ushort)
        self.u_long = MemoryProxy(self, ctypes.c_ulong)
        self.u_longlong = MemoryProxy(self, ctypes.c_ulonglong)

    def __enter__(self):
        return self

    def __exit__(self):
        self.close()

    def __delete__(self):
        self.close()

    def __repr__(self):
        pass

    def __str__(self):
        pass

    def __bool__(self):
        pass

    def __getitem__(self):
        pass

    def __setitem__(self):
        pass

    def __eq__(self):
        pass

    def close(self):
        if self.__handle:
            __PyMym.closeHandle(self.__handle)
            self.__handle = None
            self.__pid = None
            self.__application_name = None

    def set_endian(self, new_endian="little"):
        if new_endian.lower() == "big":
            self.__big_endian = True
        else:
            self.__big_endian = False

    def read_datatype(self, addr, data_type):
        r = None
        match type(data_type):
            case ctypes.c_byte:
                r = self.read_bytes(addr)
            case ctypes.c_float:
                r = self.read_float(addr)
            case ctypes.c_double:
                r = self.read_double(addr)
            case ctypes.c_short:
                r = self.read_short(addr)
            case ctypes.c_int:
                r = self.read_integer(addr)
            case ctypes.c_long:
                r = self.read_long(addr)
            case ctypes.c_longlong:
                r = self.read_longlong(addr)
            case ctypes.c_ushort:
                r = self.read_ushort(addr)
            case ctypes.c_uint:
                r = self.read_uinteger(addr)
            case ctypes.c_ulong:
                r = self.read_ulong(addr)
            case ctypes.c_ulonglong:
                r = self.read_ulonglong(addr)
        return r

    def write_datatype(self, addr, data_type, val):
        r = None
        match type(data_type):
            case ctypes.c_byte:
                r = self.write_bytes(addr, val)
            case ctypes.c_float:
                r = self.write_float(addr, val)
            case ctypes.c_double:
                r = self.write_double(addr, val)
            case ctypes.c_short:
                r = self.write_short(addr, val)
            case ctypes.c_int:
                r = self.write_integer(addr, val)
            case ctypes.c_long:
                r = self.write_long(addr, val)
            case ctypes.c_longlong:
                r = self.write_longlong(addr, val)
            case ctypes.c_ushort:
                r = self.write_ushort(addr, val)
            case ctypes.c_uint:
                r = self.write_uinteger(addr, val)
            case ctypes.c_ulong:
                r = self.write_ulong(addr, val)
            case ctypes.c_ulonglong:
                r = self.write_ulonglong(addr, val)
        return r

    def read_bytes(self, addr=None, n=1):
        if addr == None:
            raise TypeError

        return __PyMym.handledReadBytes(self.__handle, addr, n)

    def read_float(self, addr=None):
        if addr == None:
            raise TypeError

        val = __PyMym.handledReadBytes(self.__handle, addr, ctypes.sizeof(ctypes.c_float))
        ret = 0

        if self.__big_endian:
            ret = struct.unpack(">f", bytes(val))[0]
        else:
            ret = struct.unpack("<f", bytes(val))[0]

        return ret

    def read_double(self, addr=None):
        if addr == None:
            raise TypeError

        val = __PyMym.handledReadBytes(self.__handle, addr, ctypes.sizeof(ctypes.c_double))
        ret = 0

        if self.__big_endian:
            ret = struct.unpack(">d", bytes(val))[0]
        else:
            ret = struct.unpack("<d", bytes(val))[0]

        return ret

    def read_short(self, addr=None):
        if addr == None:
            raise TypeError

        val = __PyMym.handledReadBytes(self.__handle, addr, ctypes.sizeof(ctypes.c_short))
        ret = 0

        if self.__big_endian:
            ret = struct.unpack(">h", bytes(val))[0]
        else:
            ret = struct.unpack("<h", bytes(val))[0]

        return ret

    def read_int(self, addr=None):
        if addr == None:
            raise TypeError

        val = __PyMym.handledReadBytes(self.__handle, addr, ctypes.sizeof(ctypes.c_int))
        ret = 0

        if self.__big_endian:
            ret = struct.unpack(">i", bytes(val))[0]
        else:
            ret = struct.unpack("<i", bytes(val))[0]

        return ret

    def read_long():
        ...

    def read_longlong():
        ...

    def read_uint():
        ...

    def read_ushort():
        ...

    def read_ulong():
        ...

    def read_ulonglong():
        ...

    def write_bytes():
        ...

    def write_float():
        ...

    def write_double():
        ...

    def write_short():
        ...

    def write_int():
        ...

    def write_long():
        ...

    def write_longlong():
        ...

    def write_uint():
        ...

    def write_ushort():
        ...

    def write_ulong():
        ...

    def write_ulonglong():
        ...

    def module_aob_scan():
        ...

    def stack_aob_scan():
        ...

    def heap_aob_scan():
        ...

    def get_pid():
        ...

    def get_application_name():
        ...

    def get_modules():
        ...