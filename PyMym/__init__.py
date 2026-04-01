from . import PyMym as _PyMym

import ctypes
import struct
import inspect

# TODO: Make it so that strings, ints, floats, and byte arrays can be passed in as the pattern, then make mask using it

# TODO: Reduce the code for the memory scan, make a helper function that performs the search so all 3 scans can use it

# TODO: Make sure to add new functionality to the pyi file, update names in pyi and the test files
# TODO: Add in tests for the new class

# TODO: When slicing, add in a bunch of 0's if the user does not specify a fill value
# TODO: Figure out how to do slicing since different data types require different bytes, both classes

# TODO: For the AOBsearches, try and fit user given value into smallest signed data type, so try short, then int, long, longlong, or float, double in that order
# TODO: Use the constraint checker function

# TODO: Add in support for wide characters/ UTF-16

# TODO: Check for other refactors

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
        raise TypeError("Invalid type given for {}, expected type is: str | bytes | list[int]".format(__get_caller_function()))

    return ret if not flip_endian else ret[::-1]

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
    if abs(val) > _constraint_map[data_type]:
        raise OverflowError(f"Given value cannot fit within {ctypes.sizeof(data_type)} bytes")

def module_aob_scan(target=None, module_name=None, pattern=None, mask=None, offset=0, result_instance=0, flip_endian=False, hex_string=False, **kwargs):
    if None in [module_name, pattern]:
        raise TypeError("moduleAOBScan is missing the following required arguments: 'module_name' and 'pattern'")

    byte_pattern = _create_byte_pattern(pattern=pattern, hex_string=hex_string, flip_endian=flip_endian)
    fin_mask = mask
    if fin_mask == None:
        fin_mask = "x" * len(byte_pattern)
    return _PyMym.moduleAOBScan(__final_target(**kwargs), module_name, byte_pattern, fin_mask, offset, result_instance)

def get_modules(target, **kwargs):
    pid = kwargs.get('pid', target)
    application_name = kwargs.get('application_name')

    function_target = pid if pid is not None else application_name
    return _PyMym.getModules(function_target)

def get_pid(application_name):
    return _PyMym.getPID(application_name)

def get_pids():
    return _PyMym.getPIDs()

def get_process_name(pid):
    return _PyMym.getProcessName(pid)

def get_process_names():
    return _PyMym.getProcessNames()

def heap_aob_scan(target=None, pattern=None, mask=None, offset=0, result_instance=0, flip_endian=False, hex_string=False, **kwargs):
    if pattern == None:
        raise TypeError("heapAOBScan is missing the following required argument: 'pattern'")

    byte_pattern = _create_byte_pattern(pattern=pattern, hex_string=hex_string, flip_endian=flip_endian)
    fin_mask = mask
    if fin_mask == None:
        fin_mask = "x" * len(byte_pattern)
    return _PyMym.heapAOBScan(__final_target(**kwargs), byte_pattern, fin_mask, offset, result_instance)


def stack_aob_scan(target=None, pattern=None, mask=None, offset=0, result_instance=0, flip_endian=False, hex_string=False, **kwargs):
    if pattern == None:
        raise TypeError("stackAOBScan is missing the following required argument: 'pattern'")

    byte_pattern = _create_byte_pattern(pattern=pattern, hex_string=hex_string, flip_endian=flip_endian)
    fin_mask = mask
    if fin_mask == None:
        fin_mask = "x" * len(byte_pattern)
    return _PyMym.stackAOBScan(__final_target(**kwargs), byte_pattern, fin_mask, offset, result_instance)


def read_bytes(target=None, memory_address=None, num_bytes=0, flip_endian=False, **kwargs):
    val = _PyMym.readBytes(__final_target(**kwargs), memory_address, num_bytes)
    return val if not flip_endian else val[::-1]

def read_double(target=None, memory_address=None, big_endian=False, **kwargs):
    if memory_address == None:
        raise TypeError

    val = _PyMym.readBytes(__final_target(**kwargs), memory_address, ctypes.sizeof(ctypes.c_double))
    ret = 0

    if big_endian:
        ret = struct.unpack(">d", bytes(val))[0]
    else:
        ret = struct.unpack("<d", bytes(val))[0]

    return ret

def read_float(target=None, memory_address=None, big_endian=False, **kwargs):
    if memory_address == None:
        raise TypeError

    val = _PyMym.readBytes(__final_target(**kwargs), memory_address, ctypes.sizeof(ctypes.c_float))
    ret = 0

    if big_endian:
        ret = struct.unpack(">f", bytes(val))[0]
    else:
        ret = struct.unpack("<f", bytes(val))[0]

    return ret

def read_int(target=None, memory_address=None, big_endian=False, **kwargs):
    if memory_address == None:
        raise TypeError

    val = _PyMym.readBytes(__final_target(**kwargs), memory_address, ctypes.sizeof(ctypes.c_int))
    ret = 0

    if big_endian:
        ret = struct.unpack(">i", bytes(val))[0]
    else:
        ret = struct.unpack("<i", bytes(val))[0]

    return ret

def read_long(target=None, memory_address=None, big_endian=False, **kwargs):
    if memory_address == None:
        raise TypeError

    val = _PyMym.readBytes(__final_target(**kwargs), memory_address, ctypes.sizeof(ctypes.c_long))
    ret = 0

    if big_endian:
        ret = struct.unpack(">l", bytes(val))[0]
    else:
        ret = struct.unpack("<l", bytes(val))[0]

    return ret

def read_longlong(target=None, memory_address=None, big_endian=False, **kwargs):
    if memory_address == None:
        raise TypeError

    val = _PyMym.readBytes(__final_target(**kwargs), memory_address, ctypes.sizeof(ctypes.c_longlong))
    ret = 0

    if big_endian:
        ret = struct.unpack(">q", bytes(val))[0]
    else:
        ret = struct.unpack("<q", bytes(val))[0]

    return ret

def read_short(target=None, memory_address=None, big_endian=False, **kwargs):
    if memory_address == None:
        raise TypeError

    val = _PyMym.readBytes(__final_target(**kwargs), memory_address, ctypes.sizeof(ctypes.c_short))
    ret = 0

    if big_endian:
        ret = struct.unpack(">h", bytes(val))[0]
    else:
        ret = struct.unpack("<h", bytes(val))[0]

    return ret

def write_bytes(target=None, memory_address=None, bytes=None, hex_string=False, flip_endian=False, size=1, **kwargs):
    if bytes == None:
        raise TypeError

    if memory_address == None:
        raise TypeError

    bytes_to_write = _create_byte_pattern(bytes, hex_string=hex_string, flip_endian=flip_endian)

    if len(bytes_to_write) < size:
        bytes_to_write = bytes_to_write + [0] * (size - len(bytes_to_write))

    return _PyMym.writeBytes(__final_target(**kwargs), memory_address, size, bytes_to_write)

def write_double(target=None, memory_address=None, val=None, big_endian=False, **kwargs):
    _validate_input(val, ctypes.c_double, memory_address)

    bytes_to_write = bytes()
    if big_endian:
        bytes_to_write = struct.pack(">d", val)
    else:
        bytes_to_write = struct.pack("<d", val)

    fin_val = _create_byte_pattern(pattern=bytes_to_write)

    return _PyMym.writeBytes(__final_target(**kwargs), memory_address, ctypes.sizeof(ctypes.c_double), fin_val)

def write_float(target=None, memory_address=None, val=None, big_endian=False, **kwargs):
    _validate_input(val, ctypes.c_float, memory_address)

    bytes_to_write = bytes()
    if big_endian:
        bytes_to_write = struct.pack(">f", val)
    else:
        bytes_to_write = struct.pack("<f", val)

    fin_val = _create_byte_pattern(pattern=bytes_to_write)

    return _PyMym.writeBytes(__final_target(**kwargs), memory_address, ctypes.sizeof(ctypes.c_float), fin_val)

def write_int(target=None, memory_address=None, val=None, big_endian=False, **kwargs):
    _validate_input(val, ctypes.c_int, memory_address)

    bytes_to_write = bytes()
    if big_endian:
        bytes_to_write = struct.pack(">i", val)
    else:
        bytes_to_write = struct.pack("<i", val)

    fin_val = _create_byte_pattern(pattern=bytes_to_write)

    return _PyMym.writeBytes(__final_target(**kwargs), memory_address, ctypes.sizeof(ctypes.c_int), fin_val)

def write_long(target=None, memory_address=None, val=None, big_endian=False, **kwargs):
    _validate_input(val, ctypes.c_long, memory_address)

    bytes_to_write = bytes()
    if big_endian:
        bytes_to_write = struct.pack(">l", val)
    else:
        bytes_to_write = struct.pack("<l", val)

    fin_val = _create_byte_pattern(pattern=bytes_to_write)

    return _PyMym.writeBytes(__final_target(**kwargs), memory_address, ctypes.sizeof(ctypes.c_long), fin_val)

def write_longlong(target=None, memory_address=None, val=None, big_endian=False, **kwargs):
    _validate_input(val, ctypes.c_longlong, memory_address)

    bytes_to_write = bytes()
    if big_endian:
        bytes_to_write = struct.pack(">q", val)
    else:
        bytes_to_write = struct.pack("<q", val)

    fin_val = _create_byte_pattern(pattern=bytes_to_write)

    return _PyMym.writeBytes(__final_target(**kwargs), memory_address, ctypes.sizeof(ctypes.c_longlong), fin_val)

def write_short(target=None, memory_address=None, val=None, big_endian=False, **kwargs):
    _validate_input(val, ctypes.c_short, memory_address)

    bytes_to_write = bytes()
    if big_endian:
        bytes_to_write = struct.pack(">h", val)
    else:
        bytes_to_write = struct.pack("<h", val)

    fin_val = _create_byte_pattern(pattern=bytes_to_write)

    return _PyMym.writeBytes(__final_target(**kwargs), memory_address, ctypes.sizeof(ctypes.c_short), fin_val)

def read_ushort(target=None, memory_address=None, big_endian=False, **kwargs):
    if memory_address == None:
        raise TypeError

    val = _PyMym.readBytes(__final_target(**kwargs), memory_address, ctypes.sizeof(ctypes.c_ushort))
    ret = 0

    if big_endian:
        ret = struct.unpack(">H", bytes(val))[0]
    else:
        ret = struct.unpack("<H", bytes(val))[0]

    return ret

def read_uint(target=None, memory_address=None, big_endian=False, **kwargs):
    if memory_address == None:
        raise TypeError

    val = _PyMym.readBytes(__final_target(**kwargs), memory_address, ctypes.sizeof(ctypes.c_uint))
    ret = 0

    if big_endian:
        ret = struct.unpack(">I", bytes(val))[0]
    else:
        ret = struct.unpack("<I", bytes(val))[0]

    return ret

def read_ulong(target=None, memory_address=None, big_endian=False, **kwargs):
    if memory_address == None:
        raise TypeError

    val = _PyMym.readBytes(__final_target(**kwargs), memory_address, ctypes.sizeof(ctypes.c_ulong))
    ret = 0

    if big_endian:
        ret = struct.unpack(">L", bytes(val))[0]
    else:
        ret = struct.unpack("<L", bytes(val))[0]

    return ret

def read_ulonglong(target=None, memory_address=None, big_endian=False, **kwargs):
    if memory_address == None:
        raise TypeError

    val = _PyMym.readBytes(__final_target(**kwargs), memory_address, ctypes.sizeof(ctypes.c_ulonglong))
    ret = 0

    if big_endian:
        ret = struct.unpack(">Q", bytes(val))[0]
    else:
        ret = struct.unpack("<Q", bytes(val))[0]

    return ret

def write_ushort(target=None, memory_address=None, val=None, big_endian=False, **kwargs):
    _validate_input(val, ctypes.c_ushort, memory_address)

    bytes_to_write = bytes()
    if big_endian:
        bytes_to_write = struct.pack(">H", val)
    else:
        bytes_to_write = struct.pack("<H", val)

    fin_val = _create_byte_pattern(pattern=bytes_to_write)

    return _PyMym.writeBytes(__final_target(**kwargs), memory_address, ctypes.sizeof(ctypes.c_ushort), fin_val)

def write_uint(target=None, memory_address=None, val=None, big_endian=False, **kwargs):
    _validate_input(val, ctypes.c_uint, memory_address)

    bytes_to_write = bytes()
    if big_endian:
        bytes_to_write = struct.pack(">I", val)
    else:
        bytes_to_write = struct.pack("<I", val)

    fin_val = _create_byte_pattern(pattern=bytes_to_write)

    return _PyMym.writeBytes(__final_target(**kwargs), memory_address, ctypes.sizeof(ctypes.c_uint), fin_val)

def write_ulong(target=None, memory_address=None, val=None, big_endian=False, **kwargs):
    _validate_input(val, ctypes.c_ulong, memory_address)

    bytes_to_write = bytes()
    if big_endian:
        bytes_to_write = struct.pack(">L", val)
    else:
        bytes_to_write = struct.pack("<L", val)

    fin_val = _create_byte_pattern(pattern=bytes_to_write)

    return _PyMym.writeBytes(__final_target(**kwargs), memory_address, ctypes.sizeof(ctypes.c_ulong), fin_val)

def write_ulonglong(target=None, memory_address=None, val=None, big_endian=False, **kwargs):
    _validate_input(val, ctypes.c_ulonglong, memory_address)

    bytes_to_write = bytes()
    if big_endian:
        bytes_to_write = struct.pack(">Q", val)
    else:
        bytes_to_write = struct.pack("<Q", val)

    fin_val = _create_byte_pattern(pattern=bytes_to_write)

    return _PyMym.writeBytes(__final_target(**kwargs), memory_address, ctypes.sizeof(ctypes.c_ulonglong), fin_val)

class MemoryProxy:
    def __init__(self, wrapper, data_type):
        self.wrapper: ProcessWrapper = wrapper
        self.data_type = data_type

    def __getitem__(self, key):
        if isinstance(key, slice):
            ret = []

            start = key.start if key.start != None else 0
            stop = key.stop if key.stop != None else 1
            step = key.step if key.step != None else 1

            for addr in range(start, stop, step):
                ret = ret + [self.wrapper.read_datatype(addr, self.data_type)]

            return ret
        else:
            return self.wrapper.read_datatype(key, self.data_type)

    def __setitem__(self, key, val):
        if isinstance(key, slice):
            ret = []

            start = key.start if key.start != None else 0
            stop = key.stop if key.stop != None else 1
            step = key.step if key.step != None else 1

            for addr in range(start, stop, step * ctypes.sizeof(self.data_type)):
                fval = val[addr - start] if addr - start < len(val) else 0

                if abs(fval) > _constraint_map[self.data_type]:
                    raise OverflowError(f"{fval} cannot be represented within {self.data_type}")

                ret = ret + [self.wrapper.write_datatype(addr=addr, data_type=self.data_type, val=fval)]

            return False if False in ret else True
        else:
            if abs(val) > _constraint_map[self.data_type]:
                raise OverflowError(f"{val} cannot be represented within {self.data_type}")
            return self.wrapper.write_datatype(addr=key, data_type=self.data_type, val=val)

class ProcessWrapper():
    def __init__(self, target=None, big_endian=False, **kwargs):
        self.__application_name = kwargs.get('application_name')
        self.__pid = kwargs.get('pid')
        self.__big_endian = big_endian

        if self.__application_name == None and self.__pid == None:
            raise TypeError("ProcessWrapper requires one of the following: application_name or pid")

        if self.__pid == None:
            self.__pid = _PyMym.getPID(self.__application_name)
        if self.__application_name == None:
            self.__application_name = _PyMym.getProcessName(self.__pid)

        self.__handle = _PyMym.openProcess(self.__pid)

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
        return f"{self.__class__.__name__}(application_name={self.__application_name!r}, pid={self.__pid})"

    def __str__(self):
        return f"<{self.__application_name} (PID: {self.__pid}) [{"Open" if self.__handle != None else "Closed"}]>"

    def __bool__(self):
        return self.__handle != None

    def __getitem__(self, key):
        if isinstance(key, slice):
            ret = []

            start = key.start if key.start != None else 0
            stop = key.stop if key.stop != None else 1
            step = key.step if key.step != None else 1

            for addr in range(start, stop, step):
                ret = ret + self.read_bytes(addr)

            return ret
        else:
            return self.read_bytes(key)

    def __setitem__(self, key, val):
        if isinstance(key, slice):
            ret = []

            start = key.start if key.start != None else 0
            stop = key.stop if key.stop != None else 1
            step = key.step if key.step != None else 1

            for addr in range(start, stop, step):
                fval = [val[addr - start]] if addr - start < len(val) else [0]
                ret = ret + self.write_bytes(addr, fval)

            return False if False in ret else True
        else:
            return self.write_bytes(key, [val])

    def __eq__(self, other):
        if not isinstance(other, ProcessWrapper):
            return False
        return self.__pid == other.get_pid()

    def close(self):
        if self.__handle:
            _PyMym.closeHandle(self.__handle)
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
        match data_type:
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
        match data_type:
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

        return _PyMym.handledReadBytes(self.__handle, addr, n)

    def read_float(self, addr=None):
        if addr == None:
            raise TypeError

        val = _PyMym.handledReadBytes(self.__handle, addr, ctypes.sizeof(ctypes.c_float))
        ret = 0

        if self.__big_endian:
            ret = struct.unpack(">f", bytes(val))[0]
        else:
            ret = struct.unpack("<f", bytes(val))[0]

        return ret

    def read_double(self, addr=None):
        if addr == None:
            raise TypeError

        val = _PyMym.handledReadBytes(self.__handle, addr, ctypes.sizeof(ctypes.c_double))
        ret = 0

        if self.__big_endian:
            ret = struct.unpack(">d", bytes(val))[0]
        else:
            ret = struct.unpack("<d", bytes(val))[0]

        return ret

    def read_short(self, addr=None):
        if addr == None:
            raise TypeError

        val = _PyMym.handledReadBytes(self.__handle, addr, ctypes.sizeof(ctypes.c_short))
        ret = 0

        if self.__big_endian:
            ret = struct.unpack(">h", bytes(val))[0]
        else:
            ret = struct.unpack("<h", bytes(val))[0]

        return ret

    def read_int(self, addr=None):
        if addr == None:
            raise TypeError

        val = _PyMym.handledReadBytes(self.__handle, addr, ctypes.sizeof(ctypes.c_int))
        ret = 0

        if self.__big_endian:
            ret = struct.unpack(">i", bytes(val))[0]
        else:
            ret = struct.unpack("<i", bytes(val))[0]

        return ret

    def read_long(self, addr=None):
        if addr == None:
            raise TypeError

        val = _PyMym.handledReadBytes(self.__handle, addr, ctypes.sizeof(ctypes.c_long))
        ret = 0

        if self.__big_endian:
            ret = struct.unpack(">l", bytes(val))[0]
        else:
            ret = struct.unpack("<l", bytes(val))[0]

        return ret

    def read_longlong(self, addr=None):
        if addr == None:
            raise TypeError

        val = _PyMym.handledReadBytes(self.__handle, addr, ctypes.sizeof(ctypes.c_longlong))
        ret = 0

        if self.__big_endian:
            ret = struct.unpack(">q", bytes(val))[0]
        else:
            ret = struct.unpack("<q", bytes(val))[0]

        return ret

    def read_uint(self, addr=None):
        if addr == None:
            raise TypeError

        val = _PyMym.handledReadBytes(self.__handle, addr, ctypes.sizeof(ctypes.c_uint))
        ret = 0

        if self.__big_endian:
            ret = struct.unpack(">I", bytes(val))[0]
        else:
            ret = struct.unpack("<I", bytes(val))[0]

        return ret

    def read_ushort(self, addr=None):
        if addr == None:
            raise TypeError

        val = _PyMym.handledReadBytes(self.__handle, addr, ctypes.sizeof(ctypes.c_ushort))
        ret = 0

        if self.__big_endian:
            ret = struct.unpack(">H", bytes(val))[0]
        else:
            ret = struct.unpack("<H", bytes(val))[0]

        return ret

    def read_ulong(self, addr=None):
        if addr == None:
            raise TypeError

        val = _PyMym.handledReadBytes(self.__handle, addr, ctypes.sizeof(ctypes.c_ulong))
        ret = 0

        if self.__big_endian:
            ret = struct.unpack(">L", bytes(val))[0]
        else:
            ret = struct.unpack("<L", bytes(val))[0]

        return ret

    def read_ulonglong(self, addr=None):
        if addr == None:
            raise TypeError

        val = _PyMym.handledReadBytes(self.__handle, addr, ctypes.sizeof(ctypes.c_ulonglong))
        ret = 0

        if self.__big_endian:
            ret = struct.unpack(">Q", bytes(val))[0]
        else:
            ret = struct.unpack("<Q", bytes(val))[0]

        return ret

    def write_bytes(self, addr=None, val=None, size=1, overwrite_endian=False):
        if val == None:
            raise TypeError

        if addr == None:
            raise TypeError

        endian = self.__big_endian if not overwrite_endian else not self.__big_endian

        bytes_to_write = _create_byte_pattern(val, hex_string=True, flip_endian=endian)
        if len(bytes_to_write) < size:
            bytes_to_write = bytes_to_write + [0] * (size - len(bytes_to_write))
        return _PyMym.handledriteBytes(self.__handle, addr, size, bytes_to_write)


    def write_float(self, addr=None, val=None):
        _validate_input(val, ctypes.c_float, addr)

        bytes_to_write = bytes()
        if self.__big_endian:
            bytes_to_write = struct.pack(">f", val)
        else:
            bytes_to_write = struct.pack("<f", val)

        fin_val = _create_byte_pattern(pattern=bytes_to_write)

        return _PyMym.handledWriteBytes(self.__handle, addr, ctypes.sizeof(ctypes.c_float), fin_val)

    def write_double(self, addr=None, val=None):
        _validate_input(val, ctypes.c_double, addr)

        bytes_to_write = bytes()
        if self.__big_endian:
            bytes_to_write = struct.pack(">d", val)
        else:
            bytes_to_write = struct.pack("<d", val)

        fin_val = _create_byte_pattern(pattern=bytes_to_write)

        return _PyMym.handledWriteBytes(self.__handle, addr, ctypes.sizeof(ctypes.c_double), fin_val)

    def write_short(self, addr=None, val=None):
        _validate_input(val, ctypes.c_short, addr)

        bytes_to_write = bytes()
        if self.__big_endian:
            bytes_to_write = struct.pack(">h", val)
        else:
            bytes_to_write = struct.pack("<h", val)

        fin_val = _create_byte_pattern(pattern=bytes_to_write)

        return _PyMym.handledWriteBytes(self.__handle, addr, ctypes.sizeof(ctypes.c_short), fin_val)

    def write_int(self, addr=None, val=None):
        _validate_input(val, ctypes.c_int, addr)

        bytes_to_write = bytes()
        if self.__big_endian:
            bytes_to_write = struct.pack(">i", val)
        else:
            bytes_to_write = struct.pack("<i", val)

        fin_val = _create_byte_pattern(pattern=bytes_to_write)

        return _PyMym.handledWriteBytes(self.__handle, addr, ctypes.sizeof(ctypes.c_int), fin_val)

    def write_long(self, addr=None, val=None):
        _validate_input(val, ctypes.c_long, addr)

        bytes_to_write = bytes()
        if self.__big_endian:
            bytes_to_write = struct.pack(">l", val)
        else:
            bytes_to_write = struct.pack("<l", val)

        fin_val = _create_byte_pattern(pattern=bytes_to_write)

        return _PyMym.handledWriteBytes(self.__handle, addr, ctypes.sizeof(ctypes.c_long), fin_val)

    def write_longlong(self, addr=None, val=None):
        _validate_input(val, ctypes.c_longlong, addr)

        bytes_to_write = bytes()
        if self.__big_endian:
            bytes_to_write = struct.pack(">q", val)
        else:
            bytes_to_write = struct.pack("<q", val)

        fin_val = _create_byte_pattern(pattern=bytes_to_write)

        return _PyMym.handledWriteBytes(self.__handle, addr, ctypes.sizeof(ctypes.c_longlong), fin_val)

    def write_uint(self, addr=None, val=None):
        _validate_input(val, ctypes.c_uint, addr)

        bytes_to_write = bytes()
        if self.__big_endian:
            bytes_to_write = struct.pack(">I", val)
        else:
            bytes_to_write = struct.pack("<I", val)

        fin_val = _create_byte_pattern(pattern=bytes_to_write)

        return _PyMym.handledWriteBytes(self.__handle, addr, ctypes.sizeof(ctypes.c_uint), fin_val)

    def write_ushort(self, addr=None, val=None):
        _validate_input(val, ctypes.c_ushort, addr)

        bytes_to_write = bytes()
        if self.__big_endian:
            bytes_to_write = struct.pack(">H", val)
        else:
            bytes_to_write = struct.pack("<H", val)

        fin_val = _create_byte_pattern(pattern=bytes_to_write)

        return _PyMym.handledWriteBytes(self.__handle, addr, ctypes.sizeof(ctypes.c_ushort), fin_val)

    def write_ulong(self, addr=None, val=None):
        _validate_input(val, ctypes.c_ulong, addr)

        bytes_to_write = bytes()
        if self.__big_endian:
            bytes_to_write = struct.pack(">L", val)
        else:
            bytes_to_write = struct.pack("<L", val)

        fin_val = _create_byte_pattern(pattern=bytes_to_write)

        return _PyMym.handledWriteBytes(self.__handle, addr, ctypes.sizeof(ctypes.c_ulong), fin_val)

    def write_ulonglong(self, addr=None, val=None):
        _validate_input(val, ctypes.c_ulonglong, addr)

        bytes_to_write = bytes()
        if self.__big_endian:
            bytes_to_write = struct.pack(">Q", val)
        else:
            bytes_to_write = struct.pack("<Q", val)

        fin_val = _create_byte_pattern(pattern=bytes_to_write)

        return _PyMym.handledWriteBytes(self.__handle, addr, ctypes.sizeof(ctypes.c_ulonglong), fin_val)

    def module_aob_scan(self, module_name=None, pattern=None, mask=None, offset=0, result_instance=0, hex_string=False, flip_endian=False):
        if None in [module_name, pattern]:
            raise TypeError("module_aob_scan is missing the following required arguments: 'module_name' and 'pattern'")

        endian = self.__big_endian if not flip_endian else not self.__big_endian

        byte_pattern = _create_byte_pattern(pattern=pattern, hex_string=hex_string, flip_endian=endian)
        fin_mask = mask
        if fin_mask == None:
            fin_mask = "x" * len(byte_pattern)
        return _PyMym.handledModuleAOBScan(self.__handle, module_name, byte_pattern, fin_mask, offset, result_instance)

    def stack_aob_scan(self, pattern=None, mask=None, offset=0, result_instance=0, hex_string=False, flip_endian=False):
        if pattern == None:
            raise TypeError("stack_aob_scan is missing the following required argument: 'pattern'")

        endian = self.__big_endian if not flip_endian else not self.__big_endian

        byte_pattern = _create_byte_pattern(pattern=pattern, hex_string=hex_string, flip_endian=endian)
        fin_mask = mask
        if fin_mask == None:
            fin_mask = "x" * len(byte_pattern)
        return _PyMym.handledStackAOBScan(self.__handle, self.__pid, byte_pattern, fin_mask, offset, result_instance)

    def heap_aob_scan(self, pattern=None, mask=None, offset=0, result_instance=0, hex_string=False, flip_endian=False):
        if pattern == None:
            raise TypeError("heap_aob_scan is missing the following required argument: 'pattern'")

        endian = self.__big_endian if not flip_endian else not self.__big_endian

        byte_pattern = _create_byte_pattern(pattern=pattern, hex_string=hex_string, flip_endian=endian)
        fin_mask = mask
        if fin_mask == None:
            fin_mask = "x" * len(byte_pattern)
        return _PyMym.handledHeapAOBScan(self.__handle, byte_pattern, fin_mask, offset, result_instance)

    def get_pid(self):
        return self.__pid

    def get_application_name(self):
        return self.__application_name

    def get_modules(self):
        return _PyMym.handledGetModules(self.__handle)