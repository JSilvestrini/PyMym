import typing
from typing import overload, List, Literal
import ctypes

pattern_type = typing.Union[
    str, 
    bytes, 
    List[typing.SupportsInt]
]

allowed_data_types = Literal[
    ctypes.c_byte,
    ctypes.c_int,
    ctypes.c_short,
    ctypes.c_long,
    ctypes.c_longlong,
    ctypes.c_float,
    ctypes.c_double,
    ctypes.c_uint,
    ctypes.c_ushort,
    ctypes.c_ulong,
    ctypes.c_ulonglong
]

@overload
def module_aob_scan(pid: typing.SupportsInt, module_name: str = None, pattern: pattern_type = None, mask: str  = None, offset: typing.SupportsInt = 0, result_instance: typing.SupportsInt = 0, flip_endian: bool = False, hex_string: bool = False) -> int:
    """Scans the given module of the process for the given pattern.\n
    Can take an optional 'mask', with ? as a wildcard and x as a required byte\n
    'offset' is added to the result and 'result_instance' is the n+1 instance of the pattern\n
    'flip_endian' will flip the pattern if used, 'hex_string' should be set to True if the pattern is a string of bytes\n
    
    ```python
    module = get_modules(pid=pid)[0]
    addr = module_aob_scan(pid=pid, module_name=module, pattern="AA BB CC", mask="x?x", hex_string=True) # ? is a wildcard
    addr2 = module_aob_scan(application_name=name, module_name=module, pattern="Hello, World") # 'mask' will default to no wildcards
    sval = pack_int(val=522, big_endian=False) # 'big_endian' is False by default
    addr3 = module_aob_scan(pid=pid, module_name=module, pattern=sval)
    ```

    """
@overload
def module_aob_scan(application_name: str, module_name: str = None, pattern: pattern_type = None, mask: str  = None, offset: typing.SupportsInt = 0, result_instance: typing.SupportsInt = 0, flip_endian: bool = False, hex_string: bool = False) -> int:
    """"""
@overload
def get_modules(pid: typing.SupportsInt) -> list[str]:
    """Returns a list of modules for the given process"""
@overload
def get_modules(application_name: str) -> list[str]:
    """"""
def get_pid(application_name: str) -> int:
    """Returns the pid for the given process"""
def get_pids() -> list[int]:
    """Returns a list of pids for all running processes"""
def get_process_name(pid: typing.SupportsInt) -> str:
    """Returns the name of the process, the value will be empty if it is restricted by Windows"""
def get_process_names() -> list[str]:
    """Returns a list of names for all running processes, restricted processes are excluded"""
@overload
def heap_aob_scan(pid: typing.SupportsInt, pattern: pattern_type = None, mask: str  = None, offset: typing.SupportsInt = 0, result_instance: typing.SupportsInt = 0, flip_endian: bool = False, hex_string: bool = False) -> int:
    """
    Scans the heap of the process for the given pattern.\n
    Can take an optional 'mask', with ? as a wildcard and x as a required byte\n
    'offset' is added to the result and 'result_instance' is the n+1 instance of the pattern\n
    'flip_endian' will flip the pattern if used, 'hex_string' should be set to True if the pattern is a string of bytes\n
    
    ```python
    addr = heap_aob_scan(pid=pid, pattern="AA BB CC", mask="x?x", hex_string=True)
    addr2 = heap_aob_scan(application_name=name, pattern="Hello, World")
    sval = pack_int(val=522, big_endian=False)
    addr3 = heap_aob_scan(pid=pid, pattern=sval)
    ```

    """
@overload
def heap_aob_scan(application_name: str, pattern: pattern_type = None, mask: str = None, offset: typing.SupportsInt = 0, result_instance: typing.SupportsInt = 0, flip_endian: bool = False, hex_string: bool = False) -> int: ...
@overload
def stack_aob_scan(pid: typing.SupportsInt, pattern: pattern_type = None, mask: str  = None, offset: typing.SupportsInt = 0, result_instance: typing.SupportsInt = 0, flip_endian: bool = False, hex_string: bool = False) -> int:
    """
    Scans the stack of the process for the given pattern.\n
    Can take an optional 'mask', with ? as a wildcard and x as a required byte\n
    'offset' is added to the result and 'result_instance' is the n+1 instance of the pattern\n
    'flip_endian' will flip the pattern if used, 'hex_string' should be set to True if the pattern is a string of bytes\n
    
    ```python
    addr = stack_aob_scan(pid=pid, pattern="AA BB CC", mask="x?x", hex_string=True)
    addr2 = stack_aob_scan(application_name=name, pattern="Hello, World")
    sval = pack_int(val=522, big_endian=False)
    addr3 = stack_aob_scan(pid=pid, pattern=sval)
    ```

    """
@overload
def stack_aob_scan(application_name: str, pattern: pattern_type = None, mask: str  = None, offset: typing.SupportsInt = 0, result_instance: typing.SupportsInt = 0, flip_endian: bool = False, hex_string: bool = False) -> int: ...
@overload
def read_bytes(pid: typing.SupportsInt, memory_address: typing.SupportsInt = None, n: typing.SupportsInt = 1, flip_endian: bool = False) -> list[int]:
    """Returns the n bytes at the given address in a process"""
@overload
def read_bytes(application_name: str, memory_address: typing.SupportsInt = None, n: typing.SupportsInt = 1, flip_endian: bool = False) -> list[int]:
    """"""
@overload
def read_double(pid: typing.SupportsInt, memory_address: typing.SupportsInt = None, n: typing.SupportsInt = 1, big_endian: bool = False) -> float:
    """Returns a double located at a given address in a process"""
@overload
def read_double(application_name: str, memory_address: typing.SupportsInt = None, n: typing.SupportsInt = 1, big_endian: bool = False) -> float:
    """"""
@overload
def read_float(pid: typing.SupportsInt, memory_address: typing.SupportsInt = None, n: typing.SupportsInt = 1, big_endian: bool = False) -> float:
    """Returns a float located at a given address in a process"""
@overload
def read_float(application_name: str, memory_address: typing.SupportsInt = None, n: typing.SupportsInt = 1, big_endian: bool = False) -> float:
    """"""
@overload
def read_int(pid: typing.SupportsInt, memory_address: typing.SupportsInt = None, n: typing.SupportsInt = 1, big_endian: bool = False) -> int:
    """Returns an integer located at a given address in a process"""
@overload
def read_int(application_name: str, memory_address: typing.SupportsInt = None, n: typing.SupportsInt = 1, big_endian: bool = False) -> int:
    """"""
@overload
def read_long(pid: typing.SupportsInt, memory_address: typing.SupportsInt = None, n: typing.SupportsInt = 1, big_endian: bool = False) -> int:
    """Returns a long located at a given address in a process"""
@overload
def read_long(application_name: str, memory_address: typing.SupportsInt = None, n: typing.SupportsInt = 1, big_endian: bool = False) -> int:
    """"""
@overload
def read_longlong(pid: typing.SupportsInt, memory_address: typing.SupportsInt = None, n: typing.SupportsInt = 1, big_endian: bool = False) -> int:
    """Returns a long long located at a given address in a process"""
@overload
def read_longlong(application_name: str, memory_address: typing.SupportsInt = None, n: typing.SupportsInt = 1, big_endian: bool = False) -> int:
    """"""
@overload
def read_short(pid: typing.SupportsInt, memory_address: typing.SupportsInt = None, n: typing.SupportsInt = 1, big_endian: bool = False) -> int:
    """Returns a short located at a given address in a process"""
@overload
def read_short(application_name: str, memory_address: typing.SupportsInt = None, n: typing.SupportsInt = 1, big_endian: bool = False) -> int:
    """"""
@overload
def write_bytes(pid: typing.SupportsInt, memory_address: typing.SupportsInt = None, bytes: pattern_type = None, hex_string: bool = False, flip_endian: bool = False, n: typing.SupportsInt = 1) -> bool:
    """
    Writes a sequence of bytes to a given location in a process, returns true if the operation succeeded.\n
    Example:
    ```python
    writeBytes(pid=pid, memory_address=someAddress, bytes=[0x1])
    # bl = [0x10, 0xFF]
    b1 = "10 FF" # set hex_string=True
    writeBytes(pid=pid, memory_address=someAddress, bytes=bl, hex_string=True)

    ```
    """
@overload
def write_bytes(application_name: str, memory_address: typing.SupportsInt = None, bytes: pattern_type = None, hex_string: bool = False, flip_endian: bool = False, n: typing.SupportsInt = 1) -> bool:
    """"""
@overload
def write_double(pid: typing.SupportsInt, memory_address: typing.SupportsInt = None, val: typing.SupportsFloat = None, big_endian: bool = False, n: typing.SupportsInt = 1) -> bool:
    """Writes a double to a given location in a process, returns true if the operation succeeded."""
@overload
def write_double(application_name: str, memory_address: typing.SupportsInt = None, val: typing.SupportsFloat = None, big_endian: bool = False, n: typing.SupportsInt = 1) -> bool:
    """"""
@overload
def write_float(pid: typing.SupportsInt, memory_address: typing.SupportsInt = None, val: typing.SupportsFloat = None, big_endian: bool = False, n: typing.SupportsInt = 1) -> bool:
    """Writes a float to a given location in a process, returns true if the operation succeeded."""
@overload
def write_float(application_name: str, memory_address: typing.SupportsInt = None, val: typing.SupportsFloat = None, big_endian: bool = False, n: typing.SupportsInt = 1) -> bool:
    """"""
@overload
def write_integer(pid: typing.SupportsInt, memory_address: typing.SupportsInt = None, val: typing.SupportsInt = None, big_endian: bool = False, n: typing.SupportsInt = 1) -> bool:
    """Writes an integer to a given location in a process, returns true if the operation succeeded."""
@overload
def write_integer(application_name: str, memory_address: typing.SupportsInt = None, val: typing.SupportsInt = None, big_endian: bool = False, n: typing.SupportsInt = 1) -> bool:
    """"""
@overload
def write_long(pid: typing.SupportsInt, memory_address: typing.SupportsInt = None, val: typing.SupportsInt = None, big_endian: bool = False, n: typing.SupportsInt = 1) -> bool:
    """Writes a long to a given location in a process, returns true if the operation succeeded."""
@overload
def write_long(application_name: str, memory_address: typing.SupportsInt = None, val: typing.SupportsInt = None, big_endian: bool = False, n: typing.SupportsInt = 1) -> bool:
    """"""
@overload
def write_longlong(pid: typing.SupportsInt, memory_address: typing.SupportsInt = None, val: typing.SupportsInt = None, big_endian: bool = False, n: typing.SupportsInt = 1) -> bool:
    """Writes a long long to a given location in a process, returns true if the operation succeeded."""
@overload
def write_longlong(application_name: str, memory_address: typing.SupportsInt = None, val: typing.SupportsInt = None, big_endian: bool = False, n: typing.SupportsInt = 1) -> bool:
    """"""
@overload
def write_short(pid: typing.SupportsInt, memory_address: typing.SupportsInt = None, val: typing.SupportsInt = None, big_endian: bool = False, n: typing.SupportsInt = 1) -> bool:
    """Writes a short to a given location in a process, returns true if the operation succeeded."""
@overload
def write_short(application_name: str, memory_address: typing.SupportsInt = None, val: typing.SupportsInt = None, big_endian: bool = False, n: typing.SupportsInt = 1) -> bool:
    """"""

def read_ushort(pid: typing.SupportsInt, memory_address: typing.SupportsInt = None, n: typing.SupportsInt = 1, big_endian: bool = False) -> int:
    """Reads an unsigned short from the given location in a process."""

def read_ushort(pid: typing.SupportsInt, memory_address: typing.SupportsInt = None, n: typing.SupportsInt = 1, big_endian: bool = False) -> int:
    """"""

def read_uint(pid: typing.SupportsInt, memory_address: typing.SupportsInt = None, n: typing.SupportsInt = 1, big_endian: bool = False) -> int:
    """Reads an unsigned integer from the given location in a process."""

def read_uint(pid: typing.SupportsInt, memory_address: typing.SupportsInt = None, n: typing.SupportsInt = 1, big_endian: bool = False) -> int:
    """"""

def read_ulong(pid: typing.SupportsInt, memory_address: typing.SupportsInt = None, n: typing.SupportsInt = 1, big_endian: bool = False) -> int:
    """Reads an unsigned long from the given location in a process."""

def read_ulong(pid: typing.SupportsInt, memory_address: typing.SupportsInt = None, n: typing.SupportsInt = 1, big_endian: bool = False) -> int:
    """"""

def read_ulonglong(pid: typing.SupportsInt, memory_address: typing.SupportsInt = None, n: typing.SupportsInt = 1, big_endian: bool = False) -> int:
    """Reads an unsigned long long from the given location in a process."""

def read_ulonglong(pid: typing.SupportsInt, memory_address: typing.SupportsInt = None, n: typing.SupportsInt = 1, big_endian: bool = False) -> int:
    """"""

def write_ushort(pid: typing.SupportsInt, memory_address: typing.SupportsInt = None, val: typing.SupportsInt = None, big_endian: bool = False, n: typing.SupportsInt = 1) -> bool:
    """Writes an unsigned short to a given location in a process, returns true if the operation succeeded."""

def write_ushort(application_name: str, memory_address: typing.SupportsInt = None, val: typing.SupportsInt = None, big_endian: bool = False, n: typing.SupportsInt = 1) -> bool:
    """"""

def write_uint(pid: typing.SupportsInt, memory_address: typing.SupportsInt = None, val: typing.SupportsInt = None, big_endian: bool = False, n: typing.SupportsInt = 1) -> bool:
    """Writes an unsigned integer to a given location in a process, returns true if the operation succeeded."""

def write_uint(application_name: str, memory_address: typing.SupportsInt = None, val: typing.SupportsInt = None, big_endian: bool = False, n: typing.SupportsInt = 1) -> bool:
    """"""

def write_ulong(pid: typing.SupportsInt, memory_address: typing.SupportsInt = None, val: typing.SupportsInt = None, big_endian: bool = False, n: typing.SupportsInt = 1) -> bool:
    """Writes an unsigned long to a given location in a process, returns true if the operation succeeded."""

def write_ulong(application_name: str, memory_address: typing.SupportsInt = None, val: typing.SupportsInt = None, big_endian: bool = False, n: typing.SupportsInt = 1) -> bool:
    """"""

def write_ulonglong(pid: typing.SupportsInt, memory_address: typing.SupportsInt = None, val: typing.SupportsInt = None, big_endian: bool = False, n: typing.SupportsInt = 1) -> bool:
    """Writes an unsigned long long to a given location in a process, returns true if the operation succeeded."""

def write_ulonglong(application_name: str, memory_address: typing.SupportsInt = None, val: typing.SupportsInt = None, big_endian: bool = False, n: typing.SupportsInt = 1) -> bool:
    """"""

def pack_float(val: typing.SupportsFloat, big_endian: bool = False) -> list[int]:
    ...

def pack_double(val: typing.SupportsFloat, big_endian: bool = False) -> list[int]:
    ...

def pack_short(val: typing.SupportsInt, big_endian: bool = False) -> list[int]:
    ...

def pack_int(val: typing.SupportsInt, big_endian: bool = False) -> list[int]:
    ...

def pack_long(val: typing.SupportsInt, big_endian: bool = False) -> list[int]:
    ...

def pack_longlong(val: typing.SupportsInt, big_endian: bool = False) -> list[int]:
    ...

def pack_ushort(val: typing.SupportsInt, big_endian: bool = False) -> list[int]:
    ...

def pack_uint(val: typing.SupportsInt, big_endian: bool = False) -> list[int]:
    ...

def pack_ulong(val: typing.SupportsInt, big_endian: bool = False) -> list[int]:
    ...

def pack_ulonglong(val: typing.SupportsInt, big_endian: bool = False) -> list[int]:
    ...

def unpack_float(val: list[int], big_endian: bool = False) -> float:
    ...

def unpack_double(val: list[int], big_endian: bool = False) -> float:
    ...

def unpack_short(val: list[int], big_endian: bool = False) -> int:
    ...

def unpack_int(val: list[int], big_endian: bool = False) -> int:
    ...

def unpack_long(val: list[int], big_endian: bool = False) -> int:
    ...

def unpack_longlong(val: list[int], big_endian: bool = False) -> int:
    ...

def unpack_ushort(val: list[int], big_endian: bool = False) -> int:
    ...

def unpack_uint(val: list[int], big_endian: bool = False) -> int:
    ...

def unpack_ulong(val: list[int], big_endian: bool = False) -> int:
    ...

def unpack_ulonglong(val: list[int], big_endian: bool = False) -> int:
    ...

class MemoryProxy:
    def __getitem__(self, key: typing.SupportsInt) -> int | float | list[int] | list[float]:
        ...

    def __setitem__(self, key: typing.SupportsInt, val: typing.SupportsInt | typing.SupportsFloat | list[typing.SupportsInt] | list[typing.SupportsFloat]) -> bool:
        ...

class ProcessWrapper:
    """Wraps the process given by either 'pid' or 'application_name'\n
    Allows for reading, writing, and searching memory of the process.\n
    Different datatypes can be accessed through their functions or by using the MemoryProxy variable\n
    The memory proxies allow for accessing memory as a list and using specific data types to interpret bytes.\n

    ```python
    proc = ProcessWrapper(pid=pid)
    rb = proc.read_bytes(memory_address=addr, n=16)
    rb2 = proc[addr:addr + 16] # same as above
    ib = proc.int[addr:addr+4] # will read 4 ints from the process
    proc.int[addr] = 522
    proc[addr] = "FF"

    ```"""
    byte: MemoryProxy
    float: MemoryProxy
    double: MemoryProxy
    int: MemoryProxy
    short: MemoryProxy
    long: MemoryProxy
    longlong: MemoryProxy
    uint: MemoryProxy
    ushort: MemoryProxy
    ulong: MemoryProxy
    ulonglong: MemoryProxy

    @overload
    def __init__(self, pid: typing.SupportsInt, big_endian: bool = False) -> ProcessWrapper:
        ...

    @overload
    def __init__(self, application_name: str, big_endian: bool = False) -> ProcessWrapper:
        ...

    def __enter__(self) -> ProcessWrapper:
        ...

    def __exit__(self) -> None:
        ...

    def __delete__(self) -> None:
        ...

    def __repr__(self) -> str:
        ...

    def __str__(self) -> str:
        ...

    def __bool__(self) -> bool:
        ...

    def __getitem__(self, key) -> list[int]:
        ...

    def __setitem__(self, key, val: pattern_type | typing.SupportsInt) -> bool:
        ...

    def __eq__(self, other) -> bool:
        ...

    def close(self) -> None:
        """Closes the process handle"""

    def set_endian(self, new_endian: Literal["little", "big"] = "little") -> None:
        """Changes the endian-ness of the wrapper"""

    def read_bytes(self, memory_address: typing.SupportsInt = None, n: typing.SupportsInt = 1) -> list[int]:
        """Reads 'n' bytes at the given 'memory_address'"""

    def read_float(self, memory_address: typing.SupportsInt = None, n: typing.SupportsInt = 1) -> float:
        """Reads 'n' floats at the given 'memory_address', returns a list of floats regardless 'n'"""

    def read_double(self, memory_address: typing.SupportsInt = None, n: typing.SupportsInt = 1) -> float:
        """Reads 'n' doubles at the given 'memory_address', returns a list of doubles regardless 'n'"""

    def read_short(self, memory_address: typing.SupportsInt = None, n: typing.SupportsInt = 1) -> int:
        """Reads 'n' shorts at the given 'memory_address', returns a list of shorts regardless 'n'"""

    def read_int(self, memory_address: typing.SupportsInt = None, n: typing.SupportsInt = 1) -> int:
        """Reads 'n' ints at the given 'memory_address', returns a list of ints regardless 'n'"""

    def read_long(self, memory_address: typing.SupportsInt = None, n: typing.SupportsInt = 1) -> int:
        """Reads 'n' longs at the given 'memory_address', returns a list of longs regardless 'n'"""

    def read_longlong(self, memory_address: typing.SupportsInt = None, n: typing.SupportsInt = 1) -> int:
        """Reads 'n' long longs at the given 'memory_address', returns a list of long longs regardless 'n'"""

    def read_uint(self, memory_address: typing.SupportsInt = None, n: typing.SupportsInt = 1) -> int:
        """Reads 'n' unsigned ints at the given 'memory_address', returns a list of unsigned ints regardless 'n'"""

    def read_ushort(self, memory_address: typing.SupportsInt = None, n: typing.SupportsInt = 1) -> int:
        """Reads 'n' unsigned shorts at the given 'memory_address', returns a list of unsigned shorts regardless 'n'"""

    def read_ulong(self, memory_address: typing.SupportsInt = None, n: typing.SupportsInt = 1) -> int:
        """Reads 'n' unsigned longs at the given 'memory_address', returns a list of unsigned longs regardless 'n'"""

    def read_ulonglong(self, memory_address: typing.SupportsInt = None, n: typing.SupportsInt = 1) -> int:
        """Reads 'n' unsigned long longs at the given 'memory_address', returns a list of unsigned long longs regardless 'n'"""

    def write_bytes(self, memory_address: typing.SupportsInt = None, val: pattern_type = None, n: typing.SupportsInt = 1, overwrite_endian: bool = False, hex_string: bool = False) -> bool:
        """writes 'val' at given 'memory_address', if 'n' is greater than 'val' in byte form, then 0's fill in the remaining bytes"""

    def write_float(self, memory_address: typing.SupportsInt = None, val: typing.SupportsFloat = None, n: typing.SupportsInt = 1) -> bool:
        """writes 'val' at given 'memory_address', if 'n' is greater than len(val), then 0's fill the remaining floats"""

    def write_double(self, memory_address: typing.SupportsInt = None, val: typing.SupportsFloat = None, n: typing.SupportsInt = 1) -> bool:
        """writes 'val' at given 'memory_address', if 'n' is greater than len(val), then 0's fill the remaining doubles"""

    def write_short(self, memory_address: typing.SupportsInt = None, val: typing.SupportsInt = None, n: typing.SupportsInt = 1) -> bool:
        """writes 'val' at given 'memory_address', if 'n' is greater than len(val), then 0's fill the remaining shorts"""

    def write_int(self, memory_address: typing.SupportsInt = None, val: typing.SupportsInt = None, n: typing.SupportsInt = 1) -> bool:
        """writes 'val' at given 'memory_address', if 'n' is greater than len(val), then 0's fill the remaining ints"""

    def write_long(self, memory_address: typing.SupportsInt = None, val: typing.SupportsInt = None, n: typing.SupportsInt = 1) -> bool:
        """writes 'val' at given 'memory_address', if 'n' is greater than len(val), then 0's fill the remaining long"""

    def write_longlong(self, memory_address: typing.SupportsInt = None, val: typing.SupportsInt = None, n: typing.SupportsInt = 1) -> bool:
        """writes 'val' at given 'memory_address', if 'n' is greater than len(val), then 0's fill the remaining long longs"""

    def write_uint(self, memory_address: typing.SupportsInt = None, val: typing.SupportsInt = None, n: typing.SupportsInt = 1) -> bool:
        """writes 'val' at given 'memory_address', if 'n' is greater than len(val), then 0's fill the remaining unsigned ints"""

    def write_ushort(self, memory_address: typing.SupportsInt = None, val: typing.SupportsInt = None, n: typing.SupportsInt = 1) -> bool:
        """writes 'val' at given 'memory_address', if 'n' is greater than len(val), then 0's fill the remaining unsigned shorts"""

    def write_ulong(self, memory_address: typing.SupportsInt = None, val: typing.SupportsInt = None, n: typing.SupportsInt = 1) -> bool:
        """writes 'val' at given 'memory_address', if 'n' is greater than len(val), then 0's fill the remaining unsigned longs"""

    def write_ulonglong(self, memory_address: typing.SupportsInt = None, val: typing.SupportsInt = None, n: typing.SupportsInt = 1) -> bool:
        """writes 'val' at given 'memory_address', if 'n' is greater than len(val), then 0's fill the remaining unsigned long longs"""

    def module_aob_scan(self, module_name: str = None, pattern: pattern_type = None, mask: str = None, offset: typing.SupportsInt = 0, result_instance: typing.SupportsInt = 0, flip_endian: bool = False, hex_string: bool = False):
        """Scans the given module of the process for the given pattern.\n
        Can take an optional 'mask', with ? as a wildcard and x as a required byte\n
        'offset' is added to the result and 'result_instance' is the n+1 instance of the pattern\n
        'flip_endian' will flip the pattern if used, 'hex_string' should be set to True if the pattern is a string of bytes\n
        
        ```python
        proc = ProcessWrapper(pid=pid) # can use an application name as well
        module = proc.get_modules()[0]
        addr = proc.module_aob_scan(module_name=module, pattern="AA BB CC", mask="x?x", hex_string=True) # ? is a wildcard
        addr2 = proc.module_aob_scan(module_name=module, pattern="Hello, World") # 'mask' will default to no wildcards
        sval = pack_int(val=522, big_endian=False) # 'big_endian' is False by default
        addr3 = proc.module_aob_scan(module_name=module, pattern=sval)
        ```

        """

    def stack_aob_scan(self, pattern: pattern_type = None, mask: str = None, offset: typing.SupportsInt = 0, result_instance: typing.SupportsInt = 0, flip_endian: bool = False, hex_string: bool = False):
        """Scans the stack of the process for the given pattern.\n
        Can take an optional 'mask', with ? as a wildcard and x as a required byte\n
        'offset' is added to the result and 'result_instance' is the n+1 instance of the pattern\n
        'flip_endian' will flip the pattern if used, 'hex_string' should be set to True if the pattern is a string of bytes\n
        
        ```python
        proc = ProcessWrapper(pid=pid) # can use an application name as well
        addr = proc.stack_aob_scan(pattern="AA BB CC", mask="x?x", hex_string=True) # ? is a wildcard
        addr2 = proc.stack_aob_scan(pattern="Hello, World") # 'mask' will default to no wildcards
        sval = pack_int(val=522, big_endian=False) # 'big_endian' is False by default
        addr3 = proc.stack_aob_scan(pattern=sval)
        ```

        """

    def heap_aob_scan(self, pattern: pattern_type = None, mask: str = None, offset: typing.SupportsInt = 0, result_instance: typing.SupportsInt = 0, flip_endian: bool = False, hex_string: bool = False):
        """Scans the heap of the process for the given pattern.\n
        Can take an optional 'mask', with ? as a wildcard and x as a required byte\n
        'offset' is added to the result and 'result_instance' is the n+1 instance of the pattern\n
        'flip_endian' will flip the pattern if used, 'hex_string' should be set to True if the pattern is a string of bytes\n
        
        ```python
        proc = ProcessWrapper(pid=pid) # can use an application name as well
        addr = proc.heap_aob_scan(pattern="AA BB CC", mask="x?x", hex_string=True)
        addr2 = proc.heap_aob_scan(pattern="Hello, World")
        sval = pack_int(val=522, big_endian=False)
        addr3 = proc.heap_aob_scan(pattern=sval)
        ```

        """

    def get_pid(self) -> int:
        """Returns the pid of the process"""

    def get_application_name(self) -> str:
        """Returns the name of the process"""

    def get_modules(self) -> list[str]:
        """Returns the modules of the process"""