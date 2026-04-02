import typing
from typing import overload, List, Literal
import ctypes

PATTERN_TYPE = typing.Union[
    str, 
    bytes, 
    List[typing.SupportsInt]
]

ALLOWED_DATA_TYPES = Literal[
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
def module_aob_scan(pid: typing.SupportsInt, module_name: str, pattern: PATTERN_TYPE, mask: str  = None, offset: typing.SupportsInt = 0, result_instance: typing.SupportsInt = 0, flip_endian: bool = False, hex_string: bool = False) -> int:
    """
    Searches memory within the given module of a process.\n
    Takes a byte pattern and returns the location in memory of the byte pattern if found, otherwise 0.\n
    Takes an optional mask, offset, result instance, and two booleans for hex string and flip endian. The mask is a string that is the same length as the byte pattern
    'x' is an exact match and '?' is a wildcard.\n
    Offset will add the number of bytes to the final result. Instance is the n + 1 instance of the pattern, so 0 is the first instance and 1 is the second.\n\n

    Example of argumets for a pattern search:\n
    ```python
    byte_pattern = [0x48, 0x8B, 0x00, 0x48]
    byte_pattern = "48 8b 00 48" # set hex_string=True
    byte_pattern = b"SCAN" # keep hex_string=False (default)
    mask = "xx?x"
    offset = 3

    ```
    """
@overload
def module_aob_scan(application_name: str, module_name: str, pattern: PATTERN_TYPE, mask: str  = None, offset: typing.SupportsInt = 0, result_instance: typing.SupportsInt = 0, flip_endian: bool = False, hex_string: bool = False) -> int:
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
def heap_aob_scan(pid: typing.SupportsInt, pattern: PATTERN_TYPE, mask: str  = None, offset: typing.SupportsInt = 0, result_instance: typing.SupportsInt = 0, flip_endian: bool = False, hex_string: bool = False) -> int:
    """
    Searches within the heap memory of the given process.\n
    Takes a byte pattern and returns the location in memory of the byte pattern if found, otherwise 0.\n
    Takes an optional mask, offset, result instance, and two booleans for hex string and flip endian. The mask is a string that is the same length as the byte pattern
    'x' is an exact match and '?' is a wildcard.\n
    Offset will add the number of bytes to the final result. Instance is the n + 1 instance of the pattern, so 0 is the first instance and 1 is the second.\n\n

    Example of argumets for a pattern search:\n
    ```python
    byte_pattern = [0x48, 0x8B, 0x00, 0x48]
    byte_pattern = "48 8b 00 48" # set hex_string=True
    byte_pattern = b"SCAN" # keep hex_string=False (default)
    mask = "xx?x"
    offset = 3

    ```
    """
@overload
def heap_aob_scan(application_name: str, pattern: PATTERN_TYPE, mask: str = None, offset: typing.SupportsInt = 0, result_instance: typing.SupportsInt = 0, flip_endian: bool = False, hex_string: bool = False) -> int: ...
@overload
def stack_aob_scan(pid: typing.SupportsInt, pattern: PATTERN_TYPE, mask: str  = None, offset: typing.SupportsInt = 0, result_instance: typing.SupportsInt = 0, flip_endian: bool = False, hex_string: bool = False) -> int:
    """
    Searches within the stack memory of the given process.\n
    Takes a byte pattern and returns the location in memory of the byte pattern if found, otherwise 0.\n
    Takes an optional mask, offset, result instance, and two booleans for hex string and flip endian. The mask is a string that is the same length as the byte pattern
    'x' is an exact match and '?' is a wildcard.\n
    Offset will add the number of bytes to the final result. Instance is the n + 1 instance of the pattern, so 0 is the first instance and 1 is the second.\n\n

    Example of argumets for a pattern search:\n
    ```python
    byte_pattern = [0x48, 0x8B, 0x00, 0x48]
    byte_pattern = "48 8b 00 48" # set hex_string=True
    byte_pattern = b"SCAN" # keep hex_string=False (default)
    mask = "xx?x"
    offset = 3

    ```
    """
@overload
def stack_aob_scan(application_name: str, pattern: PATTERN_TYPE, mask: str  = None, offset: typing.SupportsInt = 0, result_instance: typing.SupportsInt = 0, flip_endian: bool = False, hex_string: bool = False) -> int: ...
@overload
def read_bytes(pid: typing.SupportsInt, memory_address: typing.SupportsInt, n: typing.SupportsInt = 1, flip_endian: bool = False) -> list[int]:
    """Returns the n bytes at the given address in a process"""
@overload
def read_bytes(application_name: str, memory_address: typing.SupportsInt, n: typing.SupportsInt = 1, flip_endian: bool = False) -> list[int]:
    """"""
@overload
def read_double(pid: typing.SupportsInt, memory_address: typing.SupportsInt, n: typing.SupportsInt = 1, big_endian: bool = False) -> float:
    """Returns a double located at a given address in a process"""
@overload
def read_double(application_name: str, memory_address: typing.SupportsInt, n: typing.SupportsInt = 1, big_endian: bool = False) -> float:
    """"""
@overload
def read_float(pid: typing.SupportsInt, memory_address: typing.SupportsInt, n: typing.SupportsInt = 1, big_endian: bool = False) -> float:
    """Returns a float located at a given address in a process"""
@overload
def read_float(application_name: str, memory_address: typing.SupportsInt, n: typing.SupportsInt = 1, big_endian: bool = False) -> float:
    """"""
@overload
def read_int(pid: typing.SupportsInt, memory_address: typing.SupportsInt, n: typing.SupportsInt = 1, big_endian: bool = False) -> int:
    """Returns an integer located at a given address in a process"""
@overload
def read_int(application_name: str, memory_address: typing.SupportsInt, n: typing.SupportsInt = 1, big_endian: bool = False) -> int:
    """"""
@overload
def read_long(pid: typing.SupportsInt, memory_address: typing.SupportsInt, n: typing.SupportsInt = 1, big_endian: bool = False) -> int:
    """Returns a long located at a given address in a process"""
@overload
def read_long(application_name: str, memory_address: typing.SupportsInt, n: typing.SupportsInt = 1, big_endian: bool = False) -> int:
    """"""
@overload
def read_longlong(pid: typing.SupportsInt, memory_address: typing.SupportsInt, n: typing.SupportsInt = 1, big_endian: bool = False) -> int:
    """Returns a long long located at a given address in a process"""
@overload
def read_longlong(application_name: str, memory_address: typing.SupportsInt, n: typing.SupportsInt = 1, big_endian: bool = False) -> int:
    """"""
@overload
def read_short(pid: typing.SupportsInt, memory_address: typing.SupportsInt, n: typing.SupportsInt = 1, big_endian: bool = False) -> int:
    """Returns a short located at a given address in a process"""
@overload
def read_short(application_name: str, memory_address: typing.SupportsInt, n: typing.SupportsInt = 1, big_endian: bool = False) -> int:
    """"""
@overload
def write_bytes(pid: typing.SupportsInt, memory_address: typing.SupportsInt, bytes: PATTERN_TYPE, hex_string: bool = False, flip_endian: bool = False, n: typing.SupportsInt = 1) -> bool:
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
def write_bytes(application_name: str, memory_address: typing.SupportsInt, bytes: PATTERN_TYPE, hex_string: bool = False, flip_endian: bool = False, n: typing.SupportsInt = 1) -> bool:
    """"""
@overload
def write_double(pid: typing.SupportsInt, memory_address: typing.SupportsInt, val: typing.SupportsFloat, big_endian: bool = False) -> bool:
    """Writes a double to a given location in a process, returns true if the operation succeeded."""
@overload
def write_double(application_name: str, memory_address: typing.SupportsInt, val: typing.SupportsFloat, big_endian: bool = False) -> bool:
    """"""
@overload
def write_float(pid: typing.SupportsInt, memory_address: typing.SupportsInt, val: typing.SupportsFloat, big_endian: bool = False) -> bool:
    """Writes a float to a given location in a process, returns true if the operation succeeded."""
@overload
def write_float(application_name: str, memory_address: typing.SupportsInt, val: typing.SupportsFloat, big_endian: bool = False) -> bool:
    """"""
@overload
def write_integer(pid: typing.SupportsInt, memory_address: typing.SupportsInt, val: typing.SupportsInt, big_endian: bool = False) -> bool:
    """Writes an integer to a given location in a process, returns true if the operation succeeded."""
@overload
def write_integer(application_name: str, memory_address: typing.SupportsInt, val: typing.SupportsInt, big_endian: bool = False) -> bool:
    """"""
@overload
def write_long(pid: typing.SupportsInt, memory_address: typing.SupportsInt, val: typing.SupportsInt, big_endian: bool = False) -> bool:
    """Writes a long to a given location in a process, returns true if the operation succeeded."""
@overload
def write_long(application_name: str, memory_address: typing.SupportsInt, val: typing.SupportsInt, big_endian: bool = False) -> bool:
    """"""
@overload
def write_longlong(pid: typing.SupportsInt, memory_address: typing.SupportsInt, val: typing.SupportsInt, big_endian: bool = False) -> bool:
    """Writes a long long to a given location in a process, returns true if the operation succeeded."""
@overload
def write_longlong(application_name: str, memory_address: typing.SupportsInt, val: typing.SupportsInt, big_endian: bool = False) -> bool:
    """"""
@overload
def write_short(pid: typing.SupportsInt, memory_address: typing.SupportsInt, val: typing.SupportsInt, big_endian: bool = False) -> bool:
    """Writes a short to a given location in a process, returns true if the operation succeeded."""
@overload
def write_short(application_name: str, memory_address: typing.SupportsInt, val: typing.SupportsInt, big_endian: bool = False) -> bool:
    """"""

def read_ushort(pid: typing.SupportsInt, memory_address: typing.SupportsInt, n: typing.SupportsInt = 1, big_endian: bool = False) -> int:
    """Reads an unsigned short from the given location in a process."""

def read_ushort(pid: typing.SupportsInt, memory_address: typing.SupportsInt, n: typing.SupportsInt = 1, big_endian: bool = False) -> int:
    """"""

def read_uint(pid: typing.SupportsInt, memory_address: typing.SupportsInt, n: typing.SupportsInt = 1, big_endian: bool = False) -> int:
    """Reads an unsigned integer from the given location in a process."""

def read_uint(pid: typing.SupportsInt, memory_address: typing.SupportsInt, n: typing.SupportsInt = 1, big_endian: bool = False) -> int:
    """"""

def read_ulong(pid: typing.SupportsInt, memory_address: typing.SupportsInt, n: typing.SupportsInt = 1, big_endian: bool = False) -> int:
    """Reads an unsigned long from the given location in a process."""

def read_ulong(pid: typing.SupportsInt, memory_address: typing.SupportsInt, n: typing.SupportsInt = 1, big_endian: bool = False) -> int:
    """"""

def read_ulonglong(pid: typing.SupportsInt, memory_address: typing.SupportsInt, n: typing.SupportsInt = 1, big_endian: bool = False) -> int:
    """Reads an unsigned long long from the given location in a process."""

def read_ulonglong(pid: typing.SupportsInt, memory_address: typing.SupportsInt, n: typing.SupportsInt = 1, big_endian: bool = False) -> int:
    """"""

def write_ushort(pid: typing.SupportsInt, memory_address: typing.SupportsInt, val: typing.SupportsInt, big_endian: bool = False) -> bool:
    """Writes an unsigned short to a given location in a process, returns true if the operation succeeded."""

def write_ushort(application_name: str, memory_address: typing.SupportsInt, val: typing.SupportsInt, big_endian: bool = False) -> bool:
    """"""

def write_uint(pid: typing.SupportsInt, memory_address: typing.SupportsInt, val: typing.SupportsInt, big_endian: bool = False) -> bool:
    """Writes an unsigned integer to a given location in a process, returns true if the operation succeeded."""

def write_uint(application_name: str, memory_address: typing.SupportsInt, val: typing.SupportsInt, big_endian: bool = False) -> bool:
    """"""

def write_ulong(pid: typing.SupportsInt, memory_address: typing.SupportsInt, val: typing.SupportsInt, big_endian: bool = False) -> bool:
    """Writes an unsigned long to a given location in a process, returns true if the operation succeeded."""

def write_ulong(application_name: str, memory_address: typing.SupportsInt, val: typing.SupportsInt, big_endian: bool = False) -> bool:
    """"""

def write_ulonglong(pid: typing.SupportsInt, memory_address: typing.SupportsInt, val: typing.SupportsInt, big_endian: bool = False) -> bool:
    """Writes an unsigned long long to a given location in a process, returns true if the operation succeeded."""

def write_ulonglong(application_name: str, memory_address: typing.SupportsInt, val: typing.SupportsInt, big_endian: bool = False) -> bool:
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

def unpack_float(val: bytes, big_endian: bool = False) -> float:
    ...

def unpack_double(val: bytes, big_endian: bool = False) -> float:
    ...

def unpack_short(val: bytes, big_endian: bool = False) -> int:
    ...

def unpack_int(val: bytes, big_endian: bool = False) -> int:
    ...

def unpack_long(val: bytes, big_endian: bool = False) -> int:
    ...

def unpack_longlong(val: bytes, big_endian: bool = False) -> int:
    ...

def unpack_ushort(val: bytes, big_endian: bool = False) -> int:
    ...

def unpack_uint(val: bytes, big_endian: bool = False) -> int:
    ...

def unpack_ulong(val: bytes, big_endian: bool = False) -> int:
    ...

def unpack_ulonglong(val: bytes, big_endian: bool = False) -> int:
    ...

class MemoryProxy:
    def __getitem__(self, key: typing.SupportsInt) -> int | float | list[int] | list[float]:
        ...

    def __setitem__(self, key: typing.SupportsInt, val: typing.SupportsInt | typing.SupportsFloat) -> bool:
        ...

class ProcessWrapper:
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

    def __setitem__(self, key, val: list[int] | int) -> bool:
        ...

    def __eq__(self, other) -> bool:
        ...

    def close(self) -> None:
        ...

    def set_endian(self, new_endian: Literal["little", "big"] = "little") -> None:
        ...

    def read_datatype(self, addr: typing.SupportsInt, data_type: ALLOWED_DATA_TYPES, n: typing.SupportsInt = 1) -> list[int] | int | float:
        ...

    def write_datatype(self, addr: typing.SupportsInt, data_type: ALLOWED_DATA_TYPES, val: list[int] | int | float, n: typing.SupportsInt = 1) -> bool:
        ...

    def read_bytes(self, addr: typing.SupportsInt = None, n: typing.SupportsInt = 1) -> list[int]:
        ...

    def read_float(self, addr: typing.SupportsInt = None, n: typing.SupportsInt = 1) -> float:
        ...

    def read_double(self, addr: typing.SupportsInt = None, n: typing.SupportsInt = 1) -> float:
        ...

    def read_short(self, addr: typing.SupportsInt = None, n: typing.SupportsInt = 1) -> int:
        ...

    def read_int(self, addr: typing.SupportsInt = None, n: typing.SupportsInt = 1) -> int:
        ...

    def read_long(self, addr: typing.SupportsInt = None, n: typing.SupportsInt = 1) -> int:
        ...

    def read_longlong(self, addr: typing.SupportsInt = None, n: typing.SupportsInt = 1) -> int:
        ...

    def read_uint(self, addr: typing.SupportsInt = None, n: typing.SupportsInt = 1) -> int:
        ...

    def read_ushort(self, addr: typing.SupportsInt = None, n: typing.SupportsInt = 1) -> int:
        ...

    def read_ulong(self, addr: typing.SupportsInt = None, n: typing.SupportsInt = 1) -> int:
        ...

    def read_ulonglong(self, addr: typing.SupportsInt = None, n: typing.SupportsInt = 1) -> int:
        ...

    def write_bytes(self, addr: typing.SupportsInt = None, val: PATTERN_TYPE = None, n: typing.SupportsInt = 1, overwrite_endian: bool = False) -> bool:
        ...

    def write_float(self, addr: typing.SupportsInt = None, val: typing.SupportsFloat = None, n: typing.SupportsInt = 1) -> bool:
        ...

    def write_double(self, addr: typing.SupportsInt = None, val: typing.SupportsFloat = None, n: typing.SupportsInt = 1) -> bool:
        ...

    def write_short(self, addr: typing.SupportsInt = None, val: typing.SupportsInt = None, n: typing.SupportsInt = 1) -> bool:
        ...

    def write_int(self, addr: typing.SupportsInt = None, val: typing.SupportsInt = None, n: typing.SupportsInt = 1) -> bool:
        ...

    def write_long(self, addr: typing.SupportsInt = None, val: typing.SupportsInt = None, n: typing.SupportsInt = 1) -> bool:
        ...

    def write_longlong(self, addr: typing.SupportsInt = None, val: typing.SupportsInt = None, n: typing.SupportsInt = 1) -> bool:
        ...

    def write_uint(self, addr: typing.SupportsInt = None, val: typing.SupportsInt = None, n: typing.SupportsInt = 1) -> bool:
        ...

    def write_ushort(self, addr: typing.SupportsInt = None, val: typing.SupportsInt = None, n: typing.SupportsInt = 1) -> bool:
        ...

    def write_ulong(self, addr: typing.SupportsInt = None, val: typing.SupportsInt = None, n: typing.SupportsInt = 1) -> bool:
        ...

    def write_ulonglong(self, addr: typing.SupportsInt = None, val: typing.SupportsInt = None, n: typing.SupportsInt = 1) -> bool:
        ...

    def module_aob_scan(self, module_name : str = None, pattern: PATTERN_TYPE = None, mask: str = None, offset: typing.SupportsInt = 0, result_instance: typing.SupportsInt = 0, flip_endian: bool = False, hex_string: bool = False):
        ...

    def stack_aob_scan(self, pattern: PATTERN_TYPE = None, mask: str = None, offset: typing.SupportsInt = 0, result_instance: typing.SupportsInt = 0, flip_endian: bool = False, hex_string: bool = False):
        ...

    def heap_aob_scan(self, pattern: PATTERN_TYPE = None, mask: str = None, offset: typing.SupportsInt = 0, result_instance: typing.SupportsInt = 0, flip_endian: bool = False, hex_string: bool = False):
        ...

    def get_pid(self) -> int:
        ...

    def get_application_name(self) -> str:
        ...

    def get_modules(self) -> list[str]:
        ...