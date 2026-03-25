from typing import List
import typing
from typing import overload

__pattern_type = typing.Union[
    str, 
    bytes, 
    List[typing.SupportsInt]
]

@overload
def moduleAOBScan(pid: typing.SupportsInt, module_name: str, pattern: __pattern_type, mask: str  = None, offset: typing.SupportsInt = 0, result_instance: typing.SupportsInt = 0, flip_endian: bool = False, hex_string: bool = False) -> int:
    """
    Takes a byte pattern and mask, which is used to search within the memory space of the given module.\n
    The byte pattern should be an array of bytes, a string, or a hexadecimal string, where each entry is a singular byte. If using a hex string, set hex_string=True\n
    The mask should be a string of n characters, where n is the number of bytes of the pattern we are searching for.\n
    Each character in the mask can either be x or ?, where the ? can be a random value.\n
    Offset is a memory offset that is to be applied after the pattern's location is found, this is 0 by default.\n
    The result_instance argument is used to return the n + 1 instance of the pattern, this is 0 by default which will return the first instance of the pattern.\n
    The return value is the address of the pattern within memory or 0 if the pattern is not found.\n\n

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
def moduleAOBScan(application_name: str, module_name: str, pattern: __pattern_type, mask: str  = None, offset: typing.SupportsInt = 0, result_instance: typing.SupportsInt = 0, flip_endian: bool = False, hex_string: bool = False) -> int:
    """"""
@overload
def getModules(pid: typing.SupportsInt) -> list[str]:
    """Returns a list of modules for the given process"""
@overload
def getModules(application_name: str) -> list[str]:
    """"""
def getPID(application_name: str) -> int:
    """Returns the pid for the given process"""
def getPIDs() -> list[int]:
    """Returns a list of pids for all running processes"""
def getProcessName(pid: typing.SupportsInt) -> str:
    """Returns the name of the process, the value will be empty if it is restricted by Windows"""
def getProcessNames() -> list[str]:
    """Returns a list of names for all running processes, restricted processes are excluded"""
@overload
def heapAOBScan(pid: typing.SupportsInt, pattern: __pattern_type, mask: str  = None, offset: typing.SupportsInt = 0, result_instance: typing.SupportsInt = 0, flip_endian: bool = False, hex_string: bool = False) -> int:
    """
    Returns the address of the given sequence of bytes within the heap.\n
    The byte pattern should be an array of bytes, where each entry is a singular byte.\n
    The pattern should be a string of n characters, where n is the number of bytes of the pattern we are searching for.\n
    Each character in the pattern can either be x or ?, where the ? can be a random value.\n
    Offset is a memory offset that is to be applied after the pattern's location is found, set this to 0 if it is not needed.\n
    The result_instance argument is used to find the n + 1 instance of the pattern, so 0 will return the first instance.\n
    The return value is the address of the pattern within memory or 0 if the pattern is not found.\n\n

    Example of argumets for a pattern search:\n
    ```python
    byte_pattern = [0x48, 0x8B, 0x00, 0x48]
    mask = "xx?x"
    offset = 3

    ```
    """
@overload
def heapAOBScan(application_name: str, pattern: __pattern_type, mask: str = None, offset: typing.SupportsInt = 0, result_instance: typing.SupportsInt = 0, flip_endian: bool = False, hex_string: bool = False) -> int: ...
@overload
def stackAOBScan(pid: typing.SupportsInt, pattern: __pattern_type, mask: str  = None, offset: typing.SupportsInt = 0, result_instance: typing.SupportsInt = 0, flip_endian: bool = False, hex_string: bool = False) -> int:
    """
    Returns the address of the given sequence of bytes in the stack.\n
    The byte pattern should be an array of bytes, where each entry is a singular byte.\n
    The pattern should be a string of n characters, where n is the number of bytes of the pattern we are searching for.\n
    Each character in the pattern can either be x or ?, where the ? can be a random value.\n
    Offset is a memory offset that is to be applied after the pattern's location is found, set this to 0 if it is not needed.\n
    The result_instance argument is used to find the n + 1 instance of the pattern, so 0 will return the first instance.\n
    The return value is the address of the pattern within memory or 0 if the pattern is not found.\n\n

    Example of argumets for a pattern search:\n
    ```python
    byte_pattern = [0x48, 0x8B, 0x00, 0x48]
    mask = "xx?x"
    offset = 3

    ```
    """
@overload
def stackAOBScan(application_name: str, pattern: __pattern_type, mask: str  = None, offset: typing.SupportsInt = 0, result_instance: typing.SupportsInt = 0, flip_endian: bool = False, hex_string: bool = False) -> int: ...
@overload
def readBytes(pid: typing.SupportsInt, memory_address: typing.SupportsInt, num_bytes: typing.SupportsInt, big_endian: bool = False) -> list[int]:
    """Returns the n bytes at the given address in a process"""
@overload
def readBytes(application_name: str, memory_address: typing.SupportsInt, num_bytes: typing.SupportsInt, big_endian: bool = False) -> list[int]:
    """"""
@overload
def readDouble(pid: typing.SupportsInt, memory_address: typing.SupportsInt, big_endian: bool = False) -> float:
    """Returns a double located at a given address in a process"""
@overload
def readDouble(application_name: str, memory_address: typing.SupportsInt, big_endian: bool = False) -> float:
    """"""
@overload
def readFloat(pid: typing.SupportsInt, memory_address: typing.SupportsInt, big_endian: bool = False) -> float:
    """Returns a float located at a given address in a process"""
@overload
def readFloat(application_name: str, memory_address: typing.SupportsInt, big_endian: bool = False) -> float:
    """"""
@overload
def readInteger(pid: typing.SupportsInt, memory_address: typing.SupportsInt, big_endian: bool = False) -> int:
    """Returns an integer located at a given address in a process"""
@overload
def readInteger(application_name: str, memory_address: typing.SupportsInt, big_endian: bool = False) -> int:
    """"""
@overload
def readLong(pid: typing.SupportsInt, memory_address: typing.SupportsInt, big_endian: bool = False) -> int:
    """Returns a long located at a given address in a process"""
@overload
def readLong(application_name: str, memory_address: typing.SupportsInt, big_endian: bool = False) -> int:
    """"""
@overload
def readLongLong(pid: typing.SupportsInt, memory_address: typing.SupportsInt, big_endian: bool = False) -> int:
    """Returns a long long located at a given address in a process"""
@overload
def readLongLong(application_name: str, memory_address: typing.SupportsInt, big_endian: bool = False) -> int:
    """"""
@overload
def readShort(pid: typing.SupportsInt, memory_address: typing.SupportsInt, big_endian: bool = False) -> int:
    """Returns a short located at a given address in a process"""
@overload
def readShort(application_name: str, memory_address: typing.SupportsInt, big_endian: bool = False) -> int:
    """"""
@overload
def writeBytes(pid: typing.SupportsInt, memory_address: typing.SupportsInt, bytes: __pattern_type, hex_string: bool = False, big_endian: bool = False) -> bool:
    """
    Writes a sequence of bytes to a given location in a process, returns true if the operation succeeded.\n
    Example:
    ```python
    writeBytes(pid, someAddress, 1, [0x1])
    bl = [0x10, 0xFF]
    writeBytes(pid, someAddress, 2, bl)

    ```
    """
@overload
def writeBytes(application_name: str, memory_address: typing.SupportsInt, bytes: __pattern_type, hex_string: bool = False, big_endian: bool = False) -> bool:
    """"""
@overload
def writeDouble(pid: typing.SupportsInt, memory_address: typing.SupportsInt, val: typing.SupportsFloat, big_endian: bool = False) -> bool:
    """Writes a double to a given location in a process, returns true if the operation succeeded."""
@overload
def writeDouble(application_name: str, memory_address: typing.SupportsInt, val: typing.SupportsFloat, big_endian: bool = False) -> bool:
    """"""
@overload
def writeFloat(pid: typing.SupportsInt, memory_address: typing.SupportsInt, val: typing.SupportsFloat, big_endian: bool = False) -> bool:
    """Writes a float to a given location in a process, returns true if the operation succeeded."""
@overload
def writeFloat(application_name: str, memory_address: typing.SupportsInt, val: typing.SupportsFloat, big_endian: bool = False) -> bool:
    """"""
@overload
def writeInteger(pid: typing.SupportsInt, memory_address: typing.SupportsInt, val: typing.SupportsInt, big_endian: bool = False) -> bool:
    """Writes an integer to a given location in a process, returns true if the operation succeeded."""
@overload
def writeInteger(application_name: str, memory_address: typing.SupportsInt, val: typing.SupportsInt, big_endian: bool = False) -> bool:
    """"""
@overload
def writeLong(pid: typing.SupportsInt, memory_address: typing.SupportsInt, val: typing.SupportsInt, big_endian: bool = False) -> bool:
    """Writes a long to a given location in a process, returns true if the operation succeeded."""
@overload
def writeLong(application_name: str, memory_address: typing.SupportsInt, val: typing.SupportsInt, big_endian: bool = False) -> bool:
    """"""
@overload
def writeLongLong(pid: typing.SupportsInt, memory_address: typing.SupportsInt, val: typing.SupportsInt, big_endian: bool = False) -> bool:
    """Writes a long long to a given location in a process, returns true if the operation succeeded."""
@overload
def writeLongLong(application_name: str, memory_address: typing.SupportsInt, val: typing.SupportsInt, big_endian: bool = False) -> bool:
    """"""
@overload
def writeShort(pid: typing.SupportsInt, memory_address: typing.SupportsInt, val: typing.SupportsInt, big_endian: bool = False) -> bool:
    """Writes a short to a given location in a process, returns true if the operation succeeded."""
@overload
def writeShort(application_name: str, memory_address: typing.SupportsInt, val: typing.SupportsInt, big_endian: bool = False) -> bool:
    """"""

def readUnsignedShort(pid: typing.SupportsInt, memory_address: typing.SupportsInt, big_endian: bool = False) -> int:
    """"""

def readUnsignedShort(pid: typing.SupportsInt, memory_address: typing.SupportsInt, big_endian: bool = False) -> int:
    """"""

def readUnsignedInteger(pid: typing.SupportsInt, memory_address: typing.SupportsInt, big_endian: bool = False) -> int:
    """"""

def readUnsignedInteger(pid: typing.SupportsInt, memory_address: typing.SupportsInt, big_endian: bool = False) -> int:
    """"""

def readUnsignedLong(pid: typing.SupportsInt, memory_address: typing.SupportsInt, big_endian: bool = False) -> int:
    """"""

def readUnsignedLong(pid: typing.SupportsInt, memory_address: typing.SupportsInt, big_endian: bool = False) -> int:
    """"""

def readUnsignedLongLong(pid: typing.SupportsInt, memory_address: typing.SupportsInt, big_endian: bool = False) -> int:
    """"""

def readUnsignedLongLong(pid: typing.SupportsInt, memory_address: typing.SupportsInt, big_endian: bool = False) -> int:
    """"""

def writeUnsignedShort(pid: typing.SupportsInt, memory_address: typing.SupportsInt, val: typing.SupportsInt, big_endian: bool = False) -> bool:
    """"""

def writeUnsignedShort(application_name: str, memory_address: typing.SupportsInt, val: typing.SupportsInt, big_endian: bool = False) -> bool:
    """"""

def writeUnsignedInteger(pid: typing.SupportsInt, memory_address: typing.SupportsInt, val: typing.SupportsInt, big_endian: bool = False) -> bool:
    """"""

def writeUnsignedInteger(application_name: str, memory_address: typing.SupportsInt, val: typing.SupportsInt, big_endian: bool = False) -> bool:
    """"""

def writeUnsignedLong(pid: typing.SupportsInt, memory_address: typing.SupportsInt, val: typing.SupportsInt, big_endian: bool = False) -> bool:
    """"""

def writeUnsignedLong(application_name: str, memory_address: typing.SupportsInt, val: typing.SupportsInt, big_endian: bool = False) -> bool:
    """"""

def writeUnsignedLongLong(pid: typing.SupportsInt, memory_address: typing.SupportsInt, val: typing.SupportsInt, big_endian: bool = False) -> bool:
    """"""

def writeUnsignedLongLong(application_name: str, memory_address: typing.SupportsInt, val: typing.SupportsInt, big_endian: bool = False) -> bool:
    """"""