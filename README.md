<div align="center">

# PyWin-Memr

[![GitHub License](https://img.shields.io/github/license/JSilvestrini/PyMym?style=plastic&color=darkred)](https://github.com/JSilvestrini/PyMym?tab=MIT-1-ov-file)
![Build Status](https://github.com/Jsilvestrini/PyMym/actions/workflows/dev.yml/badge.svg)
[![PyPI version](https://img.shields.io/pypi/v/PyMym.svg)](https://pypi.org/project/PyMym/)
[![Supported Versions](https://img.shields.io/pypi/pyversions/PyMym.svg)](https://pypi.org/project/PyMym/)
![OS](https://img.shields.io/badge/OS-windows-0078D4)
[![GitHub repo size](https://img.shields.io/github/repo-size/JSilvestrini/PyMym?style=plastic)](https://github.com/JSilvestrini/PyMym)

</div>
PyMym is a Python memory manipulation library that allows quick and easy memory manipulation using Python and C++ on Windows machines. While initially it was created to allow a Gymnasium environment to directly access state information from a process, it slowly became a full-fledged library with memory scanning and manipulation features, including a lightweight process wrapper for accessing memory in a Pythonic way.

<br>

## Table of Contents

- [Features](#features)
- [How to Use](#how-to-use)
    - [Memory Scanning](#memory-scanning)
    - [Memory Reading and Manipulation](#memory-reading-and-manipulation)
    - [Packing and Unpacking of Data](#packing-and-unpacking-of-data)
    - [Pythonic Process Wrapping](#pythonic-process-wrapping)
- [Roadmap](#roadmap)
- [Contribution](#contribution)
- [License](#license)

<br>

## Features

- **C++ Core Performance**: Native execution for memory-intensive operations, bypassing the overhead of traditional Python wrappers.
- **Pattern Matching**: High-speed Array of Bytes scanning to find stable hooks in frequently updating applications.
- **Zero-Config Installation**: Pre-compiled binary wheels for Windows mean no local compiler is required for most users.
    <!-- - **Memory-Safe Design**: Managed C++ backend handles pointer validation to prevent Python interpreter crashes during invalid reads. Need to do more checks before this can be claimed :( -->
- **Flexibility**: Simple Pythonic process wrapping for seamless memory manipulation or stand-alone memory manipulation without needing to use a class

## How to Use

### Memory Scanning

```python
import PyMym as pm

name = "some_application.exe"
pid = pm.get_pid(name)

# different pattern types for convenience
hex_pattern = "AA 00 AB AC 00 FF FF"
string_pattern = "Hello, world!"
list_pattern = pattern = [0x00, 0xAA, 0xAB, 0x00, 0xFF, 0xB3]
hex_mask = "x?xx?xx"
list_mask = "?xx?xx"

# pid or application_name can be used
address = pm.heap_aob_scan(
    pid=pid,
    pattern=hex_pattern,
    mask=hex_mask,
    hex_string=True
)

# masks are optional
address = pm.stack_aob_scan(
    application_name=name,
    pattern=string_pattern
)

mods = pm.get_modules(application_name=name)
address = pm.module_aob_scan(
    pid=pid,
    module_name=mods[0],
    pattern=list_pattern,
    mask=list_mask
)
```

### Memory Reading and Manipulation

PyMym offers reading and writing functions that align with C data types using the ctypes library, the current supported types are listed below with their respective functions.

<div align="center">

| Data Type          | Read Function  | Write Function  | C++ Equivalent     |
| ------------------ | -------------- | --------------- | ------------------ |
| Bytes              | read_bytes     | write_bytes     | unsigned char[]    |
| Short              | read_short     | write_short     | short              |
| Unsigned Short     | read_ushort    | write_ushort    | unsigned short     |
| Int                | read_int       | write_int       | int                |
| Unsigned Int       | read_uint      | write_uint      | unsigned int       |
| Long               | read_long      | write_long      | long               |
| Unsigned Long      | read_ulong     | write_ulong     | unsigned long      |
| Long Long          | read_longlong  | write_longlong  | long long          |
| Unsigned Long Long | read_ulonglong | write_ulonglong | unsigned long long |
| Float              | read_float     | write_float     | float              |
| Double             | read_double    | write_double    | double             |

</div>

#### Examples

```python
import PyMym as pm

## READING EXAMPLES
# All the following can be used with pid= or application_name=
name = "some_application.exe"
pid = pm.get_pid(name)
mem_addr = 0xFF00 # Example address

# Read functions can return singular values
byte_val = pm.read_bytes(application_name=name, memory_address=mem_addr)
short_val = pm.read_short(application_name=name, memory_address=mem_addr)

# Read functions can take an optional n parameter to return a list of n items
byte_list = pm.read_bytes(pid=pid, memory_address=mem_addr, n=16)
short_list = pm.read_short(pid=pid, memory_address=mem_addr, n=5)

## WRITING EXAMPLES
btw = "AF BE 3D DD"
# write_bytes returns True if all bytes were written, False otherwise
if not pm.write_bytes(pid=pid, memory_address=mem_addr, val=btw, hex_string=True):
    return -1

# write_bytes can take same types as the searches can
btw = "Hello, world!"
pm.write_bytes(application_name=name, memory_address=mem_addr, val=btw)

# Optional n parameter will fill extra unwritten bytes with 0x00
# So n - len(btw) bytes will be 0x00
pm.write_bytes(application_name=name, memory_address=mem_addr, val=btw, n=16)

# All write functions can take lists as well as singular values
pm.write_short(pid=pid, memory_address=mem_addr, val=[125, 126, 127])
# All write functions have the optional parameter n
# Which will write n - len(val) 0s to memory, matching the data type used
pm.write_short(pid=pid, memory_address=mem_addr, val=155, n=2)
```

### Packing and Unpacking of Data

PyMym has functions for packing and unpacking data types into bytes and vice versa, with the same data type support as the read and write functions.

```python
import PyMym as pm
import ctypes

# values can be packed into bytes for use with search functions
name = "some_application.exe"
pid = pm.get_pid(name)

val = 101
pval = pm.pack_int(val=val)

addr = pm.heap_aob_scan(pid=pid, pattern=pval)
# read functions will automatically unpack for you
ri = pm.read_int(application_name=name, memory_address=addr)
# but read bytes can be used instead to keep values as bytes
rb = pm.read_bytes(
    application_name=name,
    memory_address=addr,
    n=ctypes.sizeof(ctypes.c_int)
)

ui = pm.unpack_int(rb)
```

### Pythonic Process Wrapping

The ProcessWrapper class contains methods that allow for scanning and memory manipulation, like the stand-alone functions did, and allows for shorter argument lists. Besides the original read and write methods, there is also indexing and slicing specific data types to allow Pythonic access to memory.

<div align="center">

| Data Type          | Accessor                | C++ Equivalent     |
| ------------------ | ----------------------- | ------------------ |
| Bytes              | pw[start:end]           | unsigned char[]    |
| Short              | pw.short[start:end]     | short              |
| Unsigned Short     | pw.ushort[start:end]    | unsigned short     |
| Int                | pw.int[start:end]       | int                |
| Unsigned Int       | pw.uint[start:end]      | unsigned int       |
| Long               | pw.long[start:end]      | long               |
| Unsigned Long      | pw.ulong[start:end]     | unsigned long      |
| Long Long          | pw.longlong[start:end]  | long long          |
| Unsigned Long Long | pw.ulonglong[start:end] | unsigned long long |
| Float              | pw.float[start:end]     | float              |
| Double             | pw.double[start:end]    | double             |

</div>

```python
import PyMym as pm

name = "some_application.exe"
pid = pm.get_pid(name)

# We can use pid=pid or application_name=name here
with ProcessWrapper(application_name=name) as pw:
    addr = pw.heap_aob_scan(pattern=pval)
    rb = pw.read_bytes(memory_address=addr, n=16)

    # Alternative, quick and Pythonic
    rb = pw[addr: addr + 16]

    # The same goes for other data types
    # Here we read 2 integers
    ri = pw.read_int(memory_address=addr, n=2)
    ri = pw.int[addr: addr + 2]

    # We can also write in a similar fashion
    pw.int[addr] = 500
    # Same goes for multiple values at once
    # Here we are writing 4 integers
    pw.int[addr: addr + 4] = [400, 500, 200, 100]

    # We can retrieve basic information about the process
    pid = pw.get_pid()
    name = pw.get_application_name()
    modules = pw.get_modules()
    endian = pw.get_endian()

    # We can also change the way we interpret the values
    if endian == "little":
        pw.set_endian(new_endian="big")
    else:
        pw.set_endian(new_endian="little")
```

## Roadmap

- Refactoring of backend C++ code
- Wide character and UTF-16 support
- Get addresses of specific modules
- Get main thread ID as well as a list of thread IDs
- More data types, char, uchar, int32, int16, etc.
- Stronger exception and error handling
- ProcessWrapper.get_base_module and .get_address
- Stronger testing for dev branch
- Searching for list of instances rather than the first instance
- Strict and loose name search for modules and processes

## Contribution

Feel free to suggest improvements or report issues in the repository.

## License

This project is open-source and available under the MIT License.
