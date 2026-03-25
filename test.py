import struct
import PyMym as pm
import ctypes
import os
import subprocess
import time

if __name__ == "__main__":
    d_test = ctypes.c_double(12.3)
    print(pm.readDouble(pid=os.getpid(), memory_address=ctypes.addressof(d_test), big_endian=True))
    print(b"some_string"[1])

#__create_byte_pattern(pattern, hex_string, big_endian=False)
    print(type([0, 1, 2, 3, 4, 5]))
    print(pm.__create_byte_pattern([0, 1, 2, 3, 4, 5]))
    print(pm.__create_byte_pattern([0, 1, 2, 3, 4, 5], flip_endian=True))
    print(pm.__create_byte_pattern(bytes([0, 1, 2, 3, 4, 5])))
    print(pm.__create_byte_pattern(bytes([0, 1, 2, 3, 4, 5]), flip_endian=True))
    print(pm.__create_byte_pattern("Hello!"))
    print(pm.__create_byte_pattern("Hello!", flip_endian=True))
    print(pm.__create_byte_pattern("2A 1D D1", hex_string=True))
    print(pm.__create_byte_pattern("2A 1D D1", hex_string=True, flip_endian=True))

    pm.writeDouble(pid=os.getpid(), memory_address=ctypes.addressof(d_test), val=12.5)
    print(d_test.value)

    proc = subprocess.Popen(["./tests/c_test.exe"])
    time.sleep(2)

    pid = proc.pid
    pattern = "DE AD B3 3F FE ED CA FE"
    #pattern = "fe ca ed fe 3f b3 ad de"
    address = pm.stackAOBScan(pid=pid, pattern=pattern, hex_string=True, flip_endian=True)
    read_bytes = pm.readBytes(pid=pid, memory_address=address, num_bytes=len(pattern))

    print(read_bytes)
    print(address)