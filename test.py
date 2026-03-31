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

    proc = subprocess.Popen(["./tests/c_test.exe"], stdout=subprocess.PIPE)
    time.sleep(2)

    try:
        print(pm.__hexstring("ABCDEF"))
    except:
        assert True
    print(pm.__hexstring("AB CD EF"))
    #print(pm.__hexstring("ABCDE"))
    print(pm.__hexstring("AB"))
    #print(pm.__hexstring("A"))
    #print(pm.__hexstring("ABCDEFXX"))
    #print(pm.__hexstring("AB CD EF XX"))

    pid = proc.pid
    application_name = "cpp_compilation.exe"
    pattern = "DE AD B3 3F FE ED CA FE"
    #pattern = "fe ca ed fe 3f b3 ad de"
    address = pm.stackAOBScan(pid=pid, pattern=pattern, hex_string=True, flip_endian=True)
    read_bytes = pm.readBytes(pid=pid, memory_address=address, num_bytes=len(pattern))
    print(read_bytes)
    print(hex(address))

    pattern = "FE ED CA FE DE AD B3 3F"

    addr = pm.heapAOBScan(pid=pid, pattern=pattern, hex_string=True, flip_endian=True)
    rb = pm.readBytes(pid=pid, memory_address=addr, num_bytes=len(pattern))

    print(rb)
    print(hex(addr))

    pat = "This string should be on the stack. Hopefully"
    pat2 = "This string should be on the heap. Hopefully"
    #print(pm.__create_byte_pattern(pat))
    #print([hex(x) for x in pm.__create_byte_pattern(pat)])
    address = pm.stackAOBScan(pid=pid, pattern=pat, flip_endian=False)
    read_bytes = pm.readBytes(pid=pid, memory_address=address, num_bytes=len(pat))
    print(str(bytes(read_bytes)))
    print(hex(address))

    address = pm.heapAOBScan(pid=pid, pattern=pat2, flip_endian=False)
    read_bytes = pm.readBytes(pid=pid, memory_address=address, num_bytes=len(pat2))
    print(str(bytes(read_bytes)))
    print(hex(address))

    print(ctypes.c_int32(100000000000000000).value)

    c = ctypes.c_short(10)
    print(type(c))

    match type(c):
        case ctypes.c_long:
            print("LONG")
        case _:
            print("FALL THROUGH")