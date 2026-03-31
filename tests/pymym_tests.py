#from PyMym import PyMym as pm
import PyMym as pm
import os
import ctypes
import subprocess
import time
import math

def test_get_pid():
    assert pm.getPID("python.exe") == os.getpid()

def test_get_pids():
    assert len(pm.getPIDs()) != 0

def test_get_process_names():
    assert len(pm.getProcessNames()) != 0

def test_get_process_name():
    assert pm.getProcessName(os.getpid()) == "python.exe"

def test_get_modules():
    assert len(pm.getModules(os.getpid())) != 0

def test_aob_scan():
    pid = os.getpid()
    base_string = "This string is within the AOBScan testing function!"
    pattern = [int(hex(ord(x)), 16) for x in base_string]
    address = pm.heapAOBScan(pid=pid, pattern=pattern, result_instance=1)
    read_bytes = pm.readBytes(pid=pid, memory_address=address, num_bytes=len(base_string))

    assert (bytes(read_bytes)) == bytes(base_string, "utf-8")

    proc = subprocess.Popen(["./c_test.exe"], text=True, stdout= subprocess.PIPE)
    time.sleep(2)

    pid = proc.pid
    pattern = "DE AD B3 3F FE ED CA FE"
    address = pm.stackAOBScan(pid=pid, pattern=pattern, hex_string=True, flip_endian=True)
    read_bytes = pm.readBytes(pid=pid, memory_address=address, num_bytes=8)
    assert(read_bytes == pm.__create_byte_pattern(pattern, hex_string=True, flip_endian=True))
    assert(pm.readUnsignedLongLong(pid=pid, memory_address=address) == 0xdeadb33ffeedcafe)

    pattern = "FE ED CA FE DE AD B3 3F"
    address = pm.heapAOBScan(pid=pid, pattern=pattern, hex_string=True, flip_endian=True)
    read_bytes = pm.readBytes(pid=pid, memory_address=address, num_bytes=8)
    assert(read_bytes == pm.__create_byte_pattern(pattern, hex_string=True, flip_endian=True))
    assert(pm.readUnsignedLongLong(pid=pid, memory_address=address) == 0xfeedcafedeadb33f)

    pattern = "This string should be on the stack. Hopefully"
    address = pm.stackAOBScan(pid=pid, pattern=pattern, flip_endian=False)
    read_bytes = pm.readBytes(pid=pid, memory_address=address, num_bytes=len(pattern))
    assert(read_bytes == pm.__create_byte_pattern(pattern))

    pattern = "This string should be on the heap. Hopefully"
    address = pm.heapAOBScan(pid=pid, pattern=pattern, flip_endian=False)
    read_bytes = pm.readBytes(pid=pid, memory_address=address, num_bytes=len(pattern))
    assert(read_bytes == pm.__create_byte_pattern(pattern))

    proc.terminate()

def test_read_write():
    # Read bytes
    pid = os.getpid()
    search_string = ctypes.create_string_buffer(b"This string is within the reading testing function!")
    found_string = bytes(pm.readBytes(pid=pid, memory_address=ctypes.addressof(search_string), num_bytes=ctypes.sizeof(search_string)))
    assert search_string.raw == found_string

    # Write bytes
    new_val = b"This string is within the writing testing function!\x00"
    pm.writeBytes(pid=pid, memory_address=ctypes.addressof(search_string), bytes=new_val)
    assert new_val == search_string.raw

    # Read values
    cshort = ctypes.c_short(256)
    cushort = ctypes.c_ushort(378)
    cint = ctypes.c_int(522)
    cuint = ctypes.c_uint(523)
    clong = ctypes.c_long(190108228)
    culong= ctypes.c_ulong(1190124401)
    clonglong = ctypes.c_longlong(id(clong))
    culonglong = ctypes.c_ulonglong(id(culong))
    cfloat = ctypes.c_float(3.14)
    cdouble = ctypes.c_double(0.00001011)

    assert pm.readShort(pid=pid, memory_address=ctypes.addressof(cshort)) == cshort.value
    assert pm.readUnsignedShort(pid=pid, memory_address=ctypes.addressof(cushort)) == cushort.value
    assert pm.readInteger(pid=pid, memory_address=ctypes.addressof(cint)) == cint.value
    assert pm.readUnsignedInteger(pid=pid, memory_address=ctypes.addressof(cuint)) == cuint.value
    assert pm.readLong(pid=pid, memory_address=ctypes.addressof(clong)) == clong.value
    assert pm.readUnsignedLong(pid=pid, memory_address=ctypes.addressof(culong)) == culong.value
    assert pm.readLongLong(pid=pid, memory_address=ctypes.addressof(clonglong)) == clonglong.value
    assert pm.readUnsignedLongLong(pid=pid, memory_address=ctypes.addressof(culonglong)) == culonglong.value
    assert pm.readFloat(pid=pid, memory_address=ctypes.addressof(cfloat)) == cfloat.value
    assert pm.readDouble(pid=pid, memory_address=ctypes.addressof(cdouble)) == cdouble.value

    # write tests
    pm.writeShort(pid=pid, memory_address=ctypes.addressof(cshort), val=3200)
    pm.writeUnsignedShort(pid=pid, memory_address=ctypes.addressof(cushort), val=6500)
    pm.writeInteger(pid=pid, memory_address=ctypes.addressof(cint), val=4200000)
    pm.writeUnsignedInteger(pid=pid, memory_address=ctypes.addressof(cuint), val=4500000)
    pm.writeLong(pid=pid, memory_address=ctypes.addressof(clong), val=90010001)
    pm.writeUnsignedLong(pid=pid, memory_address=ctypes.addressof(culong), val=900100010)
    pm.writeLongLong(pid=pid, memory_address=ctypes.addressof(clonglong), val=65000000000)
    pm.writeUnsignedLongLong(pid=pid, memory_address=ctypes.addressof(culonglong), val=65000066000)
    pm.writeFloat(pid=pid, memory_address=ctypes.addressof(cfloat), val=6.28)
    pm.writeDouble(pid=pid, memory_address=ctypes.addressof(cdouble), val=60.1)

    assert pm.readShort(pid=pid, memory_address=ctypes.addressof(cshort)) == 3200
    assert pm.readUnsignedShort(pid=pid, memory_address=ctypes.addressof(cushort)) == 6500
    assert pm.readInteger(pid=pid, memory_address=ctypes.addressof(cint)) == 4200000
    assert pm.readUnsignedInteger(pid=pid, memory_address=ctypes.addressof(cuint)) == 4500000
    assert pm.readLong(pid=pid, memory_address=ctypes.addressof(clong)) == 90010001
    assert pm.readUnsignedLong(pid=pid, memory_address=ctypes.addressof(culong)) == 900100010
    assert pm.readLongLong(pid=pid, memory_address=ctypes.addressof(clonglong)) == 65000000000
    assert pm.readUnsignedLongLong(pid=pid, memory_address=ctypes.addressof(culonglong)) == 65000066000
    assert math.isclose(pm.readFloat(pid=pid, memory_address=ctypes.addressof(cfloat)), 6.28, rel_tol=1e-6)
    assert math.isclose(pm.readDouble(pid=pid, memory_address=ctypes.addressof(cdouble)), 60.1, rel_tol=1e-15)

if __name__ == "__main__":
    test_get_pid()
    print("pid match complete")
    test_get_pids()
    print("get pids complete")
    test_get_modules()
    print("get modules complete")
    test_get_process_name()
    print("get process name complete")
    test_get_process_names()
    print("getting process names complete")
    test_read_write()
    print("reading and writing complete")
    test_aob_scan()
    print("aob scan complete")