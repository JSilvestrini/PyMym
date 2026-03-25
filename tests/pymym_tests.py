#from PyMym import PyMym as pm
import PyMym as pm
import os
import ctypes
import subprocess
import time

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
    base_string = "This string is within the AOBScan testing function!"
    pid = os.getpid()
    pattern = [int(hex(ord(x)), 16) for x in base_string]
    address = pm.heapAOBScan(os.getpid(), pattern, "x" * len(base_string), 0, 1)
    read_bytes = pm.readBytes(pid, address, len(base_string))

    assert (bytes(read_bytes)) == bytes(base_string, "utf-8")
    print(bytes(read_bytes))

    proc = subprocess.Popen(["./c_test.exe"])
    time.sleep(2)

    pid = proc.pid
    pattern = [0xDE, 0xAD, 0xB3, 0x3F, 0xCA, 0xFE, 0xFE, 0xED, 0xCA, 0xFE]
    address = pm.stackAOBScan(pid, pattern[::-1], "xxxxxxxx")
    read_bytes = pm.readBytes(pid, address, len(pattern))

    print(address)
    print(read_bytes)
    proc.wait()

    #assert address == res
    #assert read_bytes == 0xDEADB33FCAFE

def test_read_write():
    search_string = ctypes.create_string_buffer(b"This string is within the reading testing function!")
    found_string = bytes(pm.readBytes(os.getpid(), ctypes.addressof(search_string), ctypes.sizeof(search_string)))

    assert search_string.raw == found_string

    cint = ctypes.c_int(522)
    clong = ctypes.c_long(190108228)
    clonglong = ctypes.c_longlong(id(clong))

    assert pm.readInteger(os.getpid(), ctypes.addressof(cint)) == cint.value
    assert pm.readLong(os.getpid(), ctypes.addressof(clong)) == clong.value
    assert pm.readLongLong(os.getpid(), ctypes.addressof(clonglong)) == clonglong.value

    pm.writeInteger(os.getpid(), ctypes.addressof(cint), 109)
    pm.writeLong(os.getpid(), ctypes.addressof(clong), 109009991)
    pm.writeLongLong(os.getpid(), ctypes.addressof(clonglong), id(cint))

    assert pm.readInteger(os.getpid(), ctypes.addressof(cint)) == 109
    assert pm.readLong(os.getpid(), ctypes.addressof(clong)) == 109009991
    assert pm.readLongLong(os.getpid(), ctypes.addressof(clonglong)) == id(cint)

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