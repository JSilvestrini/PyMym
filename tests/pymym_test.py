#from PyMym import PyMym as pm
import PyMym as pm
import os
import ctypes
import subprocess
import time
import math
import pytest

def test_get_pid():
    assert pm.get_pid("python.exe") == os.getpid()

def test_get_pids():
    assert len(pm.get_pids()) != 0

def test_get_process_names():
    assert len(pm.get_process_names()) != 0

def test_get_process_name():
    assert pm.get_process_name(os.getpid()) == "python.exe"

def test_get_modules():
    assert len(pm.get_modules(pid=os.getpid())) != 0

def test_aob_scan():
    pid = os.getpid()
    base_string = "This string is within the AOBScan testing function!"
    pattern = [int(hex(ord(x)), 16) for x in base_string]
    address = pm.heap_aob_scan(pid=pid, pattern=pattern, result_instance=1)
    read_bytes = pm.read_bytes(pid=pid, memory_address=address, n=len(base_string))

    assert (bytes(read_bytes)) == bytes(base_string, "utf-8")

    proc = subprocess.Popen(["./tests/c_test.exe"], text=True, stdout= subprocess.PIPE)
    time.sleep(2)

    pid = proc.pid
    pattern = "DE AD B3 3F FE ED CA FE"
    address = pm.stack_aob_scan(pid=pid, pattern=pattern, hex_string=True, flip_endian=True)
    read_bytes = pm.read_bytes(pid=pid, memory_address=address, n=8)
    assert(pm.read_ulonglong(pid=pid, memory_address=address) == 0xdeadb33ffeedcafe)

    pattern = "FE ED CA FE DE AD B3 3F"
    address = pm.heap_aob_scan(pid=pid, pattern=pattern, hex_string=True, flip_endian=True)
    read_bytes = pm.read_bytes(pid=pid, memory_address=address, n=8)
    assert(pm.read_ulonglong(pid=pid, memory_address=address) == 0xfeedcafedeadb33f)

    pattern = "This string should be on the stack. Hopefully"
    address = pm.stack_aob_scan(pid=pid, pattern=pattern, flip_endian=False)
    read_bytes = pm.read_bytes(pid=pid, memory_address=address, n=len(pattern))
    assert(read_bytes == pm._create_byte_pattern(pattern))

    pattern = "This string should be on the heap. Hopefully"
    address = pm.heap_aob_scan(pid=pid, pattern=pattern, flip_endian=False)
    read_bytes = pm.read_bytes(pid=pid, memory_address=address, n=len(pattern))
    assert(read_bytes == pm._create_byte_pattern(pattern))

    proc.terminate()

def test_read_write():
    # Read bytes
    pid = os.getpid()
    search_string = ctypes.create_string_buffer(b"This string is within the reading testing function!")
    found_string = bytes(pm.read_bytes(pid=pid, memory_address=ctypes.addressof(search_string), n=ctypes.sizeof(search_string)))
    assert search_string.raw == found_string

    # Write bytes
    new_val = b"This string is within the writing testing function!"
    assert pm.write_bytes(pid=pid, memory_address=ctypes.addressof(search_string), val=new_val) == True
    assert new_val == search_string.value

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

    assert pm.read_short(pid=pid, memory_address=ctypes.addressof(cshort)) == cshort.value
    assert pm.read_ushort(pid=pid, memory_address=ctypes.addressof(cushort)) == cushort.value
    assert pm.read_int(pid=pid, memory_address=ctypes.addressof(cint)) == cint.value
    assert pm.read_uint(pid=pid, memory_address=ctypes.addressof(cuint)) == cuint.value
    assert pm.read_long(pid=pid, memory_address=ctypes.addressof(clong)) == clong.value
    assert pm.read_ulong(pid=pid, memory_address=ctypes.addressof(culong)) == culong.value
    assert pm.read_longlong(pid=pid, memory_address=ctypes.addressof(clonglong)) == clonglong.value
    assert pm.read_ulonglong(pid=pid, memory_address=ctypes.addressof(culonglong)) == culonglong.value
    assert pm.read_float(pid=pid, memory_address=ctypes.addressof(cfloat)) == cfloat.value
    assert pm.read_double(pid=pid, memory_address=ctypes.addressof(cdouble)) == cdouble.value

    # write tests
    assert pm.write_short(pid=pid, memory_address=ctypes.addressof(cshort), val=3200) == True
    assert pm.write_ushort(pid=pid, memory_address=ctypes.addressof(cushort), val=6500) == True
    assert pm.write_int(pid=pid, memory_address=ctypes.addressof(cint), val=4200000) == True
    assert pm.write_uint(pid=pid, memory_address=ctypes.addressof(cuint), val=4500000) == True
    assert pm.write_long(pid=pid, memory_address=ctypes.addressof(clong), val=90010001) == True
    assert pm.write_ulong(pid=pid, memory_address=ctypes.addressof(culong), val=900100010) == True
    assert pm.write_longlong(pid=pid, memory_address=ctypes.addressof(clonglong), val=65000000000) == True
    assert pm.write_ulonglong(pid=pid, memory_address=ctypes.addressof(culonglong), val=65000066000) == True
    assert pm.write_float(pid=pid, memory_address=ctypes.addressof(cfloat), val=6.28) == True
    assert pm.write_double(pid=pid, memory_address=ctypes.addressof(cdouble), val=60.1) == True

    assert pm.read_short(pid=pid, memory_address=ctypes.addressof(cshort)) == 3200
    assert pm.read_ushort(pid=pid, memory_address=ctypes.addressof(cushort)) == 6500
    assert pm.read_int(pid=pid, memory_address=ctypes.addressof(cint)) == 4200000
    assert pm.read_uint(pid=pid, memory_address=ctypes.addressof(cuint)) == 4500000
    assert pm.read_long(pid=pid, memory_address=ctypes.addressof(clong)) == 90010001
    assert pm.read_ulong(pid=pid, memory_address=ctypes.addressof(culong)) == 900100010
    assert pm.read_longlong(pid=pid, memory_address=ctypes.addressof(clonglong)) == 65000000000
    assert pm.read_ulonglong(pid=pid, memory_address=ctypes.addressof(culonglong)) == 65000066000
    assert math.isclose(pm.read_float(pid=pid, memory_address=ctypes.addressof(cfloat)), 6.28, rel_tol=1e-6)
    assert math.isclose(pm.read_double(pid=pid, memory_address=ctypes.addressof(cdouble)), 60.1, rel_tol=1e-15)

    sl = (ctypes.c_short * 5)()
    usl = (ctypes.c_ushort * 5)()
    il = (ctypes.c_int * 5)()
    uil = (ctypes.c_uint * 5)()
    ll = (ctypes.c_long * 5)()
    ull = (ctypes.c_ulong * 5)()
    lll = (ctypes.c_longlong * 5)()
    ulll = (ctypes.c_ulonglong * 5)()
    fl = (ctypes.c_float * 5)()
    dl = (ctypes.c_double * 5)()

    assert pm.write_short(pid=pid, memory_address=ctypes.addressof(sl), val=[0, 1, 2, 3, 4, 5]) == True
    assert pm.write_ushort(pid=pid, memory_address=ctypes.addressof(usl), val=[0, 1, 2, 3, 4, 5]) == True
    assert pm.write_int(pid=pid, memory_address=ctypes.addressof(il), val=[0, 1, 2, 3, 4, 5]) == True
    assert pm.write_uint(pid=pid, memory_address=ctypes.addressof(uil), val=[0, 1, 2, 3, 4, 5]) == True
    assert pm.write_long(pid=pid, memory_address=ctypes.addressof(ll), val=[0, 1, 2, 3, 4, 5]) == True
    assert pm.write_ulong(pid=pid, memory_address=ctypes.addressof(ull), val=[0, 1, 2, 3, 4, 5]) == True
    assert pm.write_longlong(pid=pid, memory_address=ctypes.addressof(lll), val=[0, 1, 2, 3, 4, 5]) == True
    assert pm.write_ulonglong(pid=pid, memory_address=ctypes.addressof(ulll), val=[0, 1, 2, 3, 4, 5]) == True
    assert pm.write_float(pid=pid, memory_address=ctypes.addressof(fl), val=[0, 1, 2, 3, 4, 5]) == True
    assert pm.write_double(pid=pid, memory_address=ctypes.addressof(dl), val=[0, 1, 2, 3, 4, 5]) == True

    assert pm.read_short(pid=pid, memory_address=ctypes.addressof(sl), n=6) == [0, 1, 2, 3, 4, 5]
    assert pm.read_ushort(pid=pid, memory_address=ctypes.addressof(usl), n=6) == [0, 1, 2, 3, 4, 5]
    assert pm.read_int(pid=pid, memory_address=ctypes.addressof(il), n=6) == [0, 1, 2, 3, 4, 5]
    assert pm.read_uint(pid=pid, memory_address=ctypes.addressof(uil), n=6) == [0, 1, 2, 3, 4, 5]
    assert pm.read_long(pid=pid, memory_address=ctypes.addressof(ll), n=6) == [0, 1, 2, 3, 4, 5]
    assert pm.read_ulong(pid=pid, memory_address=ctypes.addressof(ull), n=6) == [0, 1, 2, 3, 4, 5]
    assert pm.read_longlong(pid=pid, memory_address=ctypes.addressof(lll), n=6) == [0, 1, 2, 3, 4, 5]
    assert pm.read_ulonglong(pid=pid, memory_address=ctypes.addressof(ulll), n=6) == [0, 1, 2, 3, 4, 5]

    for i in range(6):
        assert math.isclose(pm.read_float(pid=pid, memory_address=ctypes.addressof(fl) + ctypes.sizeof(ctypes.c_float) * i), i, rel_tol=1e-6)
        assert math.isclose(pm.read_double(pid=pid, memory_address=ctypes.addressof(dl)+ ctypes.sizeof(ctypes.c_double) * i), i, rel_tol=1e-15)

def test_process_wrapper():
    pw = pm.ProcessWrapper(pid=os.getpid())
    assert bool(pw) == True

    search_string = ctypes.create_string_buffer(b"This string is within the reading testing function!")
    found_string = bytes(pw.read_bytes(memory_address=ctypes.addressof(search_string), n=ctypes.sizeof(search_string)))
    assert search_string.raw == found_string

    fs2 = bytes(pw[ctypes.addressof(search_string):ctypes.addressof(search_string)+ctypes.sizeof(search_string)])
    assert search_string.raw == fs2

    # Write bytes
    new_val = b"This string is within the writing testing function!"
    assert pw.write_bytes(memory_address=ctypes.addressof(search_string), val=new_val) == True
    assert new_val == search_string.value

    pw[ctypes.addressof(search_string):ctypes.addressof(search_string)+ctypes.sizeof(search_string)] = "This string is within the reading testing function!"
    assert search_string.value == b"This string is within the reading testing function!"

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

    assert pw.read_short(memory_address=ctypes.addressof(cshort)) == cshort.value
    assert pw.read_ushort(memory_address=ctypes.addressof(cushort)) == cushort.value
    assert pw.read_int(memory_address=ctypes.addressof(cint)) == cint.value
    assert pw.read_uint(memory_address=ctypes.addressof(cuint)) == cuint.value
    assert pw.read_long(memory_address=ctypes.addressof(clong)) == clong.value
    assert pw.read_ulong(memory_address=ctypes.addressof(culong)) == culong.value
    assert pw.read_longlong(memory_address=ctypes.addressof(clonglong)) == clonglong.value
    assert pw.read_ulonglong(memory_address=ctypes.addressof(culonglong)) == culonglong.value
    assert pw.read_float(memory_address=ctypes.addressof(cfloat)) == cfloat.value
    assert pw.read_double(memory_address=ctypes.addressof(cdouble)) == cdouble.value

    assert pw.short[ctypes.addressof(cshort)] == cshort.value
    assert pw.ushort[ctypes.addressof(cushort)] == cushort.value
    assert pw.int[ctypes.addressof(cint)] == cint.value
    assert pw.uint[ctypes.addressof(cuint)] == cuint.value
    assert pw.long[ctypes.addressof(clong)] == clong.value
    assert pw.ulong[ctypes.addressof(culong)] == culong.value
    assert pw.longlong[ctypes.addressof(clonglong)] == clonglong.value
    assert pw.ulonglong[ctypes.addressof(culonglong)] == culonglong.value
    assert pw.float[ctypes.addressof(cfloat)] == cfloat.value
    assert pw.double[ctypes.addressof(cdouble)] == cdouble.value

    # write tests
    assert pw.write_short(memory_address=ctypes.addressof(cshort), val=3200) == True
    assert pw.write_ushort(memory_address=ctypes.addressof(cushort), val=6500) == True
    assert pw.write_int(memory_address=ctypes.addressof(cint), val=4200000) == True
    assert pw.write_uint(memory_address=ctypes.addressof(cuint), val=4500000) == True
    assert pw.write_long(memory_address=ctypes.addressof(clong), val=90010001) == True
    assert pw.write_ulong(memory_address=ctypes.addressof(culong), val=900100010) == True
    assert pw.write_longlong(memory_address=ctypes.addressof(clonglong), val=65000000000) == True
    assert pw.write_ulonglong(memory_address=ctypes.addressof(culonglong), val=65000066000) == True
    assert pw.write_float(memory_address=ctypes.addressof(cfloat), val=6.28) == True
    assert pw.write_double(memory_address=ctypes.addressof(cdouble), val=60.1) == True

    assert pw.read_short(memory_address=ctypes.addressof(cshort)) == 3200
    assert pw.read_ushort(memory_address=ctypes.addressof(cushort)) == 6500
    assert pw.read_int(memory_address=ctypes.addressof(cint)) == 4200000
    assert pw.read_uint(memory_address=ctypes.addressof(cuint)) == 4500000
    assert pw.read_long(memory_address=ctypes.addressof(clong)) == 90010001
    assert pw.read_ulong(memory_address=ctypes.addressof(culong)) == 900100010
    assert pw.read_longlong(memory_address=ctypes.addressof(clonglong)) == 65000000000
    assert pw.read_ulonglong(memory_address=ctypes.addressof(culonglong)) == 65000066000
    assert math.isclose(pw.read_float(memory_address=ctypes.addressof(cfloat)), 6.28, rel_tol=1e-6)
    assert math.isclose(pw.read_double(memory_address=ctypes.addressof(cdouble)), 60.1, rel_tol=1e-15)

    pw.short[ctypes.addressof(cshort)] = 32000
    pw.ushort[ctypes.addressof(cushort)] = 65000
    pw.int[ctypes.addressof(cint)] = 420000
    pw.uint[ctypes.addressof(cuint)] = 450000
    pw.long[ctypes.addressof(clong)] = 9001001
    pw.ulong[ctypes.addressof(culong)] = 9001010
    pw.longlong[ctypes.addressof(clonglong)] = 6500000
    pw.ulonglong[ctypes.addressof(culonglong)] = 65000066
    pw.float[ctypes.addressof(cfloat)] = 1000.1
    pw.double[ctypes.addressof(cdouble)] = 60001.1

    assert pw.short[ctypes.addressof(cshort)] == 32000
    assert pw.ushort[ctypes.addressof(cushort)] == 65000
    assert pw.int[ctypes.addressof(cint)] == 420000
    assert pw.uint[ctypes.addressof(cuint)] == 450000
    assert pw.long[ctypes.addressof(clong)] == 9001001
    assert pw.ulong[ctypes.addressof(culong)] == 9001010
    assert pw.longlong[ctypes.addressof(clonglong)] == 6500000
    assert pw.ulonglong[ctypes.addressof(culonglong)] == 65000066
    assert math.isclose(pw.float[ctypes.addressof(cfloat)], 1000.1, rel_tol=1e-6)
    assert math.isclose(pw.double[ctypes.addressof(cdouble)], 60001.1, rel_tol=1e-15)

    sl = (ctypes.c_short * 5)()
    usl = (ctypes.c_ushort * 5)()
    il = (ctypes.c_int * 5)()
    uil = (ctypes.c_uint * 5)()
    ll = (ctypes.c_long * 5)()
    ull = (ctypes.c_ulong * 5)()
    lll = (ctypes.c_longlong * 5)()
    ulll = (ctypes.c_ulonglong * 5)()
    fl = (ctypes.c_float * 5)()
    dl = (ctypes.c_double * 5)()

    assert pw.write_short(memory_address=ctypes.addressof(sl), val=[0, 1, 2, 3, 4, 5]) == True
    assert pw.write_ushort(memory_address=ctypes.addressof(usl), val=[0, 1, 2, 3, 4, 5]) == True
    assert pw.write_int(memory_address=ctypes.addressof(il), val=[0, 1, 2, 3, 4, 5]) == True
    assert pw.write_uint(memory_address=ctypes.addressof(uil), val=[0, 1, 2, 3, 4, 5]) == True
    assert pw.write_long(memory_address=ctypes.addressof(ll), val=[0, 1, 2, 3, 4, 5]) == True
    assert pw.write_ulong(memory_address=ctypes.addressof(ull), val=[0, 1, 2, 3, 4, 5]) == True
    assert pw.write_longlong(memory_address=ctypes.addressof(lll), val=[0, 1, 2, 3, 4, 5]) == True
    assert pw.write_ulonglong(memory_address=ctypes.addressof(ulll), val=[0, 1, 2, 3, 4, 5]) == True
    assert pw.write_float(memory_address=ctypes.addressof(fl), val=[0, 1, 2, 3, 4, 5]) == True
    assert pw.write_double(memory_address=ctypes.addressof(dl), val=[0, 1, 2, 3, 4, 5]) == True

    assert pw.read_short(memory_address=ctypes.addressof(sl), n=6) == [0, 1, 2, 3, 4, 5]
    assert pw.read_ushort(memory_address=ctypes.addressof(usl), n=6) == [0, 1, 2, 3, 4, 5]
    assert pw.read_int(memory_address=ctypes.addressof(il), n=6) == [0, 1, 2, 3, 4, 5]
    assert pw.read_uint(memory_address=ctypes.addressof(uil), n=6) == [0, 1, 2, 3, 4, 5]
    assert pw.read_long(memory_address=ctypes.addressof(ll), n=6) == [0, 1, 2, 3, 4, 5]
    assert pw.read_ulong(memory_address=ctypes.addressof(ull), n=6) == [0, 1, 2, 3, 4, 5]
    assert pw.read_longlong(memory_address=ctypes.addressof(lll), n=6) == [0, 1, 2, 3, 4, 5]
    assert pw.read_ulonglong(memory_address=ctypes.addressof(ulll), n=6) == [0, 1, 2, 3, 4, 5]

    for i in range(6):
        assert math.isclose(pw.read_float(memory_address=ctypes.addressof(fl) + ctypes.sizeof(ctypes.c_float) * i), i, rel_tol=1e-6)
        assert math.isclose(pw.read_double(memory_address=ctypes.addressof(dl)+ ctypes.sizeof(ctypes.c_double) * i), i, rel_tol=1e-15)

    pw.short[ctypes.addressof(sl)] = [5, 4, 3, 2, 1, 0]
    pw.ushort[ctypes.addressof(usl)] = [5, 4, 3, 2, 1, 0]
    pw.int[ctypes.addressof(il)] = [5, 4, 3, 2, 1, 0]
    pw.uint[ctypes.addressof(uil)] = [5, 4, 3, 2, 1, 0]
    pw.long[ctypes.addressof(ll)] = [5, 4, 3, 2, 1, 0]
    pw.ulong[ctypes.addressof(ull)] = [5, 4, 3, 2, 1, 0]
    pw.longlong[ctypes.addressof(lll)] = [5, 4, 3, 2, 1, 0]
    pw.ulonglong[ctypes.addressof(ulll)] = [5, 4, 3, 2, 1, 0]
    pw.float[ctypes.addressof(fl)] = [5, 4, 3, 2, 1, 0]
    pw.double[ctypes.addressof(dl)] = [5, 4, 3, 2, 1, 0]

    assert pw.short[ctypes.addressof(sl):ctypes.addressof(sl)+6] == [5, 4, 3, 2, 1, 0]
    assert pw.ushort[ctypes.addressof(usl):ctypes.addressof(usl)+6] == [5, 4, 3, 2, 1, 0]
    assert pw.int[ctypes.addressof(il):ctypes.addressof(il)+6] == [5, 4, 3, 2, 1, 0]
    assert pw.uint[ctypes.addressof(uil):ctypes.addressof(uil)+6] == [5, 4, 3, 2, 1, 0]
    assert pw.long[ctypes.addressof(ll):ctypes.addressof(ll)+6] == [5, 4, 3, 2, 1, 0]
    assert pw.ulong[ctypes.addressof(ull):ctypes.addressof(ull)+6] == [5, 4, 3, 2, 1, 0]
    assert pw.longlong[ctypes.addressof(lll):ctypes.addressof(lll)+6] == [5, 4, 3, 2, 1, 0]
    assert pw.ulonglong[ctypes.addressof(ulll):ctypes.addressof(ulll)+6] == [5, 4, 3, 2, 1, 0]

    for i in range(0, 6, -1):
        assert math.isclose(pw.float[ctypes.addressof(fl) + ctypes.sizeof(ctypes.c_float) * i], (5 - i), rel_tol=1e-6)
        assert math.isclose(pw.double[ctypes.addressof(dl)+ ctypes.sizeof(ctypes.c_double) * i], (5 - i), rel_tol=1e-15)

    base_string = "This string is within the AOBScan testing function!"
    pattern = [int(hex(ord(x)), 16) for x in base_string]
    address = pw.heap_aob_scan(pattern=pattern, result_instance=1)
    read_bytes = pw.read_bytes(memory_address=address, n=len(base_string))

    assert (bytes(read_bytes)) == bytes(base_string, "utf-8")

    proc = subprocess.Popen(["./tests/c_test.exe"], text=True, stdout= subprocess.PIPE)
    time.sleep(2)

    with pm.ProcessWrapper(pid=proc.pid) as pw2:
        pattern = "DE AD B3 3F FE ED CA FE"
        address = pw2.stack_aob_scan(pattern=pattern, hex_string=True, flip_endian=True)
        read_bytes = pw2.read_bytes(memory_address=address, n=8)
        assert(pw2.read_ulonglong(memory_address=address) == 0xdeadb33ffeedcafe)

        pattern = "FE ED CA FE DE AD B3 3F"
        address = pw2.heap_aob_scan(pattern=pattern, hex_string=True, flip_endian=True)
        read_bytes = pw2.read_bytes(memory_address=address, n=8)
        assert(pw2.read_ulonglong(memory_address=address) == 0xfeedcafedeadb33f)

        pattern = "This string should be on the stack. Hopefully"
        address = pw2.stack_aob_scan(pattern=pattern, flip_endian=False)
        read_bytes = pw2.read_bytes(memory_address=address, n=len(pattern))
        assert(read_bytes == pm._create_byte_pattern(pattern))

        pattern = "This string should be on the heap. Hopefully"
        address = pw2.heap_aob_scan(pattern=pattern, flip_endian=False)
        read_bytes = pw2.read_bytes(memory_address=address, n=len(pattern))
        assert(read_bytes == pm._create_byte_pattern(pattern))

        bp = pm.pack_ulonglong(0xfeedcafedeadb33f)
        address = pw2.heap_aob_scan(pattern=bp)
        assert pw2.ulonglong[address] == 0xfeedcafedeadb33f

    proc.terminate()

def test_pack_unpack():
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

    sp = pm.pack_short(cshort.value)
    usp = pm.pack_ushort(cushort.value)
    ip = pm.pack_int(cint.value)
    uip = pm.pack_uint(cuint.value)
    lp = pm.pack_long(clong.value)
    ulp = pm.pack_ulong(culong.value)
    llp = pm.pack_longlong(clonglong.value)
    ullp = pm.pack_ulonglong(culonglong.value)
    fp = pm.pack_float(cfloat.value)
    dp = pm.pack_double(cdouble.value)

    assert math.isclose(pm.unpack_double(dp), cdouble.value, rel_tol=1e-15)
    assert math.isclose(pm.unpack_float(fp), cfloat.value, rel_tol=1e-6)
    assert pm.unpack_short(sp) == cshort.value
    assert pm.unpack_ushort(usp) == cushort.value
    assert pm.unpack_int(ip) == cint.value
    assert pm.unpack_uint(uip) == cuint.value
    assert pm.unpack_long(lp) == clong.value
    assert pm.unpack_ulong(ulp) == culong.value
    assert pm.unpack_longlong(llp) == clonglong.value
    assert pm.unpack_ulonglong(ullp) == culonglong.value

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
    test_process_wrapper()
    print("process wrapper class test complete")
    test_pack_unpack()
    print("pack unpack test complete")