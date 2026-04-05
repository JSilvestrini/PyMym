import struct
import PyMym as pm
import ctypes
import os
import subprocess
import time

if __name__ == "__main__":
    proc = subprocess.Popen(["./tests/c_test.exe"], text=True, stdout= subprocess.PIPE)
    time.sleep(2)

    ta = pm.stack_aob_scan(pid=proc.pid, pattern="DE AD B3 3F FE ED CA FE", flip_endian=True, hex_string=True)
    print(ta)

    pw = pm.ProcessWrapper(pid=proc.pid)
    print(pw.__str__())
    print(pw.__repr__())
    print(pw.get_pid())
    print(pw.get_application_name())
    print(pw.get_modules())

    addr: int = pw.stack_aob_scan(pattern="DE AD B3 3F FE ED CA FE", flip_endian=True, hex_string=True)

    print(addr)
    print(pw[addr:addr+8])
    print(pw[addr:addr+8])
    pw[addr:addr+8] = [255, 255, 255, 255]
    print(pw[addr:addr+8])
    print(pw.longlong[addr])
    pw.ulonglong[addr:addr+12] = [0xBEEFDEADFEEDCAFE, 0xFEEFDEEDCFEEA333]
    print([hex(0xBEEFDEADFEEDCAFE), hex(0xFEEFDEEDCFEEA333)])
    print([hex(x) for x in pw.ulonglong[addr:addr+12]])
    pw.ulonglong[addr] = 0xBEEF00000000CAFE
    print(pw.ulonglong[addr:addr+2])

    print(type([0xBEEF00000000CAFE]))

    proc.terminate()
    print(pm.get_modules(pid=os.getpid()))