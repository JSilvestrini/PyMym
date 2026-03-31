#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <iostream>
#include <windows.h>
#include <winnt.h>
#include <tlhelp32.h>
#include <vector>
#include <memoryapi.h>
#include <psapi.h>
#include <debugapi.h>
#include <ranges>
#include <locale>
#include <codecvt>
#include <winternl.h>
#include <fstream>

namespace py = pybind11;

typedef NTSTATUS (NTAPI *pNtQueryInformationThread) (
    HANDLE          ThreadHandle,
    int             ThreadInformationClass,
    PVOID           ThreadInformation,
    ULONG           ThreadInformationLength,
    PULONG          ReturnLength
);

typedef struct _THREAD_BASIC_INFORMATION {
    NTSTATUS                ExitStatus;
    PVOID                   TebBaseAddress;
    CLIENT_ID               ClientId;
    KAFFINITY               AffinityMask;
    LONG                    Priority;
    LONG                    BasePriority;
} THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;

std::vector<std::pair<unsigned char, bool>> buildPattern(const std::vector<uint8_t>& lpPattern, const char* pszMask) {
    std::vector<std::pair<unsigned char, bool>> pattern;
    for (size_t x = 0, y = strlen(pszMask); x < y; x++) {
        pattern.push_back(std::make_pair(lpPattern[x], pszMask[x] == 'x'));
    }
    return pattern;
}

void hexDump(std::string filename, std::vector<byte> data) {
    std::fstream f;
    f.open(std::format("{}.txt", filename), std::ios::out | std::ios::trunc);

    size_t c = 0;
    f << std::hex;
    for (const auto& i : data) {
        f << static_cast<unsigned int>(i) << " ";
        c++;
        if (c % 8 == 0) {
            f << std::endl;
        } 
    }
    f.close();
}

/**
 * @brief                   Gives the PID of a given application name
 *
 * @param application       The application name as a string
 *
 * @return                  The int PID of the given application
 */
unsigned long getPID(const char* application) {
    unsigned long pid = 0;
    PROCESSENTRY32 enter;
    enter.dwSize = sizeof(PROCESSENTRY32);
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (Process32First(snapshot, &enter)) {
        while (Process32Next(snapshot, &enter)) {
            if (!_stricmp(enter.szExeFile, application)) {
                pid = enter.th32ProcessID;
            }
        }
    }

    return pid;
}

std::vector<unsigned long> getPIDs() {
    std::vector<DWORD> ret(1024);
    DWORD br = 0;

    do {
        ret.resize(ret.capacity() * 2);
        if (!EnumProcesses(ret.data(), ret.capacity() * sizeof(DWORD), &br)) {
            return std::vector<unsigned long>{};
        }
    } while (br == ret.size() / sizeof(DWORD));

    return ret | std::views::take(br / sizeof(DWORD)) | std::views::transform([](auto pid) -> unsigned long{return pid;}) | std::ranges::to<std::vector>();
}

std::string getProcessName(unsigned long pid) {
    std::string ret;
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, false, pid);
    char szProcessName[MAX_PATH];

    if (GetProcessImageFileNameA(hProcess, szProcessName, MAX_PATH)) {
        char* afterSlash = strrchr(szProcessName, '\\') + 1;
        ret = (afterSlash) ? afterSlash: szProcessName;
    }

    CloseHandle(hProcess);

    return ret;
}

std::vector<std::string> getProcessNames() {
    std::vector<unsigned long> pids = getPIDs();
    std::vector<std::string> ret{};

    for (int i = 0; i < pids.size(); i++) {
        std::string processName = getProcessName(pids[i]);

        if (processName.empty()) {
            continue;
        }

        ret.push_back(processName);
    }

    return ret;
}

std::vector<std::string> handledGetModules(HANDLE hProcess) {
    std::vector<std::string> ret{};

    HMODULE hMods[1024];
    DWORD cbNeeded;

    if (!EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        return ret;
    }

    for (int i = 0; i < cbNeeded / sizeof(HMODULE); i++) {
        char szModName[MAX_PATH];

        if (!GetModuleFileNameExA(hProcess, hMods[i], szModName, MAX_PATH)) {
            return ret;
        }

        char* moduleName = strrchr(szModName, '\\') + 1;

        ret.push_back(std::string(moduleName));
    }

    return ret;
}

/**
 * @brief                   Returns a list of modules that make up the given application
 *
 * @param pid               The PID of the process
 *
 * @return                  A vector containing modules that the given application contains
 */
std::vector<std::string> getModules(unsigned long pid) {
    std::vector<std::string> ret{};

    DWORD processID = (DWORD)pid;
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, processID);

    if (!hProcess) {
        return ret;
    }

    handledGetModules(hProcess);

    CloseHandle(hProcess);

    return ret;
}

/**
 * @brief                   Returns a list of modules that make up the given application
 *
 * @param application       The application name as a string
 *
 * @return                  A vector containing modules that the given application contain
 */
std::vector<std::string> getModules(const char* application) {
    unsigned long pid = getPID(application);

    if (!pid) {
        return std::vector<std::string>{};
    }

    return getModules(pid);
}

intptr_t handledStackAOBScan(unsigned long pid, HANDLE hProcess, const std::vector<uint8_t>& lpPattern, const char* pszMask, intptr_t offset, intptr_t resultUsage) {
    intptr_t fRet = 0;
    HANDLE hThreadSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

    if (hThreadSnapShot == INVALID_HANDLE_VALUE) {
        return fRet;
    }

    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);

    if (!Thread32First(hThreadSnapShot, &te32)) {
        CloseHandle(hThreadSnapShot);
        return fRet;
    }

    std::vector<HANDLE> hThreads;

    do {
        if (te32.th32OwnerProcessID != pid) {
            continue;
        }

        HANDLE tThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID);

        if (!tThread) {
            continue;
        }

        hThreads.push_back(tThread);

    } while (Thread32Next(hThreadSnapShot, &te32));

    if (hThreads.empty()) {
        return fRet;
    }

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    pNtQueryInformationThread NtQueryInformationThread = (pNtQueryInformationThread)GetProcAddress(hNtdll, "NtQueryInformationThread");

    if (!NtQueryInformationThread) {
        return fRet;
    }

    for (const auto& thread : hThreads) {
        if (GetCurrentThreadId() == GetThreadId(thread)) {
            continue; 
        }

        THREAD_BASIC_INFORMATION TBI{};

        if (NtQueryInformationThread(thread, THREADINFOCLASS(0), &TBI, sizeof(TBI), NULL)) {
            continue;
        }

        CONTEXT ctx;
        ZeroMemory(&ctx, sizeof(CONTEXT));

        ctx.ContextFlags = CONTEXT_CONTROL;

        if (SuspendThread(thread) == (DWORD)-1) {
            continue;
        }

        if (!GetThreadContext(thread, &ctx)) {
            ResumeThread(thread);
            continue;
        }

        intptr_t rsp = ctx.Rsp;
        intptr_t base = 0;
        intptr_t limit = 0;

        if (!ReadProcessMemory(hProcess, (LPCVOID)((intptr_t)TBI.TebBaseAddress + 0x08), &base, sizeof(base), NULL)) {
            ResumeThread(thread);
            continue;
        }

        if (!ReadProcessMemory(hProcess, (LPCVOID)((intptr_t)TBI.TebBaseAddress + 0x10), &limit, sizeof(limit), NULL)) {
            ResumeThread(thread);
            continue;
        }

        if (rsp > base || rsp < limit) {
            ResumeThread(thread);
            continue;
        }

        std::vector<byte> data(base - rsp);
        SIZE_T bytesRead = 0;

        if (!ReadProcessMemory(hProcess, (LPCVOID)(rsp), data.data(), base - rsp, &bytesRead)) {
            ResumeThread(thread);
            continue;
        }

        //hexDump("stack_scan", data);

        ResumeThread(thread);

        auto pattern = buildPattern(lpPattern, pszMask);
        auto scanStart = data.begin();
        auto resultCnt = 0;

        while (true) {
            auto ret = std::search(scanStart, data.end(), pattern.begin(), pattern.end(),
                [&](unsigned char curr, std::pair<unsigned char, bool> currPattern) {
                return (!currPattern.second) || curr == currPattern.first;
            });

            if (ret == data.end()) {
                break;
            }

            if (resultCnt == resultUsage || resultUsage == 0) {
                fRet = (std::distance(data.begin(), ret) + rsp) + offset;
                break;
            }

            resultCnt++;
            scanStart = ++ret;
        }

        if (fRet != 0) {
            break;
        }
    }

    for (const auto& thread : hThreads) {
        CloseHandle(thread);
    }

    return fRet;
}

intptr_t stackAOBScan(unsigned long pid, const std::vector<uint8_t>& lpPattern, const char* pszMask, intptr_t offset, intptr_t resultUsage) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, (DWORD)pid);

    if (!hProcess) {
        return 0;
    }

    intptr_t fRet = handledStackAOBScan(pid, hProcess, lpPattern, pszMask, offset, resultUsage);

    CloseHandle(hProcess);
    return fRet;
}

intptr_t stackAOBScan(const char* application, const std::vector<uint8_t>& lpPattern, const char* pszMask, intptr_t offset, intptr_t resultUsage) {
    unsigned long pid = getPID(application);
    return stackAOBScan(pid, lpPattern, pszMask, offset, resultUsage);
}

intptr_t handledHeapAOBScan(HANDLE hProcess, const std::vector<uint8_t>& lpPattern, const char* pszMask, intptr_t offset, intptr_t resultUsage) {
    MEMORY_BASIC_INFORMATION mbi{};
    intptr_t address = 0;

    while (VirtualQueryEx(hProcess, (LPCVOID)address, &mbi, sizeof(mbi))) {
        address += mbi.RegionSize;
        if ((mbi.State != MEM_COMMIT) || (mbi.Protect & PAGE_GUARD) || (mbi.Protect & PAGE_NOACCESS) || (mbi.Type != MEM_PRIVATE)) {
            continue;
        }

        std::vector<byte> data(mbi.RegionSize);
        SIZE_T bytesRead = 0;

        if (!ReadProcessMemory(hProcess, (LPCVOID)(mbi.BaseAddress), data.data(), mbi.RegionSize, &bytesRead)) {
            continue;
        }

        //hexDump("heap_scan", data);

        auto pattern = buildPattern(lpPattern, pszMask);
        auto scanStart = data.begin();
        auto resultCnt = 0;

        while (true) {
            auto ret = std::search(scanStart, data.end(), pattern.begin(), pattern.end(),
                [&](unsigned char curr, std::pair<unsigned char, bool> currPattern) {
                return (!currPattern.second) || curr == currPattern.first;
            });

            if (ret == data.end()) {
                break;
            }

            if (resultCnt == resultUsage || resultUsage == 0) {
                return (std::distance(data.begin(), ret) + (intptr_t)mbi.BaseAddress) + offset;
            }

            resultCnt++;
            scanStart = ++ret;
        }
    }

    return 0;
}

intptr_t heapAOBScan(unsigned long pid, const std::vector<uint8_t>& lpPattern, const char* pszMask, intptr_t offset, intptr_t resultUsage) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, (DWORD)pid);

    if (!hProcess) {
        return 0;
    }

    intptr_t fRet = handledHeapAOBScan(hProcess, lpPattern, pszMask, offset,  resultUsage);

    CloseHandle(hProcess);
    return fRet;
}

intptr_t heapAOBScan(const char* application, const std::vector<uint8_t>& lpPattern, const char* pszMask, intptr_t offset, intptr_t resultUsage) {
    unsigned long pid = getPID(application);
    return heapAOBScan(pid, lpPattern, pszMask, offset, resultUsage);
}

intptr_t handledModuleAOBScan(HANDLE hProcess, const char* moduleName, const std::vector<uint8_t>& lpPattern, const char* pszMask, intptr_t offset, intptr_t resultUsage) {
    HMODULE hMods[1024];
    DWORD cbNeeded;
    int i = 0;

    if (!EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        return 0;
    }

    for (i; i < cbNeeded / sizeof(HMODULE); i++) {
        WCHAR szModName[MAX_PATH];

        if (!GetModuleFileNameExW(hProcess, hMods[i], szModName, MAX_PATH)) {
            continue;
        }

        wchar_t wideModuleName[MAX_PATH];
        MultiByteToWideChar(CP_ACP, 0, moduleName, -1, wideModuleName, MAX_PATH);

        wchar_t* lastSlash = wcsrchr(szModName, L'\\');

        if (!lastSlash) {
            continue;
        }
        if (wcscmp(lastSlash + 1, wideModuleName) == 0) {
            break;
        }
    }

    MODULEINFO modInfo = {0};
    DWORD64 moduleBaseAddress = NULL;
    DWORD64 moduleSize = NULL;

    if (GetModuleInformation(hProcess, hMods[i], &modInfo, sizeof(modInfo))) {
        moduleBaseAddress = (DWORD64)modInfo.lpBaseOfDll;
        moduleSize = modInfo.SizeOfImage;
    }

    if (moduleBaseAddress) {
        std::vector<byte> data(moduleSize);
        SIZE_T bytesRead = 0;
        DWORD oldProtect;

        if (!VirtualProtectEx(hProcess, (LPVOID)(moduleBaseAddress), moduleSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
            return 0;
        }

        if (!ReadProcessMemory(hProcess, (LPCVOID)(moduleBaseAddress), data.data(), moduleSize, &bytesRead)) {
            return 0;
        }

        auto pattern = buildPattern(lpPattern, pszMask);

        auto scanStart = data.begin();
        auto resultCnt = 0;

        while (true) {
            auto ret = std::search(scanStart, data.end(), pattern.begin(), pattern.end(),
                [&](unsigned char curr, std::pair<unsigned char, bool> currPattern) {
                return (!currPattern.second) || curr == currPattern.first;
            });

            if (ret == data.end()) {
                break;
            }

            if (resultCnt == resultUsage || resultUsage == 0) {
                VirtualProtectEx(hProcess, (LPVOID)(moduleBaseAddress), moduleSize, oldProtect, &oldProtect);
                return (std::distance(data.begin(), ret) + moduleBaseAddress) + offset;
            }

            resultCnt++;
            scanStart = ++ret;
        }
    }

    return 0;
}

/**
 * @brief                   Scans a given chunk of data for the given pattern and mask.
 *
 * @param pid               PID of process
 * @param moduleName        Name of the module we are looking for
 * @param processAddress    The base address of where the scan data is from.
 * @param lpPattern         The pattern to scan for.
 * @param pszMask           The mask to compare against for wildcards.
 * @param offset            The offset to add to the pointer.
 * @param resultUsage       The result offset to use when locating signatures that match multiple functions.
 *
 * @return                  Pointer of the pattern found, 0 otherwise.
 */
intptr_t moduleAOBScan(unsigned long pid, const char* moduleName, const std::vector<uint8_t>& lpPattern, const char* pszMask, intptr_t offset, intptr_t resultUsage) {
    DWORD processID = (DWORD)pid;
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, processID);

    if (!hProcess) {
        return 0;
    }

    intptr_t fRet = handledModuleAOBScan(hProcess, moduleName, lpPattern, pszMask, offset, resultUsage);

    CloseHandle(hProcess);

    return fRet;
}

/**
 * @brief                   Scans a given chunk of data for the given pattern and mask.
 *
 * @param application       Application name as a string
 * @param moduleName        Name of the module we are looking for
 * @param processAddress    The base address of where the scan data is from.
 * @param lpPattern         The pattern to scan for.
 * @param pszMask           The mask to compare against for wildcards.
 * @param offset            The offset to add to the pointer.
 * @param resultUsage       The result offset to use when locating signatures that match multiple functions.
 *
 * @return                  Pointer of the pattern found, 0 otherwise.
 */
intptr_t moduleAOBScan(const char* application, const char* moduleName, const std::vector<uint8_t>& lpPattern, const char* pszMask, intptr_t offset, intptr_t resultUsage) {
    unsigned long pid = getPID(application);

    if (!pid) {
        return 0;
    }

    return moduleAOBScan(pid, moduleName, lpPattern, pszMask, offset, resultUsage);
}

std::vector<unsigned char> handledReadBytes(HANDLE hProcess, intptr_t address, int n) {
    unsigned char* buffer = new unsigned char[n];
    SIZE_T bytesRead;

    if (!ReadProcessMemory(hProcess, (LPCVOID)(address), buffer, n, &bytesRead)) {
        return std::vector<unsigned char>();
    }

    std::vector<unsigned char> ret(buffer, buffer + n);

    delete buffer;

    return ret;
}

/**
 * @brief           Reads n Bytes from a Process
 *
 * @param pid       Process ID of the Process
 * @param address   Address to Read from
 * @param n         Number of Bytes to Read
 * 
 * @return          Vector Containing the Bytes
 */
std::vector<unsigned char> readBytes(unsigned long pid, intptr_t address, int n) {
    DWORD processID = (DWORD)pid;
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, processID);

    if (!hProcess) {
        return std::vector<unsigned char>();
    }

    std::vector<unsigned char> fRet = handledReadBytes(hProcess, address, n);

    CloseHandle(hProcess);

    return fRet;
}

std::vector<unsigned char> readBytes(const char* application, intptr_t address, int n) {
    unsigned long pid = getPID(application);

    if (!pid) {
        return std::vector<unsigned char>();
    }

    return readBytes(pid, address, n);
}

bool handledWriteBytes(HANDLE hProcess, intptr_t address, int n, const std::vector<unsigned char>& bytes) {
    unsigned char* buffer = new unsigned char[n];
    std::copy(bytes.begin(), bytes.end(), buffer);
    SIZE_T bytesWritten;

    WriteProcessMemory(hProcess, (LPVOID)(address), buffer, n, &bytesWritten);

    delete buffer;

    return bytesWritten == n;
}

bool writeBytes(unsigned long pid, intptr_t address, int n, const std::vector<unsigned char>& bytes) {
    DWORD processID = (DWORD)pid;
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, processID);

    if (!hProcess) {
        return false;
    }

    bool fRet = handledWriteBytes(hProcess, address, n, bytes);

    CloseHandle(hProcess);

    return fRet;
}

bool writeBytes(const char* application, intptr_t address, int n, const std::vector<unsigned char>& bytes) {
    unsigned long pid = getPID(application);

    if (!pid) {
        return 0;
    }

    return writeBytes(pid, address, n, bytes);
}

HANDLE openProcess(unsigned long pid) {
    DWORD processID = (DWORD)pid;
    return OpenProcess(PROCESS_ALL_ACCESS, false, processID);
}

bool closeProcess(HANDLE hProcess) {
    return CloseHandle(hProcess);
}

PYBIND11_MODULE(PyMym, m) {
    m.def("moduleAOBScan", (intptr_t (*)(unsigned long, const char*, const std::vector<uint8_t>&, const char*, intptr_t, intptr_t)) &moduleAOBScan, 
        py::arg("pid"), py::arg("module_name"), py::arg("pattern"), py::arg("mask"), py::arg("offset") = 0, py::arg("result_instance") = 0);
    m.def("readBytes",(std::vector<unsigned char> (*)(unsigned long, intptr_t, int)) &readBytes,
        py::arg("pid"), py::arg("memory_address"), py::arg("num_bytes"));
    m.def("writeBytes", (bool (*)(unsigned long, intptr_t, int, const std::vector<unsigned char>&)) &writeBytes,
        py::arg("pid"), py::arg("memory_address"), py::arg("num_bytes"), py::arg("bytes"));
    m.def("getModules", (std::vector<std::string> (*)(unsigned long)) &getModules,
        py::arg("pid"));
    m.def("moduleAOBScan", (intptr_t (*)(const char*, const char*, const std::vector<uint8_t>&, const char*, intptr_t, intptr_t)) &moduleAOBScan,
        py::arg("application_name"), py::arg("module_name"), py::arg("pattern"), py::arg("mask"), py::arg("offset") = 0, py::arg("result_instance") = 0);
    m.def("readBytes", (std::vector<unsigned char> (*)(const char*, intptr_t, int)) &readBytes,
        py::arg("application_name"), py::arg("memory_address"), py::arg("num_bytes"));
    m.def("writeBytes", (bool (*)(const char*, intptr_t, int, const std::vector<unsigned char>&)) &writeBytes,
        py::arg("application_name"), py::arg("memory_address"), py::arg("num_bytes"), py::arg("bytes"));
    m.def("getModules", (std::vector<std::string> (*)(const char*)) &getModules,
        py::arg("application_name"));
    m.def("getPID", &getPID, py::arg("application_name"));
    m.def("getPIDs", &getPIDs);
    m.def("getProcessNames", &getProcessNames);
    m.def("getProcessName", &getProcessName, py::arg("pid"));
    m.def("heapAOBScan", (intptr_t (*)(unsigned long, const std::vector<uint8_t>&, const char*, intptr_t, intptr_t)) &heapAOBScan,
        py::arg("pid"), py::arg("pattern"), py::arg("mask"), py::arg("offset") = 0, py::arg("retult_instance") = 0);
    m.def("heapAOBScan", (intptr_t (*)(const char*, const std::vector<uint8_t>&, const char*, intptr_t, intptr_t)) &heapAOBScan,
        py::arg("application_name"), py::arg("pattern"), py::arg("mask"), py::arg("offset") = 0, py::arg("retult_instance") = 0);
    m.def("stackAOBScan", (intptr_t (*)(unsigned long, const std::vector<uint8_t>&, const char*, intptr_t, intptr_t)) &stackAOBScan,
        py::arg("pid"), py::arg("pattern"), py::arg("mask"), py::arg("offset") = 0, py::arg("retult_instance") = 0);
    m.def("stackAOBScan", (intptr_t (*)(const char*, const std::vector<uint8_t>&, const char*, intptr_t, intptr_t)) &stackAOBScan,
        py::arg("application_name"), py::arg("pattern"), py::arg("mask"), py::arg("offset") = 0, py::arg("retult_instance") = 0);
    m.def("handledModuleAOBScan", (intptr_t (*)(HANDLE, const char*, const std::vector<uint8_t>&, const char*, intptr_t, intptr_t)) &handledModuleAOBScan, 
        py::arg("process_handle"), py::arg("module_name"), py::arg("pattern"), py::arg("mask"), py::arg("offset") = 0, py::arg("result_instance") = 0);
    m.def("handledReadBytes",(std::vector<unsigned char> (*)(HANDLE, intptr_t, int)) &handledReadBytes,
        py::arg("process_handle"), py::arg("memory_address"), py::arg("num_bytes"));
    m.def("handledWriteBytes", (bool (*)(HANDLE, intptr_t, int, const std::vector<unsigned char>&)) &handledWriteBytes,
        py::arg("process_handle"), py::arg("memory_address"), py::arg("num_bytes"), py::arg("bytes"));
    m.def("handledHeapAOBScan", (intptr_t (*)(HANDLE, const std::vector<uint8_t>&, const char*, intptr_t, intptr_t)) &handledHeapAOBScan,
        py::arg("process_handle"), py::arg("pattern"), py::arg("mask"), py::arg("offset") = 0, py::arg("retult_instance") = 0);
    m.def("handledStackAOBScan", (intptr_t (*)(HANDLE, unsigned long, const std::vector<uint8_t>&, const char*, intptr_t, intptr_t)) &handledStackAOBScan,
        py::arg("process_handle"), py::arg("pid"), py::arg("pattern"), py::arg("mask"), py::arg("offset") = 0, py::arg("retult_instance") = 0);
    m.def("openProcess", (HANDLE (*)(unsigned long)) &openProcess, py::arg("pid"));
    m.def("openProcess", (bool (*)(HANDLE)) &closeProcess, py::arg("process_handle"));
    m.def("handledGetModules", (std::vector<std::string> (*)(HANDLE)) &handledGetModules,
        py::arg("process_handle"));
}