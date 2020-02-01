#include <iostream>
#include <Windows.h>
#include <vector>

#include "VMProtectSDK.h"

#define NT_CURRENT_PROCESS (HANDLE)-1
auto ntdllBase = GetModuleHandleW(L"ntdll");

PVOID GetNtdllExport(const char* procName) {
    return static_cast<PVOID>(GetProcAddress(ntdllBase, procName));
}

bool MemoryCompare(const BYTE* bData, const BYTE* bMask, const char* szMask) {
    for (; *szMask; ++szMask, ++bData, ++bMask) {
        if (*szMask == 'x' && *bData != *bMask) {
            return false;
        }
    }
    return (*szMask == NULL);
}

PVOID FindSignature(PVOID start, ULONG size, const BYTE* sig, const char* mask) {
    auto base = uintptr_t(start);
    
    for (DWORD i = 0; i < size; i++)
        if (MemoryCompare((const BYTE*)(base + i), (const BYTE*)sig, mask))
            return reinterpret_cast<PVOID>(base + i);

    return nullptr;
}

std::vector<PBYTE> GenerateScyllaIAT() {
    //IAT thunk begin
    static const std::vector<std::string> procNames = 
    {
        "LdrGetProcedureAddress",
        "RtlEqualUnicodeString",
        "LdrGetDllHandle",
        "DbgBreakPoint",
        "RtlImageNtHeader"
    };

    std::vector<PBYTE> retVal;
    for (const auto proc : procNames)
        retVal.push_back(static_cast<PBYTE>(GetNtdllExport(proc.c_str())));

    return retVal;
}

///Didn't wanna change 'MemoryCompare' so...
std::string GenerateIATMask(std::vector<PBYTE> iatList) {
    std::string s;
    for (size_t i = 0; i < iatList.size(); i++)
        for (size_t j = 0; j < sizeof(uintptr_t); j++)
            s += 'x';

    return s;
}

PVOID FindScyllaIAT(MEMORY_BASIC_INFORMATION mem) {
    static const auto iat = GenerateScyllaIAT();
    static const auto mask = GenerateIATMask(iat);
    
    return FindSignature(mem.AllocationBase, mem.RegionSize, reinterpret_cast<const BYTE*>(&iat[0]), mask.c_str());
}

PVOID GetScyllaHide(PULONG size) {
    static const auto NtQueryVirtualMemory = reinterpret_cast<NTSTATUS(__stdcall*)(HANDLE, PVOID, int, PVOID, ULONG, PULONG)>(GetNtdllExport(VMProtectDecryptStringA("NtQueryVirtualMemory")));
    
    MEMORY_BASIC_INFORMATION mem;   
    bool validPage = false;
        
    validPage = !NtQueryVirtualMemory(NT_CURRENT_PROCESS, nullptr, 0, &mem, sizeof(mem), nullptr);
    do {
        if (mem.Type == MEM_PRIVATE && 
            mem.State == MEM_COMMIT &&
            mem.Protect & PAGE_EXECUTE_READWRITE &&
            mem.AllocationProtect & PAGE_EXECUTE_READWRITE) {
            
            if (FindScyllaIAT(mem)) {
                if (size)
                    *size = mem.RegionSize;

                return mem.AllocationBase;
            }
        }
        
        validPage = !NtQueryVirtualMemory(NT_CURRENT_PROCESS, reinterpret_cast<PVOID>(uintptr_t(mem.BaseAddress) + mem.RegionSize), 0, &mem, sizeof(mem), nullptr);
    } while (validPage);

    return nullptr;
}

void SapScyllaHide() {
    ULONG memSize = 0;
    const auto ptr = GetScyllaHide(&memSize);

    if (ptr)
        std::memset(ptr, 0x00, memSize);
}

bool DebuggerPresent() {    
    static auto ZwQueryInformationProcess = reinterpret_cast<NTSTATUS(__stdcall*)(HANDLE, int, PVOID, ULONG, PULONG)>(GetNtdllExport(VMProtectDecryptStringA("NtQueryInformationProcess")));
    
    DWORD debuggerInherit = 0;    
    return !ZwQueryInformationProcess(NT_CURRENT_PROCESS, 7, &debuggerInherit, sizeof(debuggerInherit), NULL) && debuggerInherit;
}

int main()
{   
    VMProtectBeginUltra(__FUNCTION__);
    
    while (true) {
        SapScyllaHide();

        auto debuggerStatus = DebuggerPresent() ? VMProtectDecryptStringA("Debugger Detected !\n") : VMProtectDecryptStringA("No Debugger Detected !\n");

        printf(debuggerStatus);

        printf(VMProtectDecryptStringA("No ScyllaHide detected !\n"));
        Sleep(1000);
    }

    VMProtectEnd();
}