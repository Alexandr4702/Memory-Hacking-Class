#include "Memory.hpp"
#include <Psapi.h>
#include <iostream>

bool Memory::m_isDebugPrivilegesEnabled = false;

Memory::Memory(const std::wstring& processName) {
    EnableDebugPrivileges();

    HWND hwnd = FindWindowW(nullptr, processName.c_str());
    if (!hwnd) {
        throw std::runtime_error("Failed to find process window");
    }

    DWORD processId;
    GetWindowThreadProcessId(hwnd, &processId);

    m_processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (!m_processHandle) {
        throw std::runtime_error("Failed to open process");
    }
}

Memory::~Memory() {
    if (m_processHandle) {
        CloseHandle(m_processHandle);
    }
}

void Memory::ReadModuleToVector(const std::string& moduleName) {
    HMODULE hModules[1024];
    DWORD cbNeeded;
    size_t moduleSize = 0;
    uintptr_t moduleBase;

    if (!EnumProcessModules(m_processHandle, hModules, sizeof(hModules), &cbNeeded)) {
        throw std::runtime_error("Failed to enumerate modules");
    }

    size_t moduleCount = cbNeeded / sizeof(HMODULE);

    char moduleFileName[MAX_PATH];
    for (size_t i = 0; i < moduleCount; ++i) {
        if (GetModuleBaseNameA(m_processHandle, hModules[i], moduleFileName, sizeof(moduleFileName))) {
            if (moduleName == moduleFileName) {
                MODULEINFO modInfo;
                if (GetModuleInformation(m_processHandle, hModules[i], &modInfo, sizeof(modInfo))) {
                    moduleBase = reinterpret_cast<uintptr_t>(modInfo.lpBaseOfDll);
                    moduleSize = modInfo.SizeOfImage;
                    ReadModuleToVector(moduleBase, moduleSize);
                    return;
                }
            }
        }
    }

    throw std::runtime_error("Module not found");
}

void Memory::ReadModuleToVector(uintptr_t moduleBase, size_t moduleSize) {
    SIZE_T bytesRead = 0;
    m_moduleMemory.resize(moduleSize);

    if (!ReadProcessMemory(m_processHandle, reinterpret_cast<LPCVOID>(moduleBase), m_moduleMemory.data(), moduleSize, &bytesRead)) {
        throw std::runtime_error("Failed to read module memory");
    }

    if (bytesRead != moduleSize) {
        throw std::runtime_error("Incomplete memory read");
    }
}

const std::vector<uint8_t>& Memory::GetModuleMemory() const {
    return m_moduleMemory;
}

void Memory::EnableDebugPrivileges() {
    if(m_isDebugPrivilegesEnabled)
        return;

    HANDLE tokenHandle;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &tokenHandle)) {
        throw std::runtime_error("Failed to open process token");
    }

    SetPrivilege(tokenHandle, L"SeDebugPrivilege", true);
    CloseHandle(tokenHandle);
    m_isDebugPrivilegesEnabled = true;
}

void Memory::SetPrivilege(HANDLE hToken, const wchar_t* privilegeName, bool enablePrivilege) {
    TOKEN_PRIVILEGES tp = {};
    LUID luid;

    if (!LookupPrivilegeValueW(nullptr, privilegeName, &luid)) {
        throw std::runtime_error("Failed to look up privilege value");
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = enablePrivilege ? SE_PRIVILEGE_ENABLED : 0;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr)) {
        throw std::runtime_error("Failed to adjust token privileges");
    }
}
