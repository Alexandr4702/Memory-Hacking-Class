#include "Memory.hpp"
#include <Psapi.h>
#include <iostream>

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

uintptr_t Memory::GetModuleBase(const std::string& moduleName) {
    HMODULE hModules[1024];
    DWORD cbNeeded;

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
                    m_moduleBase = reinterpret_cast<uintptr_t>(modInfo.lpBaseOfDll);
                    m_moduleSize = modInfo.SizeOfImage;
                    return m_moduleBase;
                }
            }
        }
    }

    throw std::runtime_error("Module not found");
}

void Memory::ReadModuleToVector(const std::string& moduleName) {
    m_moduleBase = GetModuleBase(moduleName);

    m_moduleMemory.resize(m_moduleSize);
    SIZE_T bytesRead = 0;

    if (!ReadProcessMemory(m_processHandle, reinterpret_cast<LPCVOID>(m_moduleBase), m_moduleMemory.data(), m_moduleSize, &bytesRead)) {
        throw std::runtime_error("Failed to read module memory");
    }

    if (bytesRead != m_moduleSize) {
        throw std::runtime_error("Incomplete memory read");
    }
}

const std::vector<uint8_t>& Memory::GetModuleMemory() const {
    return m_moduleMemory;
}

void Memory::EnableDebugPrivileges() {
    HANDLE tokenHandle;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &tokenHandle)) {
        throw std::runtime_error("Failed to open process token");
    }

    SetPrivilege(tokenHandle, L"SeDebugPrivilege", true);
    CloseHandle(tokenHandle);
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
