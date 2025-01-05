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

    // PrintMemoryLayout(m_processHandle);
}

Memory::~Memory() {
    if (m_processHandle) {
        CloseHandle(m_processHandle);
    }
}

std::vector<uint8_t> Memory::readProcesToVector()
{
    HMODULE hModules[1024];
    DWORD cbNeeded;
    size_t moduleSize = 0;
    uintptr_t moduleBase;
    std::vector<uint8_t> result;

    if (!EnumProcessModules(m_processHandle, hModules, sizeof(hModules), &cbNeeded)) {
        throw std::runtime_error("Failed to enumerate modules");
    }

    size_t moduleCount = cbNeeded / sizeof(HMODULE);

    char moduleFileName[MAX_PATH];
    for (size_t i = 0; i < moduleCount; ++i) {
        MODULEINFO modInfo;
        if (GetModuleBaseNameA(m_processHandle, hModules[i], moduleFileName, sizeof(moduleFileName)) && GetModuleInformation(m_processHandle, hModules[i], &modInfo, sizeof(modInfo))) {
            moduleBase = reinterpret_cast<uintptr_t>(modInfo.lpBaseOfDll);
            moduleSize = modInfo.SizeOfImage;
            std::vector<uint8_t> moduleVec = ReadModuleToVector(moduleBase, moduleSize);
            result.insert(result.end(), moduleVec.begin(), moduleVec.end());
            std::cout 
            << "moduleFileName: " << moduleFileName 
            << " modInfo.lpBaseOfDll: " << modInfo.lpBaseOfDll 
            << " modInfo.SizeOfImage: " << modInfo.SizeOfImage 
            << " common size " << result.size() 
            << "\n";
        }
    }

    return result;
}

std::vector<uint8_t> Memory::ReadModuleToVector(const std::string& moduleName) {
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
        MODULEINFO modInfo;
        if (GetModuleBaseNameA(m_processHandle, hModules[i], moduleFileName, sizeof(moduleFileName)) && GetModuleInformation(m_processHandle, hModules[i], &modInfo, sizeof(modInfo))) {
            std::cout 
            << "moduleFileName: " << moduleFileName 
            << " modInfo.lpBaseOfDll: " << modInfo.lpBaseOfDll 
            << " modInfo.SizeOfImage: " << modInfo.SizeOfImage / 1024 / 1024
            << "\n";
            if (moduleName == moduleFileName)
            {
                moduleBase = reinterpret_cast<uintptr_t>(modInfo.lpBaseOfDll);
                moduleSize = modInfo.SizeOfImage;
                return ReadModuleToVector(moduleBase, moduleSize);
            }
        }
    }
    throw std::runtime_error("Module not found");
}

std::vector<uint8_t> Memory::ReadModuleToVector(uintptr_t moduleBase, size_t moduleSize) {
    SIZE_T bytesRead = 0;
    std::vector<uint8_t> moduleMemory(moduleSize);

    if (!ReadProcessMemory(m_processHandle, reinterpret_cast<LPCVOID>(moduleBase), moduleMemory.data(), moduleSize, &bytesRead)) {
        throw std::runtime_error("Failed to read module memory");
    }

    if (bytesRead != moduleSize) {
        throw std::runtime_error("Incomplete memory read");
    }
    return moduleMemory;
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

void PrintMemoryLayout(HANDLE hProcess) {
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo); // Получить информацию о системе

    MEMORY_BASIC_INFORMATION mbi;
    uintptr_t address = reinterpret_cast<uintptr_t>(sysInfo.lpMinimumApplicationAddress); // Начало памяти процесса

    std::cout << "Memory Layout:" << std::endl;

    while (address < reinterpret_cast<uintptr_t>(sysInfo.lpMaximumApplicationAddress)) {
        // Запрос информации о текущем диапазоне памяти
        if (VirtualQueryEx(hProcess, reinterpret_cast<void*>(address), &mbi, sizeof(mbi))) {
            std::cout << "Base Address: " << mbi.BaseAddress
                      << " | Size: " << mbi.RegionSize
                      << " | State: "
                      << (mbi.State == MEM_COMMIT ? "Committed" :
                          mbi.State == MEM_RESERVE ? "Reserved" :
                          "Free")
                      << " | Type: "
                      << (mbi.Type == MEM_IMAGE ? "Image" :
                          mbi.Type == MEM_MAPPED ? "Mapped" :
                          mbi.Type == MEM_PRIVATE ? "Private" :
                          "Unknown")
                      << std::endl;
        } else {
            std::cerr << "Error querying memory: " << GetLastError() << std::endl;
            break;
        }

        // Переход к следующему блоку памяти
        address += mbi.RegionSize;
    }
}

void AnalyzeModuleSections(HANDLE processHandle, uintptr_t moduleBase) {
    // Читаем DOS-заголовок
    IMAGE_DOS_HEADER dosHeader;
    if (!ReadProcessMemory(processHandle, reinterpret_cast<LPCVOID>(moduleBase), &dosHeader, sizeof(dosHeader), nullptr)) {
        std::cerr << "Failed to read DOS header\n";
        return;
    }

    // Проверяем корректность DOS-заголовка
    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
        std::cerr << "Invalid DOS signature\n";
        return;
    }

    // Читаем заголовок PE
    IMAGE_NT_HEADERS ntHeaders;
    if (!ReadProcessMemory(processHandle, reinterpret_cast<LPCVOID>(moduleBase + dosHeader.e_lfanew), &ntHeaders, sizeof(ntHeaders), nullptr)) {
        std::cerr << "Failed to read NT headers\n";
        return;
    }

    // Проверяем корректность PE-заголовка
    if (ntHeaders.Signature != IMAGE_NT_SIGNATURE) {
        std::cerr << "Invalid PE signature\n";
        return;
    }

    // Читаем секции
    uintptr_t sectionHeaderAddr = moduleBase + dosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS);
    for (int i = 0; i < ntHeaders.FileHeader.NumberOfSections; ++i) {
        IMAGE_SECTION_HEADER sectionHeader;
        if (!ReadProcessMemory(processHandle, reinterpret_cast<LPCVOID>(sectionHeaderAddr), &sectionHeader, sizeof(sectionHeader), nullptr)) {
            std::cerr << "Failed to read section header\n";
            return;
        }

        // Вывод информации о секции
        std::cout << "  Section: " << std::string(reinterpret_cast<char*>(sectionHeader.Name), 8) << "\n";
        std::cout << "    VirtualAddress: 0x" << std::hex << sectionHeader.VirtualAddress << "\n";
        std::cout << "    SizeOfRawData:  0x" << std::hex << sectionHeader.SizeOfRawData << "\n";
        std::cout << "    Characteristics: 0x" << std::hex << sectionHeader.Characteristics << "\n\n";

        // Переход к следующей секции
        sectionHeaderAddr += sizeof(IMAGE_SECTION_HEADER);
    }
}