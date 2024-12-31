#ifndef MEMORY_HPP_
#define MEMORY_HPP_

#include <windows.h>
#include <TlHelp32.h>
#include <string>
#include <vector>
#include <stdexcept>
#include <cstdint>

class Memory {
public:
    explicit Memory(const std::wstring& processName);
    ~Memory();

    uintptr_t GetModuleBase(const std::string& moduleName);
    void EnableDebugPrivileges();
    void ReadModuleToVector(const std::string& moduleName);

    const std::vector<uint8_t>& GetModuleMemory() const;

private:
    HANDLE m_processHandle = nullptr;
    uintptr_t m_moduleBase = 0;
    size_t m_moduleSize = 0;
    std::vector<uint8_t> m_moduleMemory;

    static void SetPrivilege(HANDLE hToken, const wchar_t* privilegeName, bool enablePrivilege);
};

#endif // MEMORY_HPP_
