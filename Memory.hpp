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

    void EnableDebugPrivileges();
    void ReadModuleToVector(const std::string& moduleName);
    void ReadModuleToVector(uintptr_t moduleBase, size_t moduleSize);

    const std::vector<uint8_t>& GetModuleMemory() const;

private:
    HANDLE m_processHandle = nullptr;
    std::vector<uint8_t> m_moduleMemory;

    static void SetPrivilege(HANDLE hToken, const wchar_t* privilegeName, bool enablePrivilege);
};

#endif // MEMORY_HPP_
