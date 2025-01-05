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

    static void EnableDebugPrivileges();
    std::vector<uint8_t> ReadModuleToVector(const std::string& moduleName);
    std::vector<uint8_t> ReadModuleToVector(uintptr_t moduleBase, size_t moduleSize);
    std::vector<uint8_t> readProcesToVector();
private:
    HANDLE m_processHandle = nullptr;
    static bool m_isDebugPrivilegesEnabled;

    static void SetPrivilege(HANDLE hToken, const wchar_t* privilegeName, bool enablePrivilege);
};

void PrintMemoryLayout(HANDLE hProcess);
void AnalyzeModuleSections(HANDLE processHandle, uintptr_t moduleBase);

#endif // MEMORY_HPP_
