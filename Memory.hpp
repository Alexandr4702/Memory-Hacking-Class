#ifndef MEMORY_HPP_
#define MEMORY_HPP_

#include <windows.h>
#include <TlHelp32.h>
#include <string>
#include <psapi.h>

class Memory
{
public:
    int GetProcessId(std::wstring & processName);
    HMODULE GetModuleBase(HANDLE processHandle, std::string &sModuleName);
    BOOL SetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege);
    BOOL GetDebugPrivileges(void);
    int ReadInt(HANDLE processHandle, int address);
    int GetPointerAddress(HANDLE processHandle, int startAddress, int offsets[], int offsetCount);
    int ReadPointerInt(HANDLE processHandle, int startAddress, int offsets[], int offsetCount);
    float ReadFloat(HANDLE processHandle, int address);
    float ReadPointerFloat(HANDLE processHandle, int startAddress, int offsets[], int offsetCount);
    char* ReadText(HANDLE processHandle, int address);
    char* ReadPointerText(HANDLE processHandle, int startAddress, int offsets[], int offsetCount);
};

#endif // MEMORY_HPP_