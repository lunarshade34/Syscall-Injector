#include <iostream>
#include <string>
#include <limits>
#define WIN32_NO_STATUS 
#include <Windows.h>
#undef WIN32_NO_STATUS 
#include <ntstatus.h>
#include "obfuscate.h"
#include "lazy.hpp"
#include <winternl.h>
#pragma comment(lib, "ntdll.lib")

using namespace std;

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

typedef struct _INITIAL_TEB {
    PVOID StackBase;
    PVOID StackLimit;
    PVOID StackCommit;
    PVOID StackCommitMax;
    PVOID StackReserved;
} INITIAL_TEB, * PINITIAL_TEB;

typedef NTSTATUS(NTAPI* hNtOpenProcess)(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    CLIENT_ID ClientId
    );

typedef NTSTATUS(NTAPI* hNtAllocateVirtualMemory)(
    HANDLE    ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T   RegionSize,
    ULONG     AllocationType,
    ULONG     Protect
    );

typedef NTSTATUS(NTAPI* hNtWriteVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID  BaseAddress,
    PVOID  Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten
    );

typedef NTSTATUS(NTAPI* hLdrLoadDll)(
    PWCHAR               PathToFile,
    ULONG                Flags,
    PUNICODE_STRING      ModuleFileName,
    PHANDLE             ModuleHandle
    );

typedef NTSTATUS(NTAPI* pfnNtCreateThreadEx)(
    PHANDLE            ThreadHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE             ProcessHandle,
    PVOID              StartRoutine,
    PVOID              Argument,
    ULONG              CreateFlags,
    SIZE_T             ZeroBits,
    SIZE_T             StackSize,
    SIZE_T             MaximumStackSize,
    PVOID              AttributeList
    );

int main()
{
    auto NtOpenProcess = reinterpret_cast<hNtOpenProcess>(
        LI_FN(GetProcAddress).get()(LI_FN(GetModuleHandleA).get()(xorstr_("ntdll.dll")), xorstr_("NtOpenProcess"))
        );
    auto NtAllocateVirtualMemory = reinterpret_cast<hNtAllocateVirtualMemory>(
        LI_FN(GetProcAddress).get()(LI_FN(GetModuleHandleA).get()(xorstr_("ntdll.dll")), xorstr_("NtAllocateVirtualMemory"))
        );
    auto NtWriteVirtualMemory = reinterpret_cast<hNtWriteVirtualMemory>(
        LI_FN(GetProcAddress).get()(LI_FN(GetModuleHandleA).get()(xorstr_("ntdll.dll")), xorstr_("NtWriteVirtualMemory"))
        );
    auto LdrLoadDll = reinterpret_cast<hLdrLoadDll>(
        LI_FN(GetProcAddress).get()(LI_FN(GetModuleHandleA).get()(xorstr_("ntdll.dll")), xorstr_("LdrLoadDll"))
        );
    auto NtCreateThreadEx = reinterpret_cast<pfnNtCreateThreadEx>(
        LI_FN(GetProcAddress).get()(LI_FN(GetModuleHandleA).get()(xorstr_("ntdll.dll")), xorstr_("NtCreateThreadEx"))
        );

    auto MsgBoxW = LI_FN(MessageBoxW).get();

    DWORD PID = 0;
    cout << xorstr_("Enter PID : ");
    cin >> PID;
    std::cin.ignore((std::numeric_limits<std::streamsize>::max)(), '\n');

    std::string dllPathInput;
    std::cout << xorstr_("Enter DLL path : ");
    std::getline(cin, dllPathInput);

    if (dllPathInput.size() >= 2 && dllPathInput.front() == '"' && dllPathInput.back() == '"') {
        dllPathInput = dllPathInput.substr(1, dllPathInput.size() - 2);
    }

    std::wstring dllPath(dllPathInput.begin(), dllPathInput.end());

    HANDLE hProcess = nullptr;
    OBJECT_ATTRIBUTES obj{};
    InitializeObjectAttributes(&obj, nullptr, 0, nullptr, nullptr);

    CLIENT_ID client_ID{};
    client_ID.UniqueProcess = reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(PID));
    client_ID.UniqueThread = nullptr;

    NTSTATUS status1 = NtOpenProcess(
        &hProcess,
        PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD,
        &obj,
        client_ID
    );

    if (status1 == STATUS_ACCESS_DENIED) {
        Beep(750, 1000);
        if (MsgBoxW) MsgBoxW(nullptr, xorstr_(L"Run the injector as an administrator"), xorstr_(L"Error"), MB_OK);
        return 0;
    }
    else if (!NT_SUCCESS(status1) || !hProcess) {
        Beep(750, 1000);
        if (MsgBoxW) MsgBoxW(nullptr, xorstr_(L"NtOpenProcess failed"), xorstr_(L"Error"), MB_OK);
        return 0;
    }

    PVOID remoteBaseAddr = nullptr;
    SIZE_T regionSize = (dllPath.size() + 1) * sizeof(wchar_t);

    NTSTATUS status2 = NtAllocateVirtualMemory(
        hProcess,
        &remoteBaseAddr,
        0,
        &regionSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (!NT_SUCCESS(status2) || !remoteBaseAddr) {
        Beep(750, 1000);
        if (MsgBoxW) MsgBoxW(nullptr, xorstr_(L"NtAllocateVirtualMemory failed"), xorstr_(L"Error"), MB_OK);
        LI_FN(CloseHandle).get()(hProcess);
        return 0;
    }

    SIZE_T bytesWritten = 0;
    NTSTATUS status3 = NtWriteVirtualMemory(
        hProcess,
        remoteBaseAddr,
        (PVOID)dllPath.c_str(),
        regionSize,
        &bytesWritten
    );

    if (!NT_SUCCESS(status3)) {
        Beep(750, 1000);
        if (MsgBoxW) MsgBoxW(nullptr, xorstr_(L"NtWriteVirtualMemory failed"), xorstr_(L"Error"), MB_OK);
        LI_FN(VirtualFreeEx).get()(hProcess, remoteBaseAddr, 0, MEM_RELEASE);
        LI_FN(CloseHandle).get()(hProcess);
        return 0;
    }

    HMODULE hKernel32 = LI_FN(GetModuleHandleW).get()(xorstr_(L"kernel32.dll"));
    FARPROC pLoadLibraryW = LI_FN(GetProcAddress).get()(hKernel32, xorstr_("LoadLibraryW"));
    if (!pLoadLibraryW) {
        Beep(750, 1000);
        if (MsgBoxW) MsgBoxW(nullptr, xorstr_(L"LoadLibraryW failed"), xorstr_(L"Error"), MB_OK);
        LI_FN(VirtualFreeEx).get()(hProcess, remoteBaseAddr, 0, MEM_RELEASE);
        LI_FN(CloseHandle).get()(hProcess);
        return 0;
    }

    HANDLE hThread = nullptr;
    NTSTATUS createThread = NtCreateThreadEx(
        &hThread,
        THREAD_ALL_ACCESS,
        nullptr,
        hProcess,
        reinterpret_cast<PVOID>(pLoadLibraryW),
        remoteBaseAddr,
        0,
        0,
        0,
        0,
        nullptr
    );

    if (!NT_SUCCESS(createThread) || !hThread) {
        Beep(750, 1000);
        if (MsgBoxW) MsgBoxW(nullptr, xorstr_(L"NtCreateThreadEx failed"), xorstr_(L"Error"), MB_OK);
        LI_FN(VirtualFreeEx).get()(hProcess, remoteBaseAddr, 0, MEM_RELEASE);
        LI_FN(CloseHandle).get()(hProcess);
        return 0;
    }

    cout << xorstr_("Injection success...\n");

    LI_FN(WaitForSingleObject).get()(hThread, 5000);
    LI_FN(VirtualFreeEx).get()(hProcess, remoteBaseAddr, 0, MEM_RELEASE);
    LI_FN(CloseHandle).get()(hThread);
    LI_FN(CloseHandle).get()(hProcess);

    cin.get();
    return 0;
}